package discovery

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Febrian-chiperbase/CoyoteKey/pkg/common"
	"github.com/getkin/kin-openapi/openapi3"
)

// --- Struct Argumen & State Internal ---

// Args adalah struktur untuk membawa semua dependensi dan konfigurasi ke mode discovery.
type Args struct {
	BaseURL, PathWordlistPath, ParamWordlistPath, DiscoveryMethodsRaw, FuzzMethodsRaw, BaselineIgnoreCodesRaw, FuzzTestValuesRaw string
	MaxDepth, Threads                                                                                                            int
	RateLimitIncrease                                                                                                            time.Duration
	FuzzJSONTemplatePath, SpecFilePath, FingerprintDBPath, ContextWordlistDir, MinConfidence                                     string
	RunVulnScan                                                                                                                  bool
	VulnDBPath                                                                                                                   string
	HttpClient                                                                                                                   *http.Client
	NormalLog, VerboseLog                                                                                                        *log.Logger
	DiscoveredPathMap                                                                                                            *map[string]common.DiscoveredPath
	Mutex                                                                                                                        *sync.Mutex
}

// workerArgs adalah struct internal untuk argumen worker.
type workerArgs struct {
	discoveryMethods, fuzzMethods, fuzzTestValues, paramWordlist []string
	baselineIgnoreCodes                                          map[int]bool
	fuzzJSONTemplate                                             string
	rateLimitIncrease                                            time.Duration
	httpClient                                                   *http.Client
	normalLog, verboseLog                                        *log.Logger
	resultsChan                                                  chan<- common.DiscoveredPath
	baselineProfile                                              common.BaselineProfile
}

// --- Fungsi Utama yang Diekspor ---

// Run adalah fungsi utama yang diekspor untuk menjalankan logika discovery.
func Run(args Args) {
	args.NormalLog.Println("--- Running in Discovery Mode ---")

	var specPaths, specParams []string
	if args.SpecFilePath != "" {
		specPaths, specParams = processOpenAPISpec(args.SpecFilePath, args.NormalLog)
	}

	if args.SpecFilePath == "" && args.PathWordlistPath == "" {
		args.NormalLog.Fatal("[Discovery Mode] Path Wordlist (-pw) or Spec file (--spec) is required.")
	}

	pathWordlistFromFile, err := common.LoadWordlist(args.PathWordlistPath, args.NormalLog)
	if err != nil {
		args.NormalLog.Fatalf("[Discovery Mode] Error loading path wordlist: %v", err)
	}
	paramWordlistFromFile, _ := common.LoadWordlist(args.ParamWordlistPath, args.NormalLog)

	detectedTechs := fingerprintTarget(args.BaseURL, args.HttpClient, args.FingerprintDBPath, args.NormalLog, args.VerboseLog)
	inferredStacks := inferTechnologyStack(detectedTechs)
	if len(inferredStacks) > 0 {
		args.NormalLog.Printf("[Fingerprint] Inferred technology stack(s): %v\n", inferredStacks)
	}

	contextualPathWordlist := loadContextualWordlists(detectedTechs, args.ContextWordlistDir, args.MinConfidence, args.NormalLog, args.VerboseLog)

	pathWordlist := common.MergeAndDeduplicateSlices(pathWordlistFromFile, specPaths)
	pathWordlist = common.MergeAndDeduplicateSlices(pathWordlist, contextualPathWordlist)
	paramWordlist := common.MergeAndDeduplicateSlices(paramWordlistFromFile, specParams)

	if len(pathWordlist) == 0 {
		args.NormalLog.Fatal("[Discovery Mode] No paths to test after merging all sources.")
	}
	args.NormalLog.Printf("[Discovery Mode] Total unique paths to test: %d\n", len(pathWordlist))
	if len(paramWordlist) > 0 {
		args.NormalLog.Printf("[Discovery Mode] Total unique parameters to fuzz: %d\n", len(paramWordlist))
	}

	discoveryMethods := common.ParseCommaSeparatedString(args.DiscoveryMethodsRaw)
	fuzzMethods := common.ParseCommaSeparatedString(args.FuzzMethodsRaw)
	baselineIgnoreCodes := common.ParseSuccessCodes(args.BaselineIgnoreCodesRaw, args.NormalLog)
	fuzzTestValues := common.ParseCommaSeparatedString(args.FuzzTestValuesRaw)

	var fuzzJSONTemplate string
	if args.FuzzJSONTemplatePath != "" {
		templateBytes, err := os.ReadFile(args.FuzzJSONTemplatePath)
		if err != nil {
			args.NormalLog.Fatalf("[Discovery Mode] Error reading JSON fuzz template file %s: %v", args.FuzzJSONTemplatePath, err)
		}
		fuzzJSONTemplate = string(templateBytes)
	}

	baselineProfile := performBaselineRequests(args.BaseURL, args.HttpClient, args.NormalLog, args.VerboseLog)
	args.NormalLog.Printf("[Discovery Mode] Baseline Profile: RandomPathNotFound (Status: %d, CL: %d)\n",
		baselineProfile.RandomPathNotFound.StatusCode, baselineProfile.RandomPathNotFound.ContentLength)

	currentLevelPathsToExplore := []string{strings.TrimRight(args.BaseURL, "/")}

	for depth := 0; depth <= args.MaxDepth; depth++ {
		if len(currentLevelPathsToExplore) == 0 && depth > 0 {
			args.NormalLog.Printf("[Discovery Mode] No new valid paths found at depth %d to explore further. Stopping recursion.\n", depth-1)
			break
		}
		args.NormalLog.Printf("[Discovery Mode] Starting discovery at Depth %d. Base paths to explore: %d\n", depth, len(currentLevelPathsToExplore))

		discoveryJobsChan := make(chan common.DiscoveryJob, len(currentLevelPathsToExplore)*len(pathWordlist))
		discoveryResultsChan := make(chan common.DiscoveredPath, 200)
		var wg, collectorsWg sync.WaitGroup
		collectorsWg.Add(1)

		go func() {
			defer collectorsWg.Done()
			for pathInfo := range discoveryResultsChan {
				processDiscoveryResult(pathInfo, args.DiscoveredPathMap, args.Mutex, args.NormalLog)
			}
		}()

		workerArgs := workerArgs{
			discoveryMethods:    discoveryMethods,
			baselineIgnoreCodes: baselineIgnoreCodes,
			paramWordlist:       paramWordlist,
			fuzzMethods:         fuzzMethods,
			fuzzTestValues:      fuzzTestValues,
			fuzzJSONTemplate:    fuzzJSONTemplate,
			rateLimitIncrease:   args.RateLimitIncrease,
			httpClient:          args.HttpClient,
			normalLog:           args.NormalLog,
			verboseLog:          args.VerboseLog,
			resultsChan:         discoveryResultsChan,
			baselineProfile:     baselineProfile,
		}
		for i := 0; i < args.Threads; i++ {
			wg.Add(1)
			go worker(i+1, workerArgs, discoveryJobsChan, &wg)
		}

		jobCount := 0
		wordlistForThisDepth := pathWordlistFromFile
		if depth == 0 {
			wordlistForThisDepth = pathWordlist
		}

		for _, basePath := range currentLevelPathsToExplore {
			for _, segment := range wordlistForThisDepth {
				jobCount++
				discoveryJobsChan <- common.DiscoveryJob{
					BaseURLForNextLevel: basePath,
					PathSegmentToTest:   segment,
					CurrentDepth:        depth,
				}
			}
		}
		args.NormalLog.Printf("[Discovery Mode] Depth %d: Submitted %d jobs to workers.\n", depth, jobCount)

		close(discoveryJobsChan)
		wg.Wait()
		close(discoveryResultsChan)
		collectorsWg.Wait()

		if depth < args.MaxDepth {
			newPathsToExplore := []string{}
			args.Mutex.Lock()
			for _, pathInfo := range *args.DiscoveredPathMap {
				if pathInfo.Depth == depth && pathInfo.IsLikelyValid {
					newPathsToExplore = append(newPathsToExplore, pathInfo.URL)
				}
			}
			args.Mutex.Unlock()
			currentLevelPathsToExplore = newPathsToExplore
		} else {
			args.NormalLog.Printf("[Discovery Mode] Reached max depth of %d.\n", args.MaxDepth)
		}
	}

	if args.RunVulnScan {
		runVulnerabilityProbes(args.BaseURL, detectedTechs, args)
	}
}

// --- Fungsi-Fungsi Internal Paket Discovery ---

func processDiscoveryResult(pathInfo common.DiscoveredPath, discoveredPathMap *map[string]common.DiscoveredPath, m *sync.Mutex, normalLog *log.Logger) {
	mapMutexKey := pathInfo.Method + " " + pathInfo.URL
	m.Lock()
	defer m.Unlock()

	existing, foundInMap := (*discoveredPathMap)[mapMutexKey]
	if !foundInMap || (len(pathInfo.FoundParameters) > len(existing.FoundParameters)) || (!existing.IsLikelyValid && pathInfo.IsLikelyValid) {
		if foundInMap {
			pathInfo.FoundParameters = common.MergeDiscoveredParameters(existing.FoundParameters, pathInfo.FoundParameters)
		}
		(*discoveredPathMap)[mapMutexKey] = pathInfo

		paramCount := len(pathInfo.FoundParameters)
		logMessage := ""
		if pathInfo.IsLikelyValid {
			logMessage = fmt.Sprintf("[VALID DEPTH %d] %s %s (Status: %d, CL: %d, Params: %d)",
				pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, paramCount)
		} else if paramCount > 0 {
			logMessage = fmt.Sprintf("[INFO  DEPTH %d] %s %s (Status: %d, ParamsFound: %d)",
				pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, paramCount)
		}
		if logMessage != "" {
			normalLog.Println(logMessage)
		}
	}
}

func worker(id int, args workerArgs, jobs <-chan common.DiscoveryJob, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		common.ApplyDynamicDelayAndCooldown(args.verboseLog)

		fullURL, err := url.JoinPath(job.BaseURLForNextLevel, job.PathSegmentToTest)
		if err != nil {
			args.verboseLog.Printf("[DiscoveryWorker %d] Error joining URL: %v\n", id, err)
			continue
		}
		args.verboseLog.Printf("[DiscoveryWorker %d] Path discovery: %s\n", id, fullURL)

		basePathResponses := make(map[string]common.ResponseCharacteristics)
		for _, method := range args.discoveryMethods {
			req, _ := http.NewRequest(method, fullURL, nil)
			req.Header.Set("User-Agent", "APIRecon/1.0 (Discovery)")
			resp, err := args.httpClient.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusTooManyRequests {
				common.HandleRateLimit(resp, args.rateLimitIncrease, args.normalLog, args.verboseLog)
				resp.Body.Close()
				continue
			}

			fuzzContentType := resp.Header.Get("Content-Type")
			bodyBytes, cl := common.ReadAndCloseBody(resp, args.verboseLog)
			basePathResponses[method] = common.ResponseCharacteristics{
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				ContentType:   fuzzContentType,
			}

			isLikelyValid, comparisonNote := compareWithBaseline(resp.StatusCode, cl, args.baselineIgnoreCodes, args.baselineProfile)
			foundParamsFromError := parseErrorsForParams(bodyBytes)
			allFoundOnPathParams := foundParamsFromError

			shouldFuzz := isLikelyValid || len(foundParamsFromError) > 0
			if shouldFuzz && (len(args.paramWordlist) > 0 || args.fuzzJSONTemplate != "") {
				args.verboseLog.Printf("[DiscoveryWorker %d] Starting parameter fuzzing for %s %s\n", id, method, fullURL)
				fuzzedParams := fuzzParametersOnPath(fullURL, basePathResponses[method], args, id)
				if len(fuzzedParams) > 0 {
					allFoundOnPathParams = common.MergeDiscoveredParameters(allFoundOnPathParams, fuzzedParams)
				}
			}

			args.resultsChan <- common.DiscoveredPath{
				URL: fullURL, Method: method, StatusCode: resp.StatusCode, ContentLength: cl,
				BaselineComparison: comparisonNote, IsLikelyValid: isLikelyValid,
				FoundParameters: allFoundOnPathParams, Depth: job.CurrentDepth, Timestamp: time.Now().UTC(),
			}
		}
	}
}

func fuzzParametersOnPath(pathURL string, basePathResponseChars common.ResponseCharacteristics, args workerArgs, workerID int) []common.DiscoveredParameter {
	var fuzzedParams []common.DiscoveredParameter
	uniqueParamsFound := make(map[string]common.DiscoveredParameter)

	for _, fuzzMethod := range args.fuzzMethods {
		for _, paramName := range args.paramWordlist {
			for _, testValue := range args.fuzzTestValues {
				if fuzzMethod == "GET" || fuzzMethod == "POST" {
					fuzzURL, _ := url.Parse(pathURL)
					q := fuzzURL.Query()
					q.Set(paramName, testValue)
					fuzzURL.RawQuery = q.Encode()
					req, err := http.NewRequest(fuzzMethod, fuzzURL.String(), nil)
					if err == nil {
						if p, ok := analyzeFuzzResponse(req, "query", paramName, testValue, basePathResponseChars, workerID, args); ok {
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}
				if fuzzMethod == "POST" || fuzzMethod == "PUT" || fuzzMethod == "PATCH" {
					formData := url.Values{}
					formData.Set(paramName, testValue)
					req, err := http.NewRequest(fuzzMethod, pathURL, strings.NewReader(formData.Encode()))
					if err == nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						if p, ok := analyzeFuzzResponse(req, "form_body", paramName, testValue, basePathResponseChars, workerID, args); ok {
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}
				if (fuzzMethod == "POST" || fuzzMethod == "PUT" || fuzzMethod == "PATCH") && args.fuzzJSONTemplate != "" {
					bodyStr := strings.Replace(args.fuzzJSONTemplate, "%PARAM%", paramName, -1)
					bodyStr = strings.Replace(bodyStr, "%FUZZ%", testValue, -1)
					req, err := http.NewRequest(fuzzMethod, pathURL, strings.NewReader(bodyStr))
					if err == nil {
						req.Header.Set("Content-Type", "application/json")
						if p, ok := analyzeFuzzResponse(req, "json_body", paramName, testValue, basePathResponseChars, workerID, args); ok {
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}
			}
		}
	}
	for _, p := range uniqueParamsFound {
		fuzzedParams = append(fuzzedParams, p)
	}
	return fuzzedParams
}

func analyzeFuzzResponse(req *http.Request, paramIn, paramName, testValue string, baseChars common.ResponseCharacteristics, workerID int, args workerArgs) (*common.DiscoveredParameter, bool) {
	common.ApplyDynamicDelayAndCooldown(args.verboseLog)
	req.Header.Set("User-Agent", "APIRecon/1.0 (ParamFuzzer)")

	resp, err := args.httpClient.Do(req)
	if err != nil {
		args.verboseLog.Printf("[ParamFuzzer %d] Error sending fuzz request for %s: %v\n", workerID, req.URL.String(), err)
		return nil, false
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		common.HandleRateLimit(resp, args.rateLimitIncrease, args.normalLog, args.verboseLog)
		resp.Body.Close()
		return nil, false
	}

	fuzzBodyBytes, fuzzCL := common.ReadAndCloseBody(resp, args.verboseLog)
	args.verboseLog.Printf("[ParamFuzzer %d] Fuzz Resp: %s %s (%s=%s in %s) -> Status: %d, CL: %d\n", workerID, req.Method, req.URL.Path, paramName, testValue, paramIn, resp.StatusCode, fuzzCL)

	note, isInteresting := "", false
	if resp.StatusCode != baseChars.StatusCode {
		note = fmt.Sprintf("status_changed_from_%d", baseChars.StatusCode)
		isInteresting = true
	}
	if clDiff := fuzzCL - baseChars.ContentLength; clDiff > 30 || clDiff < -30 {
		if note != "" {
			note += "; "
		}
		note += fmt.Sprintf("cl_changed_from_%d", baseChars.ContentLength)
		isInteresting = true
	}
	fuzzContentType := resp.Header.Get("Content-Type")
	if fuzzContentType != "" && baseChars.ContentType != "" && !strings.Contains(fuzzContentType, baseChars.ContentType) && !strings.Contains(baseChars.ContentType, fuzzContentType) {
		if note != "" {
			note += "; "
		}
		note += fmt.Sprintf("content_type_changed_from_%s", baseChars.ContentType)
		isInteresting = true
	}
	if len(testValue) > 3 && strings.Contains(string(fuzzBodyBytes), testValue) {
		if note != "" {
			note += "; "
		}
		note += "value_reflected_in_body"
		isInteresting = true
	}

	if isInteresting {
		args.normalLog.Printf("[PARAM FUZZ FOUND] %s %s: Param '%s' in '%s' interesting. Notes: %s\n",
			req.Method, req.URL.Path, paramName, paramIn, note)
		return &common.DiscoveredParameter{Name: paramName, In: paramIn, Notes: note, TestedValues: []string{testValue}}, true
	}
	return nil, false
}

func parseErrorsForParams(body []byte) []common.DiscoveredParameter {
	var foundParams []common.DiscoveredParameter
	bodyString := string(body)
	for _, re := range common.ErrorParamRegexList {
		matches := re.FindAllStringSubmatch(bodyString, -1)
		for _, match := range matches {
			if len(match) > 1 {
				paramName := strings.Trim(match[1], "`'\" ")
				paramName = strings.ReplaceAll(paramName, " field", "")
				if paramName != "" && !common.ParameterExists(foundParams, paramName) {
					foundParams = append(foundParams, common.DiscoveredParameter{Name: paramName, In: "unknown_from_error", Notes: "derived_from_error_message", Evidence: common.TruncateString(match[0], 100)})
				}
			}
		}
	}
	return foundParams
}

func compareWithBaseline(statusCode int, contentLength int64, baselineIgnoreCodes map[int]bool, baselineProfile common.BaselineProfile) (bool, string) {
	isLikelyValid, comparisonNote := false, ""
	clDiff := contentLength - baselineProfile.RandomPathNotFound.ContentLength
	if clDiff < 0 {
		clDiff = -clDiff
	}

	if statusCode != baselineProfile.RandomPathNotFound.StatusCode {
		isLikelyValid = true
		comparisonNote = "status_differs"
	} else if clDiff > 20 {
		isLikelyValid = true
		comparisonNote = "cl_differs"
	} else {
		comparisonNote = "matches_baseline"
	}

	if _, isIgnored := baselineIgnoreCodes[statusCode]; isIgnored {
		if isLikelyValid {
			comparisonNote += "_but_ignored"
		} else {
			comparisonNote = "is_ignored"
		}
		isLikelyValid = false
	}
	return isLikelyValid, comparisonNote
}

func performBaselineRequests(baseURL string, client *http.Client, normalLog *log.Logger, verboseLog *log.Logger) common.BaselineProfile {
	var profile common.BaselineProfile
	randPath := common.RandomString(12)
	targetURLRandomPath, err := url.JoinPath(baseURL, randPath)
	if err != nil {
		normalLog.Fatalf("Cannot create baseline URL: %v", err)
	}
	req, _ := http.NewRequest("GET", targetURLRandomPath, nil)
	req.Header.Set("User-Agent", "APIRecon/1.0 (BaselineChecker)")

	resp, err := client.Do(req)
	if err != nil {
		normalLog.Printf("Error sending baseline request: %v", err)
		return profile
	}
	_, cl := common.ReadAndCloseBody(resp, verboseLog)
	profile.RandomPathNotFound = common.ResponseCharacteristics{
		StatusCode:    resp.StatusCode,
		ContentLength: cl,
		ContentType:   resp.Header.Get("Content-Type"),
	}
	return profile
}

func processOpenAPISpec(filePath string, normalLog *log.Logger) ([]string, []string) {
	normalLog.Printf("[Discovery Mode] Loading OpenAPI specification from: %s\n", filePath)
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(filePath)
	if err != nil {
		normalLog.Fatalf("Failed to load or parse OpenAPI spec file: %v", err)
	}
	err = doc.Validate(loader.Context)
	if err != nil {
		normalLog.Fatalf("OpenAPI spec validation failed: %v", err)
	}

	pathSet, paramSet := make(map[string]bool), make(map[string]bool)
	for pathStr, pathItem := range doc.Paths.Map() {
		pathSet[pathStr] = true
		for _, operation := range pathItem.Operations() {
			for _, parameterRef := range operation.Parameters {
				if parameterRef.Value != nil {
					paramSet[parameterRef.Value.Name] = true
				}
			}
			if operation.RequestBody != nil && operation.RequestBody.Value != nil {
				for _, mediaType := range operation.RequestBody.Value.Content {
					if mediaType.Schema != nil && mediaType.Schema.Value != nil {
						for propName := range mediaType.Schema.Value.Properties {
							paramSet[propName] = true
						}
					}
				}
			}
		}
	}
	specPaths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		specPaths = append(specPaths, path)
	}
	specParams := make([]string, 0, len(paramSet))
	for param := range paramSet {
		specParams = append(specParams, param)
	}
	normalLog.Printf("[Discovery Mode] Extracted %d unique paths and %d unique parameter names from spec.\n", len(specPaths), len(specParams))
	return specPaths, specParams
}

func fingerprintTarget(baseURL string, client *http.Client, dbPath string, normalLog, verboseLog *log.Logger) []common.DetectedTech {
	verboseLog.Printf("[Fingerprint] Starting file-based technology fingerprinting for %s\n", baseURL)
	techConfidenceMap := make(map[string]int)

	dbFile, err := os.ReadFile(dbPath)
	if err != nil {
		normalLog.Printf("[Fingerprint] Warning: Could not read fingerprint file at '%s'. Skipping. Error: %v\n", dbPath, err)
		return []common.DetectedTech{}
	}
	var db common.FingerprintDB
	if err := json.Unmarshal(dbFile, &db); err != nil {
		normalLog.Printf("[Fingerprint] Warning: Could not parse fingerprint file '%s'. Skipping. Error: %v\n", dbPath, err)
		return []common.DetectedTech{}
	}
	normalLog.Printf("[Fingerprint] Loaded %d fingerprint rules from %s\n", len(db.Fingerprints), dbPath)

	initialResp, err := client.Get(baseURL)
	if err != nil {
		verboseLog.Printf("[Fingerprint] Initial request to target failed: %v\n", err)
		return []common.DetectedTech{}
	}
	defer initialResp.Body.Close()
	rootBody, _ := io.ReadAll(initialResp.Body)

	for _, rule := range db.Fingerprints {
		found := false
		switch rule.Type {
		case "header":
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				continue
			}
			if headerValue := initialResp.Header.Get(rule.Header); headerValue != "" && re.MatchString(headerValue) {
				found = true
			}
		case "cookie":
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				continue
			}
			for _, cookie := range initialResp.Cookies() {
				if re.MatchString(cookie.Name) {
					found = true
					break
				}
			}
		case "content":
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				continue
			}
			if rule.Path == "/" && len(rootBody) > 0 && re.Match(rootBody) {
				found = true
			}
		case "favicon_hash":
			faviconURL, err := url.JoinPath(baseURL, "favicon.ico")
			if err != nil {
				continue
			}
			favReq, err := http.NewRequest("GET", faviconURL, nil)
			if err != nil {
				continue
			}
			favReq.Header.Set("User-Agent", "APIRecon/1.0 (Fingerprinter/Favicon)")
			favResp, err := client.Do(favReq)
			if err != nil {
				continue
			}
			if favResp.StatusCode == 200 {
				favBody, _ := io.ReadAll(favResp.Body)
				favResp.Body.Close()
				hashBytes := md5.Sum(favBody)
				calculatedHash := hex.EncodeToString(hashBytes[:])
				verboseLog.Printf("[Fingerprint] Favicon found at %s. Hash: %s\n", faviconURL, calculatedHash)
				if calculatedHash == rule.Hash {
					found = true
				}
			} else {
				favResp.Body.Close()
			}
		}

		if found {
			confidenceScore := confidenceToInt(rule.Confidence)
			if currentScore, ok := techConfidenceMap[rule.Tech]; !ok || confidenceScore > currentScore {
				techConfidenceMap[rule.Tech] = confidenceScore
			}
		}
	}

	technologies := make([]common.DetectedTech, 0, len(techConfidenceMap))
	for tech, score := range techConfidenceMap {
		technologies = append(technologies, common.DetectedTech{
			Name:       tech,
			Confidence: intToConfidence(score),
		})
	}

	if len(technologies) > 0 {
		var techLogs []string
		for _, t := range technologies {
			techLogs = append(techLogs, fmt.Sprintf("%s (%s)", t.Name, t.Confidence))
		}
		normalLog.Printf("[Fingerprint] Detected potential technologies: %v\n", techLogs)
	} else {
		normalLog.Println("[Fingerprint] No specific technologies detected.")
	}
	return technologies
}

func confidenceToInt(level string) int {
	switch strings.ToLower(level) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func intToConfidence(score int) string {
	switch score {
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "unknown"
	}
}

func inferTechnologyStack(detectedTechs []common.DetectedTech) []string {
	stackDefinitions := map[string][]string{
		"WordPress (LEMP Stack)":   {"nginx", "php", "wordpress"},
		"WordPress (LAMP Stack)":   {"apache", "php", "wordpress"},
		"Laravel (LEMP Stack)":     {"nginx", "php", "laravel"},
		"Laravel (LAMP Stack)":     {"apache", "php", "laravel"},
		"Spring Boot (Standalone)": {"spring_boot"},
	}
	techNameSet := make(map[string]bool)
	for _, tech := range detectedTechs {
		techNameSet[tech.Name] = true
	}
	var inferredStacks []string
	for stackName, requiredTechs := range stackDefinitions {
		match := true
		for _, reqTech := range requiredTechs {
			if !techNameSet[reqTech] {
				match = false
				break
			}
		}
		if match {
			inferredStacks = append(inferredStacks, stackName)
		}
	}
	return inferredStacks
}

func loadContextualWordlists(detectedTechs []common.DetectedTech, cwd string, minConfidence string, normalLog, verboseLog *log.Logger) []string {
	contextualPathWordlist := []string{}
	minConfidenceScore := confidenceToInt(minConfidence)
	for _, tech := range detectedTechs {
		techConfidenceScore := confidenceToInt(tech.Confidence)
		if techConfidenceScore >= minConfidenceScore {
			contextFile := fmt.Sprintf("%s/%s.txt", strings.TrimRight(cwd, "/"), tech.Name)
			if _, err := os.Stat(contextFile); err == nil {
				normalLog.Printf("[Discovery Mode] Loading contextual wordlist for '%s' (Confidence: %s) from: %s\n", tech.Name, tech.Confidence, contextFile)
				techPaths, err := common.LoadWordlist(contextFile, normalLog)
				if err == nil {
					contextualPathWordlist = append(contextualPathWordlist, techPaths...)
				}
			}
		} else {
			verboseLog.Printf("[Discovery Mode] Skipping contextual wordlist for '%s' due to low confidence ('%s' < '%s')\n", tech.Name, tech.Confidence, minConfidence)
		}
	}
	return contextualPathWordlist
}

func runVulnerabilityProbes(baseURL string, detectedTechs []common.DetectedTech, args Args) {
	args.NormalLog.Println("\n--- Starting Vulnerability Probing Phase ---")

	dbFile, err := os.ReadFile(args.VulnDBPath)
	if err != nil {
		args.NormalLog.Printf("[VulnScan] Warning: Could not read vulnerability probes file at '%s'. Skipping. Error: %v\n", args.VulnDBPath, err)
		return
	}
	var db common.VulnerabilityDB
	if err := json.Unmarshal(dbFile, &db); err != nil {
		args.NormalLog.Printf("[VulnScan] Warning: Could not parse vulnerability probes file '%s'. Skipping. Error: %v\n", args.VulnDBPath, err)
		return
	}
	args.NormalLog.Printf("[VulnScan] Loaded %d vulnerability probe rules from %s\n", len(db.Probes), args.VulnDBPath)

	techSet := make(map[string]bool)
	for _, tech := range detectedTechs {
		techSet[tech.Name] = true
	}

	for _, probe := range db.Probes {
		applies := false
		for _, requiredTech := range probe.AppliesToTech {
			if techSet[requiredTech] {
				applies = true
				break
			}
		}

		if applies {
			args.VerboseLog.Printf("[VulnScan] Running probe: '%s'\n", probe.Name)
			probeURL, err := url.JoinPath(baseURL, probe.ProbeDetails.Path)
			if err != nil {
				continue
			}

			req, err := http.NewRequest(strings.ToUpper(probe.ProbeDetails.Method), probeURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "APIRecon/1.0 (VulnProbe)")

			resp, err := args.HttpClient.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode != probe.ProbeDetails.MatchStatus {
				resp.Body.Close()
				continue
			}

			bodyBytes, _ := common.ReadAndCloseBody(resp, args.VerboseLog)
			if probe.ProbeDetails.MatchContentRegex != "" {
				re, err := regexp.Compile(probe.ProbeDetails.MatchContentRegex)
				if err != nil {
					continue
				}
				if re.Match(bodyBytes) {
					args.NormalLog.Printf("[VULNERABILITY FOUND] Name: '%s' | Target: %s %s\n", probe.Name, probe.ProbeDetails.Method, probeURL)
				}
			} else {
				args.NormalLog.Printf("[VULNERABILITY FOUND] Name: '%s' | Target: %s %s\n", probe.Name, probe.ProbeDetails.Method, probeURL)
			}
		}
	}
	args.NormalLog.Println("--- Vulnerability Probing Phase Finished ---")
}
