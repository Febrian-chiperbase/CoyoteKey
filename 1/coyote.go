package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Structs (Sama seperti sebelumnya) ---
type FoundKey struct {
	Key          string    `json:"key"`
	StatusCode   int       `json:"statusCode"`
	URL          string    `json:"url"`
	Method       string    `json:"method"`
	Placement    string    `json:"placement"`
	MatchedRegex string    `json:"matchedRegex,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

type DiscoveredParameter struct {
	Name         string   `json:"name"`
	In           string   `json:"in,omitempty"`       // "query", "json_body", "form_body", "unknown_from_error"
	TestedValues []string `json:"tested_values,omitempty"` // Nilai yang menghasilkan respons menarik
	Notes        string   `json:"notes,omitempty"`     // e.g., "derived_from_error_message", "reflected_value", "status_changed"
	Evidence     string   `json:"evidence,omitempty"`
}

type DiscoveredPath struct {
	URL                string                `json:"url"`
	Method             string                `json:"method"`
	StatusCode         int                   `json:"statusCode"`
	ContentLength      int64                 `json:"contentLength"`
	BaselineComparison string                `json:"baselineComparison,omitempty"` // "differs_from_baseline", "similar_to_baseline"
	FoundParameters    []DiscoveredParameter `json:"foundParameters,omitempty"`
	IsLikelyValid      bool                  `json:"isLikelyValid"`
	Timestamp          time.Time             `json:"timestamp"`
}

type BaselineProfile struct {
	RandomPathNotFound ResponseCharacteristics `json:"randomPathNotFound"`
}

type ResponseCharacteristics struct {
	StatusCode    int   `json:"statusCode"`
	ContentLength int64 `json:"contentLength"`
}

type DiscoveryJob struct {
	// BaseURLForNextLevel adalah URL dari path valid yang ditemukan di kedalaman sebelumnya,
	// yang akan menjadi basis untuk menambahkan segmen dari pathWordlist.
	BaseURLForNextLevel string 
	PathSegmentToTest   string // Segmen dari pathWordlist yang akan ditambahkan
	CurrentDepth        int    
}

// ... (Variabel global sama, errorParamRegexList sama) ...
var (
	verboseLog *log.Logger
	normalLog  *log.Logger
	outputFile string
	allFoundKeys []FoundKey
	allDiscoveredPaths []DiscoveredPath 
	discoveredPathMap  map[string]DiscoveredPath 
	resultsMutex sync.Mutex
	globalHTTPClient *http.Client
	globalBaselineProfile BaselineProfile
	errorParamRegexList []*regexp.Regexp
)


func initErrorParamRegexes() { /* ... sama ... */ }

func main() {
	initErrorParamRegexes()
	discoveredPathMap = make(map[string]DiscoveredPath)

	verboseLog = log.New(io.Discard, "VERBOSE: ", log.Ldate|log.Ltime|log.Lshortfile)
	normalLog = log.New(os.Stdout, "", 0)
	
	// ... (Flag parsing sama persis seperti sebelumnya) ...
	// --- Common Flags ---
	targetURLFlag := flag.String("u", "", "Target Base URL (required for discovery, full endpoint for brutekey)")
	threadsFlag := flag.Int("t", 10, "Number of concurrent threads/goroutines")
	proxyURLFlag := flag.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	outputFileFlag := flag.String("o", "", "Output file to save results (JSON format)")
	verboseFlag := flag.Bool("v", false, "Enable verbose logging")
	timeoutFlag := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	modeFlag := flag.String("mode", "brutekey", "Mode of operation: 'brutekey' or 'discover'")

	// --- BruteKey Mode Flags ---
	wordlistPathFlag := flag.String("w", "", "[BruteKey] Path to wordlist file for keys/tokens (required in brutekey mode)")
	headerFormatFlag := flag.String("H", "", "[BruteKey] HTTP Header format for API Key (e.g., \"X-API-Key: %KEY%\")")
	queryParamFlag := flag.String("qp", "", "[BruteKey] Query parameter name for API Key (e.g., \"apiKey\")")
	jsonBodyTemplateFlag := flag.String("jb", "", "[BruteKey] JSON body template with %KEY% (e.g., '{\"token\":\"%KEY%\"}')")
	bkHTTPMethodFlag := flag.String("m", "GET", "[BruteKey] HTTP method")
	bkSuccessCodesRawFlag := flag.String("s", "200", "[BruteKey] Comma-separated success HTTP status codes")
	bkSuccessRegexFlag := flag.String("sr", "", "[BruteKey] Regex to match in response body for success")
	bkFilterRegexFlag := flag.String("fr", "", "[BruteKey] Regex to match in response body to filter out/ignore")
	bkDelayFlag := flag.Int("delay", 0, "[BruteKey] Delay in milliseconds between requests per thread")

	// --- Discovery Mode Flags ---
	pathWordlistFlag := flag.String("pw", "", "[Discover] Wordlist for path segments")
	paramWordlistFlag := flag.String("pp", "", "[Discover] Wordlist for parameter names (optional)")
	maxDepthFlag := flag.Int("depth", 0, "[Discover] Max recursion depth for path discovery (0 for base+wordlist, 1 for one level deeper, etc.)") 
	discoveryMethodsFlag := flag.String("dm", "GET,OPTIONS", "[Discover] Comma-separated HTTP methods for path discovery (e.g., GET,POST)")
	fuzzMethodsFlag := flag.String("fm", "GET,POST", "[Discover] Comma-separated HTTP methods for parameter fuzzing")
	baselineIgnoreCodesFlag := flag.String("bic", "404", "[Discover] Comma-separated status codes to generally consider as baseline noise if content length also similar")
	fuzzTestValuesFlag := flag.String("ptv", "1,test,true,0,admin", "[Discover] Comma-separated values to test for parameters")


	flag.Parse()
	outputFile = *outputFileFlag 

	if *verboseFlag {
		verboseLog.SetOutput(os.Stderr) 
	}

	if *targetURLFlag == "" {
		normalLog.Println("Target URL (-u) is required for all modes.")
		flag.Usage()
		os.Exit(1)
	}
	_, errParseURL := url.ParseRequestURI(*targetURLFlag)
	if errParseURL != nil {
		normalLog.Fatalf("Invalid Target URL (-u): %v", errParseURL)
	}


	globalHTTPClient = &http.Client{
		Timeout: time.Duration(*timeoutFlag) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, 
			Proxy:           http.ProxyFromEnvironment,
			MaxIdleConnsPerHost: *threadsFlag * 2, 
            DisableKeepAlives:   false, 
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
            verboseLog.Printf("Redirecting from %s to %s (via %d redirects)\n", via[0].URL.String(), req.URL.String(), len(via))
            return nil 
        },
	}
	if *proxyURLFlag != "" {
		pURL, errProxy := url.Parse(*proxyURLFlag)
		if errProxy != nil {
			normalLog.Printf("Invalid proxy URL: %v\n", errProxy)
			os.Exit(1)
		}
		if transport, ok := globalHTTPClient.Transport.(*http.Transport); ok {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}
	
	normalLog.Printf("Selected Mode: %s\n", *modeFlag)
	normalLog.Printf("Target: %s\n", *targetURLFlag)
	normalLog.Printf("Threads: %d\n", *threadsFlag)
    if *proxyURLFlag != "" {
        normalLog.Printf("Using Proxy: %s\n", *proxyURLFlag)
    }
	if outputFile != "" {
		normalLog.Printf("Output File: %s\n", outputFile)
	}
	normalLog.Printf("Verbose Mode: %t\n", *verboseFlag)

	switch *modeFlag {
	case "brutekey":
		runBruteKeyMode(bruteKeyArgs{ /* ... sama ... */ })
	case "discover":
		runDiscoveryMode(discoveryArgs{
			baseURL:             *targetURLFlag,
			pathWordlistPath:    *pathWordlistFlag,
			paramWordlistPath:   *paramWordlistFlag,
			maxDepth:            *maxDepthFlag,
			discoveryMethodsRaw: *discoveryMethodsFlag,
			fuzzMethodsRaw:      *fuzzMethodsFlag,
			baselineIgnoreCodesRaw: *baselineIgnoreCodesFlag,
			fuzzTestValuesRaw:    *fuzzTestValuesFlag,
			threads:             *threadsFlag,
			httpClient:          globalHTTPClient,
		})
	default:
		normalLog.Printf("Invalid mode: %s. Available modes: 'brutekey', 'discover'\n", *modeFlag)
		flag.Usage()
		os.Exit(1)
	}

	if outputFile != "" {
		saveResults(*modeFlag)
	}
	// ... (Logging hasil akhir sama seperti sebelumnya) ...
	foundCount := 0
	if *modeFlag == "brutekey" {
		resultsMutex.Lock()
		foundCount = len(allFoundKeys)
		resultsMutex.Unlock()
		if foundCount == 0 {
			normalLog.Println("No valid API keys found in brutekey mode.")
		} else {
			normalLog.Printf("\n[BruteKey Mode] Finished. Found %d valid API key(s).\n", foundCount)
		}
	} else if *modeFlag == "discover" {
		resultsMutex.Lock()
		validPathCount := 0
		for _, p := range discoveredPathMap { // Iterasi map untuk data unik terakhir
			if p.IsLikelyValid {
				validPathCount++
			}
		}
		resultsMutex.Unlock()
		if validPathCount == 0 {
			normalLog.Println("No likely valid API paths found in discovery mode.")
		} else {
			normalLog.Printf("\n[Discovery Mode] Finished. Discovered %d likely valid API path(s).\n", validPathCount)
		}
		normalLog.Printf("[Discovery Mode] Total unique URL+Method combinations processed: %d\n", len(discoveredPathMap))
	}
}


// --- runBruteKeyMode dan fungsi terkaitnya (Sama seperti sebelumnya) ---
// ... (Tidak ada perubahan di sini) ...
func saveResults(mode string) { /* ... sama ... */ }
type bruteKeyArgs struct { /* ... sama ... */ 
	targetURL        string
	wordlistPath     string
	headerFormat     string
	queryParam       string
	jsonBodyTemplate string
	httpMethod       string
	successCodesRaw  string
	successRegexRaw  string
	filterRegexRaw   string
	delay            int
	threads          int
	httpClient       *http.Client
}
type discoveryArgs struct { /* ... sama ... */ 
	baseURL                string
	pathWordlistPath       string
	paramWordlistPath      string
	maxDepth               int
	discoveryMethodsRaw    string
	fuzzMethodsRaw         string
	baselineIgnoreCodesRaw string
	fuzzTestValuesRaw      string
	threads                int
	httpClient             *http.Client
}
func runBruteKeyMode(args bruteKeyArgs) { /* ... implementasi sama ... */ }
type workerArgsForKeyBrute struct { /* ... sama ... */ }
func bruteKeyWorker(id int, args workerArgsForKeyBrute, keys <-chan string, results chan<- FoundKey, wg *sync.WaitGroup) { /* ... implementasi sama ... */ }


// --- Discovery Mode Logic ---
func runDiscoveryMode(args discoveryArgs) {
	normalLog.Println("--- Running in Discovery Mode ---")
	if args.pathWordlistPath == "" {
		normalLog.Println("[Discovery Mode] Path Wordlist (-pw) is required.")
		os.Exit(1)
	}

	pathWordlist, err := loadWordlist(args.pathWordlistPath)
	if err != nil {
		normalLog.Fatalf("[Discovery Mode] Error loading path wordlist: %v", err)
	}
	if len(pathWordlist) == 0 {
		normalLog.Fatalf("[Discovery Mode] Path wordlist is empty.")
	}
	normalLog.Printf("[Discovery Mode] Path Wordlist: %s (%d entries)\n", args.pathWordlistPath, len(pathWordlist))

	paramWordlist, _ := loadWordlist(args.paramWordlistPath)
	if args.paramWordlistPath != "" && len(paramWordlist) > 0 {
		normalLog.Printf("[Discovery Mode] Param Wordlist: %s (%d entries)\n", args.paramWordlistPath, len(paramWordlist))
	}

	normalLog.Printf("[Discovery Mode] Max Recursion Depth: %d\n", args.maxDepth)
	discoveryMethods := parseCommaSeparatedString(args.discoveryMethodsRaw)
	normalLog.Printf("[Discovery Mode] Discovery Methods: %v\n", discoveryMethods)
	fuzzMethods := parseCommaSeparatedString(args.fuzzMethodsRaw) // Parse metode fuzzing
	normalLog.Printf("[Discovery Mode] Fuzz Methods: %v\n", fuzzMethods)
	baselineIgnoreCodes := parseSuccessCodes(args.baselineIgnoreCodesRaw)
	normalLog.Printf("[Discovery Mode] Baseline Ignore Codes: %v\n", getIntKeys(baselineIgnoreCodes))
	fuzzTestValues := parseCommaSeparatedString(args.fuzzTestValuesRaw) // Parse nilai tes fuzzing
	normalLog.Printf("[Discovery Mode] Fuzz Test Values: %v\n", fuzzTestValues)


	normalLog.Println("[Discovery Mode] Performing baseline requests...")
	performBaselineRequests(args.baseURL, args.httpClient)
	normalLog.Printf("[Discovery Mode] Baseline Profile: RandomPathNotFound (Status: %d, CL: %d)\n",
		globalBaselineProfile.RandomPathNotFound.StatusCode, globalBaselineProfile.RandomPathNotFound.ContentLength)

	currentLevelPathsToExplore := []string{strings.TrimRight(args.baseURL, "/")}

	for depth := 0; depth <= args.maxDepth; depth++ {
		normalLog.Printf("[Discovery Mode] Starting discovery at Depth %d. Paths to explore at this level: %d\n", depth, len(currentLevelPathsToExplore))
		if len(currentLevelPathsToExplore) == 0 && depth > 0 {
			normalLog.Printf("[Discovery Mode] No new valid paths found at depth %d to explore further. Stopping recursion.\n", depth-1)
			break
		}

		discoveryJobsChan := make(chan DiscoveryJob, len(currentLevelPathsToExplore)*len(pathWordlist))
		discoveryResultsChan := make(chan DiscoveredPath, 200)
		var wg sync.WaitGroup
		
		var activeResultCollectors sync.WaitGroup
		activeResultCollectors.Add(1)
		go func() { // Goroutine pengumpul hasil
			defer activeResultCollectors.Done()
			for pathInfo := range discoveryResultsChan {
				mapMutexKey := pathInfo.Method + " " + pathInfo.URL
				resultsMutex.Lock()
				existing, foundInMap := discoveredPathMap[mapMutexKey]
				if !foundInMap || (len(pathInfo.FoundParameters) > len(existing.FoundParameters)) || (!existing.IsLikelyValid && pathInfo.IsLikelyValid) {
					if foundInMap { 
						pathInfo.FoundParameters = mergeDiscoveredParameters(existing.FoundParameters, pathInfo.FoundParameters)
					}
					discoveredPathMap[mapMutexKey] = pathInfo // Simpan atau update di map

					paramCount := len(pathInfo.FoundParameters)
					logMessage := ""
					if pathInfo.IsLikelyValid {
						logMessage = fmt.Sprintf("[VALID DEPTH %d] %s %s (Status: %d, CL: %d, Comp: %s, Params: %d)",
							pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, pathInfo.BaselineComparison, paramCount)
					} else if paramCount > 0 {
						logMessage = fmt.Sprintf("[INFO  DEPTH %d] %s %s (Status: %d, CL: %d, Comp: %s, ParamsErr/Fuzz: %d)",
							pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, pathInfo.BaselineComparison, paramCount)
					} else {
						verboseLog.Printf("[IGNORE DEPTH %d] %s %s (Status: %d, CL: %d, Comp: %s)\n",
							pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, pathInfo.BaselineComparison)
					}
					if logMessage != "" { normalLog.Println(logMessage) }
				}
				resultsMutex.Unlock()
			}
		}()

		// Start discovery workers for the current depth
		workerArgs := discoveryWorkerArgs{
			discoveryMethods:    discoveryMethods,
			baselineIgnoreCodes: baselineIgnoreCodes,
			httpClient:          args.httpClient,
			paramWordlist:       paramWordlist, // Tambahkan ke args worker
			fuzzMethods:         fuzzMethods,
			fuzzTestValues:      fuzzTestValues,
		}
		for i := 0; i < args.threads; i++ {
			wg.Add(1)
			go discoveryWorker(i+1, workerArgs, discoveryJobsChan, discoveryResultsChan, &wg)
		}

		jobCountForCurrentDepth := 0
		for _, basePathToExplore := range currentLevelPathsToExplore {
			parsedBasePath, _ := url.Parse(basePathToExplore)
			for _, segment := range pathWordlist {
				cleanSegment := strings.Trim(segment, "/")
				if cleanSegment == "" { continue }
				tempURL := &url.URL{Path: cleanSegment}
				resolvedURL := parsedBasePath.ResolveReference(tempURL)
				discoveryJobsChan <- DiscoveryJob{
					BaseURLForNextLevel: basePathToExplore,
					PathSegmentToTest:   segment,
					CurrentDepth:        depth,
					FullURLToTest:       resolvedURL.String(),
				}
				jobCountForCurrentDepth++
			}
		}
		normalLog.Printf("[Discovery Mode] Depth %d: Submitted %d jobs to workers.\n", depth, jobCountForCurrentDepth)
		
		close(discoveryJobsChan)
		wg.Wait()
		close(discoveryResultsChan)
		activeResultCollectors.Wait()

		if depth < args.maxDepth {
			newPathsToExplore := []string{}
			resultsMutex.Lock()
			for _, pathInfo := range discoveredPathMap {
				if pathInfo.Depth == depth && pathInfo.IsLikelyValid {
					newPathsToExplore = append(newPathsToExplore, pathInfo.URL)
				}
			}
			resultsMutex.Unlock()
			currentLevelPathsToExplore = newPathsToExplore
			if len(currentLevelPathsToExplore) == 0 && depth < args.maxDepth {
                normalLog.Printf("[Discovery Mode] No new valid paths found at depth %d to explore further for depth %d. Stopping recursion.\n", depth, depth+1)
                break
            }
		} else {
			normalLog.Printf("[Discovery Mode] Reached max depth of %d.\n", args.maxDepth)
		}
	} 
}

type discoveryWorkerArgs struct {
	discoveryMethods    []string
	baselineIgnoreCodes map[int]bool
	httpClient          *http.Client
	// Argumen baru untuk parameter fuzzing
	paramWordlist    []string
	fuzzMethods      []string
	fuzzTestValues   []string
}

func discoveryWorker(id int, args discoveryWorkerArgs, jobs <-chan DiscoveryJob, results chan<- DiscoveredPath, wg *sync.WaitGroup) {
	defer wg.Done()
	verboseLog.Printf("[DiscoveryWorker %d] started\n", id)

	for job := range jobs {
		if job.FullURLToTest == "" {
			verboseLog.Printf("[DiscoveryWorker %d] Skipping job with empty FullURLToTest (Base: %s, Segment: %s)\n", id, job.BaseURLForNextLevel, job.PathSegmentToTest)
			continue
		}
		verboseLog.Printf("[DiscoveryWorker %d] Processing path discovery: URL=%s (Base: %s, Segment: %s), Depth=%d\n", id, job.FullURLToTest, job.BaseURLForNextLevel, job.PathSegmentToTest, job.CurrentDepth)

		// Simpan respons dasar untuk path ini, akan digunakan untuk perbandingan saat fuzzing parameter
		basePathResponses := make(map[string]ResponseCharacteristics) // method -> characteristics

		for _, method := range args.discoveryMethods {
			req, err := http.NewRequest(method, job.FullURLToTest, nil)
			// ... (error handling dan set header sama)
			if err != nil { verboseLog.Printf("[DiscoveryWorker %d] Error creating request for %s %s: %v\n", id, method, job.FullURLToTest, err); continue }
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 GoTool/1.2 (Discovery)")

			resp, err := args.httpClient.Do(req)
			// ... (error handling sama)
			if err != nil { verboseLog.Printf("[DiscoveryWorker %d] Error sending request for %s %s: %v\n", id, method, job.FullURLToTest, err); continue }
			
			bodyBytes, readErr := io.ReadAll(resp.Body)
			contentLength := resp.ContentLength
			if contentLength == -1 { contentLength = int64(len(bodyBytes)) }
			resp.Body.Close()
			if readErr != nil { verboseLog.Printf("[DiscoveryWorker %d] Error reading body for %s %s: %v\n", id, method, job.FullURLToTest, readErr); continue }
			
			verboseLog.Printf("[DiscoveryWorker %d] Path Discovery Response: %s %s -> Status: %d, CL: %d\n", id, method, job.FullURLToTest, resp.StatusCode, contentLength)
			
			basePathResponses[method] = ResponseCharacteristics{StatusCode: resp.StatusCode, ContentLength: contentLength}


			isLikelyValid, comparisonNote := compareWithBaseline(resp.StatusCode, contentLength, args.baselineIgnoreCodes)
			
			var foundParamsFromError []DiscoveredParameter
			// ... (Logika parsing pesan error sama seperti sebelumnya) ...
			responseBodyString := string(bodyBytes)
			if (resp.StatusCode >= 400 && resp.StatusCode < 500) || !isLikelyValid {
				for _, re := range errorParamRegexList {
					matches := re.FindAllStringSubmatch(responseBodyString, -1)
					for _, match := range matches {
						if len(match) > 1 {
							paramName := strings.TrimSpace(match[1])
							paramName = strings.ReplaceAll(paramName, " field", "")
							if paramName != "" && !parameterExists(foundParamsFromError, paramName) {
								verboseLog.Printf("[DiscoveryWorker %d] PARAMETER FROM ERROR: Found '%s' in error response for %s %s (Regex: %s)\n", id, paramName, method, job.FullURLToTest, re.String())
								foundParamsFromError = append(foundParamsFromError, DiscoveredParameter{
									Name:     paramName, In: "unknown_from_error", Notes: "derived_from_error_message", Evidence: truncateString(match[0], 100),
								})
							}
						}
					}
				}
			}
			if len(foundParamsFromError) > 0 && !isLikelyValid {
				 comparisonNote += "_with_error_param_hints"
			}

			// Kumpulkan semua parameter yang ditemukan (dari error + dari fuzzing nanti)
			allFoundOnPathParams := foundParamsFromError

			// **Lakukan Parameter Fuzzing jika path menarik atau ada petunjuk parameter**
			shouldFuzz := isLikelyValid || len(foundParamsFromError) > 0
			if shouldFuzz && len(args.paramWordlist) > 0 && len(args.fuzzTestValues) > 0 && len(args.fuzzMethods) > 0 {
				verboseLog.Printf("[DiscoveryWorker %d] Starting parameter fuzzing for %s %s\n", id, method, job.FullURLToTest)
				fuzzedParams := fuzzParametersOnPath(job.FullURLToTest, method, basePathResponses[method], args, id)
				if len(fuzzedParams) > 0 {
					allFoundOnPathParams = mergeDiscoveredParameters(allFoundOnPathParams, fuzzedParams)
				}
			}


			pathInfo := DiscoveredPath{
				URL:                job.FullURLToTest,
				Method:             method,
				StatusCode:         resp.StatusCode,
				ContentLength:      contentLength,
				BaselineComparison: comparisonNote,
				IsLikelyValid:      isLikelyValid,
				FoundParameters:    allFoundOnPathParams,
				Depth:              job.CurrentDepth,
				Timestamp:          time.Now().UTC(),
			}
			results <- pathInfo
		}
	}
	verboseLog.Printf("[DiscoveryWorker %d] finished\n", id)
}

// Fungsi untuk membandingkan dengan baseline (dipindahkan ke helper)
func compareWithBaseline(statusCode int, contentLength int64, baselineIgnoreCodes map[int]bool) (bool, string) {
	isLikelyValid := false
	comparisonNote := "unknown_comparison"

	if statusCode != globalBaselineProfile.RandomPathNotFound.StatusCode {
		isLikelyValid = true
		comparisonNote = "status_differs_from_baseline_not_found"
	} else {
		clDiff := contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength
		if clDiff < 0 { clDiff = -clDiff }
		if clDiff > 20 {
			isLikelyValid = true
			comparisonNote = "status_matches_baseline_but_cl_differs_significantly"
		} else {
			comparisonNote = "status_and_cl_match_baseline_not_found_or_similar"
		}
	}

	if _, isIgnoredCode := baselineIgnoreCodes[statusCode]; isIgnoredCode {
		// Jika status ada di ignore list
		// 1. Jika status SAMA dengan baseline DAN CL SAMA dengan baseline, ini pasti tidak valid
		if statusCode == globalBaselineProfile.RandomPathNotFound.StatusCode &&
			(contentLength == globalBaselineProfile.RandomPathNotFound.ContentLength || (contentLength-globalBaselineProfile.RandomPathNotFound.ContentLength < 20 && contentLength-globalBaselineProfile.RandomPathNotFound.ContentLength > -20)) {
			isLikelyValid = false // Override, karena ini adalah noise yang sudah diketahui
			comparisonNote = "ignored_code_matches_baseline_not_found"
		} else if statusCode != globalBaselineProfile.RandomPathNotFound.StatusCode {
			// 2. Jika status BEDA dari baseline, TAPI ada di ignore list (misal 403 global), juga tidak valid
			isLikelyValid = false
			comparisonNote = fmt.Sprintf("ignored_status_code_%d_found_(differs_from_baseline_404)", statusCode)
		}
		// Kasus lain: status sama dengan ignore code, tapi CL beda signifikan dari baseline 404,
		// ini mungkin tetap menarik, jadi biarkan isLikelyValid dari perbandingan CL yang menentukan.
	}
	return isLikelyValid, comparisonNote
}


func fuzzParametersOnPath(pathURL string, originalMethod string, basePathResponseChars ResponseCharacteristics, args discoveryWorkerArgs, workerID int) []DiscoveredParameter {
	var fuzzedParams []DiscoveredParameter
	uniqueParamsFound := make(map[string]DiscoveredParameter) // Untuk menampung parameter unik yang ditemukan di fungsi ini

	for _, fuzzMethod := range args.fuzzMethods {
		// Hanya fuzz POST/PUT jika originalMethod juga POST/PUT atau jika path valid
		// Untuk GET, kita selalu bisa coba fuzz query params
		if (fuzzMethod == "POST" || fuzzMethod == "PUT" || fuzzMethod == "PATCH") && !(originalMethod == "POST" || originalMethod == "PUT" || originalMethod == "PATCH") {
			// Jika metode asli GET, dan kita mau fuzz POST, itu bisa saja valid (misalnya endpoint sama handle GET dan POST)
			// verboseLog.Printf("[ParamFuzzer %d] Skipping %s fuzz for %s (original method was %s)\n", workerID, fuzzMethod, pathURL, originalMethod)
			// continue
		}

		for _, paramName := range args.paramWordlist {
			if paramName == "" { continue }
			for _, testValue := range args.fuzzTestValues {
				
				var req *http.Request
				var err error
				fuzzedURL := pathURL
				var body io.Reader = nil
				paramIn := "unknown"

				switch strings.ToUpper(fuzzMethod) {
				case "GET":
					paramIn = "query"
					parsedURL, _ := url.Parse(pathURL)
					query := parsedURL.Query()
					query.Set(paramName, testValue)
					parsedURL.RawQuery = query.Encode()
					fuzzedURL = parsedURL.String()
					req, err = http.NewRequest("GET", fuzzedURL, nil)
				case "POST", "PUT", "PATCH":
					// Coba Form-urlencoded dulu
					paramIn = "form_body"
					formData := url.Values{}
					formData.Set(paramName, testValue)
					body = strings.NewReader(formData.Encode())
					req, err = http.NewRequest(fuzzMethod, pathURL, body)
					if err == nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					// TODO: Tambahkan fuzzing JSON body jika diperlukan (lebih kompleks karena struktur)
					// Contoh JSON sederhana:
					// paramIn = "json_body"
					// jsonData := fmt.Sprintf(`{"%s": "%s"}`, paramName, testValue) // Perlu escape value jika mengandung quote
					// body = strings.NewReader(jsonData)
					// req, err = http.NewRequest(fuzzMethod, pathURL, body)
					// if err == nil {
					// 	req.Header.Set("Content-Type", "application/json")
					// }
				default:
					verboseLog.Printf("[ParamFuzzer %d] Unsupported fuzz method: %s\n", workerID, fuzzMethod)
					continue
				}

				if err != nil {
					verboseLog.Printf("[ParamFuzzer %d] Error creating fuzz request for %s %s (%s=%s): %v\n", workerID, fuzzMethod, pathURL, paramName, testValue, err)
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 GoTool/1.2 (ParamFuzzer)")

				resp, err := args.httpClient.Do(req)
				if err != nil {
					verboseLog.Printf("[ParamFuzzer %d] Error sending fuzz request for %s %s (%s=%s): %v\n", workerID, fuzzMethod, pathURL, paramName, testValue, err)
					continue
				}

				fuzzBodyBytes, readErr := io.ReadAll(resp.Body)
				fuzzCL := resp.ContentLength
				if fuzzCL == -1 { fuzzCL = int64(len(fuzzBodyBytes)) }
				resp.Body.Close()

				if readErr != nil { continue }

				verboseLog.Printf("[ParamFuzzer %d] Fuzz Resp: %s %s (%s=%s in %s) -> Status: %d, CL: %d\n", workerID, fuzzMethod, pathURL, paramName, testValue, paramIn, resp.StatusCode, fuzzCL)

				// Analisis Perubahan Respons
				note := ""
				isInteresting := false
				if resp.StatusCode != basePathResponseChars.StatusCode {
					note = fmt.Sprintf("status_changed_from_%d_to_%d", basePathResponseChars.StatusCode, resp.StatusCode)
					isInteresting = true
				}
				clDiff := fuzzCL - basePathResponseChars.ContentLength
				if clDiff > 20 || clDiff < -20 { // Perbedaan signifikan
					if note != "" { note += "; " }
					note += fmt.Sprintf("cl_changed_from_%d_to_%d", basePathResponseChars.ContentLength, fuzzCL)
					isInteresting = true
				}
				// TODO: Analisis refleksi konten, atau hilangnya pesan error "parameter X missing"

				if isInteresting {
					mapUniqueKey := paramName + "_" + paramIn // Kunci unik untuk parameter dan lokasinya
					existingParam, found := uniqueParamsFound[mapUniqueKey]
					if !found {
						existingParam = DiscoveredParameter{Name: paramName, In: paramIn, Notes: note, TestedValues: []string{testValue}}
					} else {
						existingParam.TestedValues = appendIfMissing(existingParam.TestedValues, testValue)
						if !strings.Contains(existingParam.Notes, note) { // Hindari duplikasi notes
							existingParam.Notes += "; " + note
						}
					}
					uniqueParamsFound[mapUniqueKey] = existingParam
					normalLog.Printf("[PARAM FUZZ FOUND] %s %s: Param '%s' in '%s' with value '%s' seems interesting. Notes: %s\n",
						fuzzMethod, pathURL, paramName, paramIn, testValue, note)
				}
			} // loop test values
		} // loop param names
	} // loop fuzz methods
	
	for _, p := range uniqueParamsFound {
		fuzzedParams = append(fuzzedParams, p)
	}
	return fuzzedParams
}

// --- Utility Functions (Sebagian besar sama, beberapa tambahan) ---
func parameterExists(params []DiscoveredParameter, name string) bool { /* ... sama ... */ }
func mergeDiscoveredParameters(existing, newParams []DiscoveredParameter) []DiscoveredParameter {
    // Logika merge yang lebih baik: update jika ada, tambahkan jika baru
    mergedMap := make(map[string]DiscoveredParameter)
    for _, p := range existing {
        mergedMap[p.Name+"_"+p.In] = p // Kunci berdasarkan nama dan lokasi
    }
    for _, newP := range newParams {
        key := newP.Name + "_" + newP.In
        if existingP, ok := mergedMap[key]; ok {
            // Gabungkan notes dan tested values
            if newP.Notes != "" && !strings.Contains(existingP.Notes, newP.Notes) {
                existingP.Notes += "; " + newP.Notes
            }
            for _, tv := range newP.TestedValues {
                existingP.TestedValues = appendIfMissing(existingP.TestedValues, tv)
            }
            mergedMap[key] = existingP
        } else {
            mergedMap[key] = newP
        }
    }
    // Konversi map kembali ke slice
    finalMerged := make([]DiscoveredParameter, 0, len(mergedMap))
    for _, p := range mergedMap {
        finalMerged = append(finalMerged, p)
    }
    return finalMerged
}
func appendIfMissing(slice []string, str string) []string {
    for _, s := range slice {
        if s == str {
            return slice
        }
    }
    return append(slice, str)
}

func truncateString(s string, maxLen int) string { /* ... sama ... */ }
func performBaselineRequests(baseURL string, client *http.Client) { /* ... sama ... */ }
func loadWordlist(path string) ([]string, error) { /* ... sama ... */ }
func parseSuccessCodes(codesRaw string) map[int]bool { /* ... sama ... */ }
func getIntKeys(m map[int]bool) []int { /* ... sama ... */ }
func parseCommaSeparatedString(raw string) []string { /* ... sama ... */ }
func randomString(length int) string { /* ... sama ... */ }