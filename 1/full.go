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

// FoundKey adalah struktur untuk menyimpan hasil dari mode 'brutekey'.
type FoundKey struct {
	Key           string    `json:"key"`
	StatusCode    int       `json:"statusCode"`
	ContentLength int64     `json:"contentLength"`
	URL           string    `json:"url"`
	Method        string    `json:"method"`
	Placement     string    `json:"placement"`
	MatchedRegex  string    `json:"matchedRegex,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// DiscoveredParameter adalah struktur untuk menyimpan parameter yang ditemukan saat discovery.
type DiscoveredParameter struct {
	Name         string   `json:"name"`
	In           string   `json:"in,omitempty"`       // "query", "json_body", "form_body", "unknown_from_error"
	TestedValues []string `json:"tested_values,omitempty"` // Nilai yang menghasilkan respons menarik
	Notes        string   `json:"notes,omitempty"`     // e.g., "derived_from_error_message", "reflected_value", "status_changed"
	Evidence     string   `json:"evidence,omitempty"`  // Potongan pesan error atau konteks
}

// DiscoveredPath adalah struktur untuk menyimpan endpoint yang ditemukan saat discovery.
type DiscoveredPath struct {
	URL                string                `json:"url"`
	Method             string                `json:"method"`
	StatusCode         int                   `json:"statusCode"`
	ContentLength      int64                 `json:"contentLength"`
	BaselineComparison string                `json:"baselineComparison,omitempty"`
	FoundParameters    []DiscoveredParameter `json:"foundParameters,omitempty"`
	IsLikelyValid      bool                  `json:"isLikelyValid"`
	Depth              int                   `json:"depth"` // Kedalaman saat path ini ditemukan
	Timestamp          time.Time             `json:"timestamp"`
}

// BaselineProfile menyimpan karakteristik respons dari server target untuk request yang tidak valid.
type BaselineProfile struct {
	RandomPathNotFound ResponseCharacteristics `json:"randomPathNotFound"`
}

// ResponseCharacteristics menyimpan properti dasar dari sebuah respons HTTP.
type ResponseCharacteristics struct {
	StatusCode    int   `json:"statusCode"`
	ContentLength int64 `json:"contentLength"`
}

// DiscoveryJob mendefinisikan sebuah pekerjaan untuk discovery worker.
type DiscoveryJob struct {
	BaseURLForNextLevel string // URL dari path valid yang ditemukan di kedalaman sebelumnya
	PathSegmentToTest   string // Segmen dari pathWordlist yang akan ditambahkan
	CurrentDepth        int
}

// Variabel global untuk logging, konfigurasi, dan hasil
var (
	verboseLog         *log.Logger
	normalLog          *log.Logger
	outputFile         string
	allFoundKeys       []FoundKey
	allDiscoveredPaths []DiscoveredPath
	discoveredPathMap  map[string]DiscoveredPath // Untuk melacak path unik yang ditemukan (URL+Method -> DiscoveredPath)
	resultsMutex       sync.Mutex
	globalHTTPClient   *http.Client
	globalBaselineProfile BaselineProfile
	errorParamRegexList []*regexp.Regexp // Regex untuk parsing parameter dari pesan error
)

// initErrorParamRegexes mengompilasi daftar regex untuk menemukan nama parameter dari pesan error.
func initErrorParamRegexes() {
	patterns := []string{
		`(?i)missing required parameter: '([^']+)'`,
		`(?i)parameter '([^']+)' is required`,
		`(?i)field '([^']+)' must not be empty`,
		`(?i)the (.+?) field is required`,
		`(?i)'([^']+?)' is a required property`,
		`(?i)required request parameter '([^']+)' for method parameter type`,
		`(?i)parameter "([^"]+)" is missing`,
		`(?i)missing attribute: ([^ ]+)`,
		`(?i)field ` + "`([^`]+)`" + ` is mandatory`,
		`(?i)value for '([^']+)' is null or missing`,
	}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			errorParamRegexList = append(errorParamRegexList, re)
		} else {
			log.Printf("Warning: Could not compile error regex pattern: %s", p)
		}
	}
}

func main() {
	initErrorParamRegexes()
	discoveredPathMap = make(map[string]DiscoveredPath)

	verboseLog = log.New(io.Discard, "VERBOSE: ", log.Ldate|log.Ltime)
	normalLog = log.New(os.Stdout, "", 0)

	// --- Definisi Flags ---
	targetURLFlag := flag.String("u", "", "Target Base URL (required for discovery, full endpoint for brutekey)")
	threadsFlag := flag.Int("t", 20, "Number of concurrent threads/goroutines")
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
	baselineIgnoreCodesFlag := flag.String("bic", "404", "[Discover] Comma-separated status codes to generally consider as baseline noise")
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

	// --- Inisialisasi HTTP Client ---
	globalHTTPClient = &http.Client{
		Timeout: time.Duration(*timeoutFlag) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			Proxy:               http.ProxyFromEnvironment,
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

	// --- Log Konfigurasi Awal ---
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

	// --- Menjalankan Mode yang Dipilih ---
	switch *modeFlag {
	case "brutekey":
		runBruteKeyMode(bruteKeyArgs{
			targetURL:        *targetURLFlag,
			wordlistPath:     *wordlistPathFlag,
			headerFormat:     *headerFormatFlag,
			queryParam:       *queryParamFlag,
			jsonBodyTemplate: *jsonBodyTemplateFlag,
			httpMethod:       *bkHTTPMethodFlag,
			successCodesRaw:  *bkSuccessCodesRawFlag,
			successRegexRaw:  *bkSuccessRegexFlag,
			filterRegexRaw:   *bkFilterRegexFlag,
			delay:            *bkDelayFlag,
			threads:          *threadsFlag,
			httpClient:       globalHTTPClient,
		})
	case "discover":
		runDiscoveryMode(discoveryArgs{
			baseURL:                *targetURLFlag,
			pathWordlistPath:       *pathWordlistFlag,
			paramWordlistPath:      *paramWordlistFlag,
			maxDepth:               *maxDepthFlag,
			discoveryMethodsRaw:    *discoveryMethodsFlag,
			fuzzMethodsRaw:         *fuzzMethodsFlag,
			baselineIgnoreCodesRaw: *baselineIgnoreCodesFlag,
			fuzzTestValuesRaw:      *fuzzTestValuesFlag,
			threads:                *threadsFlag,
			httpClient:             globalHTTPClient,
		})
	default:
		normalLog.Printf("Invalid mode: %s. Available modes: 'brutekey', 'discover'\n", *modeFlag)
		flag.Usage()
		os.Exit(1)
	}

	// --- Menyimpan Hasil dan Log Akhir ---
	if outputFile != "" {
		saveResults(*modeFlag)
	}

	if *modeFlag == "brutekey" {
		resultsMutex.Lock()
		foundCount := len(allFoundKeys)
		resultsMutex.Unlock()
		if foundCount == 0 {
			normalLog.Println("\nNo valid API keys found in brutekey mode.")
		} else {
			normalLog.Printf("\n[BruteKey Mode] Finished. Found %d valid API key(s).\n", foundCount)
		}
	} else if *modeFlag == "discover" {
		resultsMutex.Lock()
		validPathCount := 0
		for _, p := range discoveredPathMap {
			if p.IsLikelyValid {
				validPathCount++
			}
		}
		resultsMutex.Unlock()
		if validPathCount == 0 {
			normalLog.Println("\nNo likely valid API paths found in discovery mode.")
		} else {
			normalLog.Printf("\n[Discovery Mode] Finished. Discovered %d likely valid API path(s).\n", validPathCount)
		}
		normalLog.Printf("[Discovery Mode] Total unique URL+Method combinations processed: %d\n", len(discoveredPathMap))
	}
}

// saveResults menyimpan data yang terkumpul ke file JSON.
func saveResults(mode string) {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	var fileData []byte
	var err error

	if mode == "brutekey" && len(allFoundKeys) > 0 {
		fileData, err = json.MarshalIndent(allFoundKeys, "", "  ")
	} else if mode == "discover" && len(discoveredPathMap) > 0 {
		pathsToSave := make([]DiscoveredPath, 0, len(discoveredPathMap))
		for _, path := range discoveredPathMap {
			pathsToSave = append(pathsToSave, path)
		}
		fileData, err = json.MarshalIndent(pathsToSave, "", "  ")
	} else {
		verboseLog.Println("No results to save for the current mode or no results found.")
		return
	}

	if err != nil {
		normalLog.Printf("Error marshalling results to JSON: %v\n", err)
		return
	}
	err = os.WriteFile(outputFile, fileData, 0644)
	if err != nil {
		normalLog.Printf("Error saving results to file %s: %v\n", outputFile, err)
	} else {
		normalLog.Printf("\nResults successfully saved to %s\n", outputFile)
	}
}

// --- Struct Argumen untuk Mode-Mode ---
type bruteKeyArgs struct {
	targetURL, wordlistPath, headerFormat, queryParam, jsonBodyTemplate, httpMethod, successCodesRaw, successRegexRaw, filterRegexRaw string
	delay, threads int
	httpClient     *http.Client
}
type discoveryArgs struct {
	baseURL, pathWordlistPath, paramWordlistPath, discoveryMethodsRaw, fuzzMethodsRaw, baselineIgnoreCodesRaw, fuzzTestValuesRaw string
	maxDepth, threads int
	httpClient        *http.Client
}

// --- Logika Mode BruteKey ---
func runBruteKeyMode(args bruteKeyArgs) {
	normalLog.Println("--- Running in BruteKey Mode ---")
	// Implementasi runBruteKeyMode sama seperti sebelumnya
	if args.wordlistPath == "" {
		normalLog.Println("[BruteKey Mode] Wordlist (-w) is required.")
		os.Exit(1)
	}

	keyPlacementMethod, keyPlacementValue := determineKeyPlacement(args)
	normalLog.Printf("[BruteKey Mode] Key Placement: %s (using: %s)\n", keyPlacementMethod, keyPlacementValue)

	keys, err := loadWordlist(args.wordlistPath)
	if err != nil || len(keys) == 0 {
		normalLog.Fatalf("[BruteKey Mode] Error loading or empty wordlist: %v", err)
	}
	normalLog.Printf("[BruteKey Mode] Wordlist: %s (%d keys)\n", args.wordlistPath, len(keys))

	successCodes, successRegex, filterRegex := parseBruteKeyCriteria(args)
	if len(successCodes) > 0 {
		normalLog.Printf("[BruteKey Mode] Success Codes: %v\n", getIntKeys(successCodes))
	}
	// ... sisa log konfigurasi ...

	jobs := make(chan string, len(keys))
	bruteKeyResultsChan := make(chan FoundKey, len(keys))
	var wg sync.WaitGroup

	for i := 0; i < args.threads; i++ {
		wg.Add(1)
		go bruteKeyWorker(i+1, workerArgsForKeyBrute{
			targetURL:         args.targetURL,
			httpMethod:        args.httpMethod,
			keyPlacementMethod: keyPlacementMethod,
			keyPlacementValue: keyPlacementValue,
			successCodes:      successCodes,
			successRegex:      successRegex,
			filterRegex:       filterRegex,
			delay:             time.Duration(args.delay) * time.Millisecond,
			httpClient:        args.httpClient,
		}, jobs, bruteKeyResultsChan, &wg)
	}

	go func() {
		for found := range bruteKeyResultsChan {
			resultsMutex.Lock()
			allFoundKeys = append(allFoundKeys, found)
			resultsMutex.Unlock()
			normalLog.Printf("[FOUND KEY] Key: %s -> Status: %d, CL: %d, Placement: %s, URL: %s\n",
				found.Key, found.StatusCode, found.ContentLength, found.Placement, found.URL)
		}
	}()

	for _, key := range keys {
		jobs <- key
	}
	close(jobs)
	wg.Wait()
	close(bruteKeyResultsChan)
	time.Sleep(100 * time.Millisecond)
}

// Helper untuk runBruteKeyMode
func determineKeyPlacement(args bruteKeyArgs) (string, string) {
	if args.queryParam != "" {
		return "query", args.queryParam
	}
	if args.jsonBodyTemplate != "" {
		if !strings.Contains(args.jsonBodyTemplate, "%KEY%") {
			normalLog.Fatal("[BruteKey Mode] JSON body template (-jb) must contain placeholder %KEY%")
		}
		return "json_body", args.jsonBodyTemplate
	}
	// Default ke header
	headerFormat := args.headerFormat
	if headerFormat == "" {
		headerFormat = "X-API-Key: %KEY%"
		normalLog.Println("[BruteKey Mode] No key placement specified, defaulting to header: X-API-Key: %KEY%")
	}
	if !strings.Contains(headerFormat, "%KEY%") {
		normalLog.Fatal("[BruteKey Mode] Header format (-H) must contain placeholder %KEY%")
	}
	return "header", headerFormat
}

// Helper untuk runBruteKeyMode
func parseBruteKeyCriteria(args bruteKeyArgs) (map[int]bool, *regexp.Regexp, *regexp.Regexp) {
	successCodes := parseSuccessCodes(args.successCodesRaw)
	var successRegex, filterRegex *regexp.Regexp
	var err error
	if args.successRegexRaw != "" {
		successRegex, err = regexp.Compile(args.successRegexRaw)
		if err != nil {
			normalLog.Fatalf("[BruteKey Mode] Error compiling success regex: %v", err)
		}
	}
	if args.filterRegexRaw != "" {
		filterRegex, err = regexp.Compile(args.filterRegexRaw)
		if err != nil {
			normalLog.Fatalf("[BruteKey Mode] Error compiling filter regex: %v", err)
		}
	}
	if len(successCodes) == 0 && successRegex == nil {
		normalLog.Fatal("[BruteKey Mode] No success criteria: provide success codes (-s) or success regex (-sr).")
	}
	return successCodes, successRegex, filterRegex
}

type workerArgsForKeyBrute struct {
	targetURL, httpMethod, keyPlacementMethod, keyPlacementValue string
	successCodes                                                 map[int]bool
	successRegex, filterRegex                                    *regexp.Regexp
	delay                                                        time.Duration
	httpClient                                                   *http.Client
}

func bruteKeyWorker(id int, args workerArgsForKeyBrute, keys <-chan string, results chan<- FoundKey, wg *sync.WaitGroup) {
	// Implementasi bruteKeyWorker sama seperti sebelumnya
	defer wg.Done()
	for key := range keys {
		if key == "" {
			continue
		}
		currentTargetURL, req, err := createBruteKeyRequest(args, key)
		if err != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error creating request for key '%s': %v\n", id, key, err)
			continue
		}

		resp, err := args.httpClient.Do(req)
		if err != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error sending request for key '%s': %v\n", id, key, err)
			continue
		}

		bodyBytes, cl := readAndCloseBody(resp)
		verboseLog.Printf("[BruteKeyWorker %d] Key '%s', URL: %s, Status: %s, CL: %d\n", id, key, currentTargetURL, resp.Status, cl)

		if args.filterRegex != nil && args.filterRegex.Match(bodyBytes) {
			continue
		}

		success, matchedRegex := isBruteKeySuccess(resp.StatusCode, bodyBytes, args.successCodes, args.successRegex)
		if success {
			results <- FoundKey{
				Key: key, StatusCode: resp.StatusCode, ContentLength: cl, URL: currentTargetURL, Method: args.httpMethod,
				Placement: args.keyPlacementMethod, MatchedRegex: matchedRegex, Timestamp: time.Now().UTC(),
			}
		}
		if args.delay > 0 {
			time.Sleep(args.delay)
		}
	}
}

// Helper untuk bruteKeyWorker
func createBruteKeyRequest(args workerArgsForKeyBrute, key string) (string, *http.Request, error) {
	var req *http.Request
	var err error
	currentTargetURL := args.targetURL
	var body io.Reader = nil

	switch args.keyPlacementMethod {
	case "header":
		headerValue := strings.ReplaceAll(args.keyPlacementValue, "%KEY%", key)
		req, err = http.NewRequest(args.httpMethod, currentTargetURL, nil)
		if err == nil {
			parts := strings.SplitN(headerValue, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			} else {
				err = fmt.Errorf("invalid header format")
			}
		}
	case "query":
		parsedURL, _ := url.Parse(currentTargetURL)
		q := parsedURL.Query()
		q.Set(args.keyPlacementValue, key)
		parsedURL.RawQuery = q.Encode()
		currentTargetURL = parsedURL.String()
		req, err = http.NewRequest(args.httpMethod, currentTargetURL, nil)
	case "json_body":
		jsonBody := strings.ReplaceAll(args.keyPlacementValue, "%KEY%", key)
		body = strings.NewReader(jsonBody)
		req, err = http.NewRequest(args.httpMethod, currentTargetURL, body)
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	default:
		err = fmt.Errorf("unknown placement method")
	}
	if err == nil {
		req.Header.Set("User-Agent", "GoTool/1.3")
	}
	return currentTargetURL, req, err
}

// Helper untuk bruteKeyWorker
func isBruteKeySuccess(statusCode int, body []byte, successCodes map[int]bool, successRegex *regexp.Regexp) (bool, string) {
	success := false
	matchedRegex := ""
	if _, ok := successCodes[statusCode]; ok {
		success = true
	}
	if successRegex != nil && successRegex.Match(body) {
		success = true
		matches := successRegex.FindStringSubmatch(string(body))
		if len(matches) > 0 {
			matchedRegex = matches[0]
		}
	}
	return success, matchedRegex
}

// --- Logika Mode Discovery ---
func runDiscoveryMode(args discoveryArgs) {
	normalLog.Println("--- Running in Discovery Mode ---")
	// Implementasi runDiscoveryMode dengan loop rekursi
	if args.pathWordlistPath == "" {
		normalLog.Println("[Discovery Mode] Path Wordlist (-pw) is required.")
		os.Exit(1)
	}

	pathWordlist, err := loadWordlist(args.pathWordlistPath)
	if err != nil || len(pathWordlist) == 0 {
		normalLog.Fatalf("[Discovery Mode] Error loading or empty path wordlist: %v", err)
	}
	paramWordlist, _ := loadWordlist(args.paramWordlistPath)
	discoveryMethods := parseCommaSeparatedString(args.discoveryMethodsRaw)
	fuzzMethods := parseCommaSeparatedString(args.fuzzMethodsRaw)
	baselineIgnoreCodes := parseSuccessCodes(args.baselineIgnoreCodesRaw)
	fuzzTestValues := parseCommaSeparatedString(args.fuzzTestValuesRaw)

	normalLog.Println("[Discovery Mode] Performing baseline requests...")
	performBaselineRequests(args.baseURL, args.httpClient)
	normalLog.Printf("[Discovery Mode] Baseline Profile: RandomPathNotFound (Status: %d, CL: %d)\n",
		globalBaselineProfile.RandomPathNotFound.StatusCode, globalBaselineProfile.RandomPathNotFound.ContentLength)

	currentLevelPathsToExplore := []string{strings.TrimRight(args.baseURL, "/")}

	for depth := 0; depth <= args.maxDepth; depth++ {
		if len(currentLevelPathsToExplore) == 0 && depth > 0 {
			normalLog.Printf("[Discovery Mode] No new valid paths found at depth %d to explore further. Stopping recursion.\n", depth-1)
			break
		}
		normalLog.Printf("[Discovery Mode] Starting discovery at Depth %d. Base paths to explore: %d\n", depth, len(currentLevelPathsToExplore))

		discoveryJobsChan := make(chan DiscoveryJob, len(currentLevelPathsToExplore)*len(pathWordlist))
		discoveryResultsChan := make(chan DiscoveredPath, 200)
		var wg sync.WaitGroup
		var activeResultCollectors sync.WaitGroup
		activeResultCollectors.Add(1)

		go func() { // Goroutine pengumpul hasil
			defer activeResultCollectors.Done()
			for pathInfo := range discoveryResultsChan {
				processDiscoveryResult(pathInfo)
			}
		}()

		workerArgs := discoveryWorkerArgs{
			discoveryMethods:    discoveryMethods,
			baselineIgnoreCodes: baselineIgnoreCodes,
			httpClient:          args.httpClient,
			paramWordlist:       paramWordlist,
			fuzzMethods:         fuzzMethods,
			fuzzTestValues:      fuzzTestValues,
		}
		for i := 0; i < args.threads; i++ {
			wg.Add(1)
			go discoveryWorker(i+1, workerArgs, discoveryJobsChan, &wg)
		}

		jobCount := 0
		for _, basePath := range currentLevelPathsToExplore {
			parsedBasePath, _ := url.Parse(basePath)
			for _, segment := range pathWordlist {
				cleanSegment := strings.Trim(segment, "/")
				if cleanSegment == "" {
					continue
				}
				resolvedURL := parsedBasePath.ResolveReference(&url.URL{Path: cleanSegment})
				discoveryJobsChan <- DiscoveryJob{
					BaseURLForNextLevel: basePath,
					PathSegmentToTest:   segment,
					CurrentDepth:        depth,
				}
				jobCount++
			}
		}
		normalLog.Printf("[Discovery Mode] Depth %d: Submitted %d jobs to workers.\n", depth, jobCount)

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
		} else {
			normalLog.Printf("[Discovery Mode] Reached max depth of %d.\n", args.maxDepth)
		}
	}
}

// processDiscoveryResult mengelola dan mencatat hasil dari discovery.
func processDiscoveryResult(pathInfo DiscoveredPath) {
	mapMutexKey := pathInfo.Method + " " + pathInfo.URL
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	// Simpan semua path yang diuji, untuk output file lengkap
	allDiscoveredPaths = append(allDiscoveredPaths, pathInfo)

	// Update map untuk deduplikasi dan rekursi
	existing, foundInMap := discoveredPathMap[mapMutexKey]
	if !foundInMap || (len(pathInfo.FoundParameters) > len(existing.FoundParameters)) || (!existing.IsLikelyValid && pathInfo.IsLikelyValid) {
		if foundInMap {
			pathInfo.FoundParameters = mergeDiscoveredParameters(existing.FoundParameters, pathInfo.FoundParameters)
		}
		discoveredPathMap[mapMutexKey] = pathInfo

		// Logging ke konsol
		paramCount := len(pathInfo.FoundParameters)
		logMessage := ""
		if pathInfo.IsLikelyValid {
			logMessage = fmt.Sprintf("[VALID DEPTH %d] %s %s (Status: %d, CL: %d, Comp: %s, Params: %d)",
				pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, pathInfo.BaselineComparison, paramCount)
		} else if paramCount > 0 {
			logMessage = fmt.Sprintf("[INFO  DEPTH %d] %s %s (Status: %d, CL: %d, ParamsFound: %d)",
				pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, paramCount)
		}
		if logMessage != "" {
			normalLog.Println(logMessage)
		}
	}
}

type discoveryWorkerArgs struct {
	discoveryMethods, fuzzMethods, fuzzTestValues, paramWordlist []string
	baselineIgnoreCodes                                          map[int]bool
	httpClient                                                   *http.Client
}

func discoveryWorker(id int, args discoveryWorkerArgs, jobs <-chan DiscoveryJob, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		parsedBase, _ := url.Parse(job.BaseURLForNextLevel)
		resolvedURL := parsedBase.ResolveReference(&url.URL{Path: job.PathSegmentToTest})
		fullURL := resolvedURL.String()

		verboseLog.Printf("[DiscoveryWorker %d] Path discovery: %s\n", id, fullURL)

		basePathResponses := make(map[string]ResponseCharacteristics)

		for _, method := range args.discoveryMethods {
			req, err := http.NewRequest(method, fullURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "GoTool/1.3 (Discovery)")

			resp, err := args.httpClient.Do(req)
			if err != nil {
				continue
			}

			bodyBytes, cl := readAndCloseBody(resp)
			basePathResponses[method] = ResponseCharacteristics{StatusCode: resp.StatusCode, ContentLength: cl}

			isLikelyValid, comparisonNote := compareWithBaseline(resp.StatusCode, cl, args.baselineIgnoreCodes)
			foundParamsFromError := parseErrorsForParams(bodyBytes)

			allFoundOnPathParams := foundParamsFromError
			if (isLikelyValid || len(foundParamsFromError) > 0) && len(args.paramWordlist) > 0 {
				fuzzedParams := fuzzParametersOnPath(fullURL, method, basePathResponses[method], args, id)
				allFoundOnPathParams = mergeDiscoveredParameters(allFoundOnPathParams, fuzzedParams)
			}

			// Kirim hasil akhir ke kolektor
			processDiscoveryResult(DiscoveredPath{
				URL: fullURL, Method: method, StatusCode: resp.StatusCode, ContentLength: cl,
				BaselineComparison: comparisonNote, IsLikelyValid: isLikelyValid,
				FoundParameters: allFoundOnPathParams, Depth: job.CurrentDepth, Timestamp: time.Now().UTC(),
			})
		}
	}
}

// parseErrorsForParams mem-parsing body respons untuk mencari petunjuk nama parameter.
func parseErrorsForParams(body []byte) []DiscoveredParameter {
	var foundParams []DiscoveredParameter
	bodyString := string(body)
	for _, re := range errorParamRegexList {
		matches := re.FindAllStringSubmatch(bodyString, -1)
		for _, match := range matches {
			if len(match) > 1 {
				paramName := strings.Trim(match[1], "`'\" ")
				paramName = strings.ReplaceAll(paramName, " field", "")
				if paramName != "" && !parameterExists(foundParams, paramName) {
					foundParams = append(foundParams, DiscoveredParameter{
						Name: paramName, In: "unknown_from_error", Notes: "derived_from_error_message",
						Evidence: truncateString(match[0], 100),
					})
				}
			}
		}
	}
	return foundParams
}

// fuzzParametersOnPath melakukan fuzzing parameter pada sebuah path yang ditemukan.
func fuzzParametersOnPath(pathURL string, originalMethod string, basePathResponseChars ResponseCharacteristics, args discoveryWorkerArgs, workerID int) []DiscoveredParameter {
	var fuzzedParams []DiscoveredParameter
	uniqueParamsFound := make(map[string]DiscoveredParameter)

	for _, fuzzMethod := range args.fuzzMethods {
		for _, paramName := range args.paramWordlist {
			for _, testValue := range args.fuzzTestValues {
				// Coba sebagai Query Parameter
				if fuzzMethod == "GET" || fuzzMethod == "POST" { // Bisa juga fuzz query param di POST
					fuzzURL, _ := url.Parse(pathURL)
					q := fuzzURL.Query()
					q.Set(paramName, testValue)
					fuzzURL.RawQuery = q.Encode()
					req, err := http.NewRequest(fuzzMethod, fuzzURL.String(), nil)
					if err == nil {
						analyzeFuzzResponse(req, "query", paramName, testValue, basePathResponseChars, uniqueParamsFound, workerID)
					}
				}

				// Coba sebagai Form Body
				if fuzzMethod == "POST" || fuzzMethod == "PUT" || fuzzMethod == "PATCH" {
					formData := url.Values{}
					formData.Set(paramName, testValue)
					req, err := http.NewRequest(fuzzMethod, pathURL, strings.NewReader(formData.Encode()))
					if err == nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						analyzeFuzzResponse(req, "form_body", paramName, testValue, basePathResponseChars, uniqueParamsFound, workerID)
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

// analyzeFuzzResponse adalah helper untuk fuzzParametersOnPath.
func analyzeFuzzResponse(req *http.Request, paramIn, paramName, testValue string, baseChars ResponseCharacteristics, uniqueParams map[string]DiscoveredParameter, workerID int) {
	req.Header.Set("User-Agent", "GoTool/1.3 (ParamFuzzer)")
	resp, err := globalHTTPClient.Do(req)
	if err != nil {
		return
	}

	_, fuzzCL := readAndCloseBody(resp)
	verboseLog.Printf("[ParamFuzzer %d] Fuzz Resp: %s %s (%s=%s in %s) -> Status: %d, CL: %d\n", workerID, req.Method, req.URL.Path, paramName, testValue, paramIn, resp.StatusCode, fuzzCL)

	note := ""
	isInteresting := false
	if resp.StatusCode != baseChars.StatusCode {
		note = fmt.Sprintf("status_changed_from_%d_to_%d", baseChars.StatusCode, resp.StatusCode)
		isInteresting = true
	}
	clDiff := fuzzCL - baseChars.ContentLength
	if clDiff > 20 || clDiff < -20 {
		if note != "" {
			note += "; "
		}
		note += fmt.Sprintf("cl_changed_from_%d_to_%d", baseChars.ContentLength, fuzzCL)
		isInteresting = true
	}

	if isInteresting {
		mapUniqueKey := paramName + "_" + paramIn
		existingParam, found := uniqueParams[mapUniqueKey]
		if !found {
			existingParam = DiscoveredParameter{Name: paramName, In: paramIn, Notes: note, TestedValues: []string{testValue}}
		} else {
			existingParam.TestedValues = appendIfMissing(existingParam.TestedValues, testValue)
			if !strings.Contains(existingParam.Notes, note) {
				existingParam.Notes += "; " + note
			}
		}
		uniqueParams[mapUniqueKey] = existingParam
		normalLog.Printf("[PARAM FUZZ FOUND] %s %s: Param '%s' in '%s' interesting. Notes: %s\n",
			req.Method, req.URL.Path, paramName, paramIn, note)
	}
}

// --- Fungsi Utilitas ---
func compareWithBaseline(statusCode int, contentLength int64, baselineIgnoreCodes map[int]bool) (bool, string) {
	// Implementasi compareWithBaseline sama seperti sebelumnya
	isLikelyValid := false
	comparisonNote := ""
	clDiff := contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength
	if clDiff < 0 {
		clDiff = -clDiff
	}

	if statusCode != globalBaselineProfile.RandomPathNotFound.StatusCode {
		isLikelyValid = true
		comparisonNote = "status_differs"
	} else if clDiff > 20 {
		isLikelyValid = true
		comparisonNote = "cl_differs"
	} else {
		comparisonNote = "matches_baseline"
	}

	if _, isIgnored := baselineIgnoreCodes[statusCode]; isIgnored {
		if isLikelyValid { // Jika tadinya dianggap valid, tapi ada di ignore list, jadi tidak valid
			comparisonNote += "_but_ignored"
		} else {
			comparisonNote = "is_ignored"
		}
		isLikelyValid = false
	}
	return isLikelyValid, comparisonNote
}

func performBaselineRequests(baseURL string, client *http.Client) {
	randPath := randomString(12)
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		normalLog.Fatalf("Cannot parse baseURL for baseline: %v", err)
	}
	targetURLRandomPath := parsedBase.ResolveReference(&url.URL{Path: randPath})
	req, _ := http.NewRequest("GET", targetURLRandomPath.String(), nil)
	req.Header.Set("User-Agent", "GoTool/1.3 (BaselineChecker)")

	resp, err := client.Do(req)
	if err != nil {
		normalLog.Printf("Error sending baseline request to %s: %v", targetURLRandomPath.String(), err)
		globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{StatusCode: -1, ContentLength: -1}
		return
	}
	_, cl := readAndCloseBody(resp)
	globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{StatusCode: resp.StatusCode, ContentLength: cl}
}

func readAndCloseBody(resp *http.Response) ([]byte, int64) {
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		verboseLog.Printf("Error reading response body: %v\n", readErr)
	}
	resp.Body.Close()
	cl := resp.ContentLength
	if cl == -1 {
		cl = int64(len(bodyBytes))
	}
	return bodyBytes, cl
}

func loadWordlist(path string) ([]string, error) {
	if path == "" {
		return []string{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" && !strings.HasPrefix(text, "#") {
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}

func parseSuccessCodes(codesRaw string) map[int]bool {
	codes := make(map[int]bool)
	if codesRaw == "" {
		return codes
	}
	for _, part := range strings.Split(codesRaw, ",") {
		code, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil {
			codes[code] = true
		}
	}
	return codes
}

func getIntKeys(m map[int]bool) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func parseCommaSeparatedString(raw string) []string {
	if raw == "" {
		return []string{}
	}
	var cleanedParts []string
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			cleanedParts = append(cleanedParts, trimmed)
		}
	}
	return cleanedParts
}

func randomString(length int) string {
	bytes := make([]byte, length/2+1)
	if _, err := rand.Read(bytes); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(bytes)[:length]
}

func parameterExists(params []DiscoveredParameter, name string) bool {
	for _, p := range params {
		if p.Name == name {
			return true
		}
	}
	return false
}

func mergeDiscoveredParameters(existing, newParams []DiscoveredParameter) []DiscoveredParameter {
	mergedMap := make(map[string]DiscoveredParameter)
	for _, p := range existing {
		key := p.Name + "_" + p.In
		mergedMap[key] = p
	}
	for _, newP := range newParams {
		key := newP.Name + "_" + newP.In
		if existingP, ok := mergedMap[key]; ok {
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

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}