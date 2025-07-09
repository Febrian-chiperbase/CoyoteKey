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
	Key           string    `json:"key"`
	StatusCode    int       `json:"statusCode"`
	ContentLength int64     `json:"contentLength"`
	URL           string    `json:"url"`
	Method        string    `json:"method"`
	Placement     string    `json:"placement"`
	MatchedRegex  string    `json:"matchedRegex,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

type DiscoveredParameter struct {
	Name         string   `json:"name"`
	In           string   `json:"in,omitempty"`
	TestedValues []string `json:"tested_values,omitempty"`
	Notes        string   `json:"notes,omitempty"`
	Evidence     string   `json:"evidence,omitempty"`
}

type DiscoveredPath struct {
	URL                string                `json:"url"`
	Method             string                `json:"method"`
	StatusCode         int                   `json:"statusCode"`
	ContentLength      int64                 `json:"contentLength"`
	BaselineComparison string                `json:"baselineComparison,omitempty"`
	FoundParameters    []DiscoveredParameter `json:"foundParameters,omitempty"`
	IsLikelyValid      bool                  `json:"isLikelyValid"`
	Depth              int                   `json:"depth"`
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

var (
	verboseLog *log.Logger
	normalLog  *log.Logger
	outputFile string
	allFoundKeys []FoundKey
	allDiscoveredPaths []DiscoveredPath // Akan menyimpan semua path yang diuji, termasuk yang tidak valid
	discoveredPathMap  map[string]DiscoveredPath // Untuk melacak path unik yang ditemukan (URL+Method -> DiscoveredPath)
	resultsMutex sync.Mutex
	globalHTTPClient *http.Client
	globalBaselineProfile BaselineProfile
	errorParamRegexList []*regexp.Regexp
)

func initErrorParamRegexes() { /* ... sama ... */
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
	discoveredPathMap = make(map[string]DiscoveredPath) // Inisialisasi map

	verboseLog = log.New(io.Discard, "VERBOSE: ", log.Ldate|log.Ltime|log.Lshortfile)
	normalLog = log.New(os.Stdout, "", 0)
	
	// ... (Flag parsing sama seperti sebelumnya) ...
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
	maxDepthFlag := flag.Int("depth", 0, "[Discover] Max recursion depth for path discovery (0 for base+wordlist, 1 for one level deeper, etc.)") // Default 0, bukan 1
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
		for _, p := range allDiscoveredPaths { // Iterasi allDiscoveredPaths untuk konsistensi
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
		normalLog.Printf("[Discovery Mode] Total unique URL+Method combinations processed: %d\n", len(allDiscoveredPaths))
	}

}

func saveResults(mode string) {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	var fileData []byte
	var err error

	// Untuk discovery mode, kita simpan allDiscoveredPaths yang berisi semua path yang diuji.
	// Jika ingin hanya yang valid, perlu filter di sini.
	if mode == "brutekey" && len(allFoundKeys) > 0 {
		fileData, err = json.MarshalIndent(allFoundKeys, "", "  ")
	} else if mode == "discover" && len(allDiscoveredPaths) > 0 {
		// Kumpulkan dari map untuk memastikan entri unik terakhir
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
		normalLog.Printf("Results successfully saved to %s\n", outputFile)
	}
}

// --- Args Structs for Modes (Sama) ---
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

// --- BruteKey Mode Logic (Sama) ---
func runBruteKeyMode(args bruteKeyArgs) { /* ... implementasi sama ... */ 
	normalLog.Println("--- Running in BruteKey Mode ---")
	if args.wordlistPath == "" {
		normalLog.Println("[BruteKey Mode] Wordlist (-w) is required.")
		os.Exit(1)
	}

	keyPlacementMethod := "header"
	keyPlacementValue := args.headerFormat
	if args.headerFormat == "" && args.queryParam == "" && args.jsonBodyTemplate == "" {
		args.headerFormat = "X-API-Key: %KEY%"
		keyPlacementValue = args.headerFormat
		normalLog.Println("[BruteKey Mode] No key placement specified, defaulting to header: X-API-Key: %KEY%")
	}

	numPlacementFlags := 0
	if args.headerFormat != "" {numPlacementFlags++}
	if args.queryParam != "" {numPlacementFlags++}
	if args.jsonBodyTemplate != "" {numPlacementFlags++}

	if numPlacementFlags > 1 {
		normalLog.Println("[BruteKey Mode] Error: Please specify only one key placement method: -H, -qp, or -jb.")
		os.Exit(1)
	}

	if args.queryParam != "" {
		keyPlacementMethod = "query"
		keyPlacementValue = args.queryParam
	} else if args.jsonBodyTemplate != "" {
		keyPlacementMethod = "json_body"
		keyPlacementValue = args.jsonBodyTemplate
		if !strings.Contains(keyPlacementValue, "%KEY%") {
			normalLog.Println("[BruteKey Mode] JSON body template (-jb) must contain placeholder %KEY%")
			os.Exit(1)
		}
		if args.httpMethod != "POST" && args.httpMethod != "PUT" && args.httpMethod != "PATCH" {
			normalLog.Println("[BruteKey Mode] Warning: JSON body is typically used with POST, PUT, or PATCH methods.")
		}
	} else {
		keyPlacementMethod = "header"
		keyPlacementValue = args.headerFormat
		if !strings.Contains(keyPlacementValue, "%KEY%") {
			normalLog.Println("[BruteKey Mode] Header format (-H) must contain placeholder %KEY%")
			os.Exit(1)
		}
	}
	normalLog.Printf("[BruteKey Mode] Key Placement: %s (using: %s)\n", keyPlacementMethod, keyPlacementValue)


	keys, err := loadWordlist(args.wordlistPath)
	if err != nil {
		normalLog.Printf("[BruteKey Mode] Error loading wordlist: %v\n", err)
		os.Exit(1)
	}
	normalLog.Printf("[BruteKey Mode] Wordlist: %s (%d keys)\n", args.wordlistPath, len(keys))


	successCodes := parseSuccessCodes(args.successCodesRaw)
	var successRegex, filterRegex *regexp.Regexp
	if args.successRegexRaw != "" {
		successRegex, err = regexp.Compile(args.successRegexRaw)
		if err != nil {
			normalLog.Printf("[BruteKey Mode] Error compiling success regex: %v\n", err)
			os.Exit(1)
		}
	}
	if args.filterRegexRaw != "" {
		filterRegex, err = regexp.Compile(args.filterRegexRaw)
		if err != nil {
			normalLog.Printf("[BruteKey Mode] Error compiling filter regex: %v\n", err)
			os.Exit(1)
		}
	}

	if len(successCodes) == 0 && successRegex == nil {
		normalLog.Println("[BruteKey Mode] No success criteria: provide success codes (-s) or success regex (-sr).")
		os.Exit(1)
	}
	if len(successCodes) > 0 { normalLog.Printf("[BruteKey Mode] Success Codes: %v\n", getIntKeys(successCodes)) }
	if successRegex != nil { normalLog.Printf("[BruteKey Mode] Success Regex: %s\n", args.successRegexRaw) }
	if filterRegex != nil { normalLog.Printf("[BruteKey Mode] Filter Regex: %s\n", args.filterRegexRaw) }
	normalLog.Printf("[BruteKey Mode] Delay per request: %dms\n", args.delay)


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
			normalLog.Printf("[FOUND KEY] Key: %s -> Status: %d, CL: %d, Placement: %s, URL: %s (Regex: %s)\n",
				found.Key, found.StatusCode, found.ContentLength, found.Placement, found.URL, found.MatchedRegex)
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
type workerArgsForKeyBrute struct { /* ... sama ... */
	targetURL         string
	httpMethod        string
	keyPlacementMethod string
	keyPlacementValue string 
	successCodes      map[int]bool
	successRegex      *regexp.Regexp
	filterRegex       *regexp.Regexp
	delay             time.Duration
	httpClient        *http.Client
 }
func bruteKeyWorker(id int, args workerArgsForKeyBrute, keys <-chan string, results chan<- FoundKey, wg *sync.WaitGroup) { /* ... implementasi sama ... */
	defer wg.Done()
	verboseLog.Printf("[BruteKeyWorker %d] started\n", id)

	for key := range keys {
		if key == "" {
			continue
		}
		verboseLog.Printf("[BruteKeyWorker %d] Trying key '%s'\n", id, key)

		var req *http.Request
		var err error
		var currentTargetURL = args.targetURL
		var requestBody io.Reader = nil

		finalKeyValue := key 
		
		var valueToPlace string

		switch args.keyPlacementMethod {
		case "header":
			valueToPlace = strings.ReplaceAll(args.keyPlacementValue, "%KEY%", finalKeyValue)
			req, err = http.NewRequest(args.httpMethod, currentTargetURL, nil)
			if err == nil {
				headerParts := strings.SplitN(valueToPlace, ":", 2)
				if len(headerParts) == 2 {
					req.Header.Set(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
				} else {
					err = fmt.Errorf("invalid header format: %s", valueToPlace)
				}
			}
		case "query":
			parsedURL, _ := url.Parse(currentTargetURL)
			queryVals := parsedURL.Query() 
			queryVals.Set(args.keyPlacementValue, finalKeyValue)
			parsedURL.RawQuery = queryVals.Encode()
			currentTargetURL = parsedURL.String()
			req, err = http.NewRequest(args.httpMethod, currentTargetURL, nil)
		case "json_body":
			valueToPlace = strings.ReplaceAll(args.keyPlacementValue, "%KEY%", finalKeyValue)
			requestBody = bytes.NewBufferString(valueToPlace)
			req, err = http.NewRequest(args.httpMethod, currentTargetURL, requestBody)
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
			}
		default:
			err = fmt.Errorf("unknown key placement method: %s", args.keyPlacementMethod)
		}

		if err != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error creating request for key '%s': %v\n", id, key, err)
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 GoTool/1.2")


		resp, err := args.httpClient.Do(req)
		if err != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error sending request for key '%s' to %s: %v\n", id, key, currentTargetURL, err)
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}
		
		responseBodyBytes, readErr := io.ReadAll(resp.Body)
		cl := resp.ContentLength 
		if cl == -1 {
			cl = int64(len(responseBodyBytes))
		}
		resp.Body.Close()

		if readErr != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error reading response body for key '%s': %v\n", id, key, readErr)
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}
		
		verboseLog.Printf("[BruteKeyWorker %d] Key '%s', URL: %s, Status: %s, CL: %d\n", id, key, currentTargetURL, resp.Status, cl)

		if args.filterRegex != nil && args.filterRegex.Match(responseBodyBytes) {
			verboseLog.Printf("[BruteKeyWorker %d] Key '%s' response filtered by regex: %s\n", id, key, args.filterRegex.String())
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}

		success := false
		matchedRegexValue := ""
		if _, ok := args.successCodes[resp.StatusCode]; ok {
			success = true
		}
		if args.successRegex != nil {
			if args.successRegex.Match(responseBodyBytes) {
				matches := args.successRegex.FindStringSubmatch(string(responseBodyBytes))
				if len(matches) > 0 { 
					matchedRegexValue = matches[0]
				}
				success = true 
			} else if success && len(args.successCodes) > 0 {
				// success by status code, but regex not match. For OR condition, this is fine.
			} else if !success { 
				success = false
			}
		}

		if success {
			results <- FoundKey{
				Key:        key,
				StatusCode: resp.StatusCode,
				ContentLength: cl,
				URL:        currentTargetURL,
				Method:     args.httpMethod,
				Placement:  args.keyPlacementMethod,
				MatchedRegex: matchedRegexValue,
				Timestamp:  time.Now().UTC(),
			}
		}
		
		if args.delay > 0 {
			time.Sleep(args.delay)
		}
	}
	verboseLog.Printf("[BruteKeyWorker %d] finished\n", id)
}

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

	paramWordlist, _ := loadWordlist(args.paramWordlistPath) // paramWordlist opsional
	if args.paramWordlistPath != "" && len(paramWordlist) > 0 {
		normalLog.Printf("[Discovery Mode] Param Wordlist: %s (%d entries)\n", args.paramWordlistPath, len(paramWordlist))
	}

	normalLog.Printf("[Discovery Mode] Max Recursion Depth: %d\n", args.maxDepth)
	discoveryMethods := parseCommaSeparatedString(args.discoveryMethodsRaw)
	normalLog.Printf("[Discovery Mode] Discovery Methods: %v\n", discoveryMethods)
	// fuzzMethods := parseCommaSeparatedString(args.fuzzMethodsRaw) // Untuk parameter fuzzing nanti
	baselineIgnoreCodes := parseSuccessCodes(args.baselineIgnoreCodesRaw)
	normalLog.Printf("[Discovery Mode] Baseline Ignore Codes: %v\n", getIntKeys(baselineIgnoreCodes))
	// fuzzTestValues := parseCommaSeparatedString(args.fuzzTestValuesRaw) // Untuk parameter fuzzing nanti

	normalLog.Println("[Discovery Mode] Performing baseline requests...")
	performBaselineRequests(args.baseURL, args.httpClient)
	normalLog.Printf("[Discovery Mode] Baseline Profile: RandomPathNotFound (Status: %d, CL: %d)\n",
		globalBaselineProfile.RandomPathNotFound.StatusCode, globalBaselineProfile.RandomPathNotFound.ContentLength)

	// --- Mulai Loop Rekursi per Kedalaman ---
	// pathsToExploreNextDepth akan menyimpan URL yang valid dari kedalaman sebelumnya
	// Untuk kedalaman 0, basisnya adalah args.baseURL
	currentLevelPathsToExplore := []string{strings.TrimRight(args.baseURL, "/")} // Pastikan tidak ada trailing slash ganda

	for depth := 0; depth <= args.maxDepth; depth++ {
		normalLog.Printf("[Discovery Mode] Starting discovery at Depth %d. Paths to explore at this level: %d\n", depth, len(currentLevelPathsToExplore))
		if len(currentLevelPathsToExplore) == 0 && depth > 0 { // Jangan berhenti jika depth 0 tapi tidak ada path (kasus baseURL saja)
			normalLog.Printf("[Discovery Mode] No new valid paths found at depth %d to explore further. Stopping recursion.\n", depth-1)
			break
		}

		discoveryJobsChan := make(chan DiscoveryJob, len(currentLevelPathsToExplore)*len(pathWordlist))
		discoveryResultsChan := make(chan DiscoveredPath, 200) // Buffer lebih besar untuk hasil
		var wg sync.WaitGroup
		
		// Goroutine untuk mengumpulkan hasil (perlu di-restart atau di-manage per kedalaman jika tidak hati-hati)
		// Cara lebih aman: kolektor berjalan terus, tapi kita tunggu wg sebelum lanjut ke depth berikutnya
		var activeResultCollectors sync.WaitGroup // Untuk memastikan kolektor selesai sebelum lanjut
		activeResultCollectors.Add(1)
		go func() {
			defer activeResultCollectors.Done()
			for pathInfo := range discoveryResultsChan {
				// Update allDiscoveredPaths dan discoveredPathMap (menggunakan mutex)
				mapMutexKey := pathInfo.Method + " " + pathInfo.URL
				resultsMutex.Lock()
				existing, foundInMap := discoveredPathMap[mapMutexKey]
				if !foundInMap || (len(pathInfo.FoundParameters) > len(existing.FoundParameters)) || (!existing.IsLikelyValid && pathInfo.IsLikelyValid) {
					// Update jika entri baru lebih baik (lebih banyak param, atau jadi valid)
					// atau jika belum ada
					if foundInMap { // Jika ada, gabungkan parameter
						pathInfo.FoundParameters = mergeDiscoveredParameters(existing.FoundParameters, pathInfo.FoundParameters)
					}
					discoveredPathMap[mapMutexKey] = pathInfo

					// Logging (sama seperti sebelumnya, bisa dipindahkan ke sini)
					paramCount := len(pathInfo.FoundParameters)
					logMessage := ""
					if pathInfo.IsLikelyValid {
						logMessage = fmt.Sprintf("[VALID DEPTH %d] %s %s (Status: %d, CL: %d, Comp: %s, Params: %d)",
							pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, pathInfo.BaselineComparison, paramCount)
					} else if paramCount > 0 {
						logMessage = fmt.Sprintf("[INFO  DEPTH %d] %s %s (Status: %d, CL: %d, Comp: %s, ParamsErr: %d)",
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
		for i := 0; i < args.threads; i++ {
			wg.Add(1)
			go discoveryWorker(i+1, discoveryWorkerArgs{
				// maxDepth tidak lagi relevan di worker, karena depth dikontrol di runDiscoveryMode
				discoveryMethods:    discoveryMethods,
				baselineIgnoreCodes: baselineIgnoreCodes,
				// pathWordlist tidak dibutuhkan worker lagi, karena job sudah spesifik
				httpClient:          args.httpClient,
			}, discoveryJobsChan, discoveryResultsChan, &wg)
		}

		// Seed jobs for the current depth
		jobCountForCurrentDepth := 0
		for _, basePathToExplore := range currentLevelPathsToExplore {
			parsedBasePath, _ := url.Parse(basePathToExplore) // Path valid dari iterasi sebelumnya
			for _, segment := range pathWordlist {
				// Hindari menambahkan segmen "//" atau path yang tidak bersih
				cleanSegment := strings.Trim(segment, "/") // Hilangkan slash di awal/akhir segmen
				if cleanSegment == "" { continue }

				// Cara gabung path yang lebih aman:
				tempURL := &url.URL{Path: cleanSegment}
				resolvedURL := parsedBasePath.ResolveReference(tempURL)
				
				// Pastikan tidak mencoba path yang sama berulang kali jika pathWordlist punya duplikat
				// (Untuk sekarang, biarkan worker yang handle, tapi bisa dioptimasi di sini)

				discoveryJobsChan <- DiscoveryJob{
					BaseURLForNextLevel: basePathToExplore, // Untuk debugging atau konteks
					PathSegmentToTest:   segment,
					CurrentDepth:        depth,
					FullURLToTest:       resolvedURL.String(),
				}
				jobCountForCurrentDepth++
			}
		}
		normalLog.Printf("[Discovery Mode] Depth %d: Submitted %d jobs to workers.\n", depth, jobCountForCurrentDepth)
		
		close(discoveryJobsChan) // Semua job untuk kedalaman ini sudah dikirim
		wg.Wait()                // Tunggu semua worker untuk kedalaman ini selesai
		close(discoveryResultsChan) // Tutup channel hasil agar kolektor bisa berhenti
		activeResultCollectors.Wait() // Pastikan kolektor selesai memproses semua hasil dari kedalaman ini

		// Persiapkan untuk iterasi kedalaman berikutnya
		if depth < args.maxDepth {
			newPathsToExplore := []string{}
			resultsMutex.Lock() // Ambil data dari map yang sudah diupdate
			for _, pathInfo := range discoveredPathMap {
				// Hanya lanjutkan rekursi pada path yang ditemukan di kedalaman saat ini DAN valid
				if pathInfo.Depth == depth && pathInfo.IsLikelyValid {
					// Pastikan URL diakhiri dengan '/' jika itu adalah direktori (heuristik)
					// atau jika server mengembalikan redirect ke versi dengan slash.
					// Untuk API, ini mungkin tidak selalu diinginkan. Kita serahkan format URL apa adanya.
					if !strings.HasSuffix(pathInfo.URL, "/") {
						// Coba tambahkan slash untuk melihat apakah itu direktori
						// Ini bisa jadi job terpisah atau variasi di worker
						// Untuk sekarang, kita ambil URL apa adanya.
					}
					newPathsToExplore = append(newPathsToExplore, pathInfo.URL)
				}
			}
			resultsMutex.Unlock()
			currentLevelPathsToExplore = newPathsToExplore // Set untuk iterasi berikutnya
			if len(currentLevelPathsToExplore) == 0 && depth < args.maxDepth {
                normalLog.Printf("[Discovery Mode] No new valid paths found at depth %d to explore further for depth %d. Stopping recursion.\n", depth, depth+1)
                break
            }
		} else {
			normalLog.Printf("[Discovery Mode] Reached max depth of %d.\n", args.maxDepth)
		}
	} // Akhir loop kedalaman
}

type discoveryWorkerArgs struct {
	// maxDepth (dihapus)
	discoveryMethods    []string
	baselineIgnoreCodes map[int]bool
	// pathWordlist (dihapus)
	httpClient *http.Client
	// Akan ditambahkan: paramWordlist, fuzzTestValues, fuzzMethods
}

func discoveryWorker(id int, args discoveryWorkerArgs, jobs <-chan DiscoveryJob, results chan<- DiscoveredPath, wg *sync.WaitGroup) {
	defer wg.Done()
	verboseLog.Printf("[DiscoveryWorker %d] started\n", id)

	for job := range jobs {
		// Pastikan FullURLToTest tidak kosong, bisa terjadi jika ada kesalahan di pembentukan URL
		if job.FullURLToTest == "" {
			verboseLog.Printf("[DiscoveryWorker %d] Skipping job with empty FullURLToTest (Base: %s, Segment: %s)\n", id, job.BaseURLForNextLevel, job.PathSegmentToTest)
			continue
		}
		verboseLog.Printf("[DiscoveryWorker %d] Processing job: URL=%s (Base: %s, Segment: %s), Depth=%d\n", id, job.FullURLToTest, job.BaseURLForNextLevel, job.PathSegmentToTest, job.CurrentDepth)

		for _, method := range args.discoveryMethods {
			req, err := http.NewRequest(method, job.FullURLToTest, nil)
			if err != nil {
				verboseLog.Printf("[DiscoveryWorker %d] Error creating request for %s %s: %v\n", id, method, job.FullURLToTest, err)
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 GoTool/1.2 (Discovery)")

			resp, err := args.httpClient.Do(req)
			if err != nil {
				verboseLog.Printf("[DiscoveryWorker %d] Error sending request for %s %s: %v\n", id, method, job.FullURLToTest, err)
				continue
			}

			bodyBytes, readErr := io.ReadAll(resp.Body)
			contentLength := resp.ContentLength
			if contentLength == -1 {
				contentLength = int64(len(bodyBytes))
			}
			resp.Body.Close()

			if readErr != nil {
				verboseLog.Printf("[DiscoveryWorker %d] Error reading body for %s %s: %v\n", id, method, job.FullURLToTest, readErr)
				continue
			}
			
			verboseLog.Printf("[DiscoveryWorker %d] Response: %s %s -> Status: %d, CL: %d\n", id, method, job.FullURLToTest, resp.StatusCode, contentLength)

			// Analisis Respons vs Baseline
			isLikelyValid := false
			comparisonNote := "unknown_comparison"
			// ... (Logika perbandingan baseline sama seperti sebelumnya) ...
			if resp.StatusCode != globalBaselineProfile.RandomPathNotFound.StatusCode {
				isLikelyValid = true
				comparisonNote = "status_differs_from_baseline_not_found"
			} else { 
				// Toleransi perbedaan kecil CL, misal 5% atau absolut 10-20 bytes
				clDiff := contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength
				if clDiff < 0 { clDiff = -clDiff } // Absolut difference

				if clDiff > 20 { // Jika perbedaan CL > 20 bytes, anggap beda
					isLikelyValid = true
					comparisonNote = "status_matches_baseline_but_cl_differs_significantly"
				} else {
					comparisonNote = "status_and_cl_match_baseline_not_found_or_similar"
				}
			}
			if _, isIgnoredCode := args.baselineIgnoreCodes[resp.StatusCode]; isIgnoredCode &&
			   ( (resp.StatusCode == globalBaselineProfile.RandomPathNotFound.StatusCode && 
			     (contentLength == globalBaselineProfile.RandomPathNotFound.ContentLength || (contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength < 20 && contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength > -20) )) ||
			     // Jika hanya kode ignore saja tanpa cek CL baseline (berguna untuk 403, dll)
			     (resp.StatusCode != globalBaselineProfile.RandomPathNotFound.StatusCode) ) {
				
				// Logika ini perlu disempurnakan. Jika status code ada di ignore list:
				// 1. Jika status code = baseline.RandomPath.StatusCode DAN CL mirip baseline -> tidak valid
				// 2. Jika status code != baseline.RandomPath.StatusCode TAPI ada di ignore list -> tidak valid (misal, 403 global)
				// Untuk sekarang, kita sederhanakan: jika ada di ignoreCodes dan statusnya SAMA dengan baseline DAN CL SAMA dengan baseline, maka tidak valid.
				if resp.StatusCode == globalBaselineProfile.RandomPathNotFound.StatusCode && 
				   (contentLength == globalBaselineProfile.RandomPathNotFound.ContentLength || (contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength < 20 && contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength > -20) ) {
					isLikelyValid = false
					if comparisonNote != "status_and_cl_match_baseline_not_found_or_similar" {
						comparisonNote += "_and_is_ignored_code_matching_baseline"
					} else {
						comparisonNote = "ignored_code_matches_baseline_not_found"
					}
				} else if resp.StatusCode != globalBaselineProfile.RandomPathNotFound.StatusCode {
					// Jika statusnya beda dari baseline, tapi ada di ignore list, tetap anggap tidak valid
					isLikelyValid = false
					comparisonNote = fmt.Sprintf("ignored_status_code_%d_found", resp.StatusCode)
				}
			}

			var foundParamsFromError []DiscoveredParameter
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
									Name:     paramName,
									In:       "unknown_from_error",
									Notes:    "derived_from_error_message",
									Evidence: truncateString(match[0], 100),
								})
							}
						}
					}
				}
			}
			
			// Jika parameter ditemukan dari error, ini membuat path lebih menarik, meskipun mungkin tidak 200 OK
			if len(foundParamsFromError) > 0 && !isLikelyValid {
				 // Kita bisa buat flag baru "HasHints" atau sejenisnya, atau update comparisonNote
				 comparisonNote += "_with_error_param_hints"
				 // Jangan set isLikelyValid = true hanya karena ini, biarkan baseline yang menentukan "valid" endpoint.
				 // Tapi kita akan tetap log sebagai INFO.
			}

			pathInfo := DiscoveredPath{
				URL:                job.FullURLToTest,
				Method:             method,
				StatusCode:         resp.StatusCode,
				ContentLength:      contentLength,
				BaselineComparison: comparisonNote,
				IsLikelyValid:      isLikelyValid,
				FoundParameters:    foundParamsFromError,
				Depth:              job.CurrentDepth,
				Timestamp:          time.Now().UTC(),
			}
			results <- pathInfo

			// Parameter fuzzing dan penanganan untuk mengirim job rekursif akan ditambahkan di sini
			// jika pathInfo.IsLikelyValid dan job.CurrentDepth < args.maxDepth
		}
	}
	verboseLog.Printf("[DiscoveryWorker %d] finished\n", id)
}

// --- Utility Functions (Sama seperti sebelumnya) ---
func parameterExists(params []DiscoveredParameter, name string) bool { /* ... sama ... */ 
	for _, p := range params {
		if p.Name == name {
			return true
		}
	}
	return false
}
func mergeDiscoveredParameters(existing, newParams []DiscoveredParameter) []DiscoveredParameter { /* ... sama ... */ 
	merged := make([]DiscoveredParameter, len(existing))
	copy(merged, existing)
	
	for _, newP := range newParams {
		if !parameterExists(merged, newP.Name) {
			merged = append(merged, newP)
		}
	}
	return merged
}
func truncateString(s string, maxLen int) string { /* ... sama ... */ 
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
func performBaselineRequests(baseURL string, client *http.Client) { /* ... sama ... */ 
	randPath := randomString(12) 
	
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		normalLog.Fatalf("Cannot parse baseURL for baseline: %v", err)
	}

	targetURLRandomPath := parsedBase.ResolveReference(&url.URL{Path: randPath})
	
	req, err := http.NewRequest("GET", targetURLRandomPath.String(), nil)
	if err != nil {
		normalLog.Printf("Error creating baseline request (random path): %v", err)
		globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{StatusCode: -1, ContentLength: -1} 
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 GoTool/1.2 (BaselineChecker)")

	resp, err := client.Do(req)
	if err != nil {
		normalLog.Printf("Error sending baseline request (random path) to %s: %v", targetURLRandomPath.String(), err)
		globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{StatusCode: -1, ContentLength: -1}
		return
	}
	defer resp.Body.Close()
	
	bodyBytes, _ := io.ReadAll(resp.Body)
	cl := resp.ContentLength
	if cl == -1 {
		cl = int64(len(bodyBytes))
	}

	globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{
		StatusCode:    resp.StatusCode,
		ContentLength: cl,
	}
}
func loadWordlist(path string) ([]string, error) { /* ... sama ... */ 
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
		if text != "" {
			if strings.HasPrefix(text, "#") {
				continue
			}
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}
func parseSuccessCodes(codesRaw string) map[int]bool { /* ... sama ... */ 
	codes := make(map[int]bool)
	if codesRaw == "" {
		return codes
	}
	parts := strings.Split(codesRaw, ",")
	for _, part := range parts {
		code, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil {
			codes[code] = true
		} else {
			normalLog.Printf("Warning: Invalid status code '%s' in codes list.\n", part)
		}
	}
	return codes
}
func getIntKeys(m map[int]bool) []int { /* ... sama ... */ 
    keys := make([]int, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    sort.Ints(keys) 
    return keys
}
func parseCommaSeparatedString(raw string) []string { /* ... sama ... */ 
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	cleanedParts := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			cleanedParts = append(cleanedParts, trimmed)
		}
	}
	return cleanedParts
}
func randomString(length int) string { /* ... sama ... */ 
	bytes := make([]byte, length/2+1)
	if _, err := rand.Read(bytes); err != nil {
		timestamp := strconv.FormatInt(time.Now().UnixNano(), 16)
		if len(timestamp) > length {
			return timestamp[:length]
		}
		return timestamp + strings.Repeat("a", length-len(timestamp))
	}
	return hex.EncodeToString(bytes)[:length]
}