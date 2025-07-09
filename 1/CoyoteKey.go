package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Structs (Shared and for Brutepackage main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Structs (Shared and for BruteKey Mode) ---
type FoundKey struct {
	Key          string    `json:"key"`
	StatusCode   int       `json:"statusCode"`
	URL          string    `json:"url"`
	Method       string    `json:"method"`
	Placement    string    `json:"placement"`
	MatchedRegex string    `json:"matchedRegex,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// --- Structs for Discovery Mode ---
type DiscoveredParameter struct {
	Name         string   `json:"name"`
	In           string   `json:"in"` // "query", "json_body", "form_body"
	TestedValues []string `json:"tested_values"`
	Notes        string   `json:"notes,omitempty"` // e.g., "reflected in response", "changed status code"
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

var (
	verboseLog *log.Logger
	normalLog  *log.Logger
	outputFile string // Global untuk diakses oleh kedua mode saat menyimpan
	allFoundKeys []FoundKey // Untuk brutekey mode
	allDiscoveredPaths []DiscoveredPath // Untuk discovery mode
	resultsMutex sync.Mutex
)

func main() {
	verboseLog = log.New(io.Discard, "VERBOSE: ", log.Ldate|log.Ltime|log.Lshortfile)
	normalLog = log.New(os.Stdout, "", 0)

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
	paramWordlistFlag := flag.String("pp", "", "[Discover] Wordlist for parameter names")
	depthFlag := flag.Int("depth", 1, "[Discover] Recursion depth for path discovery")
	discoveryMethodsFlag := flag.String("dm", "GET", "[Discover] Comma-separated HTTP methods for path discovery (e.g., GET,POST)")
	fuzzMethodsFlag := flag.String("fm", "GET,POST", "[Discover] Comma-separated HTTP methods for parameter fuzzing")
	baselineIgnoreCodesFlag := flag.String("bic", "404", "[Discover] Comma-separated status codes to consider as baseline noise")
	fuzzTestValuesFlag := flag.String("ptv", "1,test,true", "[Discover] Comma-separated values to test for parameters")


	flag.Parse()
	outputFile = *outputFileFlag // Set global outputFile

	if *verboseFlag {
		verboseLog.SetOutput(os.Stderr)
	}

	if *targetURLFlag == "" {
		normalLog.Println("Target URL (-u) is required for all modes.")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize HTTP Client (shared)
	httpClient := &http.Client{
		Timeout: time.Duration(*timeoutFlag) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Use with caution
			Proxy:           http.ProxyFromEnvironment,
		},
	}
	if *proxyURLFlag != "" {
		pURL, errProxy := url.Parse(*proxyURLFlag)
		if errProxy != nil {
			normalLog.Printf("Invalid proxy URL: %v\n", errProxy)
			os.Exit(1)
		}
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
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
			threads:          *threadsFlag, // Pass common flags
			httpClient:       httpClient,
		})
	case "discover":
		runDiscoveryMode(discoveryArgs{
			baseURL:             *targetURLFlag,
			pathWordlistPath:    *pathWordlistFlag,
			paramWordlistPath:   *paramWordlistFlag,
			depth:               *depthFlag,
			discoveryMethodsRaw: *discoveryMethodsFlag,
			fuzzMethodsRaw:      *fuzzMethodsFlag,
			baselineIgnoreCodesRaw: *baselineIgnoreCodesFlag,
			fuzzTestValuesRaw:    *fuzzTestValuesFlag,
			threads:             *threadsFlag, // Pass common flags
			httpClient:          httpClient,
		})
	default:
		normalLog.Printf("Invalid mode: %s. Available modes: 'brutekey', 'discover'\n", *modeFlag)
		flag.Usage()
		os.Exit(1)
	}

	// Save results common logic (differentiated by mode)
	if outputFile != "" {
		saveResults()
	}

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
		foundCount = len(allDiscoveredPaths) // Menghitung jumlah path unik yang dianggap valid
		resultsMutex.Unlock()
		if foundCount == 0 {
			normalLog.Println("No interesting API paths found in discovery mode.")
		} else {
			normalLog.Printf("\n[Discovery Mode] Finished. Discovered %d potentially valid/interesting API path(s).\n", foundCount)
		}
	}
}

func saveResults() {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	var fileData []byte
	var err error

	if len(allFoundKeys) > 0 { // Prioritaskan hasil brutekey jika ada (atau tentukan berdasarkan mode aktif)
		fileData, err = json.MarshalIndent(allFoundKeys, "", "  ")
	} else if len(allDiscoveredPaths) > 0 {
		fileData, err = json.MarshalIndent(allDiscoveredPaths, "", "  ")
	} else {
		verboseLog.Println("No results to save.")
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


// --- Args Structs for Modes ---
type bruteKeyArgs struct {
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

type discoveryArgs struct {
	baseURL                string
	pathWordlistPath       string
	paramWordlistPath      string
	depth                  int
	discoveryMethodsRaw    string
	fuzzMethodsRaw         string
	baselineIgnoreCodesRaw string
	fuzzTestValuesRaw      string
	threads                int
	httpClient             *http.Client
}

// --- BruteKey Mode Logic (Refactored from previous main) ---
func runBruteKeyMode(args bruteKeyArgs) {
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
	// Results channel untuk brutekey mode, akan diisi dengan FoundKey
	bruteKeyResultsChan := make(chan FoundKey, len(keys))
	var wg sync.WaitGroup

	for i := 0; i < args.threads; i++ {
		wg.Add(1)
		// Ini adalah worker lama, kita perlu memastikan ia menggunakan argumen yang benar
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
			normalLog.Printf("[FOUND KEY] Key: %s -> Status: %d, Placement: %s, URL: %s (Regex: %s)\n",
				found.Key, found.StatusCode, found.Placement, found.URL, found.MatchedRegex)
		}
	}()

	for _, key := range keys {
		jobs <- key
	}
	close(jobs)
	wg.Wait()
	close(bruteKeyResultsChan)
	time.Sleep(100 * time.Millisecond) // Ensure result collector goroutine finishes
}

// Worker struct for BruteKey - to avoid confusion with discovery worker args
type workerArgsForKeyBrute struct {
	targetURL         string
	httpMethod        string
	keyPlacementMethod string
	keyPlacementValue string // This is the format string or param name
	successCodes      map[int]bool
	successRegex      *regexp.Regexp
	filterRegex       *regexp.Regexp
	delay             time.Duration
	httpClient        *http.Client
}


// bruteKeyWorker is the renamed 'worker' function from previous versions
func bruteKeyWorker(id int, args workerArgsForKeyBrute, keys <-chan string, results chan<- FoundKey, wg *sync.WaitGroup) {
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

		finalKeyValue := key // The actual key from wordlist
		
		// Placeholder for the actual value to be placed (header value, query value, or full JSON body string)
		var valueToPlace string

		switch args.keyPlacementMethod {
		case "header":
			// args.keyPlacementValue is format like "X-Api-Key: %KEY%"
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
			// args.keyPlacementValue is the param name e.g. "apiKey"
			parsedURL, _ := url.Parse(currentTargetURL)
			query := parsedURL.Query()
			query.Set(args.keyPlacementValue, finalKeyValue)
			parsedURL.RawQuery = query.Encode()
			currentTargetURL = parsedURL.String()
			req, err = http.NewRequest(args.httpMethod, currentTargetURL, nil)
		case "json_body":
			// args.keyPlacementValue is the JSON template e.g. '{"token":"%KEY%"}'
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
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 GoBruter/1.1")


		resp, err := args.httpClient.Do(req)
		if err != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error sending request for key '%s' to %s: %v\n", id, key, currentTargetURL, err)
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}
		
		responseBodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if readErr != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error reading response body for key '%s': %v\n", id, key, readErr)
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}
		
		verboseLog.Printf("[BruteKeyWorker %d] Key '%s', URL: %s, Status: %s\n", id, key, currentTargetURL, resp.Status)

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


// --- Discovery Mode Logic (New - Skeleton for now) ---
func runDiscoveryMode(args discoveryArgs) {
	normalLog.Println("--- Running in Discovery Mode ---")
	if args.pathWordlistPath == "" {
		normalLog.Println("[Discovery Mode] Path Wordlist (-pw) is required.")
		os.Exit(1)
	}
    // Parameter wordlist is optional, can proceed without it if user only wants path discovery

	normalLog.Printf("[Discovery Mode] Path Wordlist: %s\n", args.pathWordlistPath)
    if args.paramWordlistPath != "" {
	    normalLog.Printf("[Discovery Mode] Param Wordlist: %s\n", args.paramWordlistPath)
    }
	normalLog.Printf("[Discovery Mode] Recursion Depth: %d\n", args.depth)
	normalLog.Printf("[Discovery Mode] Discovery Methods: %s\n", args.discoveryMethodsRaw)
	normalLog.Printf("[Discovery Mode] Fuzz Methods: %s\n", args.fuzzMethodsRaw)
	normalLog.Printf("[Discovery Mode] Baseline Ignore Codes: %s\n", args.baselineIgnoreCodesRaw)
	normalLog.Printf("[Discovery Mode] Fuzz Test Values: %s\n", args.fuzzTestValuesRaw)


	// TODO:
	// 1. Load pathWordlist and paramWordlist
	// paths, err := loadWordlist(args.pathWordlistPath) ...
	// params, err := loadWordlist(args.paramWordlistPath) ...

	// 2. Perform baseline requests to understand typical "Not Found" / "Bad Request" responses
	//    - Request a truly random path (e.g., args.baseURL + "/" + randomString(10))
	//    - Store its status code, content length, and maybe a hash of its content.

	// 3. Initialize job queue for paths and results channel for DiscoveredPath
	// pathJobs := make(chan DiscoveryJob, someBufferSize)
	// discoveryResultsChan := make(chan DiscoveredPath, someBufferSize)
	// var wg sync.WaitGroup

	// 4. Start discovery workers
	// for i := 0; i < args.threads; i++ {
	//    wg.Add(1)
	//    go discoveryWorker(i+1, discoveryWorkerArgs{...}, pathJobs, discoveryResultsChan, &wg)
	// }
	
	// 5. Goroutine to collect DiscoveredPath results
	// go func() {
	//    for pathInfo := range discoveryResultsChan {
	//       resultsMutex.Lock()
	//       allDiscoveredPaths = append(allDiscoveredPaths, pathInfo)
	//       resultsMutex.Unlock()
	//       normalLog.Printf("[DISCOVERED] Path: %s (%s) - Status: %d, Params: %d\n",
	//            pathInfo.URL, pathInfo.Method, pathInfo.StatusCode, len(pathInfo.FoundParameters))
	//    }
	// }()


	// 6. Seed initial jobs (paths from wordlist at depth 0)
	// initialJob := DiscoveryJob{ BasePath: args.baseURL, CurrentSegment: "", Depth: args.depth }
	// pathJobs <- initialJob // Atau loop pathwordlist dan buat job untuk setiap baseURL+pathSegment

	// 7. Wait for completion
	// close(pathJobs)
	// wg.Wait()
	// close(discoveryResultsChan)
	// time.Sleep(100 * time.Millisecond) // ensure collector finishes

	normalLog.Println("[Discovery Mode] Logic not fully implemented yet.")
    normalLog.Println("Stay tuned for recursive path discovery and parameter fuzzing!")
}


// --- Utility Functions (Shared or specific to a mode) ---
func loadWordlist(path string) ([]string, error) {
	// (Same as before, ensure it handles empty path gracefully if a wordlist is optional)
	if path == "" {
		return []string{}, nil // Return empty slice if no path, useful for optional param wordlist
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
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}

func parseSuccessCodes(codesRaw string) map[int]bool {
	// (Same as before)
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
			normalLog.Printf("Warning: Invalid status code '%s' in success codes list.\n", part)
		}
	}
	return codes
}

func getIntKeys(m map[int]bool) []int {
	// (Same as before)
    keys := make([]int, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}

func isValidIdentifier(s string) bool {
	// (Same as before - might be more relevant for discovery mode param names)
    match, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_-]*$`, s)
    return match
}

// Add more utility functions as needed for discovery (e.g., combineURL, normalizePath)
Key Mode) ---
type FoundKey struct {
	Key          string    `json:"key"`
	StatusCode   int       `json:"statusCode"`
	URL          string    `json:"url"`
	Method       string    `json:"method"`
	Placement    string    `json:"placement"`
	MatchedRegex string    `json:"matchedRegex,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// --- Structs for Discovery Mode ---
type DiscoveredParameter struct {
	Name         string   `json:"name"`
	In           string   `json:"in"` // "query", "json_body", "form_body"
	TestedValues []string `json:"tested_values"`
	Notes        string   `json:"notes,omitempty"` // e.g., "reflected in response", "changed status code"
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

var (
	verboseLog *log.Logger
	normalLog  *log.Logger
	outputFile string // Global untuk diakses oleh kedua mode saat menyimpan
	allFoundKeys []FoundKey // Untuk brutekey mode
	allDiscoveredPaths []DiscoveredPath // Untuk discovery mode
	resultsMutex sync.Mutex
)

func main() {
	verboseLog = log.New(io.Discard, "VERBOSE: ", log.Ldate|log.Ltime|log.Lshortfile)
	normalLog = log.New(os.Stdout, "", 0)

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
	paramWordlistFlag := flag.String("pp", "", "[Discover] Wordlist for parameter names")
	depthFlag := flag.Int("depth", 1, "[Discover] Recursion depth for path discovery")
	discoveryMethodsFlag := flag.String("dm", "GET", "[Discover] Comma-separated HTTP methods for path discovery (e.g., GET,POST)")
	fuzzMethodsFlag := flag.String("fm", "GET,POST", "[Discover] Comma-separated HTTP methods for parameter fuzzing")
	baselineIgnoreCodesFlag := flag.String("bic", "404", "[Discover] Comma-separated status codes to consider as baseline noise")
	fuzzTestValuesFlag := flag.String("ptv", "1,test,true", "[Discover] Comma-separated values to test for parameters")


	flag.Parse()
	outputFile = *outputFileFlag // Set global outputFile

	if *verboseFlag {
		verboseLog.SetOutput(os.Stderr)
	}

	if *targetURLFlag == "" {
		normalLog.Println("Target URL (-u) is required for all modes.")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize HTTP Client (shared)
	httpClient := &http.Client{
		Timeout: time.Duration(*timeoutFlag) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Use with caution
			Proxy:           http.ProxyFromEnvironment,
		},
	}
	if *proxyURLFlag != "" {
		pURL, errProxy := url.Parse(*proxyURLFlag)
		if errProxy != nil {
			normalLog.Printf("Invalid proxy URL: %v\n", errProxy)
			os.Exit(1)
		}
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
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
			threads:          *threadsFlag, // Pass common flags
			httpClient:       httpClient,
		})
	case "discover":
		runDiscoveryMode(discoveryArgs{
			baseURL:             *targetURLFlag,
			pathWordlistPath:    *pathWordlistFlag,
			paramWordlistPath:   *paramWordlistFlag,
			depth:               *depthFlag,
			discoveryMethodsRaw: *discoveryMethodsFlag,
			fuzzMethodsRaw:      *fuzzMethodsFlag,
			baselineIgnoreCodesRaw: *baselineIgnoreCodesFlag,
			fuzzTestValuesRaw:    *fuzzTestValuesFlag,
			threads:             *threadsFlag, // Pass common flags
			httpClient:          httpClient,
		})
	default:
		normalLog.Printf("Invalid mode: %s. Available modes: 'brutekey', 'discover'\n", *modeFlag)
		flag.Usage()
		os.Exit(1)
	}

	// Save results common logic (differentiated by mode)
	if outputFile != "" {
		saveResults()
	}

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
		foundCount = len(allDiscoveredPaths) // Menghitung jumlah path unik yang dianggap valid
		resultsMutex.Unlock()
		if foundCount == 0 {
			normalLog.Println("No interesting API paths found in discovery mode.")
		} else {
			normalLog.Printf("\n[Discovery Mode] Finished. Discovered %d potentially valid/interesting API path(s).\n", foundCount)
		}
	}
}

func saveResults() {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	var fileData []byte
	var err error

	if len(allFoundKeys) > 0 { // Prioritaskan hasil brutekey jika ada (atau tentukan berdasarkan mode aktif)
		fileData, err = json.MarshalIndent(allFoundKeys, "", "  ")
	} else if len(allDiscoveredPaths) > 0 {
		fileData, err = json.MarshalIndent(allDiscoveredPaths, "", "  ")
	} else {
		verboseLog.Println("No results to save.")
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


// --- Args Structs for Modes ---
type bruteKeyArgs struct {
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

type discoveryArgs struct {
	baseURL                string
	pathWordlistPath       string
	paramWordlistPath      string
	depth                  int
	discoveryMethodsRaw    string
	fuzzMethodsRaw         string
	baselineIgnoreCodesRaw string
	fuzzTestValuesRaw      string
	threads                int
	httpClient             *http.Client
}

// --- BruteKey Mode Logic (Refactored from previous main) ---
func runBruteKeyMode(args bruteKeyArgs) {
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
	// Results channel untuk brutekey mode, akan diisi dengan FoundKey
	bruteKeyResultsChan := make(chan FoundKey, len(keys))
	var wg sync.WaitGroup

	for i := 0; i < args.threads; i++ {
		wg.Add(1)
		// Ini adalah worker lama, kita perlu memastikan ia menggunakan argumen yang benar
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
			normalLog.Printf("[FOUND KEY] Key: %s -> Status: %d, Placement: %s, URL: %s (Regex: %s)\n",
				found.Key, found.StatusCode, found.Placement, found.URL, found.MatchedRegex)
		}
	}()

	for _, key := range keys {
		jobs <- key
	}
	close(jobs)
	wg.Wait()
	close(bruteKeyResultsChan)
	time.Sleep(100 * time.Millisecond) // Ensure result collector goroutine finishes
}

// Worker struct for BruteKey - to avoid confusion with discovery worker args
type workerArgsForKeyBrute struct {
	targetURL         string
	httpMethod        string
	keyPlacementMethod string
	keyPlacementValue string // This is the format string or param name
	successCodes      map[int]bool
	successRegex      *regexp.Regexp
	filterRegex       *regexp.Regexp
	delay             time.Duration
	httpClient        *http.Client
}


// bruteKeyWorker is the renamed 'worker' function from previous versions
func bruteKeyWorker(id int, args workerArgsForKeyBrute, keys <-chan string, results chan<- FoundKey, wg *sync.WaitGroup) {
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

		finalKeyValue := key // The actual key from wordlist
		
		// Placeholder for the actual value to be placed (header value, query value, or full JSON body string)
		var valueToPlace string

		switch args.keyPlacementMethod {
		case "header":
			// args.keyPlacementValue is format like "X-Api-Key: %KEY%"
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
			// args.keyPlacementValue is the param name e.g. "apiKey"
			parsedURL, _ := url.Parse(currentTargetURL)
			query := parsedURL.Query()
			query.Set(args.keyPlacementValue, finalKeyValue)
			parsedURL.RawQuery = query.Encode()
			currentTargetURL = parsedURL.String()
			req, err = http.NewRequest(args.httpMethod, currentTargetURL, nil)
		case "json_body":
			// args.keyPlacementValue is the JSON template e.g. '{"token":"%KEY%"}'
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
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 GoBruter/1.1")


		resp, err := args.httpClient.Do(req)
		if err != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error sending request for key '%s' to %s: %v\n", id, key, currentTargetURL, err)
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}
		
		responseBodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if readErr != nil {
			verboseLog.Printf("[BruteKeyWorker %d] Error reading response body for key '%s': %v\n", id, key, readErr)
			if args.delay > 0 { time.Sleep(args.delay) }
			continue
		}
		
		verboseLog.Printf("[BruteKeyWorker %d] Key '%s', URL: %s, Status: %s\n", id, key, currentTargetURL, resp.Status)

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


// --- Discovery Mode Logic (New - Skeleton for now) ---
func runDiscoveryMode(args discoveryArgs) {
	normalLog.Println("--- Running in Discovery Mode ---")
	if args.pathWordlistPath == "" {
		normalLog.Println("[Discovery Mode] Path Wordlist (-pw) is required.")
		os.Exit(1)
	}
    // Parameter wordlist is optional, can proceed without it if user only wants path discovery

	normalLog.Printf("[Discovery Mode] Path Wordlist: %s\n", args.pathWordlistPath)
    if args.paramWordlistPath != "" {
	    normalLog.Printf("[Discovery Mode] Param Wordlist: %s\n", args.paramWordlistPath)
    }
	normalLog.Printf("[Discovery Mode] Recursion Depth: %d\n", args.depth)
	normalLog.Printf("[Discovery Mode] Discovery Methods: %s\n", args.discoveryMethodsRaw)
	normalLog.Printf("[Discovery Mode] Fuzz Methods: %s\n", args.fuzzMethodsRaw)
	normalLog.Printf("[Discovery Mode] Baseline Ignore Codes: %s\n", args.baselineIgnoreCodesRaw)
	normalLog.Printf("[Discovery Mode] Fuzz Test Values: %s\n", args.fuzzTestValuesRaw)


	// TODO:
	// 1. Load pathWordlist and paramWordlist
	// paths, err := loadWordlist(args.pathWordlistPath) ...
	// params, err := loadWordlist(args.paramWordlistPath) ...

	// 2. Perform baseline requests to understand typical "Not Found" / "Bad Request" responses
	//    - Request a truly random path (e.g., args.baseURL + "/" + randomString(10))
	//    - Store its status code, content length, and maybe a hash of its content.

	// 3. Initialize job queue for paths and results channel for DiscoveredPath
	// pathJobs := make(chan DiscoveryJob, someBufferSize)
	// discoveryResultsChan := make(chan DiscoveredPath, someBufferSize)
	// var wg sync.WaitGroup

	// 4. Start discovery workers
	// for i := 0; i < args.threads; i++ {
	//    wg.Add(1)
	//    go discoveryWorker(i+1, discoveryWorkerArgs{...}, pathJobs, discoveryResultsChan, &wg)
	// }
	
	// 5. Goroutine to collect DiscoveredPath results
	// go func() {
	//    for pathInfo := range discoveryResultsChan {
	//       resultsMutex.Lock()
	//       allDiscoveredPaths = append(allDiscoveredPaths, pathInfo)
	//       resultsMutex.Unlock()
	//       normalLog.Printf("[DISCOVERED] Path: %s (%s) - Status: %d, Params: %d\n",
	//            pathInfo.URL, pathInfo.Method, pathInfo.StatusCode, len(pathInfo.FoundParameters))
	//    }
	// }()


	// 6. Seed initial jobs (paths from wordlist at depth 0)
	// initialJob := DiscoveryJob{ BasePath: args.baseURL, CurrentSegment: "", Depth: args.depth }
	// pathJobs <- initialJob // Atau loop pathwordlist dan buat job untuk setiap baseURL+pathSegment

	// 7. Wait for completion
	// close(pathJobs)
	// wg.Wait()
	// close(discoveryResultsChan)
	// time.Sleep(100 * time.Millisecond) // ensure collector finishes

	normalLog.Println("[Discovery Mode] Logic not fully implemented yet.")
    normalLog.Println("Stay tuned for recursive path discovery and parameter fuzzing!")
}


// --- Utility Functions (Shared or specific to a mode) ---
func loadWordlist(path string) ([]string, error) {
	// (Same as before, ensure it handles empty path gracefully if a wordlist is optional)
	if path == "" {
		return []string{}, nil // Return empty slice if no path, useful for optional param wordlist
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
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}

func parseSuccessCodes(codesRaw string) map[int]bool {
	// (Same as before)
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
			normalLog.Printf("Warning: Invalid status code '%s' in success codes list.\n", part)
		}
	}
	return codes
}

func getIntKeys(m map[int]bool) []int {
	// (Same as before)
    keys := make([]int, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}

func isValidIdentifier(s string) bool {
	// (Same as before - might be more relevant for discovery mode param names)
    match, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_-]*$`, s)
    return match
}

// Add more utility functions as needed for discovery (e.g., combineURL, normalizePath)
