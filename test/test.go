package main

import (
	"github.com/getkin/kin-openapi/openapi3"
	"bufio"
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

// --- Definisi Struktur Data ---

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
	ContentType   string `json:"contentType"`
}

// DiscoveryJob mendefinisikan sebuah pekerjaan untuk discovery worker.
type DiscoveryJob struct {
	BaseURLForNextLevel string // URL dari path valid yang ditemukan di kedalaman sebelumnya
	PathSegmentToTest   string // Segmen dari pathWordlist yang akan ditambahkan
	CurrentDepth        int
}

// --- Variabel Global & Status ---
var (
	verboseLog         *log.Logger
	normalLog          *log.Logger
	outputFile         string
	allFoundKeys       []FoundKey
	discoveredPathMap  map[string]DiscoveredPath // Untuk melacak path unik yang ditemukan (URL+Method -> DiscoveredPath)
	resultsMutex       sync.Mutex
	globalHTTPClient   *http.Client
	globalBaselineProfile BaselineProfile
	errorParamRegexList []*regexp.Regexp // Regex untuk parsing parameter dari pesan error

	// Variabel baru untuk Rate Limiting
	rateLimitState struct {
		sync.Mutex
		lastTriggerTime time.Time
		dynamicDelay    time.Duration
	}
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

// Fungsi utama program
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
	wordlistPathFlag := flag.String("w", "", "[BruteKey] Path to wordlist file for keys/tokens")
	headerFormatFlag := flag.String("H", "", "[BruteKey] HTTP Header format for API Key")
	queryParamFlag := flag.String("qp", "", "[BruteKey] Query parameter name for API Key")
	jsonBodyTemplateFlag := flag.String("jb", "", "[BruteKey] JSON body template with %KEY%")
	bkHTTPMethodFlag := flag.String("m", "GET", "[BruteKey] HTTP method")
	bkSuccessCodesRawFlag := flag.String("s", "200", "[BruteKey] Comma-separated success HTTP status codes")
	bkSuccessRegexFlag := flag.String("sr", "", "[BruteKey] Regex to match in response body for success")
	bkFilterRegexFlag := flag.String("fr", "", "[BruteKey] Regex to match in response body to filter out/ignore")
	
	// --- Flag Delay & Rate Limiting (digunakan oleh kedua mode) ---
	initialDelayFlag := flag.Int("delay", 0, "Initial delay in milliseconds between requests per thread")
	rateLimitIncreaseFlag := flag.Duration("rl-increase", 50*time.Millisecond, "Amount to increase dynamic delay by when rate limited")

	// --- Discovery Mode Flags ---
	pathWordlistFlag := flag.String("pw", "", "[Discover] Wordlist for path segments")
	paramWordlistFlag := flag.String("pp", "", "[Discover] Wordlist for parameter names (optional)")
	maxDepthFlag := flag.Int("depth", 0, "[Discover] Max recursion depth for path discovery (0 for base+wordlist)")
	discoveryMethodsFlag := flag.String("dm", "GET,OPTIONS", "[Discover] HTTP methods for path discovery")
	fuzzMethodsFlag := flag.String("fm", "GET,POST", "[Discover] HTTP methods for parameter fuzzing")
	baselineIgnoreCodesFlag := flag.String("bic", "404", "[Discover] Status codes to generally consider as baseline noise")
	fuzzTestValuesFlag := flag.String("ptv", "1,test,true,0,admin", "[Discover] Values to test for parameters")
	fuzzJSONTemplatePathFlag := flag.String("fuzz-json", "", "[Discover] Path to a JSON file to use as a template for body fuzzing. Use %PARAM% and %FUZZ% placeholders.")
	specFilePathFlag := flag.String("spec", "", "[Discover] Path to an OpenAPI/Swagger specification file (e.g., swagger.json) to seed discovery")


	flag.Parse()

	// --- Inisialisasi Konfigurasi & State ---
	outputFile = *outputFileFlag
	rateLimitState.dynamicDelay = time.Duration(*initialDelayFlag) * time.Millisecond

	setupAndRun(*targetURLFlag, *modeFlag, *threadsFlag, *proxyURLFlag, *timeoutFlag, *verboseFlag, bruteKeyArgs{
		targetURL: *targetURLFlag, wordlistPath: *wordlistPathFlag, headerFormat: *headerFormatFlag, queryParam: *queryParamFlag,
		jsonBodyTemplate: *jsonBodyTemplateFlag, httpMethod: *bkHTTPMethodFlag, successCodesRaw: *bkSuccessCodesRawFlag,
		successRegexRaw: *bkSuccessRegexFlag, filterRegexRaw: *bkFilterRegexFlag, initialDelay: *initialDelayFlag, threads: *threadsFlag,
		rateLimitIncrease: *rateLimitIncreaseFlag,
	}, discoveryArgs{
		baseURL: *targetURLFlag, pathWordlistPath: *pathWordlistFlag, paramWordlistPath: *paramWordlistFlag,
		maxDepth: *maxDepthFlag, discoveryMethodsRaw: *discoveryMethodsFlag, fuzzMethodsRaw: *fuzzMethodsFlag,
		baselineIgnoreCodesRaw: *baselineIgnoreCodesFlag, fuzzTestValuesRaw: *fuzzTestValuesFlag, threads: *threadsFlag,
		initialDelay: *initialDelayFlag, rateLimitIncrease: *rateLimitIncreaseFlag,
		fuzzJSONTemplatePath: *fuzzJSONTemplatePathFlag,
		specFilePath: *specFilePathFlag,
	})

	logFinalResults(*modeFlag)
}

// processOpenAPISpec memuat dan mem-parsing file spesifikasi OpenAPI.
// Fungsi ini sekarang mengekstrak semua path dan nama parameter dari dokumen.
func processOpenAPISpec(filePath string) (specPaths []string, specParams []string) {
	normalLog.Printf("[Discovery Mode] Loading OpenAPI specification from: %s\n", filePath)

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(filePath)
	if err != nil {
		normalLog.Fatalf("[Discovery Mode] Failed to load or parse OpenAPI spec file: %v", err)
	}

	err = doc.Validate(loader.Context)
	if err != nil {
		normalLog.Fatalf("[Discovery Mode] OpenAPI spec validation failed: %v", err)
	}

	normalLog.Printf("Successfully loaded and validated OpenAPI spec: '%s'\n", doc.Info.Title)

	// Gunakan map untuk menghindari duplikasi
	pathSet := make(map[string]bool)
	paramSet := make(map[string]bool)

	// Iterasi melalui semua path yang ada di dalam spesifikasi
	for pathStr, pathItem := range doc.Paths.Map() {
		// Tambahkan path utama ke dalam set
		pathSet[pathStr] = true

		// Iterasi melalui setiap operasi (GET, POST, PUT, dll.) di dalam path
		for _, operation := range pathItem.Operations() {
			// Iterasi melalui setiap parameter yang didefinisikan untuk operasi ini
			for _, parameterRef := range operation.Parameters {
				if parameterRef.Value != nil {
					// Tambahkan nama parameter ke dalam set
					paramSet[parameterRef.Value.Name] = true
				}
			}
			// Cek parameter di dalam request body juga
			if operation.RequestBody != nil && operation.RequestBody.Value != nil {
				// Iterasi melalui setiap tipe konten (misal, application/json)
				for _, mediaType := range operation.RequestBody.Value.Content {
					if mediaType.Schema != nil && mediaType.Schema.Value != nil {
						// Iterasi melalui properti di dalam skema body
						for propName := range mediaType.Schema.Value.Properties {
							paramSet[propName] = true
						}
					}
				}
			}
		}
	}

	// Konversi set menjadi slice
	for path := range pathSet {
		specPaths = append(specPaths, path)
	}
	for param := range paramSet {
		specParams = append(specParams, param)
	}
	
	normalLog.Printf("[Discovery Mode] Extracted %d unique paths and %d unique parameter names from spec.\n", len(specPaths), len(specParams))
	
	return specPaths, specParams
}

// setupAndRun menggabungkan setup dan eksekusi mode
func setupAndRun(targetURL, mode string, threads int, proxyURL string, timeout int, verbose bool, bkArgs bruteKeyArgs, dsArgs discoveryArgs) {
	if verbose {
		verboseLog.SetOutput(os.Stderr)
	}
	_, errParseURL := url.ParseRequestURI(targetURL)
	if errParseURL != nil {
		normalLog.Fatalf("Invalid Target URL (-u): %v", errParseURL)
	}

	globalHTTPClient = &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConnsPerHost: threads * 2,
			DisableKeepAlives:   false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			verboseLog.Printf("Redirecting from %s to %s (via %d redirects)\n", via[0].URL.String(), req.URL.String(), len(via))
			return http.ErrUseLastResponse
		},
	}
	if proxyURL != "" {
		pURL, errProxy := url.Parse(proxyURL)
		if errProxy != nil {
			normalLog.Fatalf("Invalid proxy URL: %v", errProxy)
		}
		if transport, ok := globalHTTPClient.Transport.(*http.Transport); ok {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}
	
	normalLog.Printf("--- Configuration ---")
	normalLog.Printf("Mode: %s | Target: %s | Threads: %d", mode, targetURL, threads)
	normalLog.Printf("---------------------")

	switch mode {
	case "brutekey":
		bkArgs.httpClient = globalHTTPClient
		runBruteKeyMode(bkArgs)
	case "discover":
		dsArgs.httpClient = globalHTTPClient
		runDiscoveryMode(dsArgs)
	default:
		normalLog.Fatalf("Invalid mode: %s. Available modes: 'brutekey', 'discover'\n", mode)
	}
	
	if outputFile != "" {
		saveResults(mode)
	}
}

// logFinalResults mencatat rangkuman hasil di akhir.
func logFinalResults(mode string) {
	if mode == "brutekey" {
		resultsMutex.Lock()
		foundCount := len(allFoundKeys)
		resultsMutex.Unlock()
		if foundCount == 0 {
			normalLog.Println("\nNo valid API keys found in brutekey mode.")
		} else {
			normalLog.Printf("\n[BruteKey Mode] Finished. Found %d valid API key(s).\n", foundCount)
		}
	} else if mode == "discover" {
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
	initialDelay, threads int
	rateLimitIncrease     time.Duration
	httpClient            *http.Client
}
type discoveryArgs struct {
	baseURL, pathWordlistPath, paramWordlistPath, discoveryMethodsRaw, fuzzMethodsRaw, baselineIgnoreCodesRaw, fuzzTestValuesRaw string
	maxDepth, threads, initialDelay int
	rateLimitIncrease               time.Duration
	fuzzJSONTemplatePath            string
	specFilePath                    string
	httpClient                      *http.Client
	
}

// --- Logika Mode BruteKey ---
func runBruteKeyMode(args bruteKeyArgs) {
	normalLog.Println("--- Running in BruteKey Mode ---")
	if args.wordlistPath == "" {
		normalLog.Fatal("[BruteKey Mode] Wordlist (-w) is required.")
	}

	keyPlacementMethod, keyPlacementValue := determineKeyPlacement(args)
	normalLog.Printf("[BruteKey Mode] Key Placement: %s\n", keyPlacementMethod)

	keys, err := loadWordlist(args.wordlistPath)
	if err != nil || len(keys) == 0 {
		normalLog.Fatalf("[BruteKey Mode] Error loading or empty wordlist: %v", err)
	}
	normalLog.Printf("[BruteKey Mode] Wordlist: %s (%d keys)\n", args.wordlistPath, len(keys))

	successCodes, successRegex, filterRegex := parseBruteKeyCriteria(args)
	
	jobs := make(chan string, len(keys))
	bruteKeyResultsChan := make(chan FoundKey, len(keys))
	var wg sync.WaitGroup

	workerArgs := workerArgsForKeyBrute{
		targetURL: args.targetURL, httpMethod: args.httpMethod, keyPlacementMethod: keyPlacementMethod,
		keyPlacementValue: keyPlacementValue, successCodes: successCodes, successRegex: successRegex,
		filterRegex: filterRegex, rateLimitIncrease: args.rateLimitIncrease, httpClient: args.httpClient,
	}

	for i := 0; i < args.threads; i++ {
		wg.Add(1)
		go bruteKeyWorker(i+1, workerArgs, jobs, bruteKeyResultsChan, &wg)
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

func determineKeyPlacement(args bruteKeyArgs) (string, string) {
	if args.queryParam != "" { return "query", args.queryParam }
	if args.jsonBodyTemplate != "" {
		if !strings.Contains(args.jsonBodyTemplate, "%KEY%") {
			normalLog.Fatal("[BruteKey Mode] JSON body template (-jb) must contain placeholder %KEY%")
		}
		return "json_body", args.jsonBodyTemplate
	}
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
func parseBruteKeyCriteria(args bruteKeyArgs) (map[int]bool, *regexp.Regexp, *regexp.Regexp) {
	successCodes := parseSuccessCodes(args.successCodesRaw)
	var successRegex, filterRegex *regexp.Regexp
	var err error
	if args.successRegexRaw != "" { successRegex, err = regexp.Compile(args.successRegexRaw); if err != nil { normalLog.Fatalf("Invalid success regex: %v", err) } }
	if args.filterRegexRaw != "" { filterRegex, err = regexp.Compile(args.filterRegexRaw); if err != nil { normalLog.Fatalf("Invalid filter regex: %v", err) } }
	if len(successCodes) == 0 && successRegex == nil { normalLog.Fatal("No success criteria provided for brutekey mode.") }
	return successCodes, successRegex, filterRegex
}

type workerArgsForKeyBrute struct {
	targetURL, httpMethod, keyPlacementMethod, keyPlacementValue string
	successCodes                                                 map[int]bool
	successRegex, filterRegex                                    *regexp.Regexp
	rateLimitIncrease                                            time.Duration
	httpClient                                                   *http.Client
}

func bruteKeyWorker(id int, args workerArgsForKeyBrute, keys <-chan string, results chan<- FoundKey, wg *sync.WaitGroup) {
	defer wg.Done()
	for key := range keys {
		applyDynamicDelayAndCooldown()
		if key == "" { continue }
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
		if resp.StatusCode == http.StatusTooManyRequests {
			handleRateLimit(resp, args.rateLimitIncrease)
			resp.Body.Close()
			continue
		}
		bodyBytes, cl := readAndCloseBody(resp)
		verboseLog.Printf("[BruteKeyWorker %d] Key '%s', URL: %s, Status: %s, CL: %d\n", id, key, currentTargetURL, resp.Status, cl)
		if args.filterRegex != nil && args.filterRegex.Match(bodyBytes) { continue }

		success, matchedRegex := isBruteKeySuccess(resp.StatusCode, bodyBytes, args.successCodes, args.successRegex)
		if success {
			results <- FoundKey{
				Key: key, StatusCode: resp.StatusCode, ContentLength: cl, URL: currentTargetURL, Method: args.httpMethod,
				Placement: args.keyPlacementMethod, MatchedRegex: matchedRegex, Timestamp: time.Now().UTC(),
			}
		}
	}
}

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
			if len(parts) == 2 { req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			} else { err = fmt.Errorf("invalid header format") }
		}
	case "query":
		parsedURL, _ := url.Parse(currentTargetURL)
		q := parsedURL.Query(); q.Set(args.keyPlacementValue, key); parsedURL.RawQuery = q.Encode()
		currentTargetURL = parsedURL.String()
		req, err = http.NewRequest(args.httpMethod, currentTargetURL, nil)
	case "json_body":
		jsonBody := strings.ReplaceAll(args.keyPlacementValue, "%KEY%", key)
		body = strings.NewReader(jsonBody)
		req, err = http.NewRequest(args.httpMethod, currentTargetURL, body)
		if err == nil { req.Header.Set("Content-Type", "application/json") }
	default:
		err = fmt.Errorf("unknown placement method")
	}
	if err == nil { req.Header.Set("User-Agent", "GoTool/1.4") }
	return currentTargetURL, req, err
}
func isBruteKeySuccess(statusCode int, body []byte, successCodes map[int]bool, successRegex *regexp.Regexp) (bool, string) {
	success, matchedRegex := false, ""
	if _, ok := successCodes[statusCode]; ok { success = true }
	if successRegex != nil && successRegex.Match(body) {
		success = true
		if matches := successRegex.FindStringSubmatch(string(body)); len(matches) > 0 { matchedRegex = matches[0] }
	}
	return success, matchedRegex
}

// --- Logika Mode Discovery ---
func runDiscoveryMode(args discoveryArgs) {
	normalLog.Println("--- Running in Discovery Mode ---")

	var specPaths, specParams []string
	// Proses file spesifikasi jika diberikan
	if args.specFilePath != "" {
		specPaths, specParams = processOpenAPISpec(args.specFilePath)
	}

	// Jika tidak ada spesifikasi, wordlist path wajib ada
	if args.specFilePath == "" && args.pathWordlistPath == "" {
		normalLog.Fatal("[Discovery Mode] Path Wordlist (-pw) or Spec file (--spec) is required.")
	}

	// Muat wordlist dari file
	pathWordlistFromFile, err := loadWordlist(args.pathWordlistPath)
	if err != nil {
		normalLog.Fatalf("[Discovery Mode] Error loading path wordlist: %v", err)
	}
	paramWordlistFromFile, _ := loadWordlist(args.paramWordlistPath)

	// ### LOGIKA BARU: Gabungkan wordlist dari file dengan data dari spesifikasi ###
	pathWordlist := mergeAndDeduplicateSlices(pathWordlistFromFile, specPaths)
	paramWordlist := mergeAndDeduplicateSlices(paramWordlistFromFile, specParams)

	if len(pathWordlist) == 0 {
		normalLog.Fatalf("[Discovery Mode] No paths to test. Provide a path wordlist (-pw) or a valid spec file (--spec).")
	}

	normalLog.Printf("[Discovery Mode] Total unique paths to test: %d\n", len(pathWordlist))
	if len(paramWordlist) > 0 {
		normalLog.Printf("[Discovery Mode] Total unique parameters to fuzz: %d\n", len(paramWordlist))
	}

	discoveryMethods := parseCommaSeparatedString(args.discoveryMethodsRaw)
	fuzzMethods := parseCommaSeparatedString(args.fuzzMethodsRaw)
	baselineIgnoreCodes := parseSuccessCodes(args.baselineIgnoreCodesRaw)
	fuzzTestValues := parseCommaSeparatedString(args.fuzzTestValuesRaw)
	
	var fuzzJSONTemplate string
	if args.fuzzJSONTemplatePath != "" {
		templateBytes, err := os.ReadFile(args.fuzzJSONTemplatePath)
		if err != nil {
			normalLog.Fatalf("[Discovery Mode] Error reading JSON fuzz template file %s: %v", args.fuzzJSONTemplatePath, err)
		}
		fuzzJSONTemplate = string(templateBytes)
		if !strings.Contains(fuzzJSONTemplate, "%PARAM%") || !strings.Contains(fuzzJSONTemplate, "%FUZZ%") {
			normalLog.Fatal("[Discovery Mode] JSON fuzz template must contain both %PARAM% and %FUZZ% placeholders.")
		}
		normalLog.Printf("[Discovery Mode] Loaded JSON fuzz template from %s\n", args.fuzzJSONTemplatePath)
	}
	
	normalLog.Println("[Discovery Mode] Performing baseline requests...")
	performBaselineRequests(args.baseURL, args.httpClient)
	normalLog.Printf("[Discovery Mode] Baseline Profile: RandomPathNotFound (Status: %d, CL: %d)\n",
		globalBaselineProfile.RandomPathNotFound.StatusCode, globalBaselineProfile.RandomPathNotFound.ContentLength)

	currentLevelPathsToExplore := []string{strings.TrimRight(args.baseURL, "/")}

	// Loop rekursi per kedalaman
	for depth := 0; depth <= args.maxDepth; depth++ {
		if len(currentLevelPathsToExplore) == 0 {
			normalLog.Printf("[Discovery Mode] No new valid paths found to explore further. Stopping.\n")
			break
		}
		normalLog.Printf("[Discovery Mode] Starting discovery at Depth %d. Base paths: %d\n", depth, len(currentLevelPathsToExplore))

		discoveryJobsChan := make(chan DiscoveryJob, len(currentLevelPathsToExplore)*len(pathWordlist))
		discoveryResultsChan := make(chan DiscoveredPath, 200)
		var wg, collectorsWg sync.WaitGroup
		collectorsWg.Add(1)

		go func() { // Goroutine pengumpul hasil
			defer collectorsWg.Done()
			for pathInfo := range discoveryResultsChan {
				processDiscoveryResult(pathInfo)
			}
		}()

		workerArgs := discoveryWorkerArgs{
			discoveryMethods:    discoveryMethods,
			baselineIgnoreCodes: baselineIgnoreCodes,
			paramWordlist:       paramWordlist,
			fuzzMethods:         fuzzMethods,
			fuzzTestValues:      fuzzTestValues,
			fuzzJSONTemplate:    fuzzJSONTemplate,
			rateLimitIncrease:   args.rateLimitIncrease,
			httpClient:          args.httpClient,
		}
		for i := 0; i < args.threads; i++ {
			wg.Add(1)
			go discoveryWorker(i+1, workerArgs, discoveryJobsChan, &wg)
		}

		jobCount := 0
		wordlistForThisDepth := pathWordlist
		// Jika kita berada di kedalaman 0 DAN ada path dari spec, kita hanya gunakan path spec
		// untuk menghindari duplikasi (misal, /users dari spec dan /users dari wordlist)
		if depth == 0 && len(specPaths) > 0 {
			wordlistForThisDepth = mergeAndDeduplicateSlices(specPaths, pathWordlistFromFile)
		}

		for _, basePath := range currentLevelPathsToExplore {
			for _, segment := range wordlistForThisDepth {
				// Untuk kedalaman > 0, kita hanya gunakan wordlist dari file, bukan path dari spec lagi
				if depth > 0 {
					segment = pathWordlistFromFile[len(pathWordlistFromFile)-len(wordlistForThisDepth)+jobCount%len(wordlistForThisDepth)]
				}
				jobCount++
				discoveryJobsChan <- DiscoveryJob{
					BaseURLForNextLevel: basePath,
					PathSegmentToTest:   segment,
					CurrentDepth:        depth,
				}
			}
		}
		normalLog.Printf("[Discovery Mode] Depth %d: Submitted %d jobs to workers.\n", depth, jobCount)

		close(discoveryJobsChan)
		wg.Wait()
		close(discoveryResultsChan)
		collectorsWg.Wait()

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

// Tambahkan fungsi helper ini untuk menggabungkan dan mendeduplikasi slice
func mergeAndDeduplicateSlices(sliceA, sliceB []string) []string {
	set := make(map[string]bool)
	for _, item := range sliceA {
		set[item] = true
	}
	for _, item := range sliceB {
		set[item] = true
	}

	result := make([]string, 0, len(set))
	for item := range set {
		result = append(result, item)
	}
	return result
}

func processDiscoveryResult(pathInfo DiscoveredPath) {
	mapMutexKey := pathInfo.Method + " " + pathInfo.URL
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	existing, foundInMap := discoveredPathMap[mapMutexKey]
	if !foundInMap || (len(pathInfo.FoundParameters) > len(existing.FoundParameters)) || (!existing.IsLikelyValid && pathInfo.IsLikelyValid) {
		if foundInMap {
			pathInfo.FoundParameters = mergeDiscoveredParameters(existing.FoundParameters, pathInfo.FoundParameters)
		}
		discoveredPathMap[mapMutexKey] = pathInfo

		paramCount := len(pathInfo.FoundParameters)
		logMessage := ""
		if pathInfo.IsLikelyValid {
			logMessage = fmt.Sprintf("[VALID DEPTH %d] %s %s (Status: %d, CL: %d, Params: %d)",
				pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, pathInfo.ContentLength, paramCount)
		} else if paramCount > 0 {
			logMessage = fmt.Sprintf("[INFO  DEPTH %d] %s %s (Status: %d, ParamsFound: %d)",
				pathInfo.Depth, pathInfo.Method, pathInfo.URL, pathInfo.StatusCode, paramCount)
		}
		if logMessage != "" { normalLog.Println(logMessage) }
	}
}

type discoveryWorkerArgs struct {
	discoveryMethods, fuzzMethods, fuzzTestValues, paramWordlist []string
	baselineIgnoreCodes                                          map[int]bool
	fuzzJSONTemplate                                             string
	rateLimitIncrease                                            time.Duration
	httpClient                                                   *http.Client
}

// discoveryWorker adalah goroutine yang bertugas memproses satu job penemuan.
func discoveryWorker(id int, args discoveryWorkerArgs, jobs <-chan DiscoveryJob, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		// Terapkan jeda dinamis atau cooldown jika diperlukan sebelum setiap job
		applyDynamicDelayAndCooldown()

		// Gabungkan URL dasar dari job dengan segmen path untuk mendapatkan URL lengkap
		// Menggunakan url.JoinPath (tersedia di Go 1.19+) adalah cara yang lebih aman
		fullURL, err := url.JoinPath(job.BaseURLForNextLevel, job.PathSegmentToTest)
		if err != nil {
			verboseLog.Printf("[DiscoveryWorker %d] Error joining URL: %v\n", id, err)
			continue
		}
		verboseLog.Printf("[DiscoveryWorker %d] Path discovery: %s\n", id, fullURL)

		// Simpan respons dasar untuk path ini, akan digunakan untuk perbandingan saat fuzzing parameter
		basePathResponses := make(map[string]ResponseCharacteristics)

		// Coba setiap metode HTTP yang ditentukan untuk penemuan jalur
		for _, method := range args.discoveryMethods {
			req, err := http.NewRequest(method, fullURL, nil)
			if err != nil {
				verboseLog.Printf("[DiscoveryWorker %d] Error creating request for %s %s: %v\n", id, method, fullURL, err)
				continue
			}
			req.Header.Set("User-Agent", "GoTool/1.5 (Discovery)")

			resp, err := args.httpClient.Do(req)
			if err != nil {
				verboseLog.Printf("[DiscoveryWorker %d] Error sending request for %s %s: %v\n", id, method, fullURL, err)
				continue
			}

			// Periksa jika respons adalah 429 (Rate Limiting)
			if resp.StatusCode == http.StatusTooManyRequests {
				handleRateLimit(resp, args.rateLimitIncrease)
				resp.Body.Close()
				continue // Lewati metode ini untuk job ini, lanjut ke metode berikutnya
			}

			// Simpan karakteristik respons dasar termasuk Content-Type
			fuzzContentType := resp.Header.Get("Content-Type")
			bodyBytes, cl := readAndCloseBody(resp)
			basePathResponses[method] = ResponseCharacteristics{
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				ContentType:   fuzzContentType,
			}

			// Bandingkan respons dengan baseline untuk menentukan apakah path ini valid/menarik
			isLikelyValid, comparisonNote := compareWithBaseline(resp.StatusCode, cl, args.baselineIgnoreCodes)
			
			// Coba temukan petunjuk parameter dari pesan error
			foundParamsFromError := parseErrorsForParams(bodyBytes)
			allFoundOnPathParams := foundParamsFromError

			// Jika path dianggap valid ATAU ada petunjuk dari pesan error,
			// DAN ada wordlist parameter ATAU template JSON, maka lakukan fuzzing.
			shouldFuzz := isLikelyValid || len(foundParamsFromError) > 0
			if shouldFuzz && (len(args.paramWordlist) > 0 || args.fuzzJSONTemplate != "") {
				verboseLog.Printf("[DiscoveryWorker %d] Starting parameter fuzzing for %s %s\n", id, method, fullURL)
				fuzzedParams := fuzzParametersOnPath(fullURL, method, basePathResponses[method], args, id)
				if len(fuzzedParams) > 0 {
					// Gabungkan parameter yang ditemukan dari fuzzing dengan yang dari pesan error
					allFoundOnPathParams = mergeDiscoveredParameters(allFoundOnPathParams, fuzzedParams)
				}
			}

			// Kirim hasil akhir dari pemrosesan path ini ke kolektor
			processDiscoveryResult(DiscoveredPath{
				URL:                fullURL,
				Method:             method,
				StatusCode:         resp.StatusCode,
				ContentLength:      cl,
				BaselineComparison: comparisonNote,
				IsLikelyValid:      isLikelyValid,
				FoundParameters:    allFoundOnPathParams,
				Depth:              job.CurrentDepth,
				Timestamp:          time.Now().UTC(),
			})
		}
	}
}

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
					foundParams = append(foundParams, DiscoveredParameter{ Name: paramName, In: "unknown_from_error", Notes: "derived_from_error_message", Evidence: truncateString(match[0], 100) })
				}
			}
		}
	}
	return foundParams
}

func fuzzParametersOnPath(pathURL string, originalMethod string, basePathResponseChars ResponseCharacteristics, args discoveryWorkerArgs, workerID int) []DiscoveredParameter {
	var fuzzedParams []DiscoveredParameter
	// Menggunakan map untuk menampung parameter unik yang ditemukan di sesi fuzzing ini
	uniqueParamsFound := make(map[string]DiscoveredParameter)

	// Iterasi melalui setiap metode HTTP yang ditentukan untuk fuzzing (misal, GET, POST)
	for _, fuzzMethod := range args.fuzzMethods {
		// Iterasi melalui setiap nama parameter dari wordlist
		for _, paramName := range args.paramWordlist {
			// Iterasi melalui setiap nilai tes untuk parameter tersebut
			for _, testValue := range args.fuzzTestValues {

				// 1. Coba sebagai Parameter Query (cocok untuk GET, tapi bisa juga di POST)
				if fuzzMethod == "GET" || fuzzMethod == "POST" {
					fuzzURL, _ := url.Parse(pathURL)
					q := fuzzURL.Query()
					q.Set(paramName, testValue)
					fuzzURL.RawQuery = q.Encode()
					req, err := http.NewRequest(fuzzMethod, fuzzURL.String(), nil)
					if err == nil {
						if p, ok := analyzeFuzzResponse(req, "query", paramName, testValue, basePathResponseChars, workerID, args.rateLimitIncrease); ok {
							// Jika ditemukan, simpan ke map untuk deduplikasi
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}

				// 2. Coba sebagai Form Body (hanya untuk metode yang mendukung body)
				if fuzzMethod == "POST" || fuzzMethod == "PUT" || fuzzMethod == "PATCH" {
					formData := url.Values{}
					formData.Set(paramName, testValue)
					req, err := http.NewRequest(fuzzMethod, pathURL, strings.NewReader(formData.Encode()))
					if err == nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						if p, ok := analyzeFuzzResponse(req, "form_body", paramName, testValue, basePathResponseChars, workerID, args.rateLimitIncrease); ok {
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}
				
				// 3. Coba sebagai JSON Body menggunakan Template (hanya jika template disediakan)
				if (fuzzMethod == "POST" || fuzzMethod == "PUT" || fuzzMethod == "PATCH") && args.fuzzJSONTemplate != "" {
					// Ganti placeholder %PARAM% dan %FUZZ%
					bodyStr := strings.Replace(args.fuzzJSONTemplate, "%PARAM%", paramName, -1)
					bodyStr = strings.Replace(bodyStr, "%FUZZ%", testValue, -1)
					
					req, err := http.NewRequest(fuzzMethod, pathURL, strings.NewReader(bodyStr))
					if err == nil {
						req.Header.Set("Content-Type", "application/json")
						if p, ok := analyzeFuzzResponse(req, "json_body", paramName, testValue, basePathResponseChars, workerID, args.rateLimitIncrease); ok {
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}
			}
		}
	}

	// Konversi dari map kembali ke slice untuk di-return
	for _, p := range uniqueParamsFound {
		fuzzedParams = append(fuzzedParams, p)
	}
	return fuzzedParams
}

func analyzeFuzzResponse(req *http.Request, paramIn, paramName, testValue string, baseChars ResponseCharacteristics, workerID int, rateLimitIncrease time.Duration) (*DiscoveredParameter, bool) {
	// Terapkan jeda dinamis atau cooldown sebelum setiap request fuzzing
	applyDynamicDelayAndCooldown()
	req.Header.Set("User-Agent", "GoTool/1.5 (ParamFuzzer)")

	resp, err := globalHTTPClient.Do(req)
	if err != nil {
		verboseLog.Printf("[ParamFuzzer %d] Error sending fuzz request for %s: %v\n", workerID, req.URL.String(), err)
		return nil, false
	}
	
	// Tangani rate limiting jika terjadi
	if resp.StatusCode == http.StatusTooManyRequests {
		handleRateLimit(resp, rateLimitIncrease)
		resp.Body.Close()
		return nil, false
	}

	// Baca respons dan pastikan body ditutup
	_, fuzzCL := readAndCloseBody(resp)
	verboseLog.Printf("[ParamFuzzer %d] Fuzz Resp: %s %s (%s=%s in %s) -> Status: %d, CL: %d\n", workerID, req.Method, req.URL.Path, paramName, testValue, paramIn, resp.StatusCode, fuzzCL)

	note := ""
	isInteresting := false

	// Kondisi 1: Kode status berubah. Ini adalah indikator yang sangat kuat.
	if resp.StatusCode != baseChars.StatusCode {
		note = fmt.Sprintf("status_changed_from_%d", baseChars.StatusCode)
		isInteresting = true
	}
	
	// Kondisi 2: Panjang konten berubah secara signifikan.
	// Kita gunakan selisih absolut lebih dari 30 bytes untuk menghindari noise kecil.
	clDiff := fuzzCL - baseChars.ContentLength
	if clDiff > 30 || clDiff < -30 {
		if note != "" {
			note += "; " // Tambahkan pemisah jika sudah ada catatan dari kondisi sebelumnya
		}
		note += fmt.Sprintf("cl_changed_from_%d", baseChars.ContentLength)
		isInteresting = true
	}

	// Jika salah satu kondisi di atas terpenuhi, kita anggap parameter ini menarik
	if isInteresting {
		normalLog.Printf("[PARAM FUZZ FOUND] %s %s: Param '%s' in '%s' interesting. Notes: %s\n",
			req.Method, req.URL.Path, paramName, paramIn, note)
		// Kembalikan struct parameter yang ditemukan dan boolean true
		return &DiscoveredParameter{Name: paramName, In: paramIn, Notes: note, TestedValues: []string{testValue}}, true
	}
	
	// Jika tidak menarik, kembalikan nil dan false
	return nil, false
}

// --- Fungsi Penanganan Rate Limit ---
func applyDynamicDelayAndCooldown() {
	rateLimitState.Lock()
	delay := rateLimitState.dynamicDelay
	rateLimitState.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
}
func handleRateLimit(resp *http.Response, increaseAmount time.Duration) {
	normalLog.Println("[RATE LIMIT] Detected 429 Too Many Requests. Adapting...")
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			waitDuration := time.Duration(seconds)*time.Second + 100*time.Millisecond // Tambah sedikit buffer
			if waitDuration > 30*time.Second { waitDuration = 30*time.Second } // Batasi maks tunggu
			normalLog.Printf("[RATE LIMIT] Server suggests waiting for %v. Sleeping...\n", waitDuration)
			time.Sleep(waitDuration)
			return
		}
		if date, err := http.ParseTime(retryAfter); err == nil {
			waitDuration := time.Until(date)
			if waitDuration > 0 {
				if waitDuration > 30*time.Second { waitDuration = 30*time.Second }
				normalLog.Printf("[RATE LIMIT] Server suggests waiting for %v. Sleeping...\n", waitDuration.Round(time.Second))
				time.Sleep(waitDuration)
				return
			}
		}
	}
	rateLimitState.Lock()
	defer rateLimitState.Unlock()
	if time.Since(rateLimitState.lastTriggerTime) < 10*time.Second {
		oldDelay := rateLimitState.dynamicDelay
		rateLimitState.dynamicDelay += increaseAmount
		normalLog.Printf("[RATE LIMIT] Repeatedly hit. Increasing dynamic delay from %v to %v.\n", oldDelay, rateLimitState.dynamicDelay)
	}
	rateLimitState.lastTriggerTime = time.Now()
}

// --- Fungsi Utilitas ---
func readAndCloseBody(resp *http.Response) ([]byte, int64) {
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	cl := resp.ContentLength
	if cl == -1 {
		cl = int64(len(bodyBytes))
	}
	return bodyBytes, cl
}
func compareWithBaseline(statusCode int, contentLength int64, baselineIgnoreCodes map[int]bool) (bool, string) {
	isLikelyValid, comparisonNote := false, ""
	clDiff := contentLength - globalBaselineProfile.RandomPathNotFound.ContentLength; if clDiff < 0 { clDiff = -clDiff }
	if statusCode != globalBaselineProfile.RandomPathNotFound.StatusCode { isLikelyValid, comparisonNote = true, "status_differs"
	} else if clDiff > 20 { isLikelyValid, comparisonNote = true, "cl_differs"
	} else { comparisonNote = "matches_baseline" }
	if _, isIgnored := baselineIgnoreCodes[statusCode]; isIgnored {
		if isLikelyValid { comparisonNote += "_but_ignored" } else { comparisonNote = "is_ignored" }
		isLikelyValid = false
	}
	return isLikelyValid, comparisonNote
}
func performBaselineRequests(baseURL string, client *http.Client) {
	// Buat string acak untuk memastikan path tidak ada di server
	randPath := randomString(12)
	
	// Gabungkan baseURL dengan path acak secara aman menggunakan url.JoinPath (Go 1.19+)
	targetURLRandomPath, err := url.JoinPath(baseURL, randPath)
	if err != nil {
		normalLog.Fatalf("Cannot create baseline URL: %v", err)
	}

	// Buat request GET ke URL acak tersebut
	req, err := http.NewRequest("GET", targetURLRandomPath, nil)
	if err != nil {
		normalLog.Printf("Error creating baseline request: %v", err)
		// Set ke nilai error jika request tidak bisa dibuat
		globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{StatusCode: -1, ContentLength: -1}
		return
	}
	req.Header.Set("User-Agent", "GoTool/1.5 (BaselineChecker)")

	// Kirim request
	resp, err := client.Do(req)
	if err != nil {
		normalLog.Printf("Error sending baseline request: %v", err)
		globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{StatusCode: -1, ContentLength: -1}
		return
	}

	// Baca body respons dan dapatkan panjang konten
	_, cl := readAndCloseBody(resp)
	
	// Simpan karakteristik respons baseline ke variabel global
	globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{
		StatusCode:    resp.StatusCode,
		ContentLength: cl,
		ContentType:   resp.Header.Get("Content-Type"),
	}
}
func loadWordlist(path string) ([]string, error) {
	if path == "" { return []string{}, nil }; file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close()
	var lines []string; scanner := bufio.NewScanner(file)
	for scanner.Scan() { text := strings.TrimSpace(scanner.Text()); if text != "" && !strings.HasPrefix(text, "#") { lines = append(lines, text) } }
	return lines, scanner.Err()
}
func parseSuccessCodes(codesRaw string) map[int]bool {
	codes := make(map[int]bool); if codesRaw == "" { return codes }
	for _, part := range strings.Split(codesRaw, ",") { if code, err := strconv.Atoi(strings.TrimSpace(part)); err == nil { codes[code] = true } }
	return codes
}
func getIntKeys(m map[int]bool) []int {
	keys := make([]int, 0, len(m)); for k := range m { keys = append(keys, k) }; sort.Ints(keys); return keys
}
func parseCommaSeparatedString(raw string) []string {
	if raw == "" { return []string{} }; var cleanedParts []string
	for _, part := range strings.Split(raw, ",") { trimmed := strings.TrimSpace(part); if trimmed != "" { cleanedParts = append(cleanedParts, trimmed) } }
	return cleanedParts
}
func randomString(length int) string {
	bytes := make([]byte, length/2+1); if _, err := rand.Read(bytes); err != nil { return strconv.FormatInt(time.Now().UnixNano(), 16) }
	return hex.EncodeToString(bytes)[:length]
}
func parameterExists(params []DiscoveredParameter, name string) bool {
	for _, p := range params { if p.Name == name { return true } }; return false
}
func mergeDiscoveredParameters(existing, newParams []DiscoveredParameter) []DiscoveredParameter {
	mergedMap := make(map[string]DiscoveredParameter); for _, p := range existing { key := p.Name + "_" + p.In; mergedMap[key] = p }
	for _, newP := range newParams {
		key := newP.Name + "_" + newP.In
		if existingP, ok := mergedMap[key]; ok {
			if newP.Notes != "" && !strings.Contains(existingP.Notes, newP.Notes) { existingP.Notes += "; " + newP.Notes }
			for _, tv := range newP.TestedValues { existingP.TestedValues = appendIfMissing(existingP.TestedValues, tv) }
			mergedMap[key] = existingP
		} else { mergedMap[key] = newP }
	}
	finalMerged := make([]DiscoveredParameter, 0, len(mergedMap)); for _, p := range mergedMap { finalMerged = append(finalMerged, p) }; return finalMerged
}
func appendIfMissing(slice []string, str string) []string {
	for _, s := range slice { if s == str { return slice } }; return append(slice, str)
}
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen { return s }; return s[:maxLen-3] + "..."
}
