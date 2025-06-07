package main

import (
	"bufio"
	"crypto/md5"
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

	"github.com/getkin/kin-openapi/openapi3"
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

type VulnerabilityProbe struct {
	Name           string   `json:"name"`
	AppliesToTech  []string `json:"applies_to_tech"`
	ProbeDetails   Probe    `json:"probe"`
}
type Probe struct {
	Path              string `json:"path"`
	Method            string `json:"method"`
	MatchStatus       int    `json:"match_status"`
	MatchContentRegex string `json:"match_content_regex,omitempty"`
}
type VulnerabilityDB struct {
	Probes []VulnerabilityProbe `json:"vulnerability_probes"`
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

// FingerprintRule mendefinisikan satu aturan untuk mendeteksi sebuah teknologi.
type FingerprintRule struct {
	Tech       string `json:"tech"`
	Type       string `json:"type"`
	Header     string `json:"header,omitempty"`
	Path       string `json:"path,omitempty"`
	Pattern    string `json:"pattern,omitempty"` // Pattern sekarang opsional
	Hash       string `json:"hash,omitempty"`
	Confidence string `json:"confidence"`
}

// FingerprintDB adalah struktur untuk file JSON yang berisi semua aturan.
type FingerprintDB struct {
	Fingerprints []FingerprintRule `json:"fingerprints"`
}

// DetectedTech menyimpan teknologi yang terdeteksi beserta tingkat kepercayaannya.
type DetectedTech struct {
	Name       string
	Confidence string
}

// --- Variabel Global & Status ---
var (
	verboseLog         *log.Logger
	normalLog          *log.Logger
	outputFile         string
	allFoundKeys       []FoundKey
	discoveredPathMap  map[string]DiscoveredPath
	resultsMutex       sync.Mutex
	globalHTTPClient   *http.Client
	globalBaselineProfile BaselineProfile
	errorParamRegexList []*regexp.Regexp

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
// Ganti seluruh func main() Anda dengan ini:
func main() {
	initErrorParamRegexes()
	discoveredPathMap = make(map[string]DiscoveredPath)

	verboseLog = log.New(io.Discard, "VERBOSE: ", log.Ldate|log.Ltime)
	normalLog = log.New(os.Stdout, "", 0)

	// --- Definisi Flags ---
	targetURLFlag := flag.String("u", "", "Target Base URL")
	threadsFlag := flag.Int("t", 20, "Number of concurrent threads/goroutines")
	proxyURLFlag := flag.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	outputFileFlag := flag.String("o", "", "Output file to save results (JSON format)")
	verboseFlag := flag.Bool("v", false, "Enable verbose logging")
	timeoutFlag := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	modeFlag := flag.String("mode", "brutekey", "Mode of operation: 'brutekey' or 'discover'")

	// --- BruteKey Mode Flags ---
	bkWordlistPathFlag := flag.String("w", "", "[BruteKey] Path to wordlist file for keys/tokens")
	bkHeaderFormatFlag := flag.String("H", "", "[BruteKey] HTTP Header format for API Key")
	bkQueryParamFlag := flag.String("qp", "", "[BruteKey] Query parameter name for API Key")
	bkJsonBodyTemplateFlag := flag.String("jb", "", "[BruteKey] JSON body template with %KEY%")
	bkHTTPMethodFlag := flag.String("m", "GET", "[BruteKey] HTTP method")
	bkSuccessCodesRawFlag := flag.String("s", "200", "[BruteKey] Comma-separated success HTTP status codes")
	bkSuccessRegexFlag := flag.String("sr", "", "[BruteKey] Regex to match in response body for success")
	bkFilterRegexFlag := flag.String("fr", "", "[BruteKey] Regex to match in response body to filter out/ignore")

	// --- Flag Delay & Rate Limiting ---
	initialDelayFlag := flag.Int("delay", 0, "Initial delay in milliseconds between requests per thread")
	rateLimitIncreaseFlag := flag.Duration("rl-increase", 50*time.Millisecond, "Amount to increase dynamic delay by when rate limited")

	// --- Discovery Mode Flags ---
	dsPathWordlistFlag := flag.String("pw", "", "[Discover] Wordlist for path segments")
	dsParamWordlistFlag := flag.String("pp", "", "[Discover] Wordlist for parameter names (optional)")
	dsMaxDepthFlag := flag.Int("depth", 0, "[Discover] Max recursion depth for path discovery")
	dsDiscoveryMethodsFlag := flag.String("dm", "GET,OPTIONS", "[Discover] HTTP methods for path discovery")
	dsFuzzMethodsFlag := flag.String("fm", "GET,POST", "[Discover] HTTP methods for parameter fuzzing")
	dsBaselineIgnoreCodesFlag := flag.String("bic", "404", "[Discover] Status codes to generally consider as baseline noise")
	dsFuzzTestValuesFlag := flag.String("ptv", "1,test,true,0,admin", "[Discover] Values to test for parameters")
	dsFuzzJSONTemplatePathFlag := flag.String("fuzz-json", "", "[Discover] Path to a JSON file to use as a template for body fuzzing")
	dsSpecFilePathFlag := flag.String("spec", "", "[Discover] Path to an OpenAPI/Swagger specification file")
	dsFingerprintDBPathFlag := flag.String("fp-db", "./fingerprints.json", "[Discover] Path to the fingerprint definition JSON file.")
	dsContextWordlistDirFlag := flag.String("cwd", "./context_wordlists", "[Discover] Path to directory with contextual wordlists")
	dsMinConfidenceFlag := flag.String("min-confidence", "low", "[Discover] Minimum confidence level to use contextual wordlists (low, medium, high)")
	dsRunVulnScanFlag := flag.Bool("vuln-scan", false, "[Discover] Run vulnerability probes after discovery based on detected tech")
	dsVulnDBPathFlag := flag.String("vuln-db", "./vulnerabilities.json", "[Discover] Path to the vulnerability probes definition JSON file")

	flag.Parse()

	// --- Inisialisasi Konfigurasi & State ---
	outputFile = *outputFileFlag
	rateLimitState.dynamicDelay = time.Duration(*initialDelayFlag) * time.Millisecond

	// Panggil setupAndRun dengan argumen yang benar
	setupAndRun(*targetURLFlag, *modeFlag, *threadsFlag, *proxyURLFlag, *timeoutFlag, *verboseFlag, bruteKeyArgs{
		targetURL:        *targetURLFlag,
		wordlistPath:     *bkWordlistPathFlag,
		headerFormat:     *bkHeaderFormatFlag,
		queryParam:       *bkQueryParamFlag,
		jsonBodyTemplate: *bkJsonBodyTemplateFlag,
		httpMethod:       *bkHTTPMethodFlag,
		successCodesRaw:  *bkSuccessCodesRawFlag,
		successRegexRaw:  *bkSuccessRegexFlag,
		filterRegexRaw:   *bkFilterRegexFlag,
		initialDelay:     *initialDelayFlag,
		threads:          *threadsFlag,
		rateLimitIncrease: *rateLimitIncreaseFlag,
	}, discoveryArgs{
		baseURL:                *targetURLFlag,
		pathWordlistPath:       *dsPathWordlistFlag,
		paramWordlistPath:      *dsParamWordlistFlag,
		maxDepth:               *dsMaxDepthFlag,
		discoveryMethodsRaw:    *dsDiscoveryMethodsFlag,
		fuzzMethodsRaw:         *dsFuzzMethodsFlag,
		baselineIgnoreCodesRaw: *dsBaselineIgnoreCodesFlag,
		fuzzTestValuesRaw:      *dsFuzzTestValuesFlag,
		threads:                *threadsFlag,
		initialDelay:           *initialDelayFlag,
		rateLimitIncrease:      *rateLimitIncreaseFlag,
		fuzzJSONTemplatePath:   *dsFuzzJSONTemplatePathFlag,
		specFilePath:           *dsSpecFilePathFlag,
		fingerprintDBPath:      *dsFingerprintDBPathFlag,
		contextWordlistDir:     *dsContextWordlistDirFlag,
		minConfidence:          *dsMinConfidenceFlag,
		runVulnScan:            *dsRunVulnScanFlag,
		vulnDBPath:             *dsVulnDBPathFlag,
	})

	logFinalResults(*modeFlag)
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

// processOpenAPISpec memuat dan mem-parsing file spesifikasi OpenAPI.
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

	pathSet := make(map[string]bool)
	paramSet := make(map[string]bool)

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

	for path := range pathSet {
		specPaths = append(specPaths, path)
	}
	for param := range paramSet {
		specParams = append(specParams, param)
	}
	
	normalLog.Printf("[Discovery Mode] Extracted %d unique paths and %d unique parameter names from spec.\n", len(specPaths), len(specParams))
	return specPaths, specParams
}

// fingerprintTarget mencoba mengidentifikasi teknologi berdasarkan aturan dari file definisi.
func fingerprintTarget(baseURL string, client *http.Client, dbPath string) []DetectedTech {
	verboseLog.Printf("[Fingerprint] Starting file-based technology fingerprinting for %s\n", baseURL)
	techConfidenceMap := make(map[string]int)

	dbFile, err := os.ReadFile(dbPath)
	if err != nil {
		normalLog.Printf("[Fingerprint] Warning: Could not read fingerprint file at '%s'. Skipping. Error: %v\n", dbPath, err)
		return []DetectedTech{}
	}

	var db FingerprintDB
	if err := json.Unmarshal(dbFile, &db); err != nil {
		normalLog.Printf("[Fingerprint] Warning: Could not parse fingerprint file '%s'. Skipping. Error: %v\n", dbPath, err)
		return []DetectedTech{}
	}
	normalLog.Printf("[Fingerprint] Loaded %d fingerprint rules from %s\n", len(db.Fingerprints), dbPath)

	initialResp, err := client.Get(baseURL)
	if err != nil {
		verboseLog.Printf("[Fingerprint] Initial request to target failed: %v\n", err)
		return []DetectedTech{}
	}
	defer initialResp.Body.Close()
	rootBody, _ := io.ReadAll(initialResp.Body)

	for _, rule := range db.Fingerprints {
		found := false
		switch rule.Type {
		case "header":
			re, err := regexp.Compile(rule.Pattern)
			if err != nil { continue }
			if headerValue := initialResp.Header.Get(rule.Header); headerValue != "" && re.MatchString(headerValue) {
				found = true
			}
		case "cookie":
			re, err := regexp.Compile(rule.Pattern)
			if err != nil { continue }
			for _, cookie := range initialResp.Cookies() {
				if re.MatchString(cookie.Name) {
					found = true
					break
				}
			}
		case "content":
			re, err := regexp.Compile(rule.Pattern)
			if err != nil { continue }
			if rule.Path == "/" && len(rootBody) > 0 && re.Match(rootBody) {
				found = true
			}
		case "favicon_hash":
			faviconURL, err := url.JoinPath(baseURL, "favicon.ico")
			if err != nil { continue }
			favReq, err := http.NewRequest("GET", faviconURL, nil)
			if err != nil { continue }
			favReq.Header.Set("User-Agent", "GoTool/1.6 (Fingerprinter/Favicon)")
			favResp, err := client.Do(favReq)
			if err != nil { continue }
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

	technologies := make([]DetectedTech, 0, len(techConfidenceMap))
	for tech, score := range techConfidenceMap {
		technologies = append(technologies, DetectedTech{
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

// Fungsi helper untuk mengonversi confidence string ke int untuk perbandingan
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

// Fungsi helper untuk mengonversi int kembali ke string untuk output
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
	fingerprintDBPath               string 
	contextWordlistDir              string 
	minConfidence                   string
	specFilePath                    string
	runVulnScan                     bool 
	vulnDBPath                      string
	httpClient                      *http.Client
}

// ### FUNGSI BARU: Menjalankan probe kerentanan ###
func runVulnerabilityProbes(baseURL string, detectedTechs []DetectedTech, args discoveryArgs) {
	normalLog.Println("\n--- Starting Vulnerability Probing Phase ---")

	// 1. Muat database kerentanan
	dbFile, err := os.ReadFile(args.vulnDBPath)
	if err != nil {
		normalLog.Printf("[VulnScan] Warning: Could not read vulnerability probes file at '%s'. Skipping. Error: %v\n", args.vulnDBPath, err)
		return
	}
	var db VulnerabilityDB
	if err := json.Unmarshal(dbFile, &db); err != nil {
		normalLog.Printf("[VulnScan] Warning: Could not parse vulnerability probes file '%s'. Skipping. Error: %v\n", args.vulnDBPath, err)
		return
	}
	normalLog.Printf("[VulnScan] Loaded %d vulnerability probe rules from %s\n", len(db.Probes), args.vulnDBPath)

	// 2. Buat set dari teknologi yang terdeteksi untuk pencarian cepat
	techSet := make(map[string]bool)
	for _, tech := range detectedTechs {
		techSet[tech.Name] = true
	}

	// 3. Jalankan setiap probe jika teknologinya cocok
	for _, probe := range db.Probes {
		applies := false
		for _, requiredTech := range probe.AppliesToTech {
			if techSet[requiredTech] {
				applies = true
				break
			}
		}

		if applies {
			verboseLog.Printf("[VulnScan] Running probe: '%s'\n", probe.Name)
			
			probeURL, err := url.JoinPath(baseURL, probe.ProbeDetails.Path)
			if err != nil { continue }

			req, err := http.NewRequest(strings.ToUpper(probe.ProbeDetails.Method), probeURL, nil)
			if err != nil { continue }
			req.Header.Set("User-Agent", "GoTool/1.6 (VulnProbe)")

			resp, err := args.httpClient.Do(req)
			if err != nil { continue }

			if resp.StatusCode != probe.ProbeDetails.MatchStatus {
				resp.Body.Close()
				continue
			}

			// Jika sampai sini, status code cocok. Cek konten jika ada aturannya.
			bodyBytes, _ := readAndCloseBody(resp)
			if probe.ProbeDetails.MatchContentRegex != "" {
				re, err := regexp.Compile(probe.ProbeDetails.MatchContentRegex)
				if err != nil { continue } // Regex di file JSON salah
				
				if re.Match(bodyBytes) {
					// Sukses! Ditemukan kerentanan potensial.
					normalLog.Printf("[VULNERABILITY FOUND] Name: '%s' | Target: %s %s\n", probe.Name, probe.ProbeDetails.Method, probeURL)
				}
			} else {
				// Jika tidak ada regex konten, kecocokan status sudah cukup.
				normalLog.Printf("[VULNERABILITY FOUND] Name: '%s' | Target: %s %s\n", probe.Name, probe.ProbeDetails.Method, probeURL)
			}
		}
	}
	normalLog.Println("--- Vulnerability Probing Phase Finished ---")
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

// inferTechnologyStack menganalisis teknologi yang terdeteksi dan mencoba menyimpulkan stack yang digunakan.
func inferTechnologyStack(detectedTechs []DetectedTech) []string {
	// Database sederhana untuk definisi stack
	stackDefinitions := map[string][]string{
		"WordPress (LEMP Stack)": {"nginx", "php", "wordpress"},
		"WordPress (LAMP Stack)": {"apache", "php", "wordpress"},
		"Laravel (LEMP Stack)":   {"nginx", "php", "laravel"},
		"Laravel (LAMP Stack)":   {"apache", "php", "laravel"},
		"Spring Boot (Standalone)": {"spring_boot"},
	}

	// Buat set dari nama teknologi yang terdeteksi untuk pencarian cepat
	techNameSet := make(map[string]bool)
	for _, tech := range detectedTechs {
		techNameSet[tech.Name] = true
	}

	var inferredStacks []string
	// Periksa setiap definisi stack
	for stackName, requiredTechs := range stackDefinitions {
		match := true
		// Periksa apakah semua teknologi yang dibutuhkan untuk stack ini ada di hasil deteksi
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



// --- Logika Mode Discovery ---
func runDiscoveryMode(args discoveryArgs) {
	normalLog.Println("--- Running in Discovery Mode ---")

	// --- Tahap 1: Inisialisasi & Pengumpulan Data Awal ---

	var specPaths, specParams []string
	if args.specFilePath != "" {
		specPaths, specParams = processOpenAPISpec(args.specFilePath)
	}

	if args.specFilePath == "" && args.pathWordlistPath == "" {
		normalLog.Fatal("[Discovery Mode] Path Wordlist (-pw) or Spec file (--spec) is required.")
	}

	pathWordlistFromFile, err := loadWordlist(args.pathWordlistPath)
	if err != nil {
		normalLog.Fatalf("[Discovery Mode] Error loading path wordlist: %v", err)
	}
	paramWordlistFromFile, _ := loadWordlist(args.paramWordlistPath)

	// Lakukan fingerprinting untuk mendeteksi teknologi
	detectedTechsWithConfidence := fingerprintTarget(args.baseURL, args.httpClient, args.fingerprintDBPath)
	
	// ### PENINGKATAN: Panggil fungsi inferensi stack dan laporkan hasilnya ###
	inferredStacks := inferTechnologyStack(detectedTechsWithConfidence)
	if len(inferredStacks) > 0 {
		normalLog.Printf("[Fingerprint] Inferred technology stack(s): %v\n", inferredStacks)
	}
	
	contextualPathWordlist := []string{}
	minConfidenceScore := confidenceToInt(args.minConfidence)

	// Muat wordlist kontekstual berdasarkan hasil fingerprinting
	for _, tech := range detectedTechsWithConfidence {
		techConfidenceScore := confidenceToInt(tech.Confidence)
		if techConfidenceScore >= minConfidenceScore {
			contextFile := fmt.Sprintf("%s/%s.txt", strings.TrimRight(args.contextWordlistDir, "/"), tech.Name)
			if _, err := os.Stat(contextFile); err == nil {
				normalLog.Printf("[Discovery Mode] Loading contextual wordlist for '%s' (Confidence: %s) from: %s\n", tech.Name, tech.Confidence, contextFile)
				techPaths, err := loadWordlist(contextFile)
				if err == nil {
					contextualPathWordlist = append(contextualPathWordlist, techPaths...)
				}
			}
		} else {
			verboseLog.Printf("[Discovery Mode] Skipping contextual wordlist for '%s' due to low confidence ('%s' < '%s')\n", tech.Name, tech.Confidence, args.minConfidence)
		}
	}

	// Gabungkan semua sumber path
	pathWordlist := mergeAndDeduplicateSlices(pathWordlistFromFile, specPaths)
	pathWordlist = mergeAndDeduplicateSlices(pathWordlist, contextualPathWordlist)
	paramWordlist := mergeAndDeduplicateSlices(paramWordlistFromFile, specParams)

	if len(pathWordlist) == 0 {
		normalLog.Fatalf("[Discovery Mode] No paths to test. Provide a path wordlist (-pw) or a valid spec file (--spec).")
	}

	normalLog.Printf("[Discovery Mode] Total unique paths to test after merging all sources: %d\n", len(pathWordlist))
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

	// --- Tahap 2: Loop Penemuan Rekursif ---
	currentLevelPathsToExplore := []string{strings.TrimRight(args.baseURL, "/")}

	for depth := 0; depth <= args.maxDepth; depth++ {
		if len(currentLevelPathsToExplore) == 0 {
			normalLog.Printf("[Discovery Mode] No new valid paths found at depth %d to explore further. Stopping recursion.\n", depth-1)
			break
		}
		normalLog.Printf("[Discovery Mode] Starting discovery at Depth %d. Base paths to explore: %d\n", depth, len(currentLevelPathsToExplore))

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

// ... di dalam for depth := 0; ...
		jobCount := 0
		// Untuk kedalaman 0, gunakan gabungan wordlist. Untuk kedalaman > 0, gunakan wordlist dari file saja.
		wordlistForThisDepth := pathWordlist
		if depth > 0 {
			wordlistForThisDepth = pathWordlistFromFile
		}

		for _, basePath := range currentLevelPathsToExplore {
			for _, segment := range wordlistForThisDepth {
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
	// --- Tahap 3: Pemindaian Kerentanan (Opsional) ---
	if args.runVulnScan {
		runVulnerabilityProbes(args.baseURL, detectedTechsWithConfidence, args)
	}
}
func mergeAndDeduplicateSlices(sliceA, sliceB []string) []string {
	set := make(map[string]bool)
	for _, item := range sliceA { set[item] = true }
	for _, item := range sliceB { set[item] = true }
	result := make([]string, 0, len(set))
	for item := range set { result = append(result, item) }
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

func discoveryWorker(id int, args discoveryWorkerArgs, jobs <-chan DiscoveryJob, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		applyDynamicDelayAndCooldown()

		fullURL, err := url.JoinPath(job.BaseURLForNextLevel, job.PathSegmentToTest)
		if err != nil {
			verboseLog.Printf("[DiscoveryWorker %d] Error joining URL: %v\n", id, err)
			continue
		}
		verboseLog.Printf("[DiscoveryWorker %d] Path discovery: %s\n", id, fullURL)

		basePathResponses := make(map[string]ResponseCharacteristics)
		for _, method := range args.discoveryMethods {
			req, _ := http.NewRequest(method, fullURL, nil)
			req.Header.Set("User-Agent", "GoTool/1.5 (Discovery)")
			resp, err := args.httpClient.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusTooManyRequests {
				handleRateLimit(resp, args.rateLimitIncrease)
				resp.Body.Close()
				continue
			}

			fuzzContentType := resp.Header.Get("Content-Type")
			bodyBytes, cl := readAndCloseBody(resp)
			basePathResponses[method] = ResponseCharacteristics{
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				ContentType:   fuzzContentType,
			}

			isLikelyValid, comparisonNote := compareWithBaseline(resp.StatusCode, cl, args.baselineIgnoreCodes)
			foundParamsFromError := parseErrorsForParams(bodyBytes)
			allFoundOnPathParams := foundParamsFromError

			shouldFuzz := isLikelyValid || len(foundParamsFromError) > 0
			if shouldFuzz && (len(args.paramWordlist) > 0 || args.fuzzJSONTemplate != "") {
				verboseLog.Printf("[DiscoveryWorker %d] Starting parameter fuzzing for %s %s\n", id, method, fullURL)
				fuzzedParams := fuzzParametersOnPath(fullURL, method, basePathResponses[method], args, id)
				if len(fuzzedParams) > 0 {
					allFoundOnPathParams = mergeDiscoveredParameters(allFoundOnPathParams, fuzzedParams)
				}
			}

			processDiscoveryResult(DiscoveredPath{
				URL: fullURL, Method: method, StatusCode: resp.StatusCode, ContentLength: cl,
				BaselineComparison: comparisonNote, IsLikelyValid: isLikelyValid,
				FoundParameters: allFoundOnPathParams, Depth: job.CurrentDepth, Timestamp: time.Now().UTC(),
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
	uniqueParamsFound := make(map[string]DiscoveredParameter)

	for _, fuzzMethod := range args.fuzzMethods {
		for _, paramName := range args.paramWordlist {
			for _, testValue := range args.fuzzTestValues {
				if fuzzMethod == "GET" || fuzzMethod == "POST" {
					fuzzURL, _ := url.Parse(pathURL); q := fuzzURL.Query(); q.Set(paramName, testValue); fuzzURL.RawQuery = q.Encode()
					req, err := http.NewRequest(fuzzMethod, fuzzURL.String(), nil)
					if err == nil {
						if p, ok := analyzeFuzzResponse(req, "query", paramName, testValue, basePathResponseChars, workerID, args.rateLimitIncrease); ok {
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}
				if fuzzMethod == "POST" || fuzzMethod == "PUT" || fuzzMethod == "PATCH" {
					formData := url.Values{}; formData.Set(paramName, testValue)
					req, err := http.NewRequest(fuzzMethod, pathURL, strings.NewReader(formData.Encode()))
					if err == nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						if p, ok := analyzeFuzzResponse(req, "form_body", paramName, testValue, basePathResponseChars, workerID, args.rateLimitIncrease); ok {
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
						if p, ok := analyzeFuzzResponse(req, "json_body", paramName, testValue, basePathResponseChars, workerID, args.rateLimitIncrease); ok {
							mapUniqueKey := p.Name + "_" + p.In
							uniqueParamsFound[mapUniqueKey] = *p
						}
					}
				}
			}
		}
	}
	for _, p := range uniqueParamsFound { fuzzedParams = append(fuzzedParams, p) }
	return fuzzedParams
}

func analyzeFuzzResponse(req *http.Request, paramIn, paramName, testValue string, baseChars ResponseCharacteristics, workerID int, rateLimitIncrease time.Duration) (*DiscoveredParameter, bool) {
	applyDynamicDelayAndCooldown()
	req.Header.Set("User-Agent", "GoTool/1.5 (ParamFuzzer)")

	resp, err := globalHTTPClient.Do(req)
	if err != nil {
		verboseLog.Printf("[ParamFuzzer %d] Error sending fuzz request for %s: %v\n", workerID, req.URL.String(), err)
		return nil, false
	}
	
	if resp.StatusCode == http.StatusTooManyRequests {
		handleRateLimit(resp, rateLimitIncrease)
		resp.Body.Close()
		return nil, false
	}

	fuzzBodyBytes, fuzzCL := readAndCloseBody(resp)
	verboseLog.Printf("[ParamFuzzer %d] Fuzz Resp: %s %s (%s=%s in %s) -> Status: %d, CL: %d\n", workerID, req.Method, req.URL.Path, paramName, testValue, paramIn, resp.StatusCode, fuzzCL)

	note, isInteresting := "", false
	if resp.StatusCode != baseChars.StatusCode {
		note = fmt.Sprintf("status_changed_from_%d", baseChars.StatusCode)
		isInteresting = true
	}
	
	clDiff := fuzzCL - baseChars.ContentLength
	if clDiff > 30 || clDiff < -30 {
		if note != "" { note += "; " }
		note += fmt.Sprintf("cl_changed_from_%d", baseChars.ContentLength)
		isInteresting = true
	}

	if len(testValue) > 3 && strings.Contains(string(fuzzBodyBytes), testValue) {
		if note != "" { note += "; " };
		note += "value_reflected_in_body";
		isInteresting = true;
	}

	fuzzContentType := resp.Header.Get("Content-Type");
	if fuzzContentType != "" && baseChars.ContentType != "" && !strings.Contains(fuzzContentType, baseChars.ContentType) && !strings.Contains(baseChars.ContentType, fuzzContentType) {
		if note != "" { note += "; " };
		note += fmt.Sprintf("content_type_changed_from_%s", baseChars.ContentType);
		isInteresting = true;
	}

	if isInteresting {
		normalLog.Printf("[PARAM FUZZ FOUND] %s %s: Param '%s' in '%s' interesting. Notes: %s\n",
			req.Method, req.URL.Path, paramName, paramIn, note)
		return &DiscoveredParameter{Name: paramName, In: paramIn, Notes: note, TestedValues: []string{testValue}}, true
	}
	
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
			waitDuration := time.Duration(seconds)*time.Second + 100*time.Millisecond 
			if waitDuration > 30*time.Second { waitDuration = 30*time.Second }
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
	randPath := randomString(12); targetURLRandomPath, err := url.JoinPath(baseURL, randPath)
	if err != nil { normalLog.Fatalf("Cannot create baseline URL: %v", err) }
	req, _ := http.NewRequest("GET", targetURLRandomPath, nil); req.Header.Set("User-Agent", "GoTool/1.5 (BaselineChecker)")
	resp, err := client.Do(req); if err != nil { normalLog.Printf("Error sending baseline request: %v", err); return }
	_, cl := readAndCloseBody(resp)
	globalBaselineProfile.RandomPathNotFound = ResponseCharacteristics{StatusCode: resp.StatusCode, ContentLength: cl, ContentType: resp.Header.Get("Content-Type")}
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