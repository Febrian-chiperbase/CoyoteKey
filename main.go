package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Febrian-chiperbase/CoyoteKey/pkg/brutekey"
	"github.com/Febrian-chiperbase/CoyoteKey/pkg/common"
	"github.com/Febrian-chiperbase/CoyoteKey/pkg/discovery"
)

// Variabel global hanya untuk menampung hasil akhir
var (
	outputFile        string
	allFoundKeys      []common.FoundKey
	discoveredPathMap map[string]common.DiscoveredPath
	resultsMutex      sync.Mutex
	verboseLog        *log.Logger
	normalLog         *log.Logger
)

func main() {
	discoveredPathMap = make(map[string]common.DiscoveredPath)
	verboseLog = log.New(io.Discard, "VERBOSE: ", log.Ldate|log.Ltime)
	normalLog = log.New(os.Stdout, "", 0)
	common.InitErrorParamRegexes(normalLog)

	// Definisi Flags
	targetURLFlag := flag.String("u", "", "Target Base URL")
	threadsFlag := flag.Int("t", 20, "Number of concurrent threads/goroutines")
	proxyURLFlag := flag.String("proxy", "", "Proxy URL")
	outputFileFlag := flag.String("o", "", "Output file to save results (JSON format)")
	verboseFlag := flag.Bool("v", false, "Enable verbose logging")
	timeoutFlag := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	modeFlag := flag.String("mode", "brutekey", "Mode of operation: 'brutekey' or 'discover'")

	bkWordlistPathFlag := flag.String("w", "", "[BruteKey] Path to wordlist file for keys/tokens")
	bkHeaderFormatFlag := flag.String("H", "", "[BruteKey] HTTP Header format for API Key")
	bkQueryParamFlag := flag.String("qp", "", "[BruteKey] Query parameter name for API Key")
	bkJsonBodyTemplateFlag := flag.String("jb", "", "[BruteKey] JSON body template with %KEY%")
	bkHTTPMethodFlag := flag.String("m", "GET", "[BruteKey] HTTP method")
	bkSuccessCodesRawFlag := flag.String("s", "200", "[BruteKey] Comma-separated success HTTP status codes")
	bkSuccessRegexFlag := flag.String("sr", "", "[BruteKey] Regex to match in response body for success")
	bkFilterRegexFlag := flag.String("fr", "", "[BruteKey] Regex to match in response body to filter out/ignore")

	initialDelayFlag := flag.Int("delay", 0, "Initial delay in milliseconds between requests per thread")
	rateLimitIncreaseFlag := flag.Duration("rl-increase", 50*time.Millisecond, "Amount to increase dynamic delay by when rate limited")

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
	dsMinConfidenceFlag := flag.String("min-confidence", "low", "[Discover] Minimum confidence level (low, medium, high)")
	dsRunVulnScanFlag := flag.Bool("vuln-scan", false, "[Discover] Run vulnerability probes after discovery")
	dsVulnDBPathFlag := flag.String("vuln-db", "./vulnerabilities.json", "[Discover] Path to the vulnerability probes definition file")

	flag.Parse()

	outputFile = *outputFileFlag
	common.InitRateLimitState(time.Duration(*initialDelayFlag) * time.Millisecond)

	setupAndRun(*targetURLFlag, *modeFlag, *threadsFlag, *proxyURLFlag, *timeoutFlag, *verboseFlag, brutekey.Args{
		TargetURL:         *targetURLFlag,
		WordlistPath:      *bkWordlistPathFlag,
		HeaderFormat:      *bkHeaderFormatFlag,
		QueryParam:        *bkQueryParamFlag,
		JsonBodyTemplate:  *bkJsonBodyTemplateFlag,
		HttpMethod:        *bkHTTPMethodFlag,
		SuccessCodesRaw:   *bkSuccessCodesRawFlag,
		SuccessRegexRaw:   *bkSuccessRegexFlag,
		FilterRegexRaw:    *bkFilterRegexFlag,
		Threads:           *threadsFlag,
		RateLimitIncrease: *rateLimitIncreaseFlag,
	}, discovery.Args{
		BaseURL:                *targetURLFlag,
		PathWordlistPath:       *dsPathWordlistFlag,
		ParamWordlistPath:      *dsParamWordlistFlag,
		MaxDepth:               *dsMaxDepthFlag,
		DiscoveryMethodsRaw:    *dsDiscoveryMethodsFlag,
		FuzzMethodsRaw:         *dsFuzzMethodsFlag,
		BaselineIgnoreCodesRaw: *dsBaselineIgnoreCodesFlag,
		FuzzTestValuesRaw:      *dsFuzzTestValuesFlag,
		Threads:                *threadsFlag,
		RateLimitIncrease:      *rateLimitIncreaseFlag,
		FuzzJSONTemplatePath:   *dsFuzzJSONTemplatePathFlag,
		SpecFilePath:           *dsSpecFilePathFlag,
		FingerprintDBPath:      *dsFingerprintDBPathFlag,
		ContextWordlistDir:     *dsContextWordlistDirFlag,
		MinConfidence:          *dsMinConfidenceFlag,
		RunVulnScan:            *dsRunVulnScanFlag,
		VulnDBPath:             *dsVulnDBPathFlag,
	})

	logFinalResults(*modeFlag)
}

func setupAndRun(targetURL, mode string, threads int, proxyURL string, timeout int, verbose bool, bkArgs brutekey.Args, dsArgs discovery.Args) {
	if verbose {
		verboseLog.SetOutput(os.Stderr)
	}
	if targetURL == "" {
		normalLog.Fatal("Target URL (-u) is required.")
	}
	_, errParseURL := url.ParseRequestURI(targetURL)
	if errParseURL != nil {
		normalLog.Fatalf("Invalid Target URL (-u): %v", errParseURL)
	}

	httpClient := common.NewHTTPClient(timeout, proxyURL, verboseLog)

	normalLog.Printf("--- Configuration ---")
	normalLog.Printf("Mode: %s | Target: %s | Threads: %d", mode, targetURL, threads)
	normalLog.Printf("---------------------")

	switch mode {
	case "brutekey":
		bkArgs.HttpClient = httpClient
		bkArgs.NormalLog = normalLog
		bkArgs.VerboseLog = verboseLog
		bkArgs.Results = &allFoundKeys
		bkArgs.Mutex = &resultsMutex
		brutekey.Run(bkArgs)
	case "discover":
		dsArgs.HttpClient = httpClient
		dsArgs.NormalLog = normalLog
		dsArgs.VerboseLog = verboseLog
		dsArgs.DiscoveredPathMap = &discoveredPathMap
		dsArgs.Mutex = &resultsMutex
		discovery.Run(dsArgs)
	default:
		normalLog.Fatalf("Invalid mode: '%s'. Available modes: 'brutekey', 'discover'\n", mode)
	}

	if outputFile != "" {
		saveResults(mode)
	}
}

func logFinalResults(mode string) {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()
	if mode == "brutekey" {
		foundCount := len(allFoundKeys)
		if foundCount == 0 {
			normalLog.Println("\nNo valid API keys found in brutekey mode.")
		} else {
			normalLog.Printf("\n[BruteKey Mode] Finished. Found %d valid API key(s).\n", foundCount)
		}
	} else if mode == "discover" {
		validPathCount := 0
		for _, p := range discoveredPathMap {
			if p.IsLikelyValid {
				validPathCount++
			}
		}
		if validPathCount == 0 {
			normalLog.Println("\nNo likely valid API paths found in discovery mode.")
		} else {
			normalLog.Printf("\n[Discovery Mode] Finished. Discovered %d likely valid API path(s).\n", validPathCount)
		}
		normalLog.Printf("[Discovery Mode] Total unique URL+Method combinations processed: %d\n", len(discoveredPathMap))
	}
}

func saveResults(mode string) {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()
	var fileData []byte
	var err error

	if mode == "brutekey" && len(allFoundKeys) > 0 {
		fileData, err = json.MarshalIndent(allFoundKeys, "", "  ")
	} else if mode == "discover" && len(discoveredPathMap) > 0 {
		pathsToSave := make([]common.DiscoveredPath, 0, len(discoveredPathMap))
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
