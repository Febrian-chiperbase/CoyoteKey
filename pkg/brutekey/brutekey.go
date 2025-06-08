package brutekey

import (
	"fmt"
	"io" // <-- Import yang hilang sudah ditambahkan
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	// Ganti "github.com/Febrian-chiperbase/CoyoteKey" dengan path modul Anda di go.mod
	"github.com/Febrian-chiperbase/CoyoteKey/pkg/common"
)

// Args adalah struktur untuk membawa semua dependensi dan konfigurasi ke mode brutekey.
type Args struct {
	TargetURL, WordlistPath, HeaderFormat, QueryParam, JsonBodyTemplate, HttpMethod, SuccessCodesRaw, SuccessRegexRaw, FilterRegexRaw string
	Threads                                                                                                                           int
	RateLimitIncrease                                                                                                                 time.Duration
	HttpClient                                                                                                                        *http.Client
	NormalLog                                                                                                                         *log.Logger
	VerboseLog                                                                                                                        *log.Logger
	Results                                                                                                                           *[]common.FoundKey
	Mutex                                                                                                                             *sync.Mutex
}

// workerArgs adalah struct internal untuk argumen worker.
type workerArgs struct {
	targetURL, httpMethod, keyPlacementMethod, keyPlacementValue string
	successCodes                                                 map[int]bool
	successRegex, filterRegex                                    *regexp.Regexp
	rateLimitIncrease                                            time.Duration
	httpClient                                                   *http.Client
	normalLog, verboseLog                                        *log.Logger // Ditambahkan untuk diteruskan ke helper
}

// Run adalah fungsi utama yang diekspor untuk menjalankan logika brutekey.
func Run(args Args) {
	args.NormalLog.Println("--- Running in BruteKey Mode ---")
	if args.WordlistPath == "" {
		args.NormalLog.Fatal("[BruteKey Mode] Wordlist (-w) is required.")
	}

	keyPlacementMethod, keyPlacementValue := determineKeyPlacement(args)
	args.NormalLog.Printf("[BruteKey Mode] Key Placement: %s\n", keyPlacementMethod)

	keys, err := common.LoadWordlist(args.WordlistPath, args.NormalLog)
	if err != nil || len(keys) == 0 {
		args.NormalLog.Fatalf("[BruteKey Mode] Error loading or empty wordlist: %v", err)
	}
	args.NormalLog.Printf("[BruteKey Mode] Wordlist: %s (%d keys)\n", args.WordlistPath, len(keys))

	successCodes, successRegex, filterRegex := parseBruteKeyCriteria(args)

	jobs := make(chan string, len(keys))
	resultsChan := make(chan common.FoundKey, len(keys))
	var wg sync.WaitGroup

	workerArgs := workerArgs{
		targetURL:          args.TargetURL,
		httpMethod:         args.HttpMethod,
		keyPlacementMethod: keyPlacementMethod,
		keyPlacementValue:  keyPlacementValue,
		successCodes:       successCodes,
		successRegex:       successRegex,
		filterRegex:        filterRegex,
		rateLimitIncrease:  args.RateLimitIncrease,
		httpClient:         args.HttpClient,
		normalLog:          args.NormalLog,  // Teruskan logger
		verboseLog:         args.VerboseLog, // Teruskan logger
	}

	for i := 0; i < args.Threads; i++ {
		wg.Add(1)
		go worker(i+1, workerArgs, jobs, resultsChan, &wg)
	}

	go func() {
		for found := range resultsChan {
			args.Mutex.Lock()
			*args.Results = append(*args.Results, found)
			args.Mutex.Unlock()
			args.NormalLog.Printf("[FOUND KEY] Key: %s -> Status: %d, CL: %d, Placement: %s, URL: %s\n",
				found.Key, found.StatusCode, found.ContentLength, found.Placement, found.URL)
		}
	}()

	for _, key := range keys {
		jobs <- key
	}
	close(jobs)
	wg.Wait()
	close(resultsChan)
	time.Sleep(100 * time.Millisecond)
}

// determineKeyPlacement adalah fungsi helper internal.
func determineKeyPlacement(args Args) (string, string) {
	if args.QueryParam != "" {
		return "query", args.QueryParam
	}
	if args.JsonBodyTemplate != "" {
		if !strings.Contains(args.JsonBodyTemplate, "%KEY%") {
			args.NormalLog.Fatal("[BruteKey Mode] JSON body template (-jb) must contain placeholder %KEY%")
		}
		return "json_body", args.JsonBodyTemplate
	}
	headerFormat := args.HeaderFormat
	if headerFormat == "" {
		headerFormat = "X-API-Key: %KEY%"
		args.NormalLog.Println("[BruteKey Mode] No key placement specified, defaulting to header: X-API-Key: %KEY%")
	}
	if !strings.Contains(headerFormat, "%KEY%") {
		args.NormalLog.Fatal("[BruteKey Mode] Header format (-H) must contain placeholder %KEY%")
	}
	return "header", headerFormat
}

// parseBruteKeyCriteria adalah fungsi helper internal.
func parseBruteKeyCriteria(args Args) (map[int]bool, *regexp.Regexp, *regexp.Regexp) {
	successCodes := common.ParseSuccessCodes(args.SuccessCodesRaw, args.NormalLog)
	var successRegex, filterRegex *regexp.Regexp
	var err error
	if args.SuccessRegexRaw != "" {
		successRegex, err = regexp.Compile(args.SuccessRegexRaw)
		if err != nil {
			args.NormalLog.Fatalf("Invalid success regex: %v", err)
		}
	}
	if args.FilterRegexRaw != "" {
		filterRegex, err = regexp.Compile(args.FilterRegexRaw)
		if err != nil {
			args.NormalLog.Fatalf("Invalid filter regex: %v", err)
		}
	}
	if len(successCodes) == 0 && successRegex == nil {
		args.NormalLog.Fatal("No success criteria provided for brutekey mode.")
	}
	return successCodes, successRegex, filterRegex
}

// worker adalah fungsi internal untuk goroutine brutekey.
func worker(id int, args workerArgs, keys <-chan string, results chan<- common.FoundKey, wg *sync.WaitGroup) {
	defer wg.Done()
	for key := range keys {
		// ### PERBAIKAN: Teruskan logger ke fungsi rate limiting ###
		common.ApplyDynamicDelayAndCooldown(args.verboseLog)

		if key == "" {
			continue
		}

		currentTargetURL, req, err := createBruteKeyRequest(args, key)
		if err != nil {
			args.verboseLog.Printf("[BruteKeyWorker %d] Error creating request for key '%s': %v\n", id, key, err)
			continue
		}
		resp, err := args.httpClient.Do(req)
		if err != nil {
			args.verboseLog.Printf("[BruteKeyWorker %d] Error sending request for key '%s': %v\n", id, key, err)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			// ### PERBAIKAN: Teruskan logger ke fungsi rate limiting ###
			common.HandleRateLimit(resp, args.rateLimitIncrease, args.normalLog, args.verboseLog)
			resp.Body.Close()
			continue
		}

		bodyBytes, cl := common.ReadAndCloseBody(resp, args.verboseLog)
		args.verboseLog.Printf("[BruteKeyWorker %d] Key '%s', URL: %s, Status: %s, CL: %d\n", id, key, currentTargetURL, resp.Status, cl)

		if args.filterRegex != nil && args.filterRegex.Match(bodyBytes) {
			continue
		}

		success, matchedRegex := isBruteKeySuccess(resp.StatusCode, bodyBytes, args.successCodes, args.successRegex)
		if success {
			results <- common.FoundKey{
				Key:           key,
				StatusCode:    resp.StatusCode,
				ContentLength: cl,
				URL:           currentTargetURL,
				Method:        args.httpMethod,
				Placement:     args.keyPlacementMethod,
				MatchedRegex:  matchedRegex,
				Timestamp:     time.Now().UTC(),
			}
		}
	}
}

// createBruteKeyRequest adalah fungsi helper internal.
func createBruteKeyRequest(args workerArgs, key string) (string, *http.Request, error) {
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
		req.Header.Set("User-Agent", "APIRecon/1.0 (brutekey)")
	}
	return currentTargetURL, req, err
}

// isBruteKeySuccess adalah fungsi helper internal.
func isBruteKeySuccess(statusCode int, body []byte, successCodes map[int]bool, successRegex *regexp.Regexp) (bool, string) {
	success, matchedRegex := false, ""
	if _, ok := successCodes[statusCode]; ok {
		success = true
	}
	if successRegex != nil && successRegex.Match(body) {
		success = true
		if matches := successRegex.FindStringSubmatch(string(body)); len(matches) > 0 {
			matchedRegex = matches[0]
		}
	}
	return success, matchedRegex
}
