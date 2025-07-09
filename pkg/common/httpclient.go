package common

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// State untuk rate limiting, menjadi milik paket common.
var rateLimitState struct {
	sync.Mutex
	lastTriggerTime time.Time
	dynamicDelay    time.Duration
}

// NewHTTPClient membuat instance HTTP Client baru dengan konfigurasi.
func NewHTTPClient(timeout int, proxyURL string, verboseLog *log.Logger) *http.Client {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConnsPerHost: 100,
			DisableKeepAlives:   false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			verboseLog.Printf("Redirecting from %s to %s\n", via[0].URL.String(), req.URL.String())
			return http.ErrUseLastResponse
		},
	}
	if proxyURL != "" {
		pURL, errProxy := url.Parse(proxyURL)
		if errProxy == nil {
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.Proxy = http.ProxyURL(pURL)
			}
		}
	}
	return client
}

// InitRateLimitState menginisialisasi state delay awal.
func InitRateLimitState(initialDelay time.Duration) {
	rateLimitState.dynamicDelay = initialDelay
}

// ApplyDynamicDelayAndCooldown adalah fungsi yang dipanggil oleh setiap worker sebelum request.
func ApplyDynamicDelayAndCooldown(verboseLog *log.Logger) {
	rateLimitState.Lock()
	delay := rateLimitState.dynamicDelay
	rateLimitState.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
}

// HandleRateLimit adalah fungsi yang dipanggil saat respons 429 diterima.
func HandleRateLimit(resp *http.Response, increaseAmount time.Duration, normalLog, verboseLog *log.Logger) {
	normalLog.Println("[RATE LIMIT] Detected 429 Too Many Requests. Adapting...")
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			waitDuration := time.Duration(seconds)*time.Second + 100*time.Millisecond
			if waitDuration > 30*time.Second {
				waitDuration = 30 * time.Second
			}
			normalLog.Printf("[RATE LIMIT] Server suggests waiting for %v. Sleeping...\n", waitDuration)
			time.Sleep(waitDuration)
			return
		}
		if date, err := http.ParseTime(retryAfter); err == nil {
			waitDuration := time.Until(date)
			if waitDuration > 0 {
				if waitDuration > 30*time.Second {
					waitDuration = 30 * time.Second
				}
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
