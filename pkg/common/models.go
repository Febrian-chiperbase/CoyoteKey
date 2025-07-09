package common

import "time"

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

// DiscoveredParameter adalah struktur untuk menyimpan parameter yang ditemukan.
type DiscoveredParameter struct {
	Name         string   `json:"name"`
	In           string   `json:"in,omitempty"`
	TestedValues []string `json:"tested_values,omitempty"`
	Notes        string   `json:"notes,omitempty"`
	Evidence     string   `json:"evidence,omitempty"`
}

// DiscoveredPath adalah struktur untuk menyimpan endpoint yang ditemukan.
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

// VulnerabilityProbe mendefinisikan satu tes kerentanan.
type VulnerabilityProbe struct {
	Name          string   `json:"name"`
	AppliesToTech []string `json:"applies_to_tech"`
	ProbeDetails  Probe    `json:"probe"`
}

// Probe berisi detail dari tes kerentanan.
type Probe struct {
	Path              string `json:"path"`
	Method            string `json:"method"`
	MatchStatus       int    `json:"match_status"`
	MatchContentRegex string `json:"match_content_regex,omitempty"`
}

// VulnerabilityDB adalah struktur untuk file vulnerabilities.json.
type VulnerabilityDB struct {
	Probes []VulnerabilityProbe `json:"vulnerability_probes"`
}

// BaselineProfile menyimpan karakteristik respons dari server target.
type BaselineProfile struct {
	RandomPathNotFound ResponseCharacteristics `json:"randomPathNotFound"`
}

// ResponseCharacteristics menyimpan properti dasar dari sebuah respons HTTP.
type ResponseCharacteristics struct {
	StatusCode    int
	ContentLength int64
	ContentType   string
}

// DiscoveryJob mendefinisikan sebuah pekerjaan untuk discovery worker.
type DiscoveryJob struct {
	BaseURLForNextLevel string
	PathSegmentToTest   string
	CurrentDepth        int
}

// FingerprintRule mendefinisikan satu aturan untuk mendeteksi sebuah teknologi.
type FingerprintRule struct {
	Tech       string `json:"tech"`
	Type       string `json:"type"`
	Header     string `json:"header,omitempty"`
	Path       string `json:"path,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Confidence string `json:"confidence"`
}

// FingerprintDB adalah struktur untuk file fingerprints.json.
type FingerprintDB struct {
	Fingerprints []FingerprintRule `json:"fingerprints"`
}

// DetectedTech menyimpan teknologi yang terdeteksi beserta tingkat kepercayaannya.
type DetectedTech struct {
	Name       string
	Confidence string
}
