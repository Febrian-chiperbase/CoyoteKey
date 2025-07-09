package common

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrorParamRegexList []*regexp.Regexp

func InitErrorParamRegexes(normalLog *log.Logger) {
	patterns := []string{
		`(?i)missing required parameter: '([^']+)'`,
		`(?i)parameter '([^']+)' is required`,
		`(?i)field '([^']+)' must not be empty`,
		`(?i)the (.+?) field is required`,
		`(?i)'([^']+?)' is a required property`,
		`(?i)required request parameter '([^']+)' for method parameter type`,
	}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			ErrorParamRegexList = append(ErrorParamRegexList, re)
		} else {
			normalLog.Printf("Warning: Could not compile error regex pattern: %s", p)
		}
	}
}

func LoadWordlist(path string, normalLog *log.Logger) ([]string, error) {
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

func ReadAndCloseBody(resp *http.Response, verboseLog *log.Logger) ([]byte, int64) {
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

func ParseSuccessCodes(codesRaw string, normalLog *log.Logger) map[int]bool {
	codes := make(map[int]bool)
	if codesRaw == "" {
		return codes
	}
	for _, part := range strings.Split(codesRaw, ",") {
		if code, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			codes[code] = true
		}
	}
	return codes
}

func GetIntKeys(m map[int]bool) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func ParseCommaSeparatedString(raw string) []string {
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

func RandomString(length int) string {
	bytes := make([]byte, length/2+1)
	if _, err := rand.Read(bytes); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(bytes)[:length]
}

func ParameterExists(params []DiscoveredParameter, name string) bool {
	for _, p := range params {
		if p.Name == name {
			return true
		}
	}
	return false
}

func MergeDiscoveredParameters(existing, newParams []DiscoveredParameter) []DiscoveredParameter {
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
				existingP.TestedValues = AppendIfMissing(existingP.TestedValues, tv)
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

func AppendIfMissing(slice []string, str string) []string {
	for _, s := range slice {
		if s == str {
			return slice
		}
	}
	return append(slice, str)
}

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func MergeAndDeduplicateSlices(sliceA, sliceB []string) []string {
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
