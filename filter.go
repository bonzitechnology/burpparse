package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// FilterOpts holds all filter parameters.
type FilterOpts struct {
	Index       int
	Host        string
	ExcludeHost string
	Scope       []string // include only these hosts (exact or subdomain)
	Path        string
	Method      string
	StatusCode  int
	StatusMin   int
	StatusMax   int
	ContentType string
	SearchRe    *regexp.Regexp
	Unique      bool
	HasResp     bool
}

func applyFilters(entries []*Entry, o FilterOpts) ([]*Entry, []int) {
	seen := make(map[[32]byte]struct{})
	var out []*Entry
	var idxOut []int

	for i, e := range entries {
		if o.Index >= 0 && i != o.Index {
			continue
		}
		host := strings.ToLower(e.Request.Host)
		if o.Host != "" && !strings.Contains(host, strings.ToLower(o.Host)) {
			continue
		}
		if o.ExcludeHost != "" {
			excluded := false
			for _, ex := range strings.Split(o.ExcludeHost, ",") {
				if matchesScope(host, strings.TrimSpace(strings.ToLower(ex))) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}
		if len(o.Scope) > 0 {
			inScope := false
			for _, s := range o.Scope {
				if matchesScope(host, s) {
					inScope = true
					break
				}
			}
			if !inScope {
				continue
			}
		}
		if o.Path != "" && !strings.Contains(e.Request.RequestURI, o.Path) {
			continue
		}
		if o.Method != "" && !strings.EqualFold(e.Request.Method, o.Method) {
			continue
		}
		if o.HasResp && e.Response == nil {
			continue
		}
		if o.StatusCode != 0 {
			if e.Response == nil || e.Response.StatusCode != o.StatusCode {
				continue
			}
		}
		if o.StatusMin > 0 || o.StatusMax > 0 {
			code := 0
			if e.Response != nil {
				code = e.Response.StatusCode
			}
			if o.StatusMin > 0 && code < o.StatusMin {
				continue
			}
			if o.StatusMax > 0 && code > o.StatusMax {
				continue
			}
		}
		if o.ContentType != "" {
			ct := ""
			if e.Response != nil {
				ct = strings.ToLower(e.Response.Header.Get("Content-Type"))
			}
			if !strings.Contains(ct, strings.ToLower(o.ContentType)) {
				continue
			}
		}
		if o.SearchRe != nil {
			if !o.SearchRe.Match(e.RawReq) && !o.SearchRe.Match(e.RawResp) {
				continue
			}
		}
		if o.Unique {
			h := sha256.Sum256(e.RawReq)
			if _, dup := seen[h]; dup {
				continue
			}
			seen[h] = struct{}{}
		}
		out = append(out, e)
		idxOut = append(idxOut, i)
	}
	return out, idxOut
}

// matchesScope returns true if host matches target (exact or subdomain).
// Strips port from host before comparing so "192.168.1.1:8080" matches "192.168.1.1".
func matchesScope(host, target string) bool {
	// Strip port if present.
	bare := host
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// Only strip if it looks like a port (all digits after colon).
		suffix := host[i+1:]
		isPort := len(suffix) > 0
		for _, c := range suffix {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}
		if isPort {
			bare = host[:i]
		}
	}
	return bare == target || host == target ||
		strings.HasSuffix(bare, "."+target) || strings.HasSuffix(host, "."+target)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func printStats(w interface{ Write([]byte) (int, error) }, all, filtered []*Entry) {
	type writerf interface {
		Write([]byte) (int, error)
	}
	write := func(s string) { w.Write([]byte(s)) }

	write("=== STATS ===\n")
	write(fmt.Sprintf("Total entries : %d\n", len(all)))
	write(fmt.Sprintf("Shown         : %d\n\n", len(filtered)))

	hosts := make(map[string]int)
	methods := make(map[string]int)
	codes := make(map[string]int)
	sources := make(map[string]int)
	noResp := 0

	for _, e := range filtered {
		hosts[e.Request.Host]++
		methods[e.Request.Method]++
		if e.Source != "" {
			sources[e.Source]++
		}
		if e.Response != nil {
			codes[fmt.Sprintf("%d", e.Response.StatusCode)]++
		} else {
			noResp++
		}
	}

	write("-- Methods --\n")
	printSortedCounts(w, methods)

	write("\n-- Status Codes --\n")
	if noResp > 0 {
		codes["(no response)"] = noResp
	}
	printSortedCounts(w, codes)

	write("\n-- Hosts --\n")
	printSortedCounts(w, hosts)

	if len(sources) > 1 {
		write("\n-- Sources --\n")
		printSortedCounts(w, sources)
	}
}

func printSortedCounts(w interface{ Write([]byte) (int, error) }, m map[string]int) {
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	for _, p := range pairs {
		w.Write([]byte(fmt.Sprintf("  %-40s %d\n", p.k, p.v)))
	}
}

// ─── Summary / JSON ───────────────────────────────────────────────────────────

type Summary struct {
	Index       int    `json:"index"`
	Source      string `json:"source,omitempty"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	ReqLen      int    `json:"req_len"`
	Status      int    `json:"status,omitempty"`
	RespLen     int    `json:"resp_len,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Protocol    string `json:"protocol"`
}

// FullEntry is the rich JSONL record — includes headers and decoded bodies.
type FullEntry struct {
	Index          int               `json:"index"`
	Source         string            `json:"source,omitempty"`
	Host           string            `json:"host"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Protocol       string            `json:"protocol"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestBody    string            `json:"request_body,omitempty"`
	Status         int               `json:"status,omitempty"`
	StatusText     string            `json:"status_text,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody   string            `json:"response_body,omitempty"`
	ContentType    string            `json:"content_type,omitempty"`
	ReqLen         int               `json:"req_len"`
	RespLen        int               `json:"resp_len,omitempty"`
}

func toFullEntry(i int, e *Entry, includeBodies bool) FullEntry {
	// Flatten multi-value headers to last value for simplicity.
	reqHeaders := make(map[string]string, len(e.Request.Header)+1)
	reqHeaders["Host"] = e.Request.Host
	for k, vs := range e.Request.Header {
		reqHeaders[k] = vs[len(vs)-1]
	}

	f := FullEntry{
		Index:          i,
		Source:         e.Source,
		Host:           e.Request.Host,
		Method:         e.Request.Method,
		URL:            fullURL(e),
		Protocol:       e.Request.Proto,
		RequestHeaders: reqHeaders,
		ReqLen:         len(e.RawReq),
	}
	if includeBodies {
		f.RequestBody = string(reqBody(e.RawReq))
	}

	if e.Response != nil {
		respHeaders := make(map[string]string, len(e.Response.Header))
		for k, vs := range e.Response.Header {
			respHeaders[k] = vs[len(vs)-1]
		}
		f.Status = e.Response.StatusCode
		f.StatusText = http.StatusText(e.Response.StatusCode)
		f.ResponseHeaders = respHeaders
		f.ContentType = e.Response.Header.Get("Content-Type")
		f.RespLen = len(e.RawResp)

		if includeBodies {
			if body, err := responseBody(e); err == nil {
				f.ResponseBody = string(body)
			}
		}
	}
	return f
}

func toSummary(i int, e *Entry) Summary {
	s := Summary{
		Index:    i,
		Source:   e.Source,
		Host:     e.Request.Host,
		Method:   e.Request.Method,
		URL:      fullURL(e),
		ReqLen:   len(e.RawReq),
		Protocol: e.Request.Proto,
	}
	if e.Response != nil {
		s.Status = e.Response.StatusCode
		s.RespLen = len(e.RawResp)
		s.ContentType = e.Response.Header.Get("Content-Type")
	}
	return s
}

// Trick: reference http to satisfy unused import in this file.
var _ *http.Request
