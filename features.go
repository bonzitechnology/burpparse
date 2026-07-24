package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ─── curl ─────────────────────────────────────────────────────────────────────

func toCurl(e *Entry) string {
	var sb strings.Builder
	sb.WriteString("curl")

	if strings.HasPrefix(e.Request.Proto, "HTTP/2") {
		sb.WriteString(" --http2")
	}

	if e.Request.Method != "GET" && e.Request.Method != "HEAD" {
		fmt.Fprintf(&sb, " -X %s", e.Request.Method)
	}

	skip := map[string]bool{
		"host":              true,
		"content-length":    true,
		"transfer-encoding": true,
	}
	// Stable header order.
	keys := make([]string, 0, len(e.Request.Header))
	for k := range e.Request.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if skip[strings.ToLower(k)] {
			continue
		}
		for _, v := range e.Request.Header[k] {
			fmt.Fprintf(&sb, " -H %s", shellEscape(k+": "+v))
		}
	}

	if body := reqBody(e.RawReq); len(body) > 0 {
		fmt.Fprintf(&sb, " --data-binary %s", shellEscape(string(body)))
	}

	fmt.Fprintf(&sb, " %s", shellEscape(fullURL(e)))
	return sb.String()
}

// ─── params ───────────────────────────────────────────────────────────────────

func extractParams(e *Entry) map[string][]string {
	params := make(map[string][]string)

	u, err := url.Parse(e.Request.RequestURI)
	if err == nil {
		for k, vs := range u.Query() {
			params[k] = append(params[k], vs...)
		}
	}

	ct := strings.ToLower(e.Request.Header.Get("Content-Type"))
	body := reqBody(e.RawReq)

	if strings.Contains(ct, "application/x-www-form-urlencoded") && len(body) > 0 {
		vals, err := url.ParseQuery(string(body))
		if err == nil {
			for k, vs := range vals {
				params[k] = append(params[k], vs...)
			}
		}
	}

	if strings.Contains(ct, "application/json") && len(body) > 0 {
		var obj map[string]interface{}
		if json.Unmarshal(body, &obj) == nil {
			for k := range obj {
				if _, exists := params[k]; !exists {
					params[k] = []string{"(json)"}
				}
			}
		}
	}
	return params
}

type paramAgg struct {
	name   string
	count  int
	sample []string
}

func printParams(w io.Writer, filtered []*Entry) {
	agg := make(map[string]*paramAgg)
	for _, e := range filtered {
		for k, vs := range extractParams(e) {
			if agg[k] == nil {
				agg[k] = &paramAgg{name: k}
			}
			agg[k].count++
			for _, v := range vs {
				if len(agg[k].sample) < 3 {
					agg[k].sample = append(agg[k].sample, truncate(v, 40))
				}
			}
		}
	}

	pairs := make([]*paramAgg, 0, len(agg))
	for _, v := range agg {
		pairs = append(pairs, v)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].name < pairs[j].name
	})

	fmt.Fprintf(w, "%-40s  %6s  %s\n", "Parameter", "Count", "Sample Values")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 90))
	for _, p := range pairs {
		fmt.Fprintf(w, "%-40s  %6d  %s\n", p.name, p.count, strings.Join(p.sample, " | "))
	}
}

// ─── cookies ──────────────────────────────────────────────────────────────────

type cookieInfo struct {
	name     string
	values   map[string]struct{}
	count    int
	httpOnly bool
	secure   bool
}

func sortedCookieList(m map[string]*cookieInfo) []*cookieInfo {
	result := make([]*cookieInfo, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].count != result[j].count {
			return result[i].count > result[j].count
		}
		return result[i].name < result[j].name
	})
	return result
}

func printCookies(w io.Writer, filtered []*Entry) {
	reqMap := make(map[string]*cookieInfo)
	respMap := make(map[string]*cookieInfo)

	for _, e := range filtered {
		for _, c := range e.Request.Cookies() {
			if reqMap[c.Name] == nil {
				reqMap[c.Name] = &cookieInfo{name: c.Name, values: make(map[string]struct{})}
			}
			reqMap[c.Name].count++
			reqMap[c.Name].values[truncate(c.Value, 40)] = struct{}{}
		}
		if e.Response != nil {
			for _, c := range e.Response.Cookies() {
				if respMap[c.Name] == nil {
					respMap[c.Name] = &cookieInfo{name: c.Name, values: make(map[string]struct{})}
				}
				respMap[c.Name].count++
				respMap[c.Name].values[truncate(c.Value, 40)] = struct{}{}
				if c.HttpOnly {
					respMap[c.Name].httpOnly = true
				}
				if c.Secure {
					respMap[c.Name].secure = true
				}
			}
		}
	}

	if len(reqMap) > 0 {
		fmt.Fprintln(w, "=== Request Cookies ===")
		for _, ci := range sortedCookieList(reqMap) {
			vals := cookieVals(ci)
			fmt.Fprintf(w, "  %-35s  count:%-4d  %s\n", ci.name, ci.count, vals)
		}
	}
	if len(respMap) > 0 {
		fmt.Fprintln(w, "\n=== Response Set-Cookie ===")
		for _, ci := range sortedCookieList(respMap) {
			flags := cookieFlags(ci)
			vals := cookieVals(ci)
			fmt.Fprintf(w, "  %-35s  [%s]  %s\n", ci.name, flags, vals)
		}
	}
	if len(reqMap) == 0 && len(respMap) == 0 {
		fmt.Fprintln(w, "No cookies found.")
	}
}

func cookieFlags(ci *cookieInfo) string {
	var f []string
	if ci.httpOnly {
		f = append(f, "HttpOnly")
	} else {
		f = append(f, "!HttpOnly")
	}
	if ci.secure {
		f = append(f, "Secure")
	} else {
		f = append(f, "!Secure")
	}
	return strings.Join(f, ", ")
}

func cookieVals(ci *cookieInfo) string {
	vs := make([]string, 0, len(ci.values))
	for v := range ci.values {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	return strings.Join(vs, " | ")
}

// ─── secrets ──────────────────────────────────────────────────────────────────

type SecretMatch struct {
	Pattern string
	Value   string
	Source  string // "request" | "response"
}

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_=-]{10,}\.eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=+/\-]{10,}`)},
	{"aws_key", regexp.MustCompile(`\b(AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}\b`)},
	{"bearer", regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9._~+/=\-]{20,})`)},
	{"basic_auth", regexp.MustCompile(`(?i)\bBasic\s+([A-Za-z0-9+/=]{20,})`)},
	{"password_param", regexp.MustCompile(`(?i)(?:^|&|\s)(?:password|passwd|pwd|pass)=([^&\s\r\n]{3,})`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"api_key", regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey|api_secret)[=:]["']?([A-Za-z0-9_\-]{16,})["']?`)},
	{"token_param", regexp.MustCompile(`(?i)(?:^|&|\s)(?:token|access_token|refresh_token|id_token)=([^&\s\r\n]{10,})`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`)},
	{"stripe_key", regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b`)},
}

func scanSecrets(e *Entry) []SecretMatch {
	var matches []SecretMatch
	scan := func(data []byte, src string) {
		for _, p := range secretPatterns {
			for _, m := range p.re.FindAll(data, -1) {
				matches = append(matches, SecretMatch{
					Pattern: p.name,
					Value:   string(m),
					Source:  src,
				})
			}
		}
	}
	scan(e.RawReq, "request")
	if len(e.RawResp) > 0 {
		scan(e.RawResp, "response")
	}
	return matches
}

func printSecrets(w io.Writer, filtered []*Entry, indices []int) {
	found := 0
	for i, e := range filtered {
		matches := scanSecrets(e)
		if len(matches) == 0 {
			continue
		}
		found++
		fmt.Fprintf(w, "[%d] %s %s %s\n",
			indices[i], e.Request.Method, e.Request.Host, e.Request.RequestURI)
		for _, m := range matches {
			fmt.Fprintf(w, "  %-18s  [%s]  %s\n", m.Pattern, m.Source, m.Value)
		}
	}
	if found == 0 {
		fmt.Fprintln(w, "No secrets found.")
	}
}

// ─── security headers ─────────────────────────────────────────────────────────

var interestingReqHeaders = []string{
	"Authorization", "Proxy-Authorization",
	"Cookie", "X-API-Key", "X-Auth-Token", "X-Access-Token",
	"X-CSRF-Token", "X-Requested-With",
	"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
}

var interestingRespHeaders = []string{
	"Set-Cookie",
	"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
	"Content-Security-Policy", "X-Frame-Options",
	"Strict-Transport-Security", "X-Content-Type-Options",
	"X-XSS-Protection", "WWW-Authenticate",
	"Location", "Server", "X-Powered-By",
}

func printHeaders(w io.Writer, filtered []*Entry, indices []int) {
	for i, e := range filtered {
		hasAny := false
		var lines []string

		for _, h := range interestingReqHeaders {
			if v := e.Request.Header.Get(h); v != "" {
				lines = append(lines, fmt.Sprintf("  REQ  %-40s %s", h+":", truncate(v, 80)))
				hasAny = true
			}
		}
		if e.Response != nil {
			for _, h := range interestingRespHeaders {
				if v := e.Response.Header.Get(h); v != "" {
					lines = append(lines, fmt.Sprintf("  RESP %-40s %s", h+":", truncate(v, 80)))
					hasAny = true
				}
			}
			// Flag CORS misconfiguration.
			orig := e.Response.Header.Get("Access-Control-Allow-Origin")
			cred := e.Response.Header.Get("Access-Control-Allow-Credentials")
			if orig == "*" && strings.EqualFold(cred, "true") {
				lines = append(lines, "  WARN CORS: Allow-Origin:* + Allow-Credentials:true")
			}
		}

		if !hasAny {
			continue
		}
		fmt.Fprintf(w, "[%d] %s %s %s\n",
			indices[i], e.Request.Method, e.Request.Host, e.Request.RequestURI)
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
	}
}

// ─── HAR ──────────────────────────────────────────────────────────────────────

type harFile struct {
	Log harLog `json:"log"`
}
type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}
type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
}
type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	QueryString []harParam  `json:"queryString"`
	PostData    *harPost    `json:"postData,omitempty"`
	BodySize    int         `json:"bodySize"`
	HeadersSize int         `json:"headersSize"`
	Cookies     []harCookie `json:"cookies"`
}
type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Content     harContent  `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	BodySize    int         `json:"bodySize"`
	HeadersSize int         `json:"headersSize"`
	Cookies     []harCookie `json:"cookies"`
}
type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type harParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type harPost struct {
	MimeType string     `json:"mimeType"`
	Params   []harParam `json:"params"`
	Text     string     `json:"text"`
}
type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}
type harCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	HttpOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}
type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

func buildHAR(filtered []*Entry) harFile {
	entries := make([]harEntry, 0, len(filtered))
	for _, e := range filtered {
		entries = append(entries, entryToHAR(e))
	}
	return harFile{
		Log: harLog{
			Version: "1.2",
			Creator: harCreator{Name: "burpparse", Version: "1.0"},
			Entries: entries,
		},
	}
}

func entryToHAR(e *Entry) harEntry {
	// Request headers.
	var reqHeaders []harHeader
	reqHeaders = append(reqHeaders, harHeader{"Host", e.Request.Host})
	for k, vs := range e.Request.Header {
		for _, v := range vs {
			reqHeaders = append(reqHeaders, harHeader{k, v})
		}
	}

	// Query string.
	var qs []harParam
	if u, err := parseURL(e); err == nil {
		for k, vs := range u.Query() {
			for _, v := range vs {
				qs = append(qs, harParam{k, v})
			}
		}
	}

	// Request cookies.
	var reqCookies []harCookie
	for _, c := range e.Request.Cookies() {
		reqCookies = append(reqCookies, harCookie{Name: c.Name, Value: c.Value})
	}

	// Request body.
	body := reqBody(e.RawReq)
	var postData *harPost
	if len(body) > 0 {
		ct := e.Request.Header.Get("Content-Type")
		postData = &harPost{MimeType: ct, Text: string(body)}
	}

	req := harRequest{
		Method:      e.Request.Method,
		URL:         fullURL(e),
		HTTPVersion: e.Request.Proto,
		Headers:     reqHeaders,
		QueryString: qs,
		PostData:    postData,
		BodySize:    len(body),
		HeadersSize: -1,
		Cookies:     reqCookies,
	}

	// Response.
	resp := harResponse{
		Status:      0,
		StatusText:  "",
		HTTPVersion: "HTTP/1.1",
		Headers:     []harHeader{},
		Content:     harContent{Size: 0, MimeType: ""},
		BodySize:    -1,
		HeadersSize: -1,
		Cookies:     []harCookie{},
	}
	if e.Response != nil {
		var respHeaders []harHeader
		for k, vs := range e.Response.Header {
			for _, v := range vs {
				respHeaders = append(respHeaders, harHeader{k, v})
			}
		}
		var respCookies []harCookie
		for _, c := range e.Response.Cookies() {
			respCookies = append(respCookies, harCookie{
				Name: c.Name, Value: c.Value,
				HttpOnly: c.HttpOnly, Secure: c.Secure,
			})
		}

		ct := e.Response.Header.Get("Content-Type")
		bodyBytes, err := responseBody(e)
		var contentText string
		var contentEnc string
		if err == nil {
			// Use base64 for binary content, plain text otherwise.
			if isPrintable(bodyBytes) {
				contentText = string(bodyBytes)
			} else {
				contentText = base64.StdEncoding.EncodeToString(bodyBytes)
				contentEnc = "base64"
			}
		}

		resp = harResponse{
			Status:      e.Response.StatusCode,
			StatusText:  http.StatusText(e.Response.StatusCode),
			HTTPVersion: e.Response.Proto,
			Headers:     respHeaders,
			Content: harContent{
				Size:     len(bodyBytes),
				MimeType: ct,
				Text:     contentText,
				Encoding: contentEnc,
			},
			BodySize:    len(e.RawResp),
			HeadersSize: -1,
			Cookies:     respCookies,
		}
	}

	return harEntry{
		StartedDateTime: "1970-01-01T00:00:00.000Z",
		Request:         req,
		Response:        resp,
		Timings:         harTimings{Send: 0, Wait: 0, Receive: 0},
	}
}

func parseURL(e *Entry) (*url.URL, error) {
	return url.Parse(fullURL(e))
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x09 || (b > 0x0d && b < 0x20 && b != 0x1b) {
			return false
		}
	}
	return true
}
