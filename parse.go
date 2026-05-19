package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/andybalholm/brotli"
)

var errNoResponse = errors.New("no response")

// maxBlobSize is the upper bound for a single HTTP blob.
// 512 MB covers virtually all real-world payloads; override with -max-blob.
var maxBlobSize = 512 * 1024 * 1024

// ParseStats accumulates counters across a parse run.
type ParseStats struct {
	BlobsDroppedSize  int64 // blobs skipped because inner > maxBlobSize
	ReqParseErrors    int64 // http.ReadRequest failures
	RespParseErrors   int64 // http.ReadResponse failures
	RespNotAdjacent   int64 // requests whose response wasn't at expected offset
}

func (s *ParseStats) add(o *ParseStats) {
	atomic.AddInt64(&s.BlobsDroppedSize, o.BlobsDroppedSize)
	atomic.AddInt64(&s.ReqParseErrors, o.ReqParseErrors)
	atomic.AddInt64(&s.RespParseErrors, o.RespParseErrors)
	atomic.AddInt64(&s.RespNotAdjacent, o.RespNotAdjacent)
}

func (s *ParseStats) String() string {
	return fmt.Sprintf(
		"blobs_dropped_size=%d  req_parse_errors=%d  resp_parse_errors=%d  resp_not_adjacent=%d",
		s.BlobsDroppedSize, s.ReqParseErrors, s.RespParseErrors, s.RespNotAdjacent,
	)
}

// GlobalStats accumulates stats across all files parsed in a run.
var GlobalStats ParseStats

// ParseMode selects how rows are located in the file.
type ParseMode int

const (
	// ParseModeStructural: full HashMap walk from header -> catalog -> ProxyHistoryRoot
	// -> HashMapNode -> bucket-desc -> level-1 -> level-2 -> rowPtr. Each rowPtr's
	// 31-col NodeCompact row exposes req chunk @ row+0x69 and resp chunk @ row+0x71.
	// Yields exact Burp-UI count. Falls back to
	// ParseModeScan if the chain cannot be parsed.
	ParseModeStructural ParseMode = iota
	// ParseModeScan: linear sweep for HttpChunk HTTP chunks. Schema-agnostic
	// fallback. Pairs req<->resp via inline row layout (stride 24/8).
	ParseModeScan
	// ParseModeBTree: walk the catalog NodeCompact/NodeSecondary BTree from header @0x40.
	// Diagnostic only — proxy-history rows are NOT reachable as BTree
	// leaves (they live inside HashMap chunk hierarchy).
	ParseModeBTree
)

// GlobalParseMode is set from main flags before parseFile runs.
var GlobalParseMode = ParseModeStructural

// GlobalVerbose toggles BTree walker debug output to stderr.
var GlobalVerbose = false

// GlobalDumpLeaves dumps every BTree leaf reached from root@0xFA to stderr.
var GlobalDumpLeaves = false

// Entry is a parsed HTTP transaction from a Burp project file.
type Entry struct {
	ReqPos   int64
	Source   string // filename (multi-file mode)
	Request  *http.Request
	RawReq   []byte
	Response *http.Response
	RawResp  []byte
}

// Burp proxy-history is stored as a sequence of HttpChunk-framed chunks in the
// bump-allocator heap. Each completed proxy entry produces one HTTP response
// chunk in file order. Response chunks are the structural unit Burp uses to
// count "proxy rows" in its UI.
//
// Chunk framing (HttpChunkFormat):
//   [u32 totalLen BE][u32 logLen BE][payload[totalLen-8]]
// where logLen ≤ totalLen-8 is the logical content length.
//
// Response payload begins with either "HTTP/" or a single opaque prefix byte
// followed by "HTTP/". Request payload begins with an HTTP method token.
//
// Pairing: each response chunk is associated with the nearest preceding
// request chunk in file order. Burp interleaves req/resp/metadata in the
// allocator, so they are not always adjacent — the metadata records (6-col
// NodeCompact fdir at row+4, count=6, relOffs 0x16/0x1e/0x26/0x2a/0x2e/0x36) appear
// between them but encode session/cookie state, not blob pointers.
//
// Validated row counts:

const (
	rowReqColRel  = 0  // row pointer = req chunk header offset
	rowRespColRel = 0  // unused under chunk-pair model
	rowFdirOffset = 0  // unused under chunk-pair model
)

// chunkRef identifies a HttpChunk chunk by its header offset and parsed lengths.
type chunkRef struct {
	off uint64
	tot uint32
	log uint32
}

// readBlobChunk validates a chunk header at off and returns the payload slice.
// Chunk format: [u32 totalLen BE][u32 logLen BE][payload[totalLen-8]]
// The returned slice is the first logLen bytes of the payload (logical content).
// Returns nil if invalid or out of bounds.
func readBlobChunk(data []byte, off uint64) []byte {
	n := uint64(len(data))
	if off <= 72 || off+8 > n {
		return nil
	}
	totalLen := uint64(binary.BigEndian.Uint32(data[off : off+4]))
	logLen := uint64(binary.BigEndian.Uint32(data[off+4 : off+8]))
	if totalLen < 9 || totalLen > uint64(maxBlobSize) {
		return nil
	}
	if off+totalLen > n {
		return nil
	}
	if logLen > totalLen-8 {
		return nil
	}
	return data[off+8 : off+8+logLen]
}

// scanRows finds proxy-history entries by scanning the file for HttpChunk-framed
// HTTP response chunks. Each response chunk corresponds to one completed
// proxy entry. Returned offsets are response-chunk header positions; pair
// with the nearest preceding request chunk in recordAtRow.
func scanRows(data []byte) []int64 {
	resps, _ := scanReqRespChunks(data)
	rows := make([]int64, 0, len(resps))
	for r := range resps {
		rows = append(rows, int64(r))
	}
	return rows
}

// scanReqRespChunks does ONE pass over the file finding every HttpChunk-framed
// chunk whose payload begins with "HTTP/" (resp) or an HTTP method (req).
// Returns separate sets keyed by chunk header offset.
func scanReqRespChunks(data []byte) (resps, reqs map[uint64]struct{}) {
	resps = map[uint64]struct{}{}
	reqs = map[uint64]struct{}{}
	n := uint64(len(data))
	if n < 80 {
		return
	}
	nextFree := binary.BigEndian.Uint64(data[56:64])
	if nextFree > n || nextFree < 80 {
		nextFree = n
	}
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
		[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "),
		[]byte("CONNECT "), []byte("TRACE "),
	}
	for off := uint64(72); off+16 <= nextFree; off++ {
		if data[off] != 0 {
			continue
		}
		tot := uint64(binary.BigEndian.Uint32(data[off : off+4]))
		log := uint64(binary.BigEndian.Uint32(data[off+4 : off+8]))
		if tot < 16 || tot > uint64(maxBlobSize) {
			continue
		}
		if log == 0 || log > tot-8 {
			continue
		}
		if off+tot > nextFree {
			continue
		}
		p := data[off+8:]
		if len(p) < 6 {
			continue
		}
		if bytes.HasPrefix(p, []byte("HTTP/")) ||
			(len(p) >= 6 && bytes.Equal(p[1:6], []byte("HTTP/"))) {
			resps[off] = struct{}{}
			continue
		}
		for _, m := range methods {
			if bytes.HasPrefix(p, m) {
				reqs[off] = struct{}{}
				break
			}
		}
	}
	return
}

// pairRowsStructural builds a deterministic resp→req pairing using ProxyRowFormat
// row layout. Burp stores proxy-history rows inline in Bucket bucket blobs;
// each row contains (req_ptr, ..., resp_ptr) cells with two observed
// strides:
//   stride24: req at row+R-24, then 16 zero bytes (padding cols), resp at row+R
//   stride8:  req at row+R-8 directly adjacent to resp at row+R
// For each resp chunk found, scan the file for any byte offset X where
// u64 BE @ X equals the resp offset AND u64 BE @ (X-24) or (X-8) is in the
// known request-chunk set. The first match wins (stride24 preferred).
//
// Returns a map respChunkOff → reqChunkOff. resps without a row reference
// (e.g. WebSocket frames or HTTP/2 streams that use different framing) are
// absent from the map; recordAtRow falls back to nearest-preceding for those.
func pairRowsStructural(data []byte, resps, reqs map[uint64]struct{}) map[uint64]uint64 {
	n := uint64(len(data))
	if n < 80 {
		return nil
	}
	nextFree := binary.BigEndian.Uint64(data[56:64])
	if nextFree > n || nextFree < 80 {
		nextFree = n
	}
	pair := make(map[uint64]uint64, len(resps))
	for x := uint64(24); x+8 <= nextFree; x++ {
		v := binary.BigEndian.Uint64(data[x : x+8])
		if _, ok := resps[v]; !ok {
			continue
		}
		if _, seen := pair[v]; seen {
			continue // first hit wins
		}
		r24 := binary.BigEndian.Uint64(data[x-24 : x-16])
		if _, ok := reqs[r24]; ok {
			pair[v] = r24
			continue
		}
		r8 := binary.BigEndian.Uint64(data[x-8 : x])
		if _, ok := reqs[r8]; ok {
			pair[v] = r8
		}
	}
	return pair
}

// findRequestBefore searches backward from respOff for the nearest HttpChunk chunk
// whose payload starts with an HTTP method. Returns the request-chunk header
// offset, or 0 if no plausible request found within search window.
func findRequestBefore(data []byte, respOff uint64) uint64 {
	const window = 8 * 1024 * 1024 // 8 MB lookback window
	var lo uint64
	if respOff > window {
		lo = respOff - window
	} else {
		lo = 72
	}
	// Scan downward — checking each byte for a valid chunk header pointing to
	// HTTP request.
	for off := respOff - 1; off >= lo && off >= 72; off-- {
		if data[off] != 0 {
			if off == 0 {
				break
			}
			continue
		}
		if off+16 > uint64(len(data)) {
			continue
		}
		tot := uint64(binary.BigEndian.Uint32(data[off : off+4]))
		log := uint64(binary.BigEndian.Uint32(data[off+4 : off+8]))
		if tot < 16 || tot > uint64(maxBlobSize) {
			continue
		}
		if log == 0 || log > tot-8 {
			continue
		}
		if off+tot > uint64(len(data)) {
			continue
		}
		p := data[off+8:]
		if len(p) < 8 {
			continue
		}
		if isHTTPMethodPrefix(p) {
			return off
		}
		if off == 0 {
			break
		}
	}
	return 0
}

// isHTTPMethodPrefix returns true if p starts with a recognized HTTP method
// followed by a space.
func isHTTPMethodPrefix(p []byte) bool {
	for _, m := range [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
		[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "),
		[]byte("CONNECT "), []byte("TRACE "),
	} {
		if bytes.HasPrefix(p, m) {
			return true
		}
	}
	return false
}

// recordAtRow reads req and resp blob payloads for a proxy-history entry.
// rowPtr is the response chunk's header offset. pair maps resp→req via the
// row-layout pairing; if absent, falls back to nearest-preceding heuristic.
func recordAtRow(data []byte, rowPtr int64, pair map[uint64]uint64) (rawReq, rawResp []byte) {
	if rowPtr < 0 {
		return nil, nil
	}
	respOff := uint64(rowPtr)
	rawResp = readBlobChunk(data, respOff)
	if len(rawResp) >= 6 && rawResp[0] != 'H' && bytes.Equal(rawResp[1:6], []byte("HTTP/")) {
		rawResp = rawResp[1:]
	}
	var reqOff uint64
	if pair != nil {
		reqOff = pair[respOff]
	}
	if reqOff == 0 {
		reqOff = findRequestBefore(data, respOff)
	}
	if reqOff != 0 {
		rawReq = readBlobChunk(data, reqOff)
	}
	return rawReq, rawResp
}

// parseFile parses a Burp project binary file and returns HTTP transactions.
//
// Mode dispatch:
//   - ParseModeStructural: full HashMap walk yields exact rowPtrs. Each row
//     has explicit req/resp chunk pointers — no scanning, no pairing.
//   - ParseModeScan: linear HttpChunk chunk sweep + inline-row resp→req pairing.
//   - ParseModeBTree: catalog BTree walk (diagnostic; finds 0 proxy rows).
//
// Structural mode falls back to scan if the chain cannot be parsed.
func parseFile(data []byte, source string) ([]*Entry, error) {
	var stats ParseStats

	// === Structural HashMap walk (preferred) ===
	if GlobalParseMode == ParseModeStructural {
		prows := walkProxyHistory(data)
		if len(prows) > 0 {
			if GlobalVerbose {
				fmt.Fprintf(os.Stderr, "walk: %d structural rowPtrs\n", len(prows))
			}
			return parseStructuralRows(data, source, prows, &stats)
		}
		if GlobalVerbose {
			fmt.Fprintln(os.Stderr, "walk: structural traversal failed, falling back to scan")
		}
	}

	var rows []int64
	var pair map[uint64]uint64
	switch GlobalParseMode {
	case ParseModeBTree:
		rows = walkBTree(data, walkOpts{verbose: GlobalVerbose})
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "btree: %d rows reachable from root\n", len(rows))
		}
	default:
		resps, reqs := scanReqRespChunks(data)
		rows = make([]int64, 0, len(resps))
		for r := range resps {
			rows = append(rows, int64(r))
		}
		pair = pairRowsStructural(data, resps, reqs)
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "scan: %d resp chunks, %d req chunks, %d row-paired\n",
				len(resps), len(reqs), len(pair))
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i] < rows[j] })

	var entries []*Entry
	for _, rp := range rows {
		rawReq, rawResp := recordAtRow(data, rp, pair)
		if rawReq == nil {
			atomic.AddInt64(&stats.ReqParseErrors, 1)
			continue
		}
		if len(rawReq) > maxBlobSize {
			atomic.AddInt64(&stats.BlobsDroppedSize, 1)
			continue
		}
		if rawResp != nil && len(rawResp) > maxBlobSize {
			atomic.AddInt64(&stats.BlobsDroppedSize, 1)
			rawResp = nil
		}
		if rawResp == nil {
			atomic.AddInt64(&stats.RespNotAdjacent, 1)
		}
		e, err := buildEntry(int(rp), source, rawReq, rawResp, rawResp, &stats)
		if err != nil {
			continue
		}
		entries = append(entries, e)
	}
	GlobalStats.add(&stats)
	return entries, nil
}

// parseStructuralRows builds Entry objects from rowPtrs returned by
// walkProxyHistory. Each proxyRow has explicit req/resp HttpChunk chunk offsets;
// no scanning or heuristic pairing.
func parseStructuralRows(data []byte, source string, prows []proxyRow, stats *ParseStats) ([]*Entry, error) {
	sort.Slice(prows, func(i, j int) bool { return prows[i].rowOff < prows[j].rowOff })
	entries := make([]*Entry, 0, len(prows))
	for _, pr := range prows {
		var rawReq, rawResp []byte
		if pr.reqOff != 0 {
			rawReq = readBlobChunk(data, pr.reqOff)
		}
		if pr.respOff != 0 {
			rawResp = readBlobChunk(data, pr.respOff)
			if len(rawResp) >= 6 && rawResp[0] != 'H' && bytes.Equal(rawResp[1:6], []byte("HTTP/")) {
				rawResp = rawResp[1:]
			}
		}
		if rawReq == nil {
			atomic.AddInt64(&stats.ReqParseErrors, 1)
			continue
		}
		if len(rawReq) > maxBlobSize {
			atomic.AddInt64(&stats.BlobsDroppedSize, 1)
			continue
		}
		if rawResp != nil && len(rawResp) > maxBlobSize {
			atomic.AddInt64(&stats.BlobsDroppedSize, 1)
			rawResp = nil
		}
		if rawResp == nil {
			atomic.AddInt64(&stats.RespNotAdjacent, 1)
		}
		e, err := buildEntry(int(pr.rowOff), source, rawReq, rawResp, rawResp, stats)
		if err != nil {
			continue
		}
		entries = append(entries, e)
	}
	GlobalStats.add(stats)
	return entries, nil
}

// normalizeHTTPVersion rewrites HTTP/2 and HTTP/3 version tokens to HTTP/1.1
// so that Go's net/http parser can handle them. Works for both request lines
// (version is a suffix: "GET / HTTP/2") and response status lines (version is
// a prefix: "HTTP/2 200 OK"). Always returns a new allocation (mmap-safe).
func normalizeHTTPVersion(raw []byte) []byte {
	end := bytes.Index(raw, []byte("\r\n"))
	if end < 0 {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}
	line := raw[:end]

	// Request line: version is suffix "... HTTP/2" or "... HTTP/3"
	for _, ver := range [][]byte{[]byte(" HTTP/2"), []byte(" HTTP/3")} {
		if bytes.HasSuffix(line, ver) {
			prefix := line[:len(line)-len(ver)]
			var buf bytes.Buffer
			buf.Grow(len(prefix) + 9 + 2 + len(raw[end+2:]))
			buf.Write(prefix)
			buf.WriteString(" HTTP/1.1\r\n")
			buf.Write(raw[end+2:])
			return buf.Bytes()
		}
	}

	// Response status line: version is prefix "HTTP/2 " or "HTTP/3 "
	for _, ver := range [][]byte{[]byte("HTTP/2 "), []byte("HTTP/3 ")} {
		if bytes.HasPrefix(line, ver) {
			rest := line[len(ver):]
			var buf bytes.Buffer
			buf.Grow(8 + len(rest) + 2 + len(raw[end+2:]))
			buf.WriteString("HTTP/1.1 ")
			buf.Write(rest)
			buf.WriteString("\r\n")
			buf.Write(raw[end+2:])
			return buf.Bytes()
		}
	}

	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

// parseRespHeaders parses a raw HTTP response byte slice and returns an
// *http.Response with status code, proto, and headers populated.
// It does NOT consume or validate the body — Content-Length is ignored.
// raw must begin at the HTTP status line (prefix already stripped).
func parseRespHeaders(raw []byte) (*http.Response, error) {
	// Find end of header block.
	hdrEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return nil, errors.New("response headers not terminated")
	}
	lines := bytes.Split(raw[:hdrEnd], []byte("\r\n"))
	if len(lines) == 0 {
		return nil, errors.New("empty response")
	}

	// Parse status line: HTTP/x.x <code> <text>
	statusLine := string(lines[0])
	// Normalize version for parsing only.
	for _, ver := range []string{"HTTP/2 ", "HTTP/3 "} {
		if strings.HasPrefix(statusLine, ver) {
			statusLine = "HTTP/1.1 " + statusLine[len(ver):]
			break
		}
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("bad status line: %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 999 {
		return nil, fmt.Errorf("bad status code: %q", parts[1])
	}
	proto := parts[0]
	statusText := ""
	if len(parts) == 3 {
		statusText = parts[2]
	}

	// Parse headers.
	hdr := make(http.Header)
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(
		append(bytes.Join(lines[1:], []byte("\r\n")), []byte("\r\n\r\n")...),
	)))
	mimeHdr, _ := tp.ReadMIMEHeader() // best-effort; ignore parse errors
	for k, vs := range mimeHdr {
		hdr[k] = vs
	}

	resp := &http.Response{
		Status:     parts[1] + " " + statusText,
		StatusCode: code,
		Proto:      proto,
		Header:     hdr,
		Body:       http.NoBody,
	}
	switch proto {
	case "HTTP/1.0":
		resp.ProtoMajor, resp.ProtoMinor = 1, 0
	case "HTTP/1.1":
		resp.ProtoMajor, resp.ProtoMinor = 1, 1
	default:
		resp.ProtoMajor, resp.ProtoMinor = 1, 1
	}
	return resp, nil
}

func buildEntry(reqPos int, source string, rawReq, rawResp, rawRespBody []byte, stats *ParseStats) (*Entry, error) {
	// Parse only the header block (small) to avoid copying multi-MB bodies.
	reqHdrEnd := bytes.Index(rawReq, []byte("\r\n\r\n"))
	var reqHdrSlice []byte
	if reqHdrEnd >= 0 {
		reqHdrSlice = rawReq[:reqHdrEnd+4]
	} else {
		reqHdrSlice = rawReq
	}
	// Stash original proto BEFORE normalize rewrites it. Request line ends
	// with proto token: "GET / HTTP/2".
	origProto := ""
	if lineEnd := bytes.Index(reqHdrSlice, []byte("\r\n")); lineEnd > 0 {
		line := reqHdrSlice[:lineEnd]
		if i := bytes.LastIndexByte(line, ' '); i >= 0 {
			origProto = string(line[i+1:])
		}
	}
	parseReq := normalizeHTTPVersion(reqHdrSlice)
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(parseReq)))
	if err != nil {
		atomic.AddInt64(&stats.ReqParseErrors, 1)
		return nil, err
	}
	// Restore original proto on parsed request so guessScheme sees HTTP/2/3.
	if strings.HasPrefix(origProto, "HTTP/") {
		req.Proto = origProto
	}
	// Reference mmap slices directly. Caller must keep mmap alive for entry lifetime.
	e := &Entry{
		ReqPos:  int64(reqPos),
		Source:  source,
		Request: req,
		RawReq:  rawReq,
	}
	if rawResp != nil {
		// Slice header portion only for header parsing.
		hdrEnd := bytes.Index(rawResp, []byte("\r\n\r\n"))
		hdrSlice := rawResp
		if hdrEnd >= 0 {
			hdrSlice = rawResp[:hdrEnd+4]
		}
		resp, err := parseRespHeaders(hdrSlice)
		if err != nil {
			atomic.AddInt64(&stats.RespParseErrors, 1)
		} else {
			e.Response = resp
		}
		if rawRespBody != nil {
			e.RawResp = rawRespBody
		}
	}
	return e, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func reqHash(raw []byte) [32]byte { return sha256.Sum256(raw) }

// reqBody returns the body bytes from a raw HTTP request.
func reqBody(rawReq []byte) []byte {
	idx := bytes.Index(rawReq, []byte("\r\n\r\n"))
	if idx == -1 {
		return nil
	}
	return rawReq[idx+4:]
}

// responseBody extracts and decodes the response body from e.RawResp,
// handling Content-Encoding. Does not use http.ReadResponse — parses
// the raw bytes directly to avoid Content-Length trust issues.
func responseBody(e *Entry) ([]byte, error) {
	if len(e.RawResp) == 0 {
		return nil, errNoResponse
	}
	hdrEnd := bytes.Index(e.RawResp, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return nil, errors.New("response headers not terminated")
	}
	body := e.RawResp[hdrEnd+4:]

	// Determine Content-Encoding from stored headers.
	enc := ""
	if e.Response != nil {
		enc = strings.ToLower(e.Response.Header.Get("Content-Encoding"))
	}

	var r io.Reader = bytes.NewReader(body)
	switch enc {
	case "gzip":
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			break
		}
		defer gz.Close()
		r = gz
	case "deflate":
		rc := flate.NewReader(bytes.NewReader(body))
		defer rc.Close()
		r = rc
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	}
	return io.ReadAll(r)
}

func guessScheme(e *Entry) string {
	if strings.HasPrefix(e.Request.Proto, "HTTP/2") ||
		strings.HasPrefix(e.Request.Proto, "HTTP/3") {
		return "https"
	}
	h := e.Request.Host
	if strings.HasSuffix(h, ":443") || strings.HasSuffix(h, ":8443") {
		return "https"
	}
	if e.Response != nil {
		if loc := e.Response.Header.Get("Location"); strings.HasPrefix(loc, "https://") {
			return "https"
		}
	}
	return "http"
}

func fullURL(e *Entry) string {
	return guessScheme(e) + "://" + e.Request.Host + e.Request.RequestURI
}

func autoName(idx int, e *Entry) string {
	path := e.Request.RequestURI
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	if path == "" {
		path = fmt.Sprintf("response_%d", idx)
	}
	return path
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// mmapFile memory-maps a file for read-only access.
// Returns the mapped bytes and a cleanup func. The cleanup func must be called
// after all parsing is done (it is safe to call even if err != nil).
func mmapFile(path string) (data []byte, cleanup func(), err error) {
	cleanup = func() {}
	f, err := os.Open(path)
	if err != nil {
		return nil, cleanup, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, cleanup, err
	}
	size := fi.Size()
	if size == 0 {
		f.Close()
		return []byte{}, cleanup, nil
	}
	data, err = syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	f.Close() // fd no longer needed after mmap
	if err != nil {
		return nil, cleanup, fmt.Errorf("mmap %s: %w", path, err)
	}
	cleanup = func() { syscall.Munmap(data) } //nolint:errcheck
	return data, cleanup, nil
}
