package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	var (
		// Output modes (mutually exclusive).
		outputJSON   = flag.Bool("json", false, "output as JSON array")
		outputJSONL  = flag.Bool("jsonl", false, "output as JSONL (one JSON object per line, good for jq/grep)")
		noBodyFlag   = flag.Bool("no-body", false, "omit decoded bodies from -jsonl output (headers + metadata only)")
		outputCSV    = flag.Bool("csv", false, "output as CSV")
		outputHAR   = flag.Bool("har", false, "output as HAR JSON")
		outputCurl  = flag.Bool("curl", false, "output as curl commands")
		statsFlag   = flag.Bool("stats", false, "print statistics summary")
		urlsFlag    = flag.Bool("urls", false, "print unique URLs")
		paramsFlag  = flag.Bool("params", false, "aggregate request parameter names")
		cookiesFlag = flag.Bool("cookies", false, "extract cookies from requests/responses")
		secretsFlag = flag.Bool("secrets", false, "scan for credentials and secrets")
		headersFlag = flag.Bool("headers", false, "show interesting security headers")
		bodyFlag    = flag.Bool("body", false, "print decoded response body to stdout")
		outFlag     = flag.String("out", "", "write decoded response body to file ('auto' = URL-derived name)")
		parseStats  = flag.Bool("parse-stats", false, "print parse-time drop counters (blobs skipped, parse errors)")
		maxBlobMB   = flag.Int("max-blob", 512, "max HTTP blob size in MB (default 512)")
		btreeWalk   = flag.Bool("btree", false, "walk schema BTree from root@0xFA (structural; finds metadata only — proxy-history rows live in heap)")
		dumpLeaves  = flag.Bool("dump-leaves", false, "dump every leaf node reached from root@0xFA to stderr (for catalog discovery)")
		verboseFlag = flag.Bool("v", false, "verbose: log walker stats to stderr")

		// Display modifiers.
		showReq  = flag.Bool("req", false, "print raw request for matched entries")
		showResp = flag.Bool("resp", false, "print raw response for matched entries")

		// Filters.
		filterHost    = flag.String("host", "", "filter by host substring (case-insensitive)")
		filterExclude = flag.String("exclude", "", "exclude hosts (comma-separated)")
		filterScope   = flag.String("scope", "", "include only these hosts (comma-separated, supports subdomains)")
		filterPath    = flag.String("path", "", "filter by path substring")
		filterMethod  = flag.String("method", "", "filter by HTTP method")
		filterCode    = flag.Int("status", 0, "filter by exact status code")
		filterMin     = flag.Int("status-min", 0, "filter by min status code")
		filterMax     = flag.Int("status-max", 0, "filter by max status code")
		filterCT      = flag.String("ct", "", "filter by response Content-Type substring")
		searchFlag    = flag.String("search", "", "regex search across request and response bytes")
		uniqueFlag    = flag.Bool("unique", false, "deduplicate by request content (SHA-256)")
		hasRespFlag   = flag.Bool("has-resp", false, "only entries with a response")
		indexFlag     = flag.Int("index", -1, "show single entry by index")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: burpparse <file.burp> [file2.burp ...] [flags]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  burpparse file.burp
  burpparse file.burp -unique -stats
  burpparse file.burp -urls -host example.com
  burpparse file.burp -secrets
  burpparse file.burp -cookies
  burpparse file.burp -params -unique
  burpparse file.burp -headers -scope example.com
  burpparse file.burp -curl -method POST
  burpparse file.burp -har > capture.har
  burpparse file.burp -csv > capture.csv
  burpparse file.burp -index 5 -req -resp
  burpparse file.burp -index 5 -out response.html
  burpparse file.burp -status 200 -ct json -body
  burpparse file.burp -status-min 200 -status-max 299
  burpparse a.burp b.burp c.burp -unique -stats
  burpparse file.burp -parse-stats
  burpparse file.burp -max-blob 1024 -jsonl > out.jsonl
  burpparse file.burp -jsonl -no-body -host example.com  # headers+metadata only, no bodies`)
	}

	// Parse: collect all leading non-flag args as files, rest as flags.
	args := os.Args[1:]
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	var burpFiles []string
	var flagArgs []string
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flagArgs = args[i:]
			break
		}
		burpFiles = append(burpFiles, arg)
	}
	if len(burpFiles) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if err := flag.CommandLine.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "flag: %v\n", err)
		os.Exit(1)
	}

	// Compile search regex.
	var searchRe *regexp.Regexp
	if *searchFlag != "" {
		var err error
		searchRe, err = regexp.Compile(*searchFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -search regex: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse scope list.
	var scopeList []string
	if *filterScope != "" {
		for _, s := range strings.Split(*filterScope, ",") {
			if t := strings.TrimSpace(strings.ToLower(s)); t != "" {
				scopeList = append(scopeList, t)
			}
		}
	}

	// Apply user-supplied blob size cap.
	if *maxBlobMB > 0 {
		maxBlobSize = *maxBlobMB * 1024 * 1024
	}

	// Select parse mode. Precedence: btree > scan.
	switch {
	case *btreeWalk:
		GlobalParseMode = ParseModeBTree
	}
	GlobalVerbose = *verboseFlag
	GlobalDumpLeaves = *dumpLeaves

	// Load all files. Keep mmaps alive for the duration of processing — Entry
	// fields reference mmap-backed slices to avoid copying multi-MB bodies.
	var allEntries []*Entry
	var munmaps []func()
	defer func() {
		for _, u := range munmaps {
			u()
		}
	}()
	for _, f := range burpFiles {
		data, munmap, err := mmapFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", f, err)
			os.Exit(1)
		}
		munmaps = append(munmaps, munmap)
		source := ""
		if len(burpFiles) > 1 {
			source = f
		}
		entries, err := parseFile(data, source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", f, err)
			os.Exit(1)
		}
		allEntries = append(allEntries, entries...)
	}

	// Apply filters.
	filtered, filteredIdx := applyFilters(allEntries, FilterOpts{
		Index:       *indexFlag,
		Host:        *filterHost,
		ExcludeHost: *filterExclude,
		Scope:       scopeList,
		Path:        *filterPath,
		Method:      *filterMethod,
		StatusCode:  *filterCode,
		StatusMin:   *filterMin,
		StatusMax:   *filterMax,
		ContentType: *filterCT,
		SearchRe:    searchRe,
		Unique:      *uniqueFlag,
		HasResp:     *hasRespFlag,
	})

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	switch {
	// ── Stats ──────────────────────────────────────────────────────────────
	case *statsFlag:
		printStats(w, allEntries, filtered)

	// ── URLs ───────────────────────────────────────────────────────────────
	case *urlsFlag:
		seen := make(map[string]struct{})
		for _, e := range filtered {
			u := fullURL(e)
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				fmt.Fprintln(w, u)
			}
		}

	// ── Params ─────────────────────────────────────────────────────────────
	case *paramsFlag:
		printParams(w, filtered)

	// ── Cookies ────────────────────────────────────────────────────────────
	case *cookiesFlag:
		printCookies(w, filtered)

	// ── Secrets ────────────────────────────────────────────────────────────
	case *secretsFlag:
		printSecrets(w, filtered, filteredIdx)

	// ── Security Headers ───────────────────────────────────────────────────
	case *headersFlag:
		printHeaders(w, filtered, filteredIdx)

	// ── curl ───────────────────────────────────────────────────────────────
	case *outputCurl:
		for _, e := range filtered {
			fmt.Fprintln(w, toCurl(e))
		}

	// ── HAR ────────────────────────────────────────────────────────────────
	case *outputHAR:
		w.Flush()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(buildHAR(filtered))

	// ── CSV ────────────────────────────────────────────────────────────────
	case *outputCSV:
		w.Flush()
		cw := csv.NewWriter(os.Stdout)
		cw.Write([]string{"index", "source", "method", "host", "url", "status", "req_len", "resp_len", "content_type", "protocol"})
		for i, e := range filtered {
			s := toSummary(filteredIdx[i], e)
			cw.Write([]string{
				fmt.Sprintf("%d", s.Index),
				s.Source,
				s.Method,
				s.Host,
				s.URL,
				fmt.Sprintf("%d", s.Status),
				fmt.Sprintf("%d", s.ReqLen),
				fmt.Sprintf("%d", s.RespLen),
				s.ContentType,
				s.Protocol,
			})
		}
		cw.Flush()

	// ── JSON ───────────────────────────────────────────────────────────────
	case *outputJSON:
		summaries := make([]Summary, len(filtered))
		for i, e := range filtered {
			summaries[i] = toSummary(filteredIdx[i], e)
		}
		w.Flush()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(summaries)

	// ── JSONL ──────────────────────────────────────────────────────────────
	case *outputJSONL:
		enc := json.NewEncoder(w)
		for i, e := range filtered {
			enc.Encode(toFullEntry(filteredIdx[i], e, !*noBodyFlag))
		}

	// ── Body to stdout ─────────────────────────────────────────────────────
	case *bodyFlag:
		for _, e := range filtered {
			body, err := responseBody(e)
			if err != nil {
				fmt.Fprintf(os.Stderr, "body: %v\n", err)
				continue
			}
			w.Write(body)
		}

	// ── Body to file ───────────────────────────────────────────────────────
	case *outFlag != "":
		for i, e := range filtered {
			body, err := responseBody(e)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%d] body: %v\n", filteredIdx[i], err)
				continue
			}
			name := *outFlag
			if name == "auto" {
				name = autoName(filteredIdx[i], e)
			}
			if err := os.WriteFile(name, body, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[%d] write %s: %v\n", filteredIdx[i], name, err)
				continue
			}
			ct := ""
			if e.Response != nil {
				ct = e.Response.Header.Get("Content-Type")
			}
			fmt.Fprintf(w, "[%d] wrote %s (%d bytes) [%s]\n", filteredIdx[i], name, len(body), ct)
		}

	// ── Default: table ─────────────────────────────────────────────────────
	default:
		for i, e := range filtered {
			origIdx := filteredIdx[i]
			status := "-"
			respLen := "-"
			if e.Response != nil {
				status = fmt.Sprintf("%d", e.Response.StatusCode)
				respLen = fmt.Sprintf("%d", len(e.RawResp))
			}
			src := ""
			if e.Source != "" {
				src = fmt.Sprintf(" [%s]", e.Source)
			}
			fmt.Fprintf(w, "[%d] %s %s %s => %s (req:%d resp:%s)%s\n",
				origIdx,
				e.Request.Method,
				e.Request.Host,
				e.Request.RequestURI,
				status,
				len(e.RawReq),
				respLen,
				src,
			)
			if *showReq {
				fmt.Fprintln(w, "--- REQUEST ---")
				w.Write(e.RawReq)
				fmt.Fprintln(w, "\n---")
			}
			if *showResp && len(e.RawResp) > 0 {
				fmt.Fprintln(w, "--- RESPONSE ---")
				w.Write(e.RawResp)
				fmt.Fprintln(w, "\n---")
			}
		}
		fmt.Fprintf(w, "\nTotal: %d entries (%d shown)\n", len(allEntries), len(filtered))
	}

	if *parseStats {
		w.Flush()
		fmt.Fprintf(os.Stderr, "parse-stats: %s\n", GlobalStats.String())
	}
}
