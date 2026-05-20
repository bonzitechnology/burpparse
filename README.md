# burpParse

A tool to parse Burp Suite project files (proxy-history).

## Overview

This tool reconstructs HTTP transactions from Burp's internal bump-allocator heap. It walks the structural HashMap and catalog BTree to locate and pair request/response chunks.

## Installation

```bash
go install github.com/bonzitechnology/burpparse@latest
```

## Features

- **Structural Parsing:** Follows Burp's HashMap/BTree hierarchy to extract every proxy row accurately.
- **Scan Fallback:** Schema-agnostic linear sweep for HTTP chunks when structural navigation fails.
- **Efficient Pairing:** Pairs request/response chunks using row-layout analysis.

## Usage

```bash
burpparse
Usage: burpparse <file.burp> [file2.burp ...] [flags]

Output Formats:
  -json         output as JSON array
  -jsonl        output as JSONL (one JSON object per line, good for jq/grep)
  -csv          output as CSV
  -har          output as HAR JSON
  -curl         output as curl commands
  -urls         print unique URLs

Extraction & Analysis:
  -body         print decoded response body to stdout
  -cookies      extract cookies from requests/responses
  -params       aggregate request parameter names
  -secrets      scan for credentials and secrets
  -headers      show interesting security headers
  -req          print raw request for matched entries
  -resp         print raw response for matched entries
  -out string   write decoded response body to file ('auto' = URL-derived name)

Filtering:
  -host string        filter by host substring (case-insensitive)
  -exclude string     exclude hosts (comma-separated)
  -scope string       include only these hosts (comma-separated, supports subdomains)
  -path string        filter by path substring
  -method string      filter by HTTP method
  -status int         filter by exact status code
  -status-min int     filter by min status code
  -status-max int     filter by max status code
  -ct string          filter by response Content-Type substring
  -search string      regex search across request and response bytes
  -has-resp           only entries with a response
  -index int          show single entry by index (default -1)

Processing Options:
  -unique             deduplicate by request content (SHA-256)
  -no-body            omit decoded bodies from -jsonl output (headers + metadata only)
  -max-blob int       max HTTP blob size in MB (default 512)

Stats & Debugging:
  -stats              print statistics summary
  -parse-stats        print parse-time drop counters (blobs skipped, parse errors)
  -btree              walk schema BTree from root@0xFA (structural; finds metadata only — proxy-history rows live in heap)
  -dump-leaves        dump every leaf node reached from root@0xFA to stderr (for catalog discovery)
  -v                  verbose: log walker stats to stderr

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
  burpparse file.burp -jsonl -no-body -host example.com  # headers+metadata only, no bodies
```
