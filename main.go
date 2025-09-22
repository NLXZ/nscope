package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ScopeEntry struct {
	Raw      string
	Wildcard bool
	Base     string
}

func main() {
	scopePath := flag.String("s", "", "Path to scope file (required)")
	listPath := flag.String("l", "", "Path to input list (urls/domains). If empty, read stdin")
	outPath := flag.String("o", "", "Write output to file (optional)")
	invert := flag.Bool("r", false, "Reverse: show lines that do NOT match scope")
	help := flag.Bool("h", false, "Show help")
	flag.Parse()

	if *help || *scopePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(0)

	scopeEntries, err := loadScope(*scopePath)
	if err != nil {
		log.Fatalf("failed to load scope: %v", err)
	}
	if len(scopeEntries) == 0 {
		log.Fatalf("scope file %q contains no entries", *scopePath)
	}

	var in *os.File
	if *listPath != "" {
		in, err = os.Open(*listPath)
		if err != nil {
			log.Fatalf("failed to open input file %q: %v", *listPath, err)
		}
		defer in.Close()
	} else {
		in = os.Stdin
	}

	var out *os.File
	if *outPath != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("failed to create directories for output file: %v", err)
		}
		out, err = os.Create(*outPath)
		if err != nil {
			log.Fatalf("failed to create output file %q: %v", *outPath, err)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	s := bufio.NewScanner(in)
	matchedLines := []string{}
	unmatchedLines := []string{}

	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		domain := extractHostname(line)
		if domain == "" {
			unmatchedLines = append(unmatchedLines, line)
			continue
		}

		if matchesScope(domain, scopeEntries) {
			matchedLines = append(matchedLines, line)
		} else {
			unmatchedLines = append(unmatchedLines, line)
		}
	}
	if err := s.Err(); err != nil {
		log.Fatalf("error reading input: %v", err)
	}

	var toPrint []string
	if *invert {
		toPrint = unmatchedLines
	} else {
		toPrint = matchedLines
	}

	sort.Strings(toPrint)

	w := bufio.NewWriter(out)
	for _, l := range toPrint {
		fmt.Fprintln(w, l)
	}
	w.Flush()
}

func loadScope(path string) ([]ScopeEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	entries := []ScopeEntry{}
	lineNo := 0
	for s.Scan() {
		lineNo++
		raw := strings.TrimSpace(s.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		raw = strings.ToLower(strings.TrimSuffix(raw, "."))

		if strings.HasPrefix(raw, "*.") {
			base := strings.TrimPrefix(raw, "*.")
			base = strings.TrimSuffix(base, ".")
			if base == "" {
				log.Printf("warning: invalid scope entry at line %d: %q", lineNo, raw)
				continue
			}
			entries = append(entries, ScopeEntry{Raw: raw, Wildcard: true, Base: base})
		} else {
			entries = append(entries, ScopeEntry{Raw: raw, Wildcard: false, Base: raw})
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func extractHostname(input string) string {
	input = strings.TrimSpace(input)
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err == nil && u.Host != "" {
			host := stripPort(u.Host)
			return strings.ToLower(strings.TrimSuffix(host, "."))
		}
	}
	h := stripPort(input)
	if h == "localhost" || strings.Contains(h, ".") {
		return strings.ToLower(strings.TrimSuffix(h, "."))
	}
	if net.ParseIP(h) != nil {
		return h
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]:"); i != -1 {
			return host[1:i]
		}
		return strings.Trim(host, "[]")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func matchesScope(domain string, entries []ScopeEntry) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, e := range entries {
		if e.Wildcard {
			if domain == e.Base {
				return true
			}
			if strings.HasSuffix(domain, "."+e.Base) {
				return true
			}
		} else {
			if domain == e.Base {
				return true
			}
		}
	}
	return false
}
