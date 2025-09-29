package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/idna"
)

type scopeKind int

const (
	scopeExact scopeKind = iota
	scopeLeadingWildcard
	scopePatternWildcard
)

type scopeEntry struct {
	raw           string
	kind          scopeKind
	base          string
	port          string
	patternLabels []string
}

func main() {
	listFile := flag.String("l", "", "file containing list of urls/domains (if empty read from stdin)")
	scopeFile := flag.String("s", "", "file containing scope domains (required)")
	reverse := flag.Bool("r", false, "print lines that do not match scope")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n  nscope [flags]\n\nFlags:\n  -l string \tfile containing list of urls/domains (if empty read from stdin)\n  -s string \tfile containing scope domains (required)\n  -r \t\tprint lines that do not match scope\n")
	}
	flag.Parse()

	if *scopeFile == "" {
		fmt.Fprintln(os.Stderr, "error: -s scope file is required")
		os.Exit(1)
	}

	scope, err := loadScope(*scopeFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading scope file: %v\n", err)
		os.Exit(1)
	}

	var in io.Reader
	if *listFile == "" {
		in = os.Stdin
	} else {
		f, err := os.Open(*listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening list file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}

	if err := processLines(in, os.Stdout, scope, *reverse); err != nil {
		fmt.Fprintf(os.Stderr, "error processing lines: %v\n", err)
		os.Exit(1)
	}
}

func loadScope(path string) ([]scopeEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []scopeEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(trimmed, "#"); idx != -1 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if trimmed == "" {
			continue
		}
		ent := parseScopeLine(trimmed)
		out = append(out, ent)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseScopeLine(line string) scopeEntry {
	orig := line
	line = strings.TrimSpace(line)
	line = strings.TrimSuffix(line, ".")
	if strings.HasPrefix(line, "*.") {
		without := strings.TrimPrefix(line, "*.")
		host, port := stripPort(without)
		host = strings.TrimSuffix(host, ".")
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = stripBrackets(host)
		}
		if ascii, err := idna.ToASCII(host); err == nil {
			host = ascii
		}
		host = strings.ToLower(host)
		return scopeEntry{raw: orig, kind: scopeLeadingWildcard, base: host, port: port}
	}
	if strings.Contains(line, "*") {
		labels := strings.Split(line, ".")
		for i := range labels {
			lbl := strings.TrimSpace(labels[i])
			if lbl == "" {
				labels[i] = lbl
				continue
			}
			if strings.Contains(lbl, ":") {
				h, p := stripPort(lbl)
				h = strings.TrimSuffix(h, ".")
				if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
					h = stripBrackets(h)
				}
				if ascii, err := idna.ToASCII(h); err == nil {
					h = ascii
				}
				labels[i] = h
				if p != "" {
					labels = append(labels, "__PORT__:"+p)
				}
				continue
			}
			if lbl != "*" {
				if ascii, err := idna.ToASCII(lbl); err == nil {
					lbl = ascii
				}
			}
			labels[i] = strings.ToLower(lbl)
		}
		var port string
		if len(labels) > 0 {
			last := labels[len(labels)-1]
			if strings.HasPrefix(last, "__PORT__:") {
				port = strings.TrimPrefix(last, "__PORT__:")
				labels = labels[:len(labels)-1]
			}
		}
		return scopeEntry{raw: orig, kind: scopePatternWildcard, patternLabels: labels, port: port}
	}

	host, port := stripPort(line)
	host = strings.TrimSuffix(host, ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = stripBrackets(host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return scopeEntry{raw: orig, kind: scopeExact, base: ip.String(), port: port}
	}
	if ascii, err := idna.ToASCII(host); err == nil {
		host = ascii
	}
	host = strings.ToLower(host)
	return scopeEntry{raw: orig, kind: scopeExact, base: host, port: port}
}

func processLines(r io.Reader, w io.Writer, scope []scopeEntry, reverse bool) error {
	scanner := bufio.NewScanner(r)
	const maxCapacity = 16 * 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxCapacity)
	for scanner.Scan() {
		line := scanner.Text()
		host, port, ok := extractHostFromLine(line)
		if !ok {
			continue
		}
		normHost, err := normalizeHost(host)
		if err != nil || normHost == "" {
			continue
		}
		matched := matchHost(normHost, port, scope)
		if matched && !reverse {
			fmt.Fprintln(w, line)
		}
		if !matched && reverse {
			fmt.Fprintln(w, line)
		}
	}
	return scanner.Err()
}

func extractHostFromLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", false
	}
	first := fields[0]
	if strings.Contains(first, "://") {
		u, err := url.Parse(first)
		if err != nil {
			return "", "", false
		}
		if u.Host == "" {
			return "", "", false
		}
		h, p := stripPort(u.Host)
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
			h = stripBrackets(h)
		}
		return h, p, true
	}
	if strings.HasPrefix(first, "[") && strings.Contains(first, "]") {
		h, p := stripPort(first)
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
			h = stripBrackets(h)
		}
		return h, p, true
	}
	if strings.Contains(first, "/") {
		u, err := url.Parse("http://" + first)
		if err == nil && u.Host != "" {
			h, p := stripPort(u.Host)
			if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
				h = stripBrackets(h)
			}
			return h, p, true
		}
	}
	h, p := stripPort(first)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = stripBrackets(h)
	}
	return h, p, true
}

func normalizeHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", nil
	}
	h = strings.TrimSuffix(h, ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), nil
	}
	if ascii, err := idna.ToASCII(h); err == nil {
		h = ascii
	}
	h = strings.ToLower(h)
	return h, nil
}

func stripPort(h string) (string, string) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", ""
	}
	if strings.HasPrefix(h, "[") {
		if idx := strings.LastIndex(h, "]"); idx != -1 {
			host := h[:idx+1]
			rest := h[idx+1:]
			if strings.HasPrefix(rest, ":") {
				return host, strings.TrimPrefix(rest, ":")
			}
			return host, ""
		}
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		return host, port
	}
	parts := strings.Split(h, ":")
	if len(parts) > 1 && net.ParseIP(parts[len(parts)-1]) == nil {
		p := parts[len(parts)-1]
		h = strings.Join(parts[:len(parts)-1], ":")
		return h, p
	}
	return h, ""
}

func stripBrackets(s string) string {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return s
}

func matchHost(host, port string, scope []scopeEntry) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, e := range scope {
			if e.kind != scopeExact {
				continue
			}
			if otherIP := net.ParseIP(e.base); otherIP != nil && otherIP.Equal(ip) {
				if e.port != "" {
					if e.port == port {
						return true
					}
					continue
				}
				return true
			}
			if strings.EqualFold(e.base, host) {
				if e.port != "" {
					if e.port == port {
						return true
					}
					continue
				}
				return true
			}
		}
		return false
	}
	for _, e := range scope {
		switch e.kind {
		case scopeExact:
			if equalHost(host, e.base) {
				if e.port != "" {
					if e.port == port {
						return true
					}
					continue
				}
				return true
			}
		case scopeLeadingWildcard:
			if matchLeadingWildcard(host, e.base) {
				if e.port != "" {
					if e.port == port {
						return true
					}
					continue
				}
				return true
			}
		case scopePatternWildcard:
			if matchPatternWildcard(host, e.patternLabels) {
				if e.port != "" {
					if e.port == port {
						return true
					}
					continue
				}
				return true
			}
		}
	}
	return false
}

func equalHost(a, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	return strings.EqualFold(a, b)
}

func matchLeadingWildcard(host, base string) bool {
	if equalHost(host, base) {
		return true
	}
	if strings.HasSuffix(host, "."+base) {
		return true
	}
	return false
}

func matchPatternWildcard(host string, pattern []string) bool {
	host = strings.TrimSuffix(host, ".")
	hl := strings.Split(host, ".")
	if len(hl) != len(pattern) {
		return false
	}
	for i := range pattern {
		p := strings.ToLower(strings.TrimSpace(pattern[i]))
		if p == "*" {
			if hl[i] == "" {
				return false
			}
			continue
		}
		if !strings.EqualFold(hl[i], p) {
			return false
		}
	}
	return true
}
