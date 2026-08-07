// SPDX-License-Identifier: ISC

// Command pinbump reports which dcroxide crates a dcrd parity-pin bump
// touches.
//
// Moving the parity target means reading the upstream delta and deciding
// which parts of this port need re-reading. Done by hand that is a whole-diff
// review whose completeness rests on one person's memory of what maps where.
// PARITY.md already carries the mapping — one row per dcrd package, naming
// the dcroxide crates that port it — so the mechanical part can be
// mechanical: list the upstream files that changed, resolve each to its
// package, and print the crates on the other side.
//
// This is deliberately package-granular, not line-granular. Cuprate records
// upstream commit, file and line range at each ported RPC type definition,
// which is finer, but line ranges rot with every upstream commit and cover
// only code touched since the convention started, so a partially-populated
// index cannot replace the manual pass. Package granularity is derivable
// from data that already exists and is complete on day one.
//
// The output is a review list, not a verdict. A crate appearing here means
// the delta touched a package it ports; whether anything must change is the
// reviewer's call. Unmapped packages are reported separately and matter
// most: they are either genuinely not ported or a gap in PARITY.md.
//
// Usage:
//
//	pinbump -dcrd <path> -from <commit> -to <commit> [-parity <path>]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
)

// backticked pulls every `quoted` item out of a PARITY.md table cell.
var backticked = regexp.MustCompile("`([^`]+)`")

// tableRow matches a mapping row: it starts with a backticked package.
var tableRow = regexp.MustCompile("^\\| *`")

// mapping is package path -> the crates that port it.
type mapping map[string][]string

// parseParity reads PARITY.md's package-to-crate table.
//
// A row may name several packages and several crates, and they do NOT
// correspond positionally: `internal/rpcserver`, `rpc/jsonrpc/types` and
// `dcrjson` map onto `dcroxide-rpc`, `dcroxide-dcrjson` and
// `dcroxide-rpctypes` in a different order. Every package in a row is
// therefore associated with every crate in that row. That errs toward
// over-reporting, which is the safe direction for a review list.
func parseParity(path string) (mapping, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := mapping{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !tableRow.MatchString(line) {
			continue
		}
		// Split on unescaped pipes only: the Notes column contains \| .
		cells := splitCells(line)
		if len(cells) < 2 {
			continue
		}
		pkgs := names(cells[0])
		crates := names(cells[1])
		if len(pkgs) == 0 || len(crates) == 0 {
			continue
		}
		for _, p := range pkgs {
			m[p] = append(m[p], crates...)
			if alias, ok := pkgAliases[p]; ok {
				m[alias] = append(m[alias], crates...)
			}
		}
	}
	return m, sc.Err()
}

// splitCells splits a markdown row on pipes that are not backslash-escaped.
func splitCells(line string) []string {
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) && line[i+1] == '|' {
			cur.WriteByte('|')
			i++
			continue
		}
		if c == '|' {
			cells = append(cells, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	cells = append(cells, cur.String())
	// A leading "| " produces an empty first cell; drop it.
	if len(cells) > 0 && strings.TrimSpace(cells[0]) == "" {
		cells = cells[1:]
	}
	return cells
}

func names(cell string) []string {
	var out []string
	for _, m := range backticked.FindAllStringSubmatch(cell, -1) {
		n := strings.TrimSpace(m[1])
		// Cells sometimes qualify a crate, e.g. "(`stdaddr`/`stdscript`
		// modules)". Those are module names, not crates or packages;
		// they carry no slash and no dcroxide- prefix, and are filtered
		// by the caller's use of the first two cells only when they look
		// like paths or crate names.
		if n == "" {
			continue
		}
		// PARITY.md abbreviates runs of sibling crates: the addrmgr row
		// reads "`dcroxide-addrmgr` / `-connmgr` / `-peer`". Expand the
		// shorthand so the output names real crates.
		if strings.HasPrefix(n, "-") {
			n = "dcroxide" + n
		}
		out = append(out, n)
	}
	return out
}

// pkgAliases maps the label PARITY.md uses for a dcrd package to its actual
// path in the upstream tree, where the two differ. dcrd moved several
// packages under internal/ without PARITY.md's labels following.
var pkgAliases = map[string]string{
	"connmgr":   "internal/connmgr",
	"mining":    "internal/mining",
	"netsync":   "internal/netsync",
	"fees":      "internal/fees",
	"mempool":   "internal/mempool",
	"rpcserver": "internal/rpcserver",
}

// changedFiles lists the files touched between two commits in a repo.
func changedFiles(repo, from, to string) ([]string, error) {
	cmd := exec.Command("git", "-C", repo, "diff", "--name-only", from+".."+to)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("git diff failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var files []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			files = append(files, l)
		}
	}
	return files, nil
}

// resolve finds the mapping entry for a file by taking its directory and
// walking up until a package matches. dcrd package paths in PARITY.md are
// directories ("internal/mempool"), and a file may sit in a subdirectory of
// a ported package.
func resolve(m mapping, file string) (string, []string, bool) {
	dir := path.Dir(file)
	for dir != "." && dir != "/" && dir != "" {
		if crates, ok := m[dir]; ok {
			return dir, crates, true
		}
		dir = path.Dir(dir)
	}
	// Top-level files (server.go, config.go) belong to dcrd's main package,
	// which PARITY.md tracks under the node crate rather than by directory.
	if crates, ok := m["."]; ok && path.Dir(file) == "." {
		return ".", crates, true
	}
	return "", nil, false
}

func main() {
	repo := flag.String("dcrd", "", "path to a dcrd checkout (required)")
	from := flag.String("from", "", "the current parity pin (required)")
	to := flag.String("to", "", "the candidate parity pin (required)")
	parity := flag.String("parity", "PARITY.md", "path to PARITY.md")
	flag.Parse()

	if *repo == "" || *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: pinbump -dcrd <path> -from <commit> -to <commit> [-parity <path>]")
		os.Exit(2)
	}

	m, err := parseParity(*parity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", *parity, err)
		os.Exit(1)
	}
	if len(m) == 0 {
		fmt.Fprintf(os.Stderr, "no package rows found in %s -- has the table format changed?\n", *parity)
		os.Exit(1)
	}

	files, err := changedFiles(*repo, *from, *to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	crateFiles := map[string][]string{}
	unmapped := map[string][]string{}
	for _, f := range files {
		// Upstream test files do not constrain this port; its own
		// differential vectors do.
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		pkg, crates, ok := resolve(m, f)
		if !ok {
			unmapped[path.Dir(f)] = append(unmapped[path.Dir(f)], f)
			continue
		}
		_ = pkg
		for _, c := range crates {
			crateFiles[c] = append(crateFiles[c], f)
		}
	}

	fmt.Printf("dcrd %s..%s: %d files changed\n\n", *from, *to, len(files))

	if len(crateFiles) > 0 {
		fmt.Println("Crates to re-review:")
		for _, c := range sortedKeys(crateFiles) {
			fs := dedupe(crateFiles[c])
			fmt.Printf("  %-24s %d file(s)\n", c, len(fs))
			for _, f := range fs {
				fmt.Printf("      %s\n", f)
			}
		}
		fmt.Println()
	} else {
		fmt.Println("No changed file resolves to a ported package.")
		fmt.Println()
	}

	if len(unmapped) > 0 {
		fmt.Println("Unmapped upstream paths -- either not ported, or missing from PARITY.md:")
		for _, d := range sortedKeys(unmapped) {
			fmt.Printf("  %-40s %d file(s)\n", d, len(unmapped[d]))
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
