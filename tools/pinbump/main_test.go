// SPDX-License-Identifier: ISC

package main

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// TestClassifyKeepsUpstreamTests pins that a changed upstream `_test.go`
// file reaches the review list under the crate that ports its package. The
// file list is the test-file half of the 29f17894..b9634e01 delta, where
// staketx_test.go gained the zero-commitment revocation vector and pinbump
// used to drop all four files silently.
func TestClassifyKeepsUpstreamTests(t *testing.T) {
	m := mapping{
		"addrmgr":          {"dcroxide-addrmgr"},
		"blockchain/stake": {"dcroxide-stake"},
		"peer":             {"dcroxide-peer"},
	}
	files := []string{
		"addrmgr/network.go",
		"addrmgr/network_test.go",
		"blockchain/stake/internal/tickettreap/immutable_test.go",
		"blockchain/stake/staketx.go",
		"blockchain/stake/staketx_test.go",
		"docs/release-notes/release-notes-2.1.6.md",
		"peer/peer_test.go",
	}
	r := classify(m, files)

	wantCode := map[string][]string{
		"dcroxide-addrmgr": {"addrmgr/network.go"},
		"dcroxide-stake":   {"blockchain/stake/staketx.go"},
	}
	if !reflect.DeepEqual(r.code, wantCode) {
		t.Errorf("code files: got %v, want %v", r.code, wantCode)
	}
	wantTests := map[string][]string{
		"dcroxide-addrmgr": {"addrmgr/network_test.go"},
		"dcroxide-stake": {
			"blockchain/stake/internal/tickettreap/immutable_test.go",
			"blockchain/stake/staketx_test.go",
		},
		"dcroxide-peer": {"peer/peer_test.go"},
	}
	if !reflect.DeepEqual(r.tests, wantTests) {
		t.Errorf("test files: got %v, want %v", r.tests, wantTests)
	}
	wantUnmapped := map[string][]string{
		"docs/release-notes": {"docs/release-notes/release-notes-2.1.6.md"},
	}
	if !reflect.DeepEqual(r.unmapped, wantUnmapped) {
		t.Errorf("unmapped: got %v, want %v", r.unmapped, wantUnmapped)
	}
}

// TestChangedFilesListsBothSidesOfAMove pins that a file moved out of a
// ported package is reported at its old path as well as its new one. With
// git's default rename detection only the destination is printed.
//
// The two revisions are bare trees built with plumbing, so the test makes
// no commit and needs no identity or signing configuration.
func TestChangedFilesListsBothSidesOfAMove(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	git := func(stdin string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("", "init", "-q")
	blob := git("package stake\n\nfunc CheckSSRtx() {}\n\nfunc IsSSRtx() bool { return false }\n",
		"hash-object", "-w", "--stdin")
	pkg := git("100644 blob "+blob+"\tstaketx.go\n", "mktree")
	from := git("040000 tree "+pkg+"\tstake\n", "mktree")
	to := git("040000 tree "+pkg+"\tmoved\n", "mktree")

	files, err := changedFiles(dir, from, to)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"moved/staketx.go", "stake/staketx.go"}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("got %v, want %v", files, want)
	}
}
