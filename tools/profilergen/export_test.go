// SPDX-License-Identifier: ISC

//go:build dcroxide_export

// The generator of crates/dcroxide-node/tests/data/profiler_vectors.txt,
// which crates/dcroxide-node/tests/profiler_vectors.rs replays.  It runs as a
// test inside dcrd's package main, beside profiler.go, so every verdict it
// writes is what dcrd's own profileServer.Start returned; run.sh in this
// directory arranges that without touching the dcrd checkout.
//
// Each row is one Start call: `start|<allow>|<addr>|<verdict>`, the address
// in hex, allow 1 when the flag to allow non loopback addresses is set, and
// the verdict either `err|<hex error text>` or `accept`.  `accept` means the
// address passed every check Start makes before it binds a listener: Start
// returned nil with listeners, or failed only in net.Listen, which it reports
// as "unable to listen on ...".  Whether a bind succeeds depends on the host
// running the generator, so both are written the same way and a run at an
// unchanged parity pin writes the same file byte for byte.
//
// Start binds and serves for an accepted address, so the case list is
// guarded.  No host may name an interface, which would make the rows depend
// on the host's interfaces.  Without the flag Start refuses every address
// that is not loopback before it binds; with it, no host may be empty,
// unspecified, or an address assigned to an interface other than loopback.
// Every bind a run makes is therefore to a loopback address, or to a
// documentation address no interface has, which fails.  One profileServer
// serves every row, as dcrd's http.Handle("/") redirect may be registered
// only once a process, and it is stopped after each accepted row.
package main

import (
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// exportProfilerCases are the Start calls the generator makes, in order.
var exportProfilerCases = []struct {
	addr  string
	allow bool
}{
	// net.SplitHostPort refusals, with and without the address prefix.
	{"", false},
	{"bogus", false},
	{"127.0.0.1", false},
	{" 6060", false},
	{"::1", false},
	{"[::1]", false},
	{"[::1", false},
	{"[::1]x:6060", false},
	{"[::1]:6060:7070", false},
	{"1.2.3.4:5:6060", false},
	{"a[b:6060", false},
	{"a]b:6060", false},

	// validateProfileAddr's port range, after portToLocalHostAddr.
	{"127.0.0.1:80", false},
	{"127.0.0.1:1023", false},
	{"127.0.0.1:65536", false},
	{"127.0.0.1:", false},
	{"127.0.0.1:http", false},
	{"127.0.0.1:-1", false},
	{"127.0.0.1:99999999999999999999", false},
	{"0", false},
	{"80", false},
	{"-1", false},
	{"127.0.0.1:80", true},

	// The loopback check over netip.ParseAddrPort.
	{"192.0.2.1:20104", false},
	{"localhost:20104", false},
	{":20104", false},
	{"0.0.0.0:20104", false},
	{"[::]:20104", false},
	{"[fe80::1]:20104", false},
	{"[::ffff:192.0.2.1]:20104", false},
	{"0127.0.0.1:20104", false},
	{"127.1:20104", false},
	{"127.0.0.1%lo:20104", false},
	{"[::1%]:20104", false},
	{"+20104", false},
	{"127.0.0.1:+20104", false},
	{"127.0.0.1\x00:20104", false},
	{"ä:20104", false},
	{" :20104", false},
	{"\"q\":20104", false},

	// Addresses that pass every check without the flag.
	{"127.0.0.1:20103", false},
	{"20103", false},
	{"1024", false},
	{"65535", false},
	{"127.0.0.1:020103", false},
	{"127.0.0.2:20103", false},
	{"127.255.255.254:20103", false},
	{"[127.0.0.1]:20103", false},
	{"[::1]:20103", false},
	{"[0:0:0:0:0:0:0:1]:20103", false},
	{"[::ffff:127.0.0.1]:20103", false},
	{"[::1%lo]:20103", false},

	// With the flag: parseListeners' refusals, and addresses it accepts.
	{"localhost:20104", true},
	{"example.invalid:20104", true},
	{"0:20104", true},
	{"127.0.0.1%lo:20104", true},
	{"0127.0.0.1:20104", true},
	{"[::1%]:20104", true},
	{"1.2.3.4%:20104", true},
	{"192.0.2.1:20104", true},
	{"[2001:db8::1]:20104", true},
	{"[::ffff:192.0.2.1]:20104", true},
	{"127.0.0.1:+20104", true},
	{"127.0.0.1:20103", true},
	{"20103", true},
}

// exportGuardProfilerCase fails the test for an address whose normalization
// depends on the host's interfaces, or that Start could bind beyond loopback
// when the flag allows it.
func exportGuardProfilerCase(t *testing.T, addr string, allow bool, local map[netip.Addr]bool) {
	t.Helper()
	host, _, err := net.SplitHostPort(portToLocalHostAddr(addr))
	if err != nil {
		return
	}
	if _, err := net.InterfaceByName(host); err == nil {
		t.Fatalf("case %q names an interface of this host", addr)
	}
	if !allow {
		return
	}
	if host == "" {
		t.Fatalf("case %q listens on every interface", addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	ip = ip.Unmap().WithZone("")
	if ip.IsUnspecified() {
		t.Fatalf("case %q listens on every interface", addr)
	}
	if local[ip] && !ip.IsLoopback() {
		t.Fatalf("case %q is an address of this host", addr)
	}
}

func TestExportProfilerVectors(t *testing.T) {
	out := os.Getenv("DCROXIDE_PROFILER_VECTORS")
	if out == "" {
		t.Skip("DCROXIDE_PROFILER_VECTORS is not set")
	}

	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	local := make(map[netip.Addr]bool)
	for _, a := range ifaceAddrs {
		if prefix, err := netip.ParsePrefix(a.String()); err == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}

	var profiler profileServer
	defer profiler.Stop()
	var rows strings.Builder
	for _, c := range exportProfilerCases {
		exportGuardProfilerCase(t, c.addr, c.allow, local)
		allow := "0"
		if c.allow {
			allow = "1"
		}
		verdict := "accept"
		err := profiler.Start(c.addr, c.allow)
		switch {
		case err == nil:
			if len(profiler.Listeners()) == 0 {
				t.Fatalf("case %q started without listeners", c.addr)
			}
			if err := profiler.Stop(); err != nil {
				t.Fatal(err)
			}
		case strings.HasPrefix(err.Error(), "unable to listen on "):
		default:
			verdict = "err|" + hex.EncodeToString([]byte(err.Error()))
		}
		rows.WriteString("start|" + allow + "|" +
			hex.EncodeToString([]byte(c.addr)) + "|" + verdict + "\n")
	}
	if err := os.WriteFile(out, []byte(rows.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
