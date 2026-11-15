// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

func mustFQDN(t *testing.T, s string) dnsname.FQDN {
	t.Helper()
	fq, err := dnsname.ToFQDN(s)
	if err != nil {
		t.Fatalf("ToFQDN(%q): %v", s, err)
	}
	return fq
}

func buildQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  typ,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("question: %v", err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return out
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Hosts: map[dnsname.FQDN][]netip.Addr{
			mustFQDN(t, "dash.ferret-bellatrix.ts.net"):  {netip.MustParseAddr("100.116.88.115")},
			mustFQDN(t, "s010w.ferret-bellatrix.ts.net"): {netip.MustParseAddr("100.121.211.104")},
		},
		// What dnsConfig() builds for a tailnet with MagicDNS proxied: the
		// suffix plus the reverse-DNS zones, all with no resolvers.
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			mustFQDN(t, "ferret-bellatrix.ts.net"): nil,
			mustFQDN(t, "100.100.in-addr.arpa"):    nil,
		},
	}
}

func TestExpandSingleLabel(t *testing.T) {
	e, ok := expandSingleLabelQuery(testConfig(t), buildQuery(t, "dash.", dnsmessage.TypeA))
	if !ok {
		t.Fatal("single-label query was not expanded")
	}
	if got, want := e.orig.Name.String(), "dash."; got != want {
		t.Errorf("original question = %q, want %q", got, want)
	}
	if got, want := e.target.String(), "dash.ferret-bellatrix.ts.net."; got != want {
		t.Errorf("target = %q, want %q", got, want)
	}

	var p dnsmessage.Parser
	if _, err := p.Start(e.query); err != nil {
		t.Fatalf("parse expanded: %v", err)
	}
	eq, err := p.Question()
	if err != nil {
		t.Fatalf("expanded question: %v", err)
	}
	if got, want := eq.Name.String(), "dash.ferret-bellatrix.ts.net."; got != want {
		t.Errorf("expanded query name = %q, want %q", got, want)
	}
}

func TestExpandSingleLabelSkipsQualifiedNames(t *testing.T) {
	for _, name := range []string{"dash.ferret-bellatrix.ts.net.", "host.lan."} {
		if _, ok := expandSingleLabelQuery(testConfig(t), buildQuery(t, name, dnsmessage.TypeA)); ok {
			t.Errorf("%q should not be expanded", name)
		}
	}
}

func TestExpandSingleLabelSkipsOtherTypes(t *testing.T) {
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeMX, dnsmessage.TypeSRV} {
		if _, ok := expandSingleLabelQuery(testConfig(t), buildQuery(t, "dash.", typ)); ok {
			t.Errorf("type %v should not be expanded", typ)
		}
	}
}

func TestExpandSingleLabelNeedsMagicDNSSuffix(t *testing.T) {
	// Search domains are user-configured suffixes for other resolvers. Using
	// one of them here would expand short names for split DNS, which is the
	// job of the stub resolver, so the netmap must name the tailnet suffix.
	cfg := &Config{SearchDomains: []dnsname.FQDN{mustFQDN(t, "corp.example.com")}}
	if _, ok := expandSingleLabelQuery(cfg, buildQuery(t, "dash.", dnsmessage.TypeA)); ok {
		t.Error("search domains alone should not trigger expansion")
	}

	if _, ok := expandSingleLabelQuery(&Config{}, buildQuery(t, "dash.", dnsmessage.TypeA)); ok {
		t.Error("empty config should not expand anything")
	}
}

func TestMagicDNSSuffix(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "declared route wins",
			cfg: &Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					mustFQDN(t, "dash.ferret-bellatrix.ts.net"): {netip.MustParseAddr("100.116.88.115")},
				},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					mustFQDN(t, "ferret-bellatrix.ts.net"): nil,
					mustFQDN(t, "100.100.in-addr.arpa"):    nil,
				},
			},
			want: "ferret-bellatrix.ts.net.",
		},
		{
			name: "empty split DNS route is not the suffix",
			cfg: &Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					mustFQDN(t, "dash.ferret-bellatrix.ts.net"): {netip.MustParseAddr("100.116.88.115")},
				},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					// Issue 2706: an explicit but empty route makes us
					// authoritative for NXDOMAIN, and has no hosts beneath it.
					mustFQDN(t, "corp.example.com"):        nil,
					mustFQDN(t, "ferret-bellatrix.ts.net"): nil,
				},
			},
			want: "ferret-bellatrix.ts.net.",
		},
		{
			name: "route with resolvers is split DNS",
			cfg: &Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					mustFQDN(t, "dash.ferret-bellatrix.ts.net"): {netip.MustParseAddr("100.116.88.115")},
				},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					mustFQDN(t, "corp.example.com"): {{Addr: "10.0.0.1"}},
				},
			},
			want: "ferret-bellatrix.ts.net.",
		},
		{
			name: "falls back to host records",
			cfg: &Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					mustFQDN(t, "dash.ferret-bellatrix.ts.net"):  {netip.MustParseAddr("100.116.88.115")},
					mustFQDN(t, "s010w.ferret-bellatrix.ts.net"): {netip.MustParseAddr("100.121.211.104")},
					mustFQDN(t, "nas.lan"):                       {netip.MustParseAddr("192.168.1.5")},
				},
			},
			want: "ferret-bellatrix.ts.net.",
		},
		{
			name: "nothing to go on",
			cfg:  &Config{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(magicDNSSuffix(tt.cfg)); got != tt.want {
				t.Errorf("magicDNSSuffix = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMagicDNSSuffixIsStable(t *testing.T) {
	// Extra records can hang hosts under an empty split-DNS route, which leaves
	// two suffixes looking like candidates. Route order is map iteration order,
	// so the answer must be broken deterministically rather than jittering.
	cfg := &Config{
		Hosts: map[dnsname.FQDN][]netip.Addr{
			mustFQDN(t, "dash.ferret-bellatrix.ts.net"):  {netip.MustParseAddr("100.116.88.115")},
			mustFQDN(t, "s010w.ferret-bellatrix.ts.net"): {netip.MustParseAddr("100.121.211.104")},
			mustFQDN(t, "wiki.corp.example.com"):         {netip.MustParseAddr("10.0.0.9")},
		},
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			mustFQDN(t, "ferret-bellatrix.ts.net"): nil,
			mustFQDN(t, "corp.example.com"):        nil,
		},
	}
	for i := 0; i < 100; i++ {
		if got, want := string(magicDNSSuffix(cfg)), "ferret-bellatrix.ts.net."; got != want {
			t.Fatalf("iteration %d: magicDNSSuffix = %q, want %q", i, got, want)
		}
	}
}

func TestRewriteSingleLabelResponse(t *testing.T) {
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("dash."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	target := dnsmessage.MustNewName("dash.ferret-bellatrix.ts.net.")

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: true, RCode: dnsmessage.RCodeSuccess})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{Name: target, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("question: %v", err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatalf("start answers: %v", err)
	}
	if err := b.AResource(dnsmessage.ResourceHeader{
		Name:  target,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   600,
	}, dnsmessage.AResource{A: [4]byte{100, 116, 88, 115}}); err != nil {
		t.Fatalf("a resource: %v", err)
	}
	resp, err := b.Finish()
	if err != nil {
		t.Fatalf("build response: %v", err)
	}

	out, ok := rewriteSingleLabelResponse(resp, singleLabelExpansion{orig: q, target: target})
	if !ok {
		t.Fatal("response was not rewritten")
	}
	var p dnsmessage.Parser
	if _, err := p.Start(out); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	oq, err := p.Question()
	if err != nil {
		t.Fatalf("question: %v", err)
	}
	if got, want := oq.Name.String(), "dash."; got != want {
		t.Errorf("question = %q, want %q", got, want)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatalf("answers: %v", err)
	}
	if len(answers) != 2 {
		t.Fatalf("got %d answers, want 2 (CNAME + A)", len(answers))
	}
	if answers[0].Header.Type != dnsmessage.TypeCNAME {
		t.Errorf("first answer is %v, want CNAME", answers[0].Header.Type)
	}
	cname, ok := answers[0].Body.(*dnsmessage.CNAMEResource)
	if !ok {
		t.Fatalf("first body is %T, want *CNAMEResource", answers[0].Body)
	}
	if got, want := cname.CNAME.String(), target.String(); got != want {
		t.Errorf("CNAME = %q, want %q", got, want)
	}
	if answers[1].Header.Type != dnsmessage.TypeA {
		t.Errorf("second answer is %v, want A", answers[1].Header.Type)
	}
}

func TestRewriteSingleLabelResponseRejectsFailure(t *testing.T) {
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("dash."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	target := dnsmessage.MustNewName("dash.ferret-bellatrix.ts.net.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true, RCode: dnsmessage.RCodeNameError})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: target, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	resp, err := b.Finish()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := rewriteSingleLabelResponse(resp, singleLabelExpansion{orig: q, target: target}); ok {
		t.Error("NXDOMAIN response should not be rewritten")
	}
}
