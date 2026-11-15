// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/dnsname"
)

// singleLabelExpansion describes a bare hostname query that was rewritten into
// its MagicDNS FQDN, together with what is needed afterwards to make the answer
// acceptable to the client that asked for the bare name.
type singleLabelExpansion struct {
	query  []byte              // the rewritten query to send to the resolver
	orig   dnsmessage.Question // what the client actually asked for
	target dnsmessage.Name     // the FQDN the query was rewritten to
}

// expandSingleLabelQuery rewrites a bare hostname query ("dash") into the
// MagicDNS FQDN ("dash.tailnet.ts.net").
//
// Expanding short names is the stub resolver's job: the client is supposed to
// append its search domains before sending. Linux gets them from the "search"
// line tailscaled writes to /etc/resolv.conf. Android has no such file, and the
// resolver configuration lives in netd, which only accepts per-network search
// lists from ConnectivityManager: the official app supplies them through
// VpnService.Builder.addSearchDomain, and a root daemon has no equivalent
// (`ndc resolver setnetdns` was removed in Android 10). netd therefore expands
// a bare name only with the suffixes it learned from DHCP and, once those all
// fail, asks for the bare name. This answers that last query.
func expandSingleLabelQuery(cfg *Config, query []byte) (singleLabelExpansion, bool) {
	var none singleLabelExpansion
	if cfg == nil {
		return none, false
	}

	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return none, false
	}
	q, err := p.Question()
	if err != nil || q.Class != dnsmessage.ClassINET {
		return none, false
	}
	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
		return none, false
	}
	bare, err := dnsname.ToFQDN(q.Name.String())
	if err != nil || bare.NumLabels() != 1 {
		return none, false
	}
	suffix := magicDNSSuffix(cfg)
	if suffix == "" {
		return none, false
	}
	full, err := dnsname.ToFQDN(bare.WithoutTrailingDot() + "." + suffix.WithoutTrailingDot())
	if err != nil {
		return none, false
	}
	target := dnsmessage.MustNewName(full.WithTrailingDot())

	b := dnsmessage.NewBuilder(nil, h)
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: target, Type: q.Type, Class: q.Class})
	expanded, err := b.Finish()
	if err != nil {
		return none, false
	}
	return singleLabelExpansion{query: expanded, orig: q, target: target}, true
}

// magicDNSSuffix returns the tailnet's MagicDNS suffix, or "" when the netmap
// does not expose one.
func magicDNSSuffix(cfg *Config) dnsname.FQDN {
	owners := hostParents(cfg)
	if fq := declaredSuffix(cfg, owners); fq != "" {
		return fq
	}
	// Netmaps that do not advertise the suffix as a local domain still carry
	// the host records, so fall back to the parent domain owning most of them.
	return busiestDomain(owners)
}

// hostParents counts host records per parent domain. MagicDNS host records are
// named <node>.<tailnet>, so their parent domains name the suffix without
// depending on any single record.
func hostParents(cfg *Config) map[dnsname.FQDN]int {
	owners := make(map[dnsname.FQDN]int, len(cfg.Hosts))
	for fq := range cfg.Hosts {
		if parent := fq.Parent(); parent.NumLabels() >= 2 {
			owners[parent]++
		}
	}
	return owners
}

// declaredSuffix picks the suffix the coordination server declared as a route
// with no resolvers, meaning "answer this suffix locally". Reverse-DNS zones
// are declared the same way, and so is an empty split-DNS route, so a candidate
// must also have host records underneath: that is what distinguishes the
// tailnet suffix from a route that only makes us authoritative for NXDOMAIN.
func declaredSuffix(cfg *Config, owners map[dnsname.FQDN]int) dnsname.FQDN {
	var candidates []dnsname.FQDN
	for suffix, resolvers := range cfg.Routes {
		switch {
		case len(resolvers) > 0,
			owners[suffix] == 0,
			suffix.NumLabels() < 2,
			dnsname.HasSuffix(suffix.WithoutTrailingDot(), ".arpa"):
			continue
		}
		candidates = append(candidates, suffix)
	}
	if len(candidates) == 0 {
		return ""
	}
	// Routes is a map, so break ties explicitly instead of letting the answer
	// jitter run to run. Extra records can put hosts under a split-DNS suffix
	// as well; the tailnet suffix carries the node records, normally the
	// larger set.
	slices.SortFunc(candidates, func(a, b dnsname.FQDN) int {
		if owners[a] != owners[b] {
			return owners[b] - owners[a]
		}
		return strings.Compare(string(a), string(b))
	})
	return candidates[0]
}

// busiestDomain returns the domain owning the most host records, preferring the
// lexicographically smaller one on a tie so the result is stable.
func busiestDomain(owners map[dnsname.FQDN]int) dnsname.FQDN {
	var best dnsname.FQDN
	bestN := 0
	for fq, n := range owners {
		if n > bestN || (n == bestN && string(fq) < string(best)) {
			best, bestN = fq, n
		}
	}
	return best
}

// rewriteSingleLabelResponse makes an expanded answer acceptable to a client
// that asked for the bare name: it keeps the original question and prepends a
// CNAME pointing at the MagicDNS name, followed by the original answer records.
// The stub resolver follows the CNAME within the same response, so no second
// round trip is needed.
func rewriteSingleLabelResponse(resp []byte, e singleLabelExpansion) ([]byte, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return nil, false
	}
	if _, err := p.Question(); err != nil {
		return nil, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false
	}
	answers, err := p.AllAnswers()
	if err != nil || len(answers) == 0 {
		return nil, false
	}

	b := dnsmessage.NewBuilder(nil, h)
	b.EnableCompression()
	b.StartQuestions()
	b.Question(e.orig)
	b.StartAnswers()
	if err := b.CNAMEResource(dnsmessage.ResourceHeader{
		Name:  e.orig.Name,
		Type:  dnsmessage.TypeCNAME,
		Class: dnsmessage.ClassINET,
		TTL:   answers[0].Header.TTL,
	}, dnsmessage.CNAMEResource{CNAME: e.target}); err != nil {
		return nil, false
	}
	for _, rr := range answers {
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(rr.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(rr.Header, *body)
		case *dnsmessage.CNAMEResource:
			err = b.CNAMEResource(rr.Header, *body)
		case *dnsmessage.UnknownResource:
			err = b.UnknownResource(rr.Header, *body)
		default:
			return nil, false
		}
		if err != nil {
			return nil, false
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, false
	}
	return out, true
}
