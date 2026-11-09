// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package dns

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/syspolicy/policyclient"
)

func init() {
	androidExpandSingleLabel = func(m *Manager, query []byte) (singleLabelExpansion, bool) {
		m.mu.Lock()
		cfg := m.config
		m.mu.Unlock()
		return expandSingleLabelQuery(cfg, query)
	}
	androidRewriteSingleLabel = rewriteSingleLabelResponse
	androidSetUpstreams = publishAndroidUpstreams
}

// androidUpstreams holds the resolver addresses the forwarder may dial. The
// redirect chain excludes them, so a forwarded query cannot be redirected back
// into the resolver that issued it.
var androidUpstreams atomic.Pointer[[]netip.Addr]

func androidUpstreamSnapshot() []netip.Addr {
	if p := androidUpstreams.Load(); p != nil {
		return *p
	}
	return nil
}

// publishAndroidUpstreams records the resolvers the daemon may dial.
//
// Only IPv4 matters here: the IPv6 half of the hijack never installs on kernels
// without an ip6tables nat table, so there is nothing to exclude on that side.
func publishAndroidUpstreams(cfg Config) {
	var addrs []netip.Addr
	add := func(rs []*dnstype.Resolver) {
		for _, a := range toIPsOnly(rs) {
			if a.Is4() && !slices.Contains(addrs, a) {
				addrs = append(addrs, a)
			}
		}
	}
	add(cfg.DefaultResolvers)
	for _, rs := range cfg.Routes {
		add(rs)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	androidUpstreams.Store(&addrs)
}

type androidManager struct {
	logf logger.Logf

	mu       sync.Mutex
	hijacked bool
}

func NewOSConfigurator(logf logger.Logf, _ *health.Tracker, _ *eventbus.Bus, _ policyclient.Client, _ *controlknobs.Knobs, _ string) (OSConfigurator, error) {
	return &androidManager{logf: logf}, nil
}

func (m *androidManager) SetDNS(cfg OSConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Only hijack when there is somewhere to forward non-Tailscale queries:
	// redirecting every lookup into a resolver with no upstream breaks DNS for
	// the whole device, which is worse than leaving it alone.
	if len(cfg.Nameservers) == 0 {
		m.disableLocked()
		return nil
	}
	if err := installDNSRules(false); err != nil {
		m.logf("dns: failed to set up rules: %v", err)
		return err
	}
	// Not every Android kernel has an ip6tables nat table, so the IPv6 half
	// failing is a degraded mode rather than an error.
	if err := installDNSRules(true); err != nil {
		m.logf("dns: IPv6 rules unavailable (non-fatal): %v", err)
	}
	if !m.hijacked {
		m.hijacked = true
		m.logf("dns: hijack enabled")
	}
	return nil
}

func (m *androidManager) SupportsSplitDNS() bool {
	return false
}

// GetBaseConfig returns the resolvers Android's netd is currently using.
//
// Android has no /etc/resolv.conf: the resolver configuration lives inside netd
// and is only exposed through the framework. Reporting nothing tells tailscaled
// the OS has no resolvers at all, which means SERVFAIL on every query for any
// tailnet that does not push a global nameserver, and it also keeps the hijack
// rules from ever being installed.
func (m *androidManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{Nameservers: androidBaseNameservers()}, nil
}

func (m *androidManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.hijacked {
		m.disableLocked()
	}
	return nil
}

// disableLocked removes the redirect rules.
//
// It runs even when m.hijacked is false: that field only reflects this process,
// while a rule left behind by an earlier one would keep intercepting DNS with
// nothing tracking it.
func (m *androidManager) disableLocked() {
	if err := removeDNSRules(false); err != nil {
		m.logf("dns: failed to remove rules: %v", err)
	}
	if err := removeDNSRules(true); err != nil {
		m.logf("dns: IPv6 rules removal failed (non-fatal): %v", err)
	}
	if m.hijacked {
		m.hijacked = false
		m.logf("dns: hijack disabled")
	}
}

// rule is a single netfilter rule to install or remove.
type rule struct {
	table string
	chain string
	args  []string
}

// androidDNSChain is the nat chain that performs the redirect.
//
// The upstream resolvers are excluded with RETURN rules inside the chain rather
// than with a list of negated destinations on the jump rule: iptables rejects a
// rule naming more than one destination ("multiple -d flags not allowed"), and
// the upstream set changes with the tailnet's DNS configuration.
const androidDNSChain = "TS_DNS_HIJACK"

func androidDNSChainName(ipv6 bool) string {
	if ipv6 {
		return androidDNSChain + "6"
	}
	return androidDNSChain
}

// dnsJumpRules returns the rules that send DNS traffic into the redirect chain.
//
// Destinations inside the tailnet ranges never enter the chain: tailscaled
// resolves split-DNS and exit-node queries by dialling the resolver itself, and
// those packets leave through the tailnet interface. Matching on the address
// range instead of the interface name also covers setups where the tun is
// called tailscale0 rather than tun0; the previous name-based exclusion
// ("! -o tun+") never matched, so a split-DNS route pointing at a tailnet
// address was redirected straight back into the local resolver until its
// request queue overflowed and all DNS on the device failed.
//
// TCP is redirected as well as UDP: Android falls back to TCP for truncated
// answers and for some resolvers, and those lookups bypassed the hijack.
func dnsJumpRules(ipv6 bool, chain string) []rule {
	tailnet := tsaddr.CGNATRange().String()
	if ipv6 {
		tailnet = tsaddr.TailscaleULARange().String()
	}
	spec := func(proto string) []string {
		return []string{"!", "-d", tailnet, "-p", proto, "--dport", "53", "-j", chain}
	}
	return []rule{
		// DNS originating on this device.
		{"nat", "OUTPUT", spec("udp")},
		{"nat", "OUTPUT", spec("tcp")},
		// DNS from hotspot clients.
		{"nat", "PREROUTING", spec("udp")},
		{"nat", "PREROUTING", spec("tcp")},
	}
}

// dnsChainRules returns the body of the redirect chain: RETURN the upstream
// resolvers the daemon itself dials, then send everything else to the local
// resolver. Without those RETURN rules every forwarded query would come back
// into the resolver that issued it and the request queue would fill up. The
// packet uid cannot separate the two, because netd resolves on behalf of apps
// as root just like tailscaled does.
func dnsChainRules(ipv6 bool) [][]string {
	dnsIP := tsaddr.TailscaleServiceIPString
	if ipv6 {
		dnsIP = tsaddr.TailscaleServiceIPv6String
	}
	var rules [][]string
	if !ipv6 {
		for _, a := range androidUpstreamSnapshot() {
			rules = append(rules, []string{"-d", a.String(), "-j", "RETURN"})
		}
	}
	toTailscale := []string{"-j", "DNAT", "--to-destination", dnsIP + ":53"}
	for _, proto := range []string{"udp", "tcp"} {
		rules = append(rules, append([]string{"-p", proto}, toTailscale...))
	}
	return rules
}

// legacyCleanup tracks the one-time removal of the rules installed by older
// builds of this file, indexed by protocol (IPv4, IPv6).
var legacyCleanup [2]sync.Once

func protocolSlot(ipv6 bool) int {
	if ipv6 {
		return 1
	}
	return 0
}

// removeLegacyRules deletes rules left by older builds.
//
// They survive a module upgrade, because a restarted tailscaled never sees what
// its predecessor installed, and the UDP-only "! -o tun+" rule keeps the
// split-DNS loop alive even after the new rules are in place.
func removeLegacyRules(ipt *iptables.IPTables, ipv6 bool) {
	dnsIP := tsaddr.TailscaleServiceIPString
	if ipv6 {
		dnsIP = tsaddr.TailscaleServiceIPv6String
	}
	toTailscale := []string{"-j", "DNAT", "--to-destination", dnsIP + ":53"}
	legacy := []rule{
		{"nat", "OUTPUT", append([]string{"!", "-o", "tun+", "!", "-d", dnsIP, "-p", "udp", "--dport", "53"}, toTailscale...)},
		{"nat", "PREROUTING", append([]string{"!", "-i", "tun+", "-p", "udp", "--dport", "53"}, toTailscale...)},
	}
	legacyCleanup[protocolSlot(ipv6)].Do(func() {
		for _, r := range legacy {
			if exists, err := ipt.Exists(r.table, r.chain, r.args...); err == nil && exists {
				_ = ipt.Delete(r.table, r.chain, r.args...)
			}
		}
	})
}

func newIPTables(ipv6 bool) (*iptables.IPTables, error) {
	proto := iptables.ProtocolIPv4
	if ipv6 {
		proto = iptables.ProtocolIPv6
	}
	return iptables.NewWithProtocol(proto)
}

// installDNSRules (re)builds the redirect chain and ensures the jump rules that
// feed it are present.
func installDNSRules(ipv6 bool) error {
	ipt, err := newIPTables(ipv6)
	if err != nil {
		return err
	}
	chain := androidDNSChainName(ipv6)
	removeLegacyRules(ipt, ipv6)

	// Rebuild from scratch: the upstream set changes with the tailnet's DNS
	// configuration, and a stale RETURN rule would silently stop redirecting a
	// resolver we do want to answer for.
	_ = ipt.NewChain("nat", chain) // "already exists" on reconnect
	if err := ipt.ClearChain("nat", chain); err != nil {
		return err
	}
	for _, args := range dnsChainRules(ipv6) {
		if err := ipt.Append("nat", chain, args...); err != nil {
			return err
		}
	}
	for _, r := range dnsJumpRules(ipv6, chain) {
		exists, err := ipt.Exists(r.table, r.chain, r.args...)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if err := ipt.Append(r.table, r.chain, r.args...); err != nil {
			return err
		}
	}
	return nil
}

// removeDNSRules removes the jump rules and then the chain itself. Removing the
// jumps first is required: a chain that is still referenced cannot be deleted.
func removeDNSRules(ipv6 bool) error {
	ipt, err := newIPTables(ipv6)
	if err != nil {
		return err
	}
	chain := androidDNSChainName(ipv6)
	for _, r := range dnsJumpRules(ipv6, chain) {
		if exists, err := ipt.Exists(r.table, r.chain, r.args...); err == nil && exists {
			_ = ipt.Delete(r.table, r.chain, r.args...)
		}
	}
	_ = ipt.ClearChain("nat", chain)
	_ = ipt.DeleteChain("nat", chain)
	return nil
}

// androidBaseNameservers returns the DNS resolvers Android is currently using,
// or nil if they cannot be determined.
//
// TS_ANDROID_DNS (comma or space separated) overrides the detection, which is
// handy for ROMs that hide the network list from a root daemon.
func androidBaseNameservers() []netip.Addr {
	if v := strings.TrimSpace(os.Getenv("TS_ANDROID_DNS")); v != "" {
		return dedupeAddrs(parseAddrList(v))
	}

	// Some devices still export net.dnsN even though netd is the real owner.
	var addrs []netip.Addr
	for _, prop := range []string{"net.dns1", "net.dns2", "net.dns3", "net.dns4"} {
		out, err := exec.Command("/system/bin/getprop", prop).Output()
		if err != nil {
			break
		}
		addrs = append(addrs, parseAddrList(string(out))...)
	}
	if len(addrs) > 0 {
		return dedupeAddrs(addrs)
	}

	// Fall back to the network list, which prints one
	// "DnsAddresses: [ /192.168.77.1, /... ]" line per network. The output is
	// large, so bound the runtime in case dumpsys wedges.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/system/bin/dumpsys", "connectivity").Output()
	if err != nil {
		return nil
	}
	const marker = "DnsAddresses: ["
	rest := string(out)
	for {
		i := strings.Index(rest, marker)
		if i < 0 {
			break
		}
		rest = rest[i+len(marker):]
		j := strings.IndexByte(rest, ']')
		if j < 0 {
			break
		}
		addrs = append(addrs, parseAddrList(rest[:j])...)
		rest = rest[j:]
	}
	return dedupeAddrs(addrs)
}

func parseAddrList(s string) []netip.Addr {
	var addrs []netip.Addr
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', ' ', '\t', '\n', '\r':
			return true
		}
		return false
	}) {
		f = strings.TrimPrefix(strings.TrimSpace(f), "/")
		if ip, err := netip.ParseAddr(f); err == nil {
			addrs = append(addrs, ip.Unmap())
		}
	}
	return addrs
}

// dedupeAddrs drops unusable and repeated addresses, preserving order.
func dedupeAddrs(in []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]bool, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, ip := range in {
		if ip.IsUnspecified() || ip.IsLoopback() || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}
