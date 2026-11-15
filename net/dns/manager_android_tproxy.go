// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/sys/unix"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

// Android kernels are commonly built without CONFIG_IP6_NF_NAT: the GKI
// defconfig enables CONFIG_IP_NF_NAT but never the IPv6 half, so
// "ip6tables -t nat" fails with "Table does not exist" and the DNAT hijack that
// covers IPv4 cannot be used for IPv6 at all.
//
// TPROXY lives in the mangle table, which every Android kernel has, so it can
// cover IPv6. TPROXY itself is a PREROUTING target, so locally generated
// queries use the equivalent output-path setup:
//
//	ip6tables -t mangle -A OUTPUT -p udp --dport 53 -j TS_TPROXY6
//	ip6tables -t mangle -A OUTPUT -p tcp --dport 53 -j TS_TPROXY6
//	TS_TPROXY6: RETURN for tailnet + upstreams, then MARK --set-xmark 0x20000000
//	ip -6 rule add fwmark 0x20000000/0x20000000 lookup 5453 pref 1300
//	ip -6 route add local default dev lo table 5453
//
// The packets are then delivered to the IPV6_TRANSPARENT sockets below instead
// of leaving the device. Replies are sent with the original destination address
// as their source (IPV6_PKTINFO for UDP; the transparent socket's local address
// for TCP), which is what the client's DNS stack checks. Both feed the same
// dns.Manager.Query handler the IPv4 DNAT path uses, so MagicDNS, single-label
// expansion and split DNS behave identically.
//
// The mark is a single high bit with a mask of the same width, so netd's netId
// bits (the low 17, plus the 0x1e000000 network-stack range) survive: if our
// policy rule is ever missing, the packet is still routed where netd intended.
const (
	androidTPROXYMark  = 0x20000000
	androidTPROXYTable = 5453
	androidTPROXYPref  = 1300
	androidTPROXYChain = "TS_TPROXY6"

	// Both transports run concurrently: a single slow upstream must not park
	// every other lookup behind it. The IPv4 netstack path is per-query too.
	tproxyMaxInFlight = 32
	tproxyMaxConns    = 64
	tproxyQueryTime   = 5 * time.Second
	tproxyTCPIdle     = 15 * time.Second
)

var (
	tproxyMu    sync.Mutex
	tproxyConn  *net.UDPConn
	tproxyTCP   net.Listener
	tproxyClose context.CancelFunc
)

// startAndroidTPROXY brings up the IPv6 DNS interception, or re-asserts its
// routing state when it is already running.
//
// It is called on every DNS recompile, which is exactly what happens on a
// network change: netd rewrites the policy routing chain then, dropping rules it
// did not add itself, so the rule and the local route have to be redone.
func startAndroidTPROXY(m *Manager) {
	tproxyMu.Lock()
	defer tproxyMu.Unlock()

	if tproxyConn != nil {
		// Re-asserting the rule and the local route is ~10 exec calls (~120ms
		// on a phone), and the caller holds the DNS manager lock that every
		// lookup also needs. Refresh off the lock: the state is idempotent and
		// a short delay is harmless, whereas stalling lookups during a network
		// change is not.
		go func() {
			tproxyMu.Lock()
			defer tproxyMu.Unlock()
			if tproxyConn == nil {
				return // stopped in the meantime
			}
			if err := installAndroidTPROXY6Rules(); err != nil {
				m.logf("dns: v6 TPROXY rule refresh failed (non-fatal): %v", err)
			}
		}()
		return
	}

	conn, err := listenAndroidTPROXY6()
	if err != nil {
		// Kernels without CONFIG_NETFILTER_XT_TARGET_TPROXY, or a port 53
		// already taken, land here. IPv4 hijacking is unaffected.
		m.logf("dns: v6 TPROXY listener unavailable (non-fatal): %v", err)
		return
	}
	if err := installAndroidTPROXY6Rules(); err != nil {
		m.logf("dns: v6 TPROXY rules unavailable (non-fatal): %v", err)
		conn.Close()
		removeAndroidTPROXY6Rules()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	tproxyConn = conn
	tproxyClose = cancel
	go androidTPROXY6Loop(ctx, m, conn, m.logf)

	// UDP carries almost everything; TCP carries truncated answers and the
	// resolvers that refuse UDP. Failing to listen on TCP degrades the v6 path
	// rather than breaking it, so it stays non-fatal.
	if ln, err := listenAndroidTPROXY6TCP(); err != nil {
		m.logf("dns: v6 TPROXY TCP listener unavailable (non-fatal): %v", err)
	} else {
		tproxyTCP = ln
		go androidTPROXY6TCPLoop(ctx, m, ln, m.logf)
	}

	m.logf("dns: IPv6 DNS TPROXY enabled (mark %#x, table %d)", androidTPROXYMark, androidTPROXYTable)
}

// stopAndroidTPROXY tears the interception down again, so that disabling
// accept-dns leaves no rule behind that nobody is listening for.
func stopAndroidTPROXY(logf logger.Logf) {
	tproxyMu.Lock()
	defer tproxyMu.Unlock()

	if tproxyConn == nil {
		return
	}
	if tproxyClose != nil {
		tproxyClose()
	}
	tproxyConn.Close()
	tproxyConn = nil
	if tproxyTCP != nil {
		tproxyTCP.Close()
		tproxyTCP = nil
	}
	tproxyClose = nil
	removeAndroidTPROXY6Rules()
	logf("dns: IPv6 DNS TPROXY disabled")
}

// transparentControl sets what a transparent socket needs before bind.
func transparentControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			serr = err
			return
		}
		// Without TRANSPARENT the socket cannot receive packets whose
		// destination is not a local address, and cannot answer as it.
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			serr = err
		}
	}); err != nil {
		return err
	}
	return serr
}

// listenAndroidTPROXY6 opens the transparent UDP socket that receives the
// marked queries.
func listenAndroidTPROXY6() (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if err := transparentControl(network, address, c); err != nil {
				return err
			}
			var serr error
			if err := c.Control(func(fd uintptr) {
				// Needed to learn the destination address the client used,
				// which the reply has to appear to come from.
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
					serr = err
				}
			}); err != nil {
				return err
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp6", "[::]:53")
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errors.New("transparent DNS listener is not a UDPConn")
	}
	return uc, nil
}

// listenAndroidTPROXY6TCP accepts the TCP half. Android falls back to TCP for
// truncated answers, and a resolver that always answers over TCP would
// otherwise send those lookups straight to the carrier, where MagicDNS names
// do not exist. The accepted socket's local address is the original
// destination, so replies get the right source without IPV6_PKTINFO.
func listenAndroidTPROXY6TCP() (net.Listener, error) {
	lc := net.ListenConfig{Control: transparentControl}
	return lc.Listen(context.Background(), "tcp6", "[::]:53")
}

func androidTPROXY6Loop(ctx context.Context, m *Manager, uc *net.UDPConn, logf logger.Logf) {
	sem := make(chan struct{}, tproxyMaxInFlight)
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		// One buffer per packet: the handler below runs concurrently.
		buf := make([]byte, 4096)
		oob := make([]byte, 256)
		n, oobn, _, src, err := uc.ReadMsgUDP(buf, oob)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logf("dns: v6 TPROXY read error: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if n == 0 {
			continue
		}
		dst, ok := pktinfoDst(oob[:oobn])
		if !ok {
			logf("dns: v6 TPROXY packet without IPV6_PKTINFO, dropped")
			continue
		}
		from, ok := udpAddrPort(src)
		if !ok {
			continue
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		query := buf[:n]
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			qctx, cancel := context.WithTimeout(ctx, tproxyQueryTime)
			resp, err := m.Query(qctx, query, "udp", from)
			cancel()
			if err != nil || len(resp) == 0 {
				return
			}
			if _, _, err := uc.WriteMsgUDP(resp, pktinfoOOB(dst), src); err != nil {
				logf("dns: v6 TPROXY reply to %v failed: %v", src, err)
			}
		}()
	}
}

func androidTPROXY6TCPLoop(ctx context.Context, m *Manager, ln net.Listener, logf logger.Logf) {
	sem := make(chan struct{}, tproxyMaxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logf("dns: v6 TPROXY TCP accept error: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			c.Close()
			return
		}
		go func(c net.Conn) {
			defer func() { <-sem; c.Close() }()
			androidTPROXY6TCPConn(ctx, m, c, logf)
		}(c)
	}
}

// androidTPROXY6TCPConn serves one client connection. DNS over TCP is
// length-prefixed and clients may pipeline several queries on the same
// connection, so this keeps reading until the peer closes or goes idle.
func androidTPROXY6TCPConn(ctx context.Context, m *Manager, c net.Conn, logf logger.Logf) {
	from, ok := netAddrPort(c.RemoteAddr())
	if !ok {
		return
	}
	var hdr [2]byte
	for {
		if err := c.SetReadDeadline(time.Now().Add(tproxyTCPIdle)); err != nil {
			return
		}
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}

		qctx, cancel := context.WithTimeout(ctx, tproxyQueryTime)
		resp, err := m.Query(qctx, query, "tcp", from)
		cancel()
		if err != nil || len(resp) == 0 {
			return
		}

		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		if err := c.SetWriteDeadline(time.Now().Add(tproxyTCPIdle)); err != nil {
			return
		}
		if _, err := c.Write(out); err != nil {
			logf("dns: v6 TPROXY TCP write to %v failed: %v", from, err)
			return
		}
	}
}

// pktinfoDst extracts the address the client sent the query to, which is also
// the address the reply has to appear to come from.
func pktinfoDst(oob []byte) (netip.Addr, bool) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, c := range cmsgs {
		if c.Header.Level != unix.IPPROTO_IPV6 || c.Header.Type != unix.IPV6_PKTINFO {
			continue
		}
		if len(c.Data) < unix.SizeofInet6Pktinfo {
			continue
		}
		var a [16]byte
		copy(a[:], c.Data[:16])
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

func pktinfoOOB(src netip.Addr) []byte {
	b := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_IPV6
	h.Type = unix.IPV6_PKTINFO
	h.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
	pi := (*unix.Inet6Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
	pi.Addr = src.As16()
	pi.Ifindex = 0
	return b
}

func udpAddrPort(a *net.UDPAddr) (netip.AddrPort, bool) {
	if a == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), true
}

func netAddrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.TCPAddr:
		if v == nil {
			return netip.AddrPort{}, false
		}
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(v.Port)), true
	case *net.UDPAddr:
		return udpAddrPort(v)
	}
	return netip.AddrPort{}, false
}

// installAndroidTPROXY6Rules is idempotent and cheap enough to run on every
// recompile.
func installAndroidTPROXY6Rules() error {
	mark := fmt.Sprintf("%#x/%#x", androidTPROXYMark, androidTPROXYMark)
	table := strconv.Itoa(androidTPROXYTable)
	pref := strconv.Itoa(androidTPROXYPref)

	if err := runIP("-6", "rule", "add", "fwmark", mark, "lookup", table, "pref", pref); err != nil &&
		!strings.Contains(err.Error(), "File exists") {
		return err
	}
	if err := runIP("-6", "route", "replace", "local", "default", "dev", "lo", "table", table); err != nil {
		return err
	}

	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return err
	}
	chain := androidTPROXYChain
	_ = ipt.NewChain("mangle", chain) // "already exists" on refresh
	if err := ipt.ClearChain("mangle", chain); err != nil {
		return err
	}
	// Never capture traffic bound for the tailnet or for an upstream the
	// daemon itself dials, or the forwarder would feed queries back into
	// itself and the request queue would fill up.
	if err := ipt.Append("mangle", chain, []string{"-d", tsaddr.TailscaleULARange().String(), "-j", "RETURN"}...); err != nil {
		return err
	}
	for _, a := range androidUpstreamSnapshot() {
		if !a.Is6() {
			continue
		}
		if err := ipt.Append("mangle", chain, []string{"-d", a.String(), "-j", "RETURN"}...); err != nil {
			return err
		}
	}
	if err := ipt.Append("mangle", chain, []string{"-j", "MARK", "--set-xmark", mark}...); err != nil {
		return err
	}

	for _, proto := range []string{"udp", "tcp"} {
		jump := []string{"-p", proto, "--dport", "53", "-j", chain}
		if exists, err := ipt.Exists("mangle", "OUTPUT", jump...); err == nil && exists {
			continue
		}
		if err := ipt.Insert("mangle", "OUTPUT", 1, jump...); err != nil {
			return err
		}
	}
	return nil
}

func removeAndroidTPROXY6Rules() {
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		for _, proto := range []string{"udp", "tcp"} {
			jump := []string{"-p", proto, "--dport", "53", "-j", androidTPROXYChain}
			if exists, err := ipt.Exists("mangle", "OUTPUT", jump...); err == nil && exists {
				_ = ipt.Delete("mangle", "OUTPUT", jump...)
			}
		}
		_ = ipt.ClearChain("mangle", androidTPROXYChain)
		_ = ipt.DeleteChain("mangle", androidTPROXYChain)
	}
	mark := fmt.Sprintf("%#x/%#x", androidTPROXYMark, androidTPROXYMark)
	table := strconv.Itoa(androidTPROXYTable)
	pref := strconv.Itoa(androidTPROXYPref)
	_ = runIP("-6", "rule", "del", "fwmark", mark, "lookup", table, "pref", pref)
	_ = runIP("-6", "route", "flush", "table", table)
}

func runIP(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/system/bin/ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
