package netspoof

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

type Session struct {
	IfaceName string
	Iface     *net.Interface
	IfaceMAC  net.HardwareAddr

	OurIPv4    netip.Addr
	OurIPv4Net net.IPNet
	OurIPv6    netip.Addr

	GatewayIPv4 netip.Addr
	GatewayMAC  net.HardwareAddr
	GatewayIPv6 netip.Addr

	// Targets is the set of IPs we send spoofed ARP replies *to*.
	Targets []netip.Addr

	// Spoofed is the set of IPs we claim to *be* (default: just the gateway).
	Spoofed []netip.Addr

	// DNS config
	DNSAddress netip.Addr
	DNSDomains []DNSRule
	DHCP6DNS   netip.Addr

	FullDuplex bool

	Lan *Lan
	Tx  *TxQueue

	// restore state for sysctls
	prevIPForward string
	prevSysctls   map[string]string

	NDPTargets  []netip.Addr
	NDPPrefix   string
	NDPLifetime int
	NDPNoNA     bool
	gwIPv6Set   bool
	DHCP6Active bool
	SniffAll    bool

	handles []io.Closer
}

type DNSRule struct {
	Pattern string // lower-case, may contain '*'
	Address netip.Addr
}

// NewSession auto-detects everything. Any override in `opts` wins.
type SessionOptions struct {
	IfaceName   string
	GatewayIPv4 string
	TargetsArg  string
	SpoofArg    string
	DNSAddress  string
	DNSDomains  string // comma-separated patterns
	DNSRules    string // "domain=ip,domain2=ip2"
	DHCP6DNS    string
	FullDuplex  bool
	NDPTargets  string
	NDPPrefix   string
	NDPLifetime int
	NDPNoNA     bool
	SniffAll    bool
}

func NewSession(opts SessionOptions) (*Session, error) {
	ifi, err := pickInterface(opts.IfaceName)
	if err != nil {
		return nil, err
	}

	ourIP, ourNet, err := pickOurIPv4(ifi)
	if err != nil {
		return nil, err
	}

	// Gateway IP: explicit override, else default route for this interface.
	var gwIP netip.Addr
	if opts.GatewayIPv4 != "" {
		gwIP, err = netip.ParseAddr(opts.GatewayIPv4)
		if err != nil {
			return nil, fmt.Errorf("bad -gateway: %w", err)
		}
	} else {
		gwIP, err = defaultGatewayIPv4(ifi.Name)
		if err != nil {
			return nil, fmt.Errorf("cannot auto-detect gateway: %w", err)
		}
	}

	// If our first IPv4 isn't on the gateway's subnet, look for one that is.
	if !sameSubnet(ourIP, ourNet.Mask, gwIP) {
		if altIP, altNet, ok := findIPv4OnSubnet(ifi, gwIP); ok {
			ourIP, ourNet = altIP, altNet
		} else {
			return nil, fmt.Errorf("no interface address on gateway's subnet (%s)", gwIP)
		}
	}

	sess := &Session{
		IfaceName:   ifi.Name,
		Iface:       ifi,
		IfaceMAC:    ifi.HardwareAddr,
		OurIPv4:     ourIP,
		OurIPv4Net:  ourNet,
		GatewayIPv4: gwIP,
		FullDuplex:  opts.FullDuplex,
		Lan:         NewLan(),
	}

	// Our link-local IPv6 (for RA/NA source).
	if addrs, err := ifi.Addrs(); err == nil {
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			if addr.Is6() && !addr.Is4In6() && addr.IsLinkLocalUnicast() {
				sess.OurIPv6 = addr
				break
			}
		}
	}

	// Targets
	if opts.TargetsArg != "" {
		sess.Targets, err = parseTargets(opts.TargetsArg)
		if err != nil {
			return nil, fmt.Errorf("bad -targets: %w", err)
		}
	} else {
		sess.Targets = nil // dynamic: arp.go will filter sess.Lan by subnet
	}

	// Spoofed set: default = gateway only.
	if opts.SpoofArg != "" {
		sess.Spoofed, err = parseTargets(opts.SpoofArg)
		if err != nil {
			return nil, fmt.Errorf("bad -spoof: %w", err)
		}
	} else {
		sess.Spoofed = []netip.Addr{gwIP}
	}

	// DNS
	if opts.DNSAddress != "" {
		addr, err := netip.ParseAddr(opts.DNSAddress)
		if err != nil {
			return nil, fmt.Errorf("bad -dns-address: %w", err)
		}
		sess.DNSAddress = addr
	}
	rules, err := buildDNSRules(opts.DNSDomains, opts.DNSRules, sess.DNSAddress)
	if err != nil {
		return nil, err
	}
	sess.DNSDomains = rules

	// DHCP6 DNS advertised to clients (default: our own link-local).
	if opts.DHCP6DNS != "" {
		a, err := netip.ParseAddr(opts.DHCP6DNS)
		if err != nil {
			return nil, fmt.Errorf("bad -dhcp6-dns: %w", err)
		}
		sess.DHCP6DNS = a
	} else if sess.OurIPv6.IsValid() {
		sess.DHCP6DNS = sess.OurIPv6
	}

	// NDP options.
	sess.NDPPrefix = opts.NDPPrefix
	if sess.NDPPrefix == "" {
		sess.NDPPrefix = "d00d::/64"
	}
	sess.NDPLifetime = opts.NDPLifetime
	if sess.NDPLifetime == 0 {
		sess.NDPLifetime = 30
	}
	sess.NDPNoNA = opts.NDPNoNA
	if opts.NDPTargets != "" {
		for _, p := range strings.Split(opts.NDPTargets, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			a, err := netip.ParseAddr(p)
			if err != nil {
				return nil, fmt.Errorf("bad -ndp-targets entry %q: %w", p, err)
			}
			sess.NDPTargets = append(sess.NDPTargets, a)
		}
	}
	sess.SniffAll = opts.SniffAll

	return sess, nil
}

func (s *Session) setGatewayIPv6(ip netip.Addr) {
	if !ip.Is6() || ip.Is4In6() {
		return
	}
	s.gwIPv6Set = true
	s.GatewayIPv6 = ip
}

func (s *Session) TrackHandle(h io.Closer) {
	s.handles = append(s.handles, h)
}

// --- interface & address helpers ---

func pickInterface(name string) (*net.Interface, error) {
	if name != "" {
		return net.InterfaceByName(name)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifaces[i].Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if ok && ipnet.IP.To4() != nil {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable interface found")
}

func pickOurIPv4(ifi *net.Interface) (netip.Addr, net.IPNet, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, net.IPNet{}, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		return addr.Unmap(), *ipnet, nil
	}
	return netip.Addr{}, net.IPNet{}, fmt.Errorf("no IPv4 address on %s", ifi.Name)
}

func findIPv4OnSubnet(ifi *net.Interface, gw netip.Addr) (netip.Addr, net.IPNet, bool) {
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if sameSubnet(addr, ipnet.Mask, gw) {
			return addr, *ipnet, true
		}
	}
	return netip.Addr{}, net.IPNet{}, false
}

func sameSubnet(ip netip.Addr, mask net.IPMask, other netip.Addr) bool {
	ip4 := ip.As4()
	o4 := other.As4()
	m := mask
	if len(m) == 16 {
		m = m[12:]
	}
	return ip4[0]&m[0] == o4[0]&m[0] &&
		ip4[1]&m[1] == o4[1]&m[1] &&
		ip4[2]&m[2] == o4[2]&m[2] &&
		ip4[3]&m[3] == o4[3]&m[3]
}

func defaultGatewayIPv4(iface string) (netip.Addr, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	var fallback netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		gwHex := fields[2]
		if len(gwHex) != 8 || gwHex == "00000000" {
			continue
		}
		var b [4]byte
		_, err := fmt.Sscanf(gwHex, "%02x%02x%02x%02x", &b[3], &b[2], &b[1], &b[0])
		if err != nil {
			continue
		}
		addr := netip.AddrFrom4(b)
		if iface != "" && fields[0] == iface {
			return addr, nil
		}
		if !fallback.IsValid() {
			fallback = addr
		}
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.Addr{}, fmt.Errorf("no default route for %s", iface)
}

func parseTargets(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			pref, err := netip.ParsePrefix(p)
			if err != nil {
				return nil, err
			}
			for a := pref.Masked().Addr(); pref.Contains(a); a = a.Next() {
				if a.Is4() {
					out = append(out, a)
				}
			}
			continue
		}
		a, err := netip.ParseAddr(p)
		if err != nil {
			return nil, err
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// --- DNS rule helpers ---

func buildDNSRules(domains, rules string, globalAddr netip.Addr) ([]DNSRule, error) {
	var out []DNSRule
	for _, d := range strings.Split(domains, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if !globalAddr.IsValid() {
			return nil, fmt.Errorf("-dns-domains requires -dns-address")
		}
		out = append(out, DNSRule{Pattern: d, Address: globalAddr})
	}
	for _, r := range strings.Split(rules, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		eq := strings.IndexByte(r, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("bad -dns rule %q (want domain=ip)", r)
		}
		dom := strings.ToLower(strings.TrimSpace(r[:eq]))
		addr, err := netip.ParseAddr(strings.TrimSpace(r[eq+1:]))
		if err != nil {
			return nil, fmt.Errorf("bad -dns rule %q: %w", r, err)
		}
		out = append(out, DNSRule{Pattern: dom, Address: addr})
	}
	return out, nil
}
