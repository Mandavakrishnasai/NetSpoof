package netspoof

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SnifferConfig controls what the sniffer logs.
type SnifferConfig struct {
	All      bool // log every packet, not just app-aware events
	MaxBytes int  // cap per-packet payload we look at
}

// RunSniff captures traffic and logs parsed events.
func RunSniff(ctx context.Context, sess *Session) error {
	cfg := SnifferConfig{
		All:      sess.SniffAll,
		MaxBytes: 4096,
	}

	handle, err := OpenPacketHandle(sess.IfaceName, true)
	if err != nil {
		return fmt.Errorf("[sniff] packet handle open: %w", err)
	}
	defer handle.Close()
	sess.TrackHandle(handle)

	filter := "not arp and not (ip6 and udp and (port 546 or port 547))"

	fmt.Printf("[sniff] started (mode=%s filter=%q)\n", modeLabel(cfg.All), filter)

	src := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	src.NoCopy = true
	packets := src.Packets()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[sniff] stopping")
			return nil
		case pkt, ok := <-packets:
			if !ok || pkt == nil {
				continue
			}
			handleSniffPacket(sess, pkt, cfg)
		}
	}
}

func modeLabel(all bool) string {
	if all {
		return "verbose"
	}
	return "app-aware"
}

func handleSniffPacket(sess *Session, pkt gopacket.Packet, cfg SnifferConfig) {
	ip4 := pkt.Layer(layers.LayerTypeIPv4)
	ip6 := pkt.Layer(layers.LayerTypeIPv6)
	if ip4 == nil && ip6 == nil {
		return
	}

	var srcIP, dstIP net.IP
	if ip4 != nil {
		l := ip4.(*layers.IPv4)
		srcIP, dstIP = l.SrcIP, l.DstIP
	} else {
		l := ip6.(*layers.IPv6)
		srcIP, dstIP = l.SrcIP, l.DstIP
	}

	if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
		tcp := tcpL.(*layers.TCP)
		if payload := tcp.Payload; len(payload) > 0 {
			if parseTCPPayload(sess, pkt, srcIP, dstIP, tcp, payload, cfg) {
				return
			}
		}
		if cfg.All {
			fmt.Printf("[tcp] %s:%d -> %s:%d (%d bytes)\n",
				srcIP, tcp.SrcPort, dstIP, tcp.DstPort, len(tcp.Payload))
		}
		return
	}

	if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)
		if payload := udp.Payload; len(payload) > 0 {
			if parseUDPPayload(sess, pkt, srcIP, dstIP, udp, payload, cfg) {
				return
			}
		}
		if cfg.All {
			fmt.Printf("[udp] %s:%d -> %s:%d (%d bytes)\n",
				srcIP, udp.SrcPort, dstIP, udp.DstPort, len(udp.Payload))
		}
		return
	}

	if cfg.All {
		if pkt.Layer(layers.LayerTypeICMPv4) != nil {
			fmt.Printf("[icmp4] %s -> %s\n", srcIP, dstIP)
		} else if pkt.Layer(layers.LayerTypeICMPv6) != nil {
			fmt.Printf("[icmp6] %s -> %s\n", srcIP, dstIP)
		}
	}
}

func parseTCPPayload(sess *Session, pkt gopacket.Packet, srcIP, dstIP net.IP, tcp *layers.TCP, payload []byte, cfg SnifferConfig) bool {
	if limit := cfg.MaxBytes; limit > 0 && len(payload) > limit {
		payload = payload[:limit]
	}

	if parseHTTP(srcIP, dstIP, tcp, payload) {
		return true
	}
	if parseTLSSNI(srcIP, dstIP, tcp, payload) {
		return true
	}
	if parseFTP(srcIP, dstIP, tcp, payload) {
		return true
	}
	if parseSMTP(srcIP, dstIP, tcp, payload) {
		return true
	}
	if parseNTLM(srcIP, dstIP, tcp, payload) {
		return true
	}
	return false
}

func parseHTTP(srcIP, dstIP net.IP, tcp *layers.TCP, payload []byte) bool {
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "}
	first := payload
	if i := bytes.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	line := strings.TrimRight(string(first), "\r")
	isReq := false
	for _, m := range methods {
		if strings.HasPrefix(line, m) {
			isReq = true
			break
		}
	}
	if !isReq {
		if strings.HasPrefix(line, "HTTP/") {
			fmt.Printf("[http] %s:%d <- %s:%d %s\n",
				srcIP, tcp.SrcPort, dstIP, tcp.DstPort, line)
			return true
		}
		return false
	}

	host := ""
	for _, l := range strings.Split(string(payload), "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			host = strings.TrimSpace(l[5:])
			break
		}
	}
	tag := ""
	if host != "" {
		tag = " host=" + host
	}
	fmt.Printf("[http] %s -> %s:%d %s%s\n", srcIP, dstIP, tcp.DstPort, line, tag)
	return true
}

func parseTLSSNI(srcIP, dstIP net.IP, tcp *layers.TCP, payload []byte) bool {
	if len(payload) < 10 {
		return false
	}
	if payload[0] != 0x16 || payload[5] != 0x01 {
		return false
	}

	body := payload[9:]
	if len(body) < 34 {
		return false
	}
	body = body[34:]
	if len(body) < 1 {
		return false
	}
	sidLen := int(body[0])
	body = body[1:]
	if len(body) < sidLen+2 {
		return false
	}
	body = body[sidLen:]
	csLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < csLen+1 {
		return false
	}
	body = body[csLen:]
	compLen := int(body[0])
	body = body[1:]
	if len(body) < compLen+2 {
		return false
	}
	body = body[compLen:]
	extLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) > extLen {
		body = body[:extLen]
	}

	for len(body) >= 4 {
		etype := binary.BigEndian.Uint16(body[:2])
		elen := int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if len(body) < elen {
			break
		}
		if etype == 0x0000 {
			ext := body[:elen]
			if len(ext) < 5 {
				break
			}
			nameLen := int(binary.BigEndian.Uint16(ext[3:5]))
			if len(ext) < 5+nameLen {
				break
			}
			name := string(ext[5 : 5+nameLen])
			fmt.Printf("[tls] %s -> %s:%d SNI=%s\n", srcIP, dstIP, tcp.DstPort, name)
			return true
		}
		body = body[elen:]
	}
	return false
}

func parseFTP(srcIP, dstIP net.IP, tcp *layers.TCP, payload []byte) bool {
	if tcp.SrcPort != 21 && tcp.DstPort != 21 {
		return false
	}
	text := strings.TrimRight(string(payload), "\r\n")
	upper := strings.ToUpper(text)
	for _, cmd := range []string{"USER ", "PASS ", "RETR ", "STOR ", "CWD ", "LIST"} {
		if strings.HasPrefix(upper, cmd) {
			fmt.Printf("[ftp] %s:%d -> %s:%d %s\n", srcIP, tcp.SrcPort, dstIP, tcp.DstPort, text)
			return true
		}
	}
	if len(text) >= 3 && text[0] >= '2' && text[0] <= '5' {
		fmt.Printf("[ftp] %s:%d <- %s:%d %s\n", srcIP, tcp.SrcPort, dstIP, tcp.DstPort, text)
		return true
	}
	return false
}

func parseSMTP(srcIP, dstIP net.IP, tcp *layers.TCP, payload []byte) bool {
	if tcp.SrcPort != 25 && tcp.DstPort != 25 && tcp.SrcPort != 587 && tcp.DstPort != 587 {
		return false
	}
	text := strings.TrimRight(string(payload), "\r\n")
	upper := strings.ToUpper(text)
	for _, cmd := range []string{"MAIL FROM", "RCPT TO", "AUTH ", "HELO ", "EHLO ", "VRFY "} {
		if strings.HasPrefix(upper, cmd) {
			fmt.Printf("[smtp] %s:%d -> %s:%d %s\n", srcIP, tcp.SrcPort, dstIP, tcp.DstPort, text)
			return true
		}
	}
	return false
}

func parseNTLM(srcIP, dstIP net.IP, tcp *layers.TCP, payload []byte) bool {
	if !bytes.Contains(payload, []byte("NTLMSSP\x00")) {
		return false
	}
	fmt.Printf("[ntlm] %s:%d -> %s:%d (NTLMSSP handshake, %d bytes)\n",
		srcIP, tcp.SrcPort, dstIP, tcp.DstPort, len(payload))
	return true
}

func parseUDPPayload(sess *Session, pkt gopacket.Packet, srcIP, dstIP net.IP, udp *layers.UDP, payload []byte, cfg SnifferConfig) bool {
	if dnsL := pkt.Layer(layers.LayerTypeDNS); dnsL != nil {
		dns := dnsL.(*layers.DNS)
		if parseDNS(srcIP, dstIP, udp, dns) {
			return true
		}
	}
	return false
}

func parseDNS(srcIP, dstIP net.IP, udp *layers.UDP, dns *layers.DNS) bool {
	if dns.QR {
		var parts []string
		for _, a := range dns.Answers {
			if a.IP != nil {
				parts = append(parts, fmt.Sprintf("%s=%s", string(a.Name), a.IP.String()))
			} else if a.CNAME != nil {
				parts = append(parts, fmt.Sprintf("%s=CNAME:%s", string(a.Name), string(a.CNAME)))
			}
		}
		if len(parts) == 0 {
			return false
		}
		fmt.Printf("[dns] %s:%d <- %s:%d %s\n",
			srcIP, udp.SrcPort, dstIP, udp.DstPort, strings.Join(parts, " "))
		return true
	}

	if len(dns.Questions) == 0 {
		return false
	}
	var parts []string
	for _, q := range dns.Questions {
		parts = append(parts, fmt.Sprintf("%s(%s)", string(q.Name), q.Type))
	}
	fmt.Printf("[dns] %s:%d -> %s:%d %s\n",
		srcIP, udp.SrcPort, dstIP, udp.DstPort, strings.Join(parts, " "))
	return true
}

var _ = time.Second
