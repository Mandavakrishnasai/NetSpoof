package netspoof

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RunDiscovery polls `ip neigh` every second and fills the shared Lan table.
// It also fires bounded fire-and-forget ARP probes for known targets that
// haven't appeared in the cache yet.
func RunDiscovery(ctx context.Context, sess *Session) {
	probes := map[netip.Addr]probeState{}

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	// run once immediately so ARP can start spoofing fast
	refreshNeigh(sess)
	refreshNeigh6(sess)
	probeMissing(sess, probes)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			refreshNeigh(sess)
			refreshNeigh6(sess)
			probeMissing(sess, probes)
		}
	}
}

type probeState struct {
	count   int
	lastTry time.Time
}

func refreshNeigh(sess *Session) {
	out, err := exec.Command("ip", "neigh", "show", "dev", sess.IfaceName).Output()
	if err != nil {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		idx := -1
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "lladdr" {
				idx = i
				break
			}
		}
		if idx == -1 || idx+1 >= len(fields) {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || !ip.Is4() {
			continue
		}
		mac, err := net.ParseMAC(fields[idx+1])
		if err != nil {
			continue
		}
		sess.Lan.Set(ip.Unmap(), mac)
	}
}

// refreshNeigh6 polls `ip -6 neigh` and updates the Lan table with IPv6
// entries. It also detects the router flag to identify the gateway IPv6.
func refreshNeigh6(sess *Session) {
	out, err := exec.Command("ip", "-6", "neigh", "show", "dev", sess.IfaceName).Output()
	if err != nil {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		idx := -1
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "lladdr" {
				idx = i
				break
			}
		}
		if idx == -1 || idx+1 >= len(fields) {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || !ip.Is6() || ip.Is4In6() {
			continue
		}
		mac, err := net.ParseMAC(fields[idx+1])
		if err != nil {
			continue
		}
		sess.Lan.Set(ip, mac)

		for _, f := range fields {
			if f == "router" {
				sess.setGatewayIPv6(ip)
				break
			}
		}
	}
}

// probeMissing sends one ARP request per missing target, at most once every
// 5 seconds and at most 3 total attempts per target. Fire and forget.
func probeMissing(sess *Session, probes map[netip.Addr]probeState) {
	now := time.Now()
	for _, tgt := range sess.Targets {
		if _, known := sess.Lan.Get(tgt); known {
			continue
		}
		st := probes[tgt]
		if st.count >= 3 {
			continue
		}
		if !st.lastTry.IsZero() && now.Sub(st.lastTry) < 5*time.Second {
			continue
		}
		// build one ARP request and send it via the tx queue
		raw := buildARPRequest(sess.IfaceMAC, sess.OurIPv4, tgt)
		if raw != nil {
			_ = sess.Tx.Send(raw)
		}
		probes[tgt] = probeState{count: st.count + 1, lastTry: now}
	}
}

func buildARPRequest(fromMAC net.HardwareAddr, fromIP, targetIP netip.Addr) []byte {
	eth := layers.Ethernet{
		SrcMAC:       fromMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   fromMAC,
		SourceProtAddress: fromIP.AsSlice(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP.AsSlice(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil
	}
	return buf.Bytes()
}
