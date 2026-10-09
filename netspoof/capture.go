package netspoof

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

const maxFrameSize = 65536

// PacketHandle captures and injects Ethernet frames without linking libpcap.
type PacketHandle struct {
	rx      *pcapgo.EthernetHandle
	txfd    int
	ifIndex int
}

func OpenPacketHandle(iface string, promisc bool) (*PacketHandle, error) {
	intf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}

	rx, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return nil, err
	}
	if err := rx.SetCaptureLength(maxFrameSize); err != nil {
		rx.Close()
		return nil, err
	}
	if promisc {
		if err := rx.SetPromiscuous(true); err != nil {
			rx.Close()
			return nil, err
		}
	}

	txfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		rx.Close()
		return nil, fmt.Errorf("tx socket: %w", err)
	}

	return &PacketHandle{
		rx:      rx,
		txfd:    txfd,
		ifIndex: intf.Index,
	}, nil
}

func (h *PacketHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return h.rx.ReadPacketData()
}

func (h *PacketHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return h.rx.ZeroCopyReadPacketData()
}

func (h *PacketHandle) WritePacketData(data []byte) error {
	return unix.Sendto(h.txfd, data, 0, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  h.ifIndex,
	})
}

func (h *PacketHandle) Close() error {
	if h.rx != nil {
		h.rx.Close()
	}
	if h.txfd >= 0 {
		_ = unix.Close(h.txfd)
		h.txfd = -1
	}
	return nil
}

func htons(data uint16) uint16 {
	return data<<8 | data>>8
}
