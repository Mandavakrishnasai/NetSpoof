package netspoof

import (
	"net"
	"net/netip"
	"sync"
)

// Lan is the single shared source of truth for "what MAC does this IP have".
// Works for both IPv4 and IPv6 addresses.
type Lan struct {
	mu    sync.RWMutex
	table map[netip.Addr]net.HardwareAddr
}

func NewLan() *Lan {
	return &Lan{table: make(map[netip.Addr]net.HardwareAddr)}
}

func (l *Lan) Get(ip netip.Addr) (net.HardwareAddr, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	mac, ok := l.table[ip.Unmap()]
	return mac, ok
}

func (l *Lan) Set(ip netip.Addr, mac net.HardwareAddr) {
	if !ip.IsValid() || mac == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make(net.HardwareAddr, len(mac))
	copy(cp, mac)
	l.table[ip.Unmap()] = cp
}

func (l *Lan) Snapshot() map[netip.Addr]net.HardwareAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[netip.Addr]net.HardwareAddr, len(l.table))
	for ip, mac := range l.table {
		cp := make(net.HardwareAddr, len(mac))
		copy(cp, mac)
		out[ip] = cp
	}
	return out
}

// SnapshotV6 returns only IPv6 entries (link-local and global).
func (l *Lan) SnapshotV6() map[netip.Addr]net.HardwareAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[netip.Addr]net.HardwareAddr)
	for ip, mac := range l.table {
		if ip.Is6() && !ip.Is4In6() {
			cp := make(net.HardwareAddr, len(mac))
			copy(cp, mac)
			out[ip] = cp
		}
	}
	return out
}
