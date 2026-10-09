package main

import (
	"NetSpoof/netspoof"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	var (
		iface       = flag.String("iface", "", "interface (auto-detect if empty)")
		gateway     = flag.String("gateway", "", "gateway IPv4 (auto-detect if empty)")
		targets     = flag.String("targets", "", "comma-separated targets (default: whole subnet)")
		spoof       = flag.String("spoof", "", "comma-separated IPs to impersonate (default: gateway)")
		fulldup     = flag.Bool("fullduplex", false, "also spoof the gateway's view of each target")
		dnsAddr     = flag.String("dns-address", "", "IP to reply with for matched DNS domains (required for dns module)")
		dnsDom      = flag.String("dns-domains", "", "comma-separated domain patterns (wildcards allowed)")
		dnsRules    = flag.String("dns", "", "per-domain overrides, domain=ip,domain2=ip2")
		dhcp6DNS    = flag.String("dhcp6-dns", "", "DNS IPv6 to advertise via DHCPv6 (default: our link-local)")
		run         = flag.String("run", "arp", "comma-separated modules: arp,dns,ndp,dhcp6,sniff")
		ndpTargets  = flag.String("ndp-targets", "", "comma-separated IPv6 addresses for NA (default: all discovered)")
		ndpPrefix   = flag.String("ndp-prefix", "d00d::/64", "prefix advertised in Router Advertisements")
		ndpLifetime = flag.Int("ndp-lifetime", 30, "router lifetime in seconds")
		ndpNoNA     = flag.Bool("ndp-no-na", false, "skip Neighbor Advertisements, only send RA")
		sniffAll    = flag.Bool("sniff-all", false, "log every packet, not just app-aware events")
		runTime     = flag.Duration("time", 0, "cleanly stop after this duration, e.g. 30s, 2m, 1h (0 = run until signal)")
	)
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "candy: must run as root")
		os.Exit(1)
	}

	sess, err := netspoof.NewSession(netspoof.SessionOptions{
		IfaceName:   *iface,
		GatewayIPv4: *gateway,
		TargetsArg:  *targets,
		SpoofArg:    *spoof,
		DNSAddress:  *dnsAddr,
		DNSDomains:  *dnsDom,
		DNSRules:    *dnsRules,
		DHCP6DNS:    *dhcp6DNS,
		FullDuplex:  *fulldup,
		NDPTargets:  *ndpTargets,
		NDPPrefix:   *ndpPrefix,
		NDPLifetime: *ndpLifetime,
		NDPNoNA:     *ndpNoNA,
		SniffAll:    *sniffAll,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "candy: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[session] iface=%s our=%s gw=%s targets=%d spoofed=%v\n",
		sess.IfaceName, sess.OurIPv4, sess.GatewayIPv4, len(sess.Targets), sess.Spoofed)

	// Open one raw packet handle for capture+inject. Same handle reused for Tx.
	handle, err := netspoof.OpenPacketHandle(sess.IfaceName, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "candy: packet handle open: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()
	sess.TrackHandle(handle)

	sess.Tx = netspoof.NewTxQueue(handle, 1024)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess.Tx.Run(ctx)

	if *runTime > 0 {
		go func() {
			timer := time.NewTimer(*runTime)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				fmt.Printf("[candy] -time %s reached, shutting down cleanly\n", runTime.String())
				cancel()
			}
		}()
	}

	// signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[candy] signal received, shutting down")
		cancel()
	}()

	// always-on discovery
	go netspoof.RunDiscovery(ctx, sess)

	// modules
	mods := strings.Split(*run, ",")
	for _, m := range mods {
		if strings.TrimSpace(m) == "dhcp6" {
			sess.DHCP6Active = true
			break
		}
	}

	var wg sync.WaitGroup
	wgErr := make(chan error, len(mods))

	for _, m := range mods {
		m = strings.TrimSpace(m)
		switch m {
		case "arp":
			runInBackground(&wg, wgErr, "arp", func() error {
				return netspoof.RunARP(ctx, sess)
			})
		case "dns":
			runInBackground(&wg, wgErr, "dns", func() error {
				return netspoof.RunDNS(ctx, sess)
			})
		case "ndp":
			runInBackground(&wg, wgErr, "ndp", func() error {
				return netspoof.RunNDP(ctx, sess)
			})
		case "dhcp6":
			runInBackground(&wg, wgErr, "dhcp6", func() error {
				return netspoof.RunDHCP6(ctx, sess)
			})
		case "sniff":
			runInBackground(&wg, wgErr, "sniff", func() error {
				return netspoof.RunSniff(ctx, sess)
			})
		case "":
			// ignore
		default:
			fmt.Fprintf(os.Stderr, "candy: unknown module %q\n", m)
			os.Exit(1)
		}
	}

	select {
	case <-ctx.Done():
	case err := <-wgErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "candy: module error: %v\n", err)
			cancel()
		}
	}

	wg.Wait()
	sess.Tx.Close()
}

func runInBackground(wg *sync.WaitGroup, errCh chan<- error, name string, fn func() error) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] %v\n", name, err)
			errCh <- err
		}
	}()
}
