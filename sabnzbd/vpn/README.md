# Multi-WireGuard VPN routing

Route your NNTP (Usenet) traffic through one of several WireGuard tunnels,
automatically chosen by which one currently gives you the best connection to
your Usenet provider. Upload as many WireGuard configs as you like, keep them
all connected at once, and let SABnzbd pick the best one before each
download — or pick one yourself.

Everything else about SABnzbd is unaffected: the web interface stays
reachable over your normal network, and if you turn VPN routing off, NNTP
connections behave exactly as they did before this feature existed.

**Linux only**, including inside Docker containers. On Windows/macOS, Config
> VPN shows a notice explaining that, and nothing else changes.

## Quick start

1. Open **Config > VPN**.
2. Click **+ Add WireGuard configuration**, give it a name (e.g. "Frankfurt"),
   and upload the `.conf` file for that server/location.
3. Repeat for every tunnel you want SABnzbd to be able to use. Each one gets
   its own internal interface (`wg-sab-0`, `wg-sab-1`, …) and stays up
   independently — you don't activate one at the expense of another.
4. Tick **Enable VPN routing**. Leave **Kill switch** on unless you have a
   specific reason not to (see below).
5. Save. SABnzbd brings up every enabled tunnel, benchmarks them against your
   primary Usenet server, and starts using the best one immediately.

That's it for normal use. The rest of this document covers how selection
works, what to do when something looks wrong, and Docker specifics.

### A note on VPN providers and multiple tunnels

Some WireGuard VPN providers (Mullvad is a common example) assign the same
internal client IP address to every server config generated from the same
account key. If you upload two configs like that, SABnzbd will reject the
second one with a "Tunnel IP is already used by another VPN profile" error —
this isn't a bug, it's a real constraint: SABnzbd tells tunnels apart by
their source IP, so two tunnels sharing one IP would make VPN selection have
no actual effect (the OS would always send traffic through whichever one it
saw first, regardless of which one SABnzbd "selected"). The fix is on the
provider side: generate a **separate WireGuard key** for each tunnel you want
to run simultaneously (most providers support several keys/devices per
account, and each one gets its own IP). Reusing one key across multiple
downloaded configs only works if you intend to use them one at a time.

## How automatic selection works

Before a new NZB becomes the active download (never per-article, never on a
timer), SABnzbd benchmarks every enabled, healthy tunnel with a handful of
plain TCP connects to your primary configured Usenet server and picks a
winner according to the selected strategy:

- **Lowest latency** (default) — the tunnel with the lowest median
  connect time wins.
- **Balanced (latency + bandwidth)** — combines that same fresh latency
  reading with the most recent result of a manual **Bandwidth test**
  (Config > VPN, per-profile or "Bandwidth test all"). A tunnel that's never
  had a bandwidth test yet is scored on latency alone, so it isn't
  penalized for missing data — but if you want bandwidth to actually
  influence selection, you need to click a bandwidth test at least once
  (and again whenever you want it refreshed; it's never run automatically,
  since a real bandwidth test moves real data and can take several seconds
  per tunnel — running it before every download would be slow and wasteful).

Either way, a **switch threshold** (default 10%) prevents flapping between
two near-identical tunnels: SABnzbd only switches away from your currently
active, still-healthy tunnel if a candidate is *meaningfully* better by that
margin. If the active tunnel goes unhealthy, SABnzbd switches immediately
regardless of the threshold — hysteresis only guards against small,
insignificant improvements, never against a real failure.

You can also click **Activate** on any enabled profile to force it active
right now, bypassing both the benchmark and the threshold.

## Kill switch

With the kill switch on (the default once VPN routing is enabled), SABnzbd
**never** falls back to your normal internet connection for NNTP traffic. If
no tunnel is healthy, downloading pauses with a clear status message
("Download paused: no healthy WireGuard VPN is available") instead of
quietly using your bare connection. If your active tunnel fails mid-download,
SABnzbd disconnects the affected connections, tries to fail over to another
healthy tunnel, and only pauses if none is available.

Turning the kill switch off is an explicit choice to allow that fallback: NNTP
traffic uses your normal `outgoing_nntp_ip` setting (or no restriction at all)
whenever no VPN tunnel is healthy.

## Dashboard indicator

A compact status box appears on the main queue page whenever VPN routing is
enabled: `VPN: Frankfurt · 18ms`, or `VPN: No healthy tunnel` if nothing is
currently active. It turns red when the kill switch is actively blocking
downloads. This is a status readout only — manage profiles from Config > VPN.

## Docker

WireGuard interface and routing management needs the `NET_ADMIN` capability.
**Unlike most WireGuard container tutorials, `/dev/net/tun` is *not* required**
— SABnzbd uses the Linux kernel's native WireGuard netdevice
(`ip link add type wireguard`), not the userspace `wireguard-go`/TUN
implementation most guides assume, so the extra device passthrough (and the
attack surface that comes with exposing it) isn't needed. This was verified
by actually running SABnzbd in a container with only `--cap-add=NET_ADMIN`.

```yaml
services:
  sabnzbd:
    image: your-sabnzbd-image
    cap_add:
      - NET_ADMIN
    volumes:
      - ./config:/config
```

The container also needs the WireGuard kernel module available on the
**host** — containers share the host's kernel and can't load their own
modules. Most current distributions ship it built in (`modinfo wireguard`
on the host to check); if not, `modprobe wireguard` on the host first, or
install `wireguard-dkms`/your distro's equivalent.

Without `NET_ADMIN`, VPN profiles are created but fail to come up with a
clear, non-fatal error (`VPN profile <name> could not be initialized:
CAP_NET_ADMIN is unavailable`) — normal, non-VPN downloading keeps working
exactly as before. SABnzbd doesn't assume it runs as root and never tries to
elevate its own privileges.

## Troubleshooting

**A profile shows "Unreachable" right after I upload it.**
Nothing is tested automatically on upload — click **Test** (or wait for VPN
routing to actually select among your tunnels, if it's enabled) to run a
benchmark. If it stays unreachable after that, check:
- Is `NET_ADMIN` granted (Docker) or are you running as a user that can
  manage network interfaces (bare Linux/LXC)?
- Does the host kernel have WireGuard support (`modinfo wireguard`)?
- Is the tunnel's `Endpoint` actually reachable from this host — firewalled
  networks sometimes block outbound UDP on the WireGuard port.
- Check the log around the time of the test for a specific error; SABnzbd
  logs both the OS-level failure (e.g. "CAP_NET_ADMIN is unavailable") and
  the benchmark result separately, so the log usually says exactly what
  went wrong.

**Uploading a second `.conf` fails with "Tunnel IP is already used by
another VPN profile".** See "A note on VPN providers and multiple tunnels"
above — you need a separate WireGuard key per simultaneous tunnel, not just
a second server config from the same key.

**I want to confirm traffic really isn't leaking outside the tunnel.**
From the host: `ss -tnp | grep :<nntp-port>` should show your NNTP
connections' local address as the tunnel's IP (`ip addr show wg-sab-0`),
never the host's normal address. A packet capture on the host's normal
interface for your Usenet server's IP/port should show nothing while a VPN'd
download is active; the same capture on the `wg-sab-*` interface should show
the traffic.

## Known limitations

- One active tunnel is shared by all configured NNTP servers — there's no
  per-server VPN selection yet.
- The `balanced` strategy's bandwidth component only updates when you
  manually run a bandwidth test (or "Bandwidth test all"); it does not
  refresh automatically before each job, since a real bandwidth test moves
  real data and takes several seconds per tunnel.
- `highest_throughput` and `manual` selection strategies are reserved in the
  code but not implemented yet.
- Tunnels are torn down on every clean SABnzbd restart and rebuilt on the
  next startup, rather than persisting across restarts.
- SABnzbd identifies its own routing rules/tables by a numeric range
  (`51820`–`52075`), since `ip rule show` output doesn't carry interface
  names. An unrelated process using a table number in that same range could
  in theory be misidentified as SABnzbd-owned during cleanup.
- IPv6 tunnel addresses parse correctly but aren't exercised by the routing
  or benchmarking code paths, or covered by the test suite, yet.
- If `vpn_enabled`/`vpn_killswitch` somehow get set on an unsupported
  platform (e.g. restoring a config exported from a Linux install onto
  Windows/macOS) the kill switch does not engage — it silently behaves as if
  VPN routing were off, with no tunnel and no protection. The Config > VPN
  page itself prevents enabling VPN routing on an unsupported platform, so
  this only matters if the setting is changed some other way (config file
  edit, restore, or the generic config API).

## For maintainers

Architecture: `sabnzbd/vpn/manager.py` is the single coordinator (thread-safe,
one lock) that everything else in SABnzbd talks to. `wireguard.py` wraps
`wg`/`ip` (argument-array `subprocess.run`, never `shell=True`) and does
`.conf` parsing/validation. `routing.py` does the per-tunnel policy routing.
`benchmark.py` does latency (TCP connect) and bandwidth (reuses
`sabnzbd.internetspeed`, bound to the tunnel's source address) measurement.
Integration with the rest of SABnzbd is deliberately narrow: `newswrapper.py`
calls `get_effective_outgoing_nntp_ip()` instead of reading
`cfg.outgoing_nntp_ip()` directly, and `nzbqueue.py` has a single cheap
id-diff check that notifies the manager once per newly-active NZB.

Run the tests:

```
pytest tests/test_vpn_manager.py tests/test_vpn_benchmark.py tests/test_vpn_routing.py tests/test_vpn_config.py
```

All OS-level operations (`subprocess`, sockets) are mocked — no real
WireGuard tunnel, network access, or root privileges are required. The
feature has also been validated against real WireGuard tunnels and real
NNTP traffic (including a live packet-capture leak check) on a Linux LXC
container and in Docker.
