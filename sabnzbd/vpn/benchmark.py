#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
sabnzbd.vpn.benchmark - Measure each VPN tunnel's latency to the primary
NNTP server (not a generic public endpoint) by opening plain TCP connections
bound to the tunnel's own source address.

This is the path that actually matters for SABnzbd: how fast can a
connection bound to this tunnel reach the configured Usenet server. It says
nothing about a VPN's own network health beyond that, which is intentional -
V1 explicitly measures the path used for real downloads rather than a
proxy metric like a public DNS resolver.

Never raises: every socket operation is wrapped, and a failure - timeout,
refused connection, DNS failure, tunnel not up so bind() fails - is recorded
in the returned VPNBenchmarkResult rather than propagated.

Also provides measure_bandwidth(), a separate manual/on-demand throughput
test that reuses SABnzbd's existing internetspeed test-download mechanism.
It is not part of automatic VPN selection in V1 - see VPNSelectionStrategy
in models.py for the (reserved, unimplemented) HIGHEST_THROUGHPUT strategy
this could eventually feed.
"""

import socket
import statistics
import time

import sabnzbd.internetspeed as internetspeed
from sabnzbd.vpn.models import VPNBandwidthResult, VPNBenchmarkResult, WireGuardProfile

# Same MB/s -> Mbps conversion sabnzbd.internetspeed itself uses for its
# debug log and dashboard figure - kept identical here for consistency.
_MB_TO_MBIT = 8.05


def benchmark_profile(
    profile: WireGuardProfile,
    nntp_host: str,
    nntp_port: int,
    samples: int,
    timeout: float,
) -> VPNBenchmarkResult:
    """Bind a TCP socket to `profile.tunnel_ip` and time `samples` connects
    to (nntp_host, nntp_port). Returns the median of the successful samples;
    `healthy` is True as long as at least one sample succeeded."""
    latencies: list[float] = []
    last_error: str = ""

    for _ in range(max(1, samples)):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.bind((profile.tunnel_ip, 0))
            start = time.monotonic()
            sock.connect((nntp_host, nntp_port))
            latencies.append((time.monotonic() - start) * 1000.0)
        except (TimeoutError, socket.error, OSError) as exc:
            last_error = str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    if not latencies:
        return VPNBenchmarkResult(
            profile_uuid=profile.uuid,
            healthy=False,
            latency_samples_ms=[],
            median_latency_ms=None,
            error=last_error or "No successful connection",
        )

    return VPNBenchmarkResult(
        profile_uuid=profile.uuid,
        healthy=True,
        latency_samples_ms=latencies,
        median_latency_ms=statistics.median(latencies),
        error=None,
    )


def measure_bandwidth(profile: WireGuardProfile) -> VPNBandwidthResult:
    """Manual, on-demand bandwidth test: reuses SABnzbd's own built-in
    test-download mechanism (sabnzbd.internetspeed - the same one used for
    the general Config dashboard bandwidth figure), bound to the tunnel's
    source address instead of the host's normal outgoing interface.

    Deliberately a separate, explicit action from benchmark_profile() above:
    a real multi-second download, not a cheap connect-latency probe, and
    never run automatically or as part of VPN selection in V1.
    """
    speed_mb_per_sec = internetspeed.internetspeed_interal(family=socket.AF_INET, bind_ip=profile.tunnel_ip)
    if speed_mb_per_sec <= 0:
        return VPNBandwidthResult(profile_uuid=profile.uuid, healthy=False, mbps=None, error="No successful connection")
    return VPNBandwidthResult(profile_uuid=profile.uuid, healthy=True, mbps=round(speed_mb_per_sec * _MB_TO_MBIT, 2), error=None)
