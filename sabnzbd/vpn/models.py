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
sabnzbd.vpn.models - Data models for the WireGuard VPN subsystem.

Pure dataclasses/enums only: no I/O, no subprocess/socket usage. This keeps
the module trivially importable and unit-testable on every platform, and
keeps the "what does a profile/result look like" definitions in one place
shared by wireguard.py, routing.py, benchmark.py and manager.py.

None of these types ever carry a WireGuard private key - only wireguard.py's
short-lived internal parsing result does, and that is never returned to any
of the other modules.
"""

import enum
import time
from dataclasses import dataclass, field
from typing import Optional


class VPNSelectionStrategy(enum.Enum):
    """VPN selection strategies. LOWEST_LATENCY and BALANCED are implemented;
    the rest are reserved so future strategies can be added without
    reworking every call site that references a strategy.

    BALANCED combines each round's fresh latency benchmark with the most
    recent manual bandwidth-test result (see VPNManager._compute_scores());
    a profile that's never had a bandwidth test yet is scored on latency
    alone rather than penalized for missing data.
    """

    LOWEST_LATENCY = "lowest_latency"
    BALANCED = "balanced"
    HIGHEST_THROUGHPUT = "highest_throughput"  # reserved, not implemented
    MANUAL = "manual"  # reserved, not implemented

    @classmethod
    def from_value(cls, value: str) -> "VPNSelectionStrategy":
        """Convert a stored config string to a strategy, falling back to
        LOWEST_LATENCY for unknown/legacy/not-yet-implemented values."""
        try:
            strategy = cls(value)
        except ValueError:
            return cls.LOWEST_LATENCY
        if strategy in (cls.HIGHEST_THROUGHPUT, cls.MANUAL):
            # Reserved for future implementation
            return cls.LOWEST_LATENCY
        return strategy


@dataclass
class WireGuardProfile:
    """Metadata for a single WireGuard tunnel managed by SABnzbd.

    Never carries the private key - only the path to the 0600 .conf file
    that does, and that path is only ever used by wireguard.py to invoke
    `wg setconf`.
    """

    uuid: str
    name: str
    interface: str  # "wg-sab-<index>", assigned internally, never from the upload
    interface_index: int
    conf_path: str  # path to the 0600 .conf file; content is never read here
    enabled: bool
    endpoint_host: str
    endpoint_port: int
    tunnel_ip: str  # parsed from [Interface] Address
    tunnel_prefix: int
    routing_table: int
    created: float = field(default_factory=time.time)

    @property
    def endpoint(self) -> str:
        return f"{self.endpoint_host}:{self.endpoint_port}"


@dataclass
class VPNBenchmarkResult:
    """Result of benchmarking one profile's path to the primary NNTP server.
    Always produced, even on total failure - benchmark.py never raises."""

    profile_uuid: str
    healthy: bool
    latency_samples_ms: list[float]
    median_latency_ms: Optional[float]
    error: Optional[str]
    timestamp: float = field(default_factory=time.time)


@dataclass
class VPNBandwidthResult:
    """Result of a manual, on-demand bandwidth test for one profile, using
    SABnzbd's existing test-download mechanism (sabnzbd.internetspeed)
    bound to the tunnel's source address. This is a separate, explicit
    action from the lightweight latency benchmark above - never run
    automatically or as part of VPN selection in V1."""

    profile_uuid: str
    healthy: bool
    mbps: Optional[float]
    error: Optional[str]
    timestamp: float = field(default_factory=time.time)


@dataclass
class VPNStatus:
    """Snapshot of overall VPN subsystem state, safe to expose via the API
    and web UI in full - contains no secrets."""

    platform_supported: bool
    enabled: bool
    killswitch: bool
    selection_mode: VPNSelectionStrategy
    active_profile_uuid: Optional[str]
    active_profile_name: Optional[str]
    active_latency_ms: Optional[float]
    killswitch_active: bool  # True = currently blocking downloads
    reason: Optional[str]  # human-readable status/error, for UI/API only
