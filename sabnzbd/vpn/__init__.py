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
sabnzbd.vpn - Native multi-WireGuard VPN routing subsystem.

Lets a user upload multiple WireGuard .conf files, keeps every enabled
tunnel up simultaneously via per-tunnel source-based policy routing (see
routing.py), benchmarks them against the primary NNTP server (benchmark.py)
and routes NNTP traffic through whichever tunnel is currently best
(manager.py), with an optional kill switch that blocks downloading rather
than ever falling back to the bare WAN.

Linux-only in V1 (interface/route management relies on `wg`/`ip`). This
package is always safe to import on any platform: is_platform_supported()
is the single gate everything else in the package - and every integration
point elsewhere in SABnzbd - checks before doing anything OS-specific.

Submodules:
    models    - plain dataclasses/enums, no I/O
    wireguard - subprocess wrapper around `wg`/`ip`, .conf parsing/validation
    routing   - Linux policy-routing (one table per tunnel)
    benchmark - TCP-connect latency measurement against the primary NNTP server
    manager   - VPNManager, the single coordinator the rest of SABnzbd talks to
"""

import sabnzbd


def is_platform_supported() -> bool:
    """WireGuard VPN routing (interface/route management via `wg`/`ip`) is
    only supported on Linux in V1."""
    return not sabnzbd.WINDOWS and not sabnzbd.MACOS
