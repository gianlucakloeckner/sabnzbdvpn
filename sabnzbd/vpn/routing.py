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
sabnzbd.vpn.routing - Linux source-based policy routing, one table per tunnel.

Design: every enabled WireGuard tunnel stays up simultaneously (no
"wg-quick down old / wg-quick up new" churn, no replacing the host's default
route). Instead, each tunnel gets its own routing table:

    ip route add default dev wg-sab-<n> table <BASE_TABLE + n>
    ip rule  add from <tunnel_ip>       table <BASE_TABLE + n>

Only traffic explicitly sourced from a tunnel's own address is affected -
sockets that don't bind to a tunnel IP keep using the host's normal default
route via table `main`, which this module never touches.

Why WireGuard's own UDP endpoint traffic can't recursively loop through its
own tunnel: an `ip rule from <tunnel_ip>` rule matches only packets whose
*source address* is that tunnel's own inner address. The WireGuard kernel
driver's outbound UDP encapsulation packets (the actual handshake/transport
traffic to the configured Endpoint) are emitted using the host's normal
default-route source address - the tunnel interface's address is only ever
meaningful for traffic *entering* the tunnel, not for the outer UDP socket
the kernel driver itself opens on the underlying interface. A `from
<tunnel_ip>` policy rule therefore structurally cannot capture that traffic,
so no additional exclusion rule is required and none is added here.

Ownership for reconciliation/cleanup is tracked purely by routing table
number, since `ip rule show` output carries no interface name: any rule or
table whose number falls inside [BASE_TABLE, BASE_TABLE + MAX_PROFILES) is
considered SABnzbd-owned. Nothing outside that range - and never `main`,
`default` or `local` - is ever modified or removed.
"""

import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from sabnzbd.vpn.wireguard import IP_BIN, VPNSubprocessError, run_command

# WireGuard's own default UDP port, reused here purely because it's a
# recognizable, unusual-enough base for operators to spot; it has no other
# significance and nothing depends on it matching an actual WireGuard port.
BASE_TABLE = 51820
MAX_PROFILES = 256
TABLE_RANGE = range(BASE_TABLE, BASE_TABLE + MAX_PROFILES)


def table_for_index(index: int) -> int:
    return BASE_TABLE + index


@dataclass
class ParsedRule:
    table: int
    source: Optional[str]


def setup_routing(interface: str, tunnel_ip: str, table: int) -> None:
    """Create the default route and source-based rule for one tunnel.
    Idempotent: re-running for an already-configured tunnel is a no-op."""
    try:
        run_command([IP_BIN, "route", "replace", "default", "dev", interface, "table", str(table)])
    except VPNSubprocessError as exc:
        raise VPNSubprocessError(f"Could not add routing table {table} for {interface}: {exc}")

    if not _rule_exists(tunnel_ip, table):
        run_command([IP_BIN, "rule", "add", "from", tunnel_ip, "table", str(table)])


def teardown_routing(tunnel_ip: Optional[str], table: int) -> None:
    """Remove the rule and flush the routing table for one tunnel.
    Idempotent: removing an already-absent rule/table is not an error."""
    if tunnel_ip:
        try:
            run_command([IP_BIN, "rule", "del", "from", tunnel_ip, "table", str(table)])
        except VPNSubprocessError as exc:
            if "not found" not in str(exc).lower() and "no such" not in str(exc).lower():
                raise
    try:
        run_command([IP_BIN, "route", "flush", "table", str(table)])
    except VPNSubprocessError as exc:
        if "not found" not in str(exc).lower() and "no such" not in str(exc).lower():
            raise


def _rule_exists(tunnel_ip: str, table: int) -> bool:
    for rule in list_sabnzbd_rules():
        if rule.table == table and rule.source == tunnel_ip:
            return True
    return False


# Matches lines like: "32764:	from 10.50.0.2 lookup 51820"
_RULE_LINE_RE = re.compile(r"from\s+(?P<source>\S+)\s+.*?lookup\s+(?P<table>\d+)")


def list_sabnzbd_rules() -> list[ParsedRule]:
    """All `ip rule` entries whose table falls inside SABnzbd's owned
    numeric range. This - not interface name, which `ip rule show` doesn't
    carry - is the sole ownership marker used for reconciliation/cleanup."""
    try:
        result = subprocess.run([IP_BIN, "rule", "show"], capture_output=True, text=True, timeout=5, shell=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    rules: list[ParsedRule] = []
    for line in result.stdout.splitlines():
        match = _RULE_LINE_RE.search(line)
        if not match:
            continue
        table = int(match.group("table"))
        if table in TABLE_RANGE:
            rules.append(ParsedRule(table=table, source=match.group("source")))
    return rules


def reconcile_stale_rules(expected: dict[int, str]) -> None:
    """Remove any SABnzbd-owned rule/table that doesn't match a currently
    expected (table -> tunnel_ip) mapping - cleans up leftovers from a prior
    crash or a profile that was since deleted/disabled. Never touches a rule
    or table outside the owned numeric range."""
    for rule in list_sabnzbd_rules():
        expected_source = expected.get(rule.table)
        if expected_source is None or expected_source != rule.source:
            teardown_routing(rule.source, rule.table)
