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
sabnzbd.vpn.wireguard - Thin wrapper around the `wg`/`ip` command-line tools.

Every external command is invoked via subprocess.run() with an argument
array (shell=False, always) - never shell=True, never string-formatted into
a shell command, so there is no command-injection surface here even though
some values (profile names, uploaded file content) are user-controlled.

SABnzbd only ever creates/removes/inspects interfaces whose name starts with
IFACE_PREFIX ("wg-sab-"). That prefix is the *only* signal used anywhere in
this module (and in routing.py, via the table-number range) to decide "is
this something SABnzbd owns" - nothing outside that naming scheme is ever
touched, so a stale or foreign WireGuard interface on the host is never at
risk of being altered or removed.

Private keys are handled as briefly as possible: parse_conf() extracts one
from the uploaded text purely to hand it to `wg setconf` (via a temp/target
file, never via argv or logging), and the returned ParsedWireGuardConf
object masks the key in its repr so an accidental log/print/debug dump can
never leak it.
"""

import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

WG_BIN = "wg"
IP_BIN = "ip"

# Sole ownership marker for interfaces SABnzbd creates/removes/inspects.
IFACE_PREFIX = "wg-sab-"

_DEFAULT_TIMEOUT = 10.0


class VPNError(Exception):
    """Base class for all VPN subsystem errors."""


class VPNBinaryMissingError(VPNError):
    """The `wg` or `ip` binary could not be found."""


class VPNPermissionError(VPNError):
    """Missing capability (e.g. CAP_NET_ADMIN) or otherwise not permitted."""


class VPNValidationError(VPNError):
    """A profile or operation failed validation before anything was touched."""


class VPNSubprocessError(VPNError):
    """A wg/ip invocation failed for a reason other than missing-binary/permission."""

    def __init__(self, message: str, returncode: Optional[int] = None):
        super().__init__(message)
        self.returncode = returncode


@dataclass
class ParsedPeer:
    public_key: str
    endpoint_host: Optional[str]
    endpoint_port: Optional[int]
    allowed_ips: list[str] = field(default_factory=list)


@dataclass
class ParsedWireGuardConf:
    """Result of parsing an uploaded .conf. Deliberately short-lived: manager.py
    uses it only long enough to write the .conf file to disk and populate a
    WireGuardProfile (which never carries the key). Never serialize this with
    dataclasses.asdict()/vars() for anything user-facing - use safe_summary()."""

    private_key: str
    address: str  # "ip/prefixlen", e.g. "10.50.0.2/32"
    peers: list[ParsedPeer] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"ParsedWireGuardConf(address={self.address!r}, peers={len(self.peers)}, private_key=<redacted>)"

    __str__ = __repr__

    def safe_summary(self) -> dict:
        """Metadata safe to log/return via the API - never the private key."""
        return {"address": self.address, "peer_count": len(self.peers)}


def run_command(args: list[str], timeout: float = _DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a wg/ip command safely (argument array, shell=False always).

    Raises VPNBinaryMissingError, VPNPermissionError or VPNSubprocessError.
    Never includes file contents in `args`, so nothing sensitive ever reaches
    argv, logs, or exception messages via this helper.
    """
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
    except FileNotFoundError:
        raise VPNBinaryMissingError(f"Required binary not found: {args[0]}")
    except subprocess.TimeoutExpired:
        raise VPNSubprocessError(f"Command timed out: {' '.join(args[:2])}")

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if "Operation not permitted" in stderr or "not permitted" in stderr.lower():
            raise VPNPermissionError(f"Permission denied running '{' '.join(args[:2])}': {stderr}")
        raise VPNSubprocessError(f"'{' '.join(args[:2])}' failed: {stderr}", returncode=result.returncode)
    return result


def wg_binary_available() -> bool:
    """True if both required binaries are present on PATH."""
    return shutil.which(WG_BIN) is not None and shutil.which(IP_BIN) is not None


def _ip_json_link_show(name: Optional[str] = None) -> list[dict]:
    """Return `ip -json link show [name]` parsed, or [] on any failure.
    Never raises - callers use this for best-effort state inspection."""
    args = [IP_BIN, "-json", "link", "show"]
    if name:
        args.append(name)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5, shell=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout or "[]")
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []


def interface_exists(name: str) -> bool:
    return bool(_ip_json_link_show(name))


def interface_is_up(name: str) -> bool:
    """Cheap, read-only check: interface exists, is administratively UP, and
    its operstate isn't DOWN (WireGuard interfaces commonly report UNKNOWN
    operstate since there's no physical carrier detection)."""
    entries = _ip_json_link_show(name)
    if not entries:
        return False
    entry = entries[0]
    flags = entry.get("flags", [])
    return "UP" in flags and entry.get("operstate") != "DOWN"


def list_sabnzbd_interfaces() -> list[str]:
    """All interfaces on the host whose name matches SABnzbd's naming
    convention - the sole mechanism used to determine "does SABnzbd own
    this". Never inspects or returns anything outside that prefix."""
    return [entry["ifname"] for entry in _ip_json_link_show() if str(entry.get("ifname", "")).startswith(IFACE_PREFIX)]


# `wg setconf` only understands this strict subset of wg-quick's .conf syntax
# (see wg(8)) - everything else (Address, DNS, MTU, Table, PreUp/PostUp/...)
# is a wg-quick-only directive that wg-quick itself strips before ever
# calling `wg setconf`. Since we deliberately don't use wg-quick (no
# PostUp/PreDown script execution, no automatic default-route replacement),
# we have to do that same stripping ourselves.
_WG_SETCONF_INTERFACE_KEYS = {"privatekey", "listenport", "fwmark"}
_WG_SETCONF_PEER_KEYS = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}


def _strip_to_wg_setconf_format(conf_text: str) -> str:
    """Reduce a wg-quick-style .conf to just the keys `wg setconf` accepts."""
    lines: list[str] = []
    section: Optional[str] = None
    for raw_line in conf_text.splitlines():
        stripped = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            if section in ("interface", "peer"):
                lines.append(f"[{section.capitalize()}]")
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key_lower = key.strip().lower()
        if section == "interface" and key_lower in _WG_SETCONF_INTERFACE_KEYS:
            lines.append(f"{key.strip()} = {value.strip()}")
        elif section == "peer" and key_lower in _WG_SETCONF_PEER_KEYS:
            lines.append(f"{key.strip()} = {value.strip()}")
    return "\n".join(lines) + "\n"


def create_interface(name: str, conf_path: str) -> None:
    """Create (if missing) a WireGuard interface and (re-)load its crypto
    config. Idempotent and safe to call repeatedly - `wg setconf` fully
    replaces the interface's key/peer config each time, which is exactly
    what we want for self-healing a tunnel that ended up half-configured.

    Deliberately does NOT use `wg-quick`: no PostUp/PreDown script execution
    (arbitrary shell snippets from an uploaded file are never a good idea),
    no automatic default-route replacement. Just the kernel interface plus
    `wg setconf`, matching the "keep every tunnel up, route with policy
    rules" design - routing is handled separately by routing.py.
    """
    if not name.startswith(IFACE_PREFIX):
        raise VPNValidationError(f"Refusing to manage non-SABnzbd interface name: {name}")
    if not wg_binary_available():
        raise VPNBinaryMissingError("The 'wg' and/or 'ip' command was not found on this system")
    if not interface_exists(name):
        run_command([IP_BIN, "link", "add", name, "type", "wireguard"])

    try:
        with open(conf_path) as fp:
            raw_conf_text = fp.read()
    except OSError as exc:
        raise VPNSubprocessError(f"Could not read stored configuration for {name}: {exc}")

    setconf_text = _strip_to_wg_setconf_format(raw_conf_text)

    # wg setconf needs a real file path - write the filtered (still
    # key-bearing) text to a private temp file for the duration of the
    # call only, never the original upload path itself.
    fd, temp_path = tempfile.mkstemp(prefix="sab-wg-", suffix=".conf")
    try:
        os.chmod(temp_path, 0o600)
        with os.fdopen(fd, "w") as fp:
            fp.write(setconf_text)
        # `wg setconf` reads the private key from the file itself - it never
        # appears in argv, logs, or any exception raised here.
        run_command([WG_BIN, "setconf", name, temp_path])
    finally:
        with suppress(OSError):
            os.remove(temp_path)


_ADDRESS_ALREADY_PRESENT_MARKERS = ("file exists", "already assigned")


def assign_tunnel_address(name: str, tunnel_ip: str, prefix: int) -> None:
    """Assign the tunnel's own address and bring the interface up. Idempotent:
    re-adding an already-present address is treated as success.

    Different iproute2 versions report this differently for the exact same
    condition - older ones surface the raw kernel errno text ("RTNETLINK
    answers: File exists"), newer ones give a friendlier per-family message
    ("Error: ipv4: Address already assigned."/"ipv6: ..."). Both markers are
    checked so this stays idempotent across iproute2 versions.
    """
    if not name.startswith(IFACE_PREFIX):
        raise VPNValidationError(f"Refusing to manage non-SABnzbd interface name: {name}")
    try:
        run_command([IP_BIN, "address", "add", f"{tunnel_ip}/{prefix}", "dev", name])
    except VPNSubprocessError as exc:
        message = str(exc).lower()
        if not any(marker in message for marker in _ADDRESS_ALREADY_PRESENT_MARKERS):
            raise
    run_command([IP_BIN, "link", "set", name, "up"])


def remove_interface(name: str) -> None:
    """Remove a SABnzbd-owned interface. Idempotent - removing an interface
    that's already gone is not an error."""
    if not name.startswith(IFACE_PREFIX):
        raise VPNValidationError(f"Refusing to remove non-SABnzbd interface name: {name}")
    try:
        run_command([IP_BIN, "link", "delete", name])
    except VPNSubprocessError as exc:
        message = str(exc)
        if "Cannot find device" not in message and "does not exist" not in message:
            raise


def write_conf_file(path: str, conf_bytes: bytes) -> None:
    """Write an uploaded .conf to its final location with restrictive (0600)
    permissions from the moment it's created, avoiding any TOCTOU window
    where the file would briefly be readable with default permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(conf_bytes)
    except Exception:
        with suppress(OSError):
            os.remove(path)
        raise


def _split_endpoint(raw: str) -> tuple[Optional[str], Optional[int]]:
    """Split a WireGuard "Endpoint" value (host:port, or [ipv6]:port) into
    (host, port). Returns (None, None) if it can't be parsed - never raises."""
    try:
        parsed = urlsplit("//" + raw.strip())
        if not parsed.hostname or parsed.port is None:
            return None, None
        return parsed.hostname, parsed.port
    except ValueError:
        return None, None


def parse_conf(conf_text: str) -> tuple[Optional[ParsedWireGuardConf], list[str]]:
    """Parse (and syntactically validate) a WireGuard .conf file's text.

    Never raises, regardless of how malformed the input is. Returns
    (profile, []) on success, or (None, [error, ...]) if the file cannot be
    used. Checks, per the upload-validation requirements: [Interface]
    exists, a PrivateKey exists, at least one [Peer] exists, each peer has
    an Endpoint and parseable AllowedIPs, and the interface Address parses.
    """
    errors: list[str] = []
    section: Optional[str] = None
    interface_values: dict[str, str] = {}
    peer_blocks: list[dict[str, str]] = []
    current_peer: Optional[dict[str, str]] = None

    for raw_line in conf_text.splitlines():
        # Strip inline comments (# or ;) and whitespace
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                current_peer = {}
                peer_blocks.append(current_peer)
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if section == "interface":
            interface_values[key] = value
        elif section == "peer" and current_peer is not None:
            current_peer[key] = value

    if not interface_values:
        errors.append(T("Missing [Interface] section"))

    private_key = interface_values.get("privatekey", "")
    if not private_key:
        errors.append(T("Missing PrivateKey in [Interface] section"))

    address_value: Optional[str] = None
    address_raw = interface_values.get("address", "")
    if not address_raw:
        errors.append(T("Missing Address in [Interface] section"))
    else:
        first_address = address_raw.split(",")[0].strip()
        try:
            address_value = str(ipaddress.ip_interface(first_address))
        except ValueError:
            errors.append(T('Could not parse interface Address "%s"') % first_address)

    if not peer_blocks:
        errors.append(T("At least one [Peer] section is required"))

    peers: list[ParsedPeer] = []
    for index, peer_values in enumerate(peer_blocks, start=1):
        public_key = peer_values.get("publickey", "")
        if not public_key:
            errors.append(T("Peer %s is missing PublicKey") % index)

        endpoint_host: Optional[str] = None
        endpoint_port: Optional[int] = None
        endpoint_raw = peer_values.get("endpoint", "")
        if not endpoint_raw:
            errors.append(T("Peer %s is missing Endpoint") % index)
        else:
            endpoint_host, endpoint_port = _split_endpoint(endpoint_raw)
            if endpoint_host is None or endpoint_port is None:
                errors.append(T('Could not parse peer Endpoint "%s"') % endpoint_raw)

        allowed_ips_raw = peer_values.get("allowedips", "")
        allowed_ips = [entry.strip() for entry in allowed_ips_raw.split(",") if entry.strip()]
        if not allowed_ips:
            errors.append(T("Peer %s is missing AllowedIPs") % index)
        else:
            for allowed_ip in allowed_ips:
                try:
                    ipaddress.ip_network(allowed_ip, strict=False)
                except ValueError:
                    errors.append(T('Could not parse AllowedIPs entry "%s"') % allowed_ip)

        peers.append(
            ParsedPeer(
                public_key=public_key,
                endpoint_host=endpoint_host,
                endpoint_port=endpoint_port,
                allowed_ips=allowed_ips,
            )
        )

    if errors or address_value is None:
        return None, errors

    return ParsedWireGuardConf(private_key=private_key, address=address_value, peers=peers), []


def validate_conf(parsed: ParsedWireGuardConf, existing_tunnel_ips: set[str]) -> list[str]:
    """Additional semantic validation that needs knowledge beyond the file
    itself - currently just duplicate/conflicting tunnel IP detection
    against already-stored profiles. Never raises."""
    errors: list[str] = []
    try:
        tunnel_ip = str(ipaddress.ip_interface(parsed.address).ip)
    except ValueError:
        return [T("Could not parse interface Address")]
    if tunnel_ip in existing_tunnel_ips:
        errors.append(T("Tunnel IP %s is already used by another VPN profile") % tunnel_ip)
    return errors
