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
tests.test_vpn_config - Tests of WireGuard .conf parsing/validation and
ConfigVPNProfile persistence, and outgoing_nntp_ip backward compatibility.
"""

from unittest import mock

import pytest

import sabnzbd
import sabnzbd.config as config
import sabnzbd.vpn.manager as manager
import sabnzbd.vpn.wireguard as wireguard

VALID_CONF = """
[Interface]
PrivateKey = cGl2YXRla2V5c2VjcmV0dmFsdWUxMjM0NTY3ODkwMTI=
Address = 10.50.0.2/32

[Peer]
PublicKey = cHVibGlja2V5dmFsdWUxMjM0NTY3ODkwMTIzNDU2Nzg=
Endpoint = vpn.example.net:51820
AllowedIPs = 0.0.0.0/0
"""


class TestConfParsing:
    def test_valid_conf_parses(self):
        parsed, errors = wireguard.parse_conf(VALID_CONF)
        assert errors == []
        assert parsed is not None
        assert parsed.address == "10.50.0.2/32"
        assert len(parsed.peers) == 1
        assert parsed.peers[0].endpoint_host == "vpn.example.net"
        assert parsed.peers[0].endpoint_port == 51820
        assert parsed.peers[0].allowed_ips == ["0.0.0.0/0"]

    def test_missing_interface_section(self):
        parsed, errors = wireguard.parse_conf("[Peer]\nPublicKey = x\nEndpoint = a:1\nAllowedIPs = 0.0.0.0/0\n")
        assert parsed is None
        assert any("Interface" in e for e in errors)

    def test_missing_private_key(self):
        conf = "[Interface]\nAddress = 10.50.0.2/32\n\n[Peer]\nPublicKey = x\nEndpoint = a:1\nAllowedIPs = 0.0.0.0/0\n"
        parsed, errors = wireguard.parse_conf(conf)
        assert parsed is None
        assert any("PrivateKey" in e for e in errors)

    def test_missing_peer_section(self):
        conf = "[Interface]\nPrivateKey = x\nAddress = 10.50.0.2/32\n"
        parsed, errors = wireguard.parse_conf(conf)
        assert parsed is None
        assert any("Peer" in e for e in errors)

    def test_missing_peer_endpoint(self):
        conf = "[Interface]\nPrivateKey = x\nAddress = 10.50.0.2/32\n\n[Peer]\nPublicKey = y\nAllowedIPs = 0.0.0.0/0\n"
        parsed, errors = wireguard.parse_conf(conf)
        assert parsed is None
        assert any("Endpoint" in e for e in errors)

    def test_unparseable_allowed_ips(self):
        conf = "[Interface]\nPrivateKey = x\nAddress = 10.50.0.2/32\n\n[Peer]\nPublicKey = y\nEndpoint = a:1\nAllowedIPs = not-an-ip\n"
        parsed, errors = wireguard.parse_conf(conf)
        assert parsed is None
        assert any("AllowedIPs" in e for e in errors)

    def test_unparseable_address(self):
        conf = "[Interface]\nPrivateKey = x\nAddress = not-an-address\n\n[Peer]\nPublicKey = y\nEndpoint = a:1\nAllowedIPs = 0.0.0.0/0\n"
        parsed, errors = wireguard.parse_conf(conf)
        assert parsed is None
        assert any("Address" in e for e in errors)

    def test_completely_garbage_input_never_raises(self):
        parsed, errors = wireguard.parse_conf("this is not a wireguard config at all\n\n\x00\x01binary")
        assert parsed is None
        assert errors  # some errors, but no exception

    def test_duplicate_tunnel_ip_rejected(self):
        parsed, errors = wireguard.parse_conf(VALID_CONF)
        assert parsed is not None
        errors = wireguard.validate_conf(parsed, existing_tunnel_ips={"10.50.0.2"})
        assert any("already used" in e for e in errors)

    def test_unique_tunnel_ip_accepted(self):
        parsed, errors = wireguard.parse_conf(VALID_CONF)
        assert parsed is not None
        errors = wireguard.validate_conf(parsed, existing_tunnel_ips={"10.51.0.2"})
        assert errors == []


class TestPrivateKeySafety:
    def test_repr_never_contains_private_key(self):
        parsed, _ = wireguard.parse_conf(VALID_CONF)
        assert "cGl2YXRla2V5" not in repr(parsed)
        assert "cGl2YXRla2V5" not in str(parsed)

    def test_safe_summary_excludes_private_key(self):
        parsed, _ = wireguard.parse_conf(VALID_CONF)
        summary = parsed.safe_summary()
        assert "private_key" not in summary
        assert "cGl2YXRla2V5" not in str(summary)

    def test_get_profiles_public_never_includes_conf_path_or_key(self):
        vpn_manager = manager.VPNManager()
        profile = mock.Mock()
        profile.uuid = "abc123"
        profile.name = "Frankfurt"
        profile.interface = "wg-sab-0"
        profile.interface_index = 0
        profile.endpoint = "vpn.example.net:51820"
        profile.enabled = True
        vpn_manager.profiles = {"abc123": profile}
        public = vpn_manager.get_profiles_public()
        assert len(public) == 1
        assert "conf_path" not in public[0]
        assert "private_key" not in public[0]
        assert set(public[0]) == {
            "id",
            "name",
            "interface",
            "endpoint",
            "enabled",
            "healthy",
            "latency_ms",
            "error",
            "bandwidth_mbps",
            "selected",
        }

    def test_config_vpn_profile_get_dict_excludes_conf_path_for_public_api(self):
        profile = config.ConfigVPNProfile(
            "keytest",
            {
                "display_name": "Test",
                "interface": "wg-sab-0",
                "conf_path": "/secret/path/keytest.conf",
            },
        )
        try:
            public_dict = profile.get_dict(for_public_api=True)
            full_dict = profile.get_dict(for_public_api=False)
            assert "conf_path" not in public_dict
            assert full_dict["conf_path"] == "/secret/path/keytest.conf"
        finally:
            profile.delete()


class TestConfigVPNProfilePersistence:
    def test_round_trips_through_special_sections(self):
        profile = config.ConfigVPNProfile(
            "roundtrip",
            {
                "display_name": "Zurich",
                "interface": "wg-sab-2",
                "interface_index": 2,
                "enabled": True,
                "endpoint_host": "zurich.example.net",
                "endpoint_port": 51820,
                "tunnel_ip": "10.52.0.2",
                "tunnel_prefix": 32,
                "conf_path": "/tmp/roundtrip.conf",
                "created": 100.0,
            },
        )
        try:
            assert "roundtrip" in config.get_vpn_profiles()
            fetched = config.get_config("vpn_profiles", "roundtrip")
            assert fetched is profile
            assert fetched.display_name() == "Zurich"
            assert fetched.interface() == "wg-sab-2"
            assert fetched.tunnel_ip() == "10.52.0.2"
        finally:
            profile.delete()
        assert "roundtrip" not in config.get_vpn_profiles()

    def test_special_sections_registration(self):
        assert config.CONFIG.SPECIAL_SECTIONS.get("vpn_profiles") is config.ConfigVPNProfile


class TestWgSetconfStripping:
    """Regression tests for a real-world bug: `wg setconf` only understands a
    strict subset of wg-quick's .conf syntax (PrivateKey/ListenPort/FwMark +
    peer crypto fields) - wg-quick itself strips everything else (Address,
    DNS, MTU, ...) before calling it. Since we deliberately don't use
    wg-quick, we have to do that stripping ourselves, or `wg setconf` fails
    outright and the tunnel never gets its key/peer config applied."""

    DUAL_STACK_CONF = (
        "[Interface]\n"
        "PrivateKey = cGl2YXRla2V5c2VjcmV0dmFsdWUxMjM0NTY3ODkwMTI=\n"
        "Address = 10.68.155.86/32,fc00:bbbb:bbbb:bb01::5:9b55/128\n"
        "DNS = 10.64.0.1\n"
        "\n"
        "[Peer]\n"
        "PublicKey = cHVibGlja2V5dmFsdWUxMjM0NTY3ODkwMTIzNDU2Nzg=\n"
        "Endpoint = 80.66.197.3:51820\n"
        "AllowedIPs = 0.0.0.0/0,::/0\n"
    )

    def test_strips_address_and_dns_keeps_crypto_fields(self):
        result = wireguard._strip_to_wg_setconf_format(self.DUAL_STACK_CONF)
        assert "Address" not in result
        assert "DNS" not in result
        assert "PrivateKey" in result
        assert "PublicKey" in result
        assert "Endpoint" in result
        assert "AllowedIPs" in result

    def test_create_interface_never_passes_address_line_to_wg_setconf(self, tmp_path):
        conf_path = tmp_path / "profile.conf"
        conf_path.write_text(self.DUAL_STACK_CONF)

        setconf_calls = []

        def fake_run(args, **kwargs):
            if args[:2] == ["wg", "setconf"]:
                setconf_calls.append(open(args[3]).read())
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run), mock.patch(
            "sabnzbd.vpn.wireguard.wg_binary_available", return_value=True
        ):
            wireguard.create_interface("wg-sab-0", str(conf_path))

        assert len(setconf_calls) == 1
        assert "Address" not in setconf_calls[0]
        assert "PrivateKey" in setconf_calls[0]

    def test_create_interface_cleans_up_temp_file(self, tmp_path):
        conf_path = tmp_path / "profile.conf"
        conf_path.write_text(self.DUAL_STACK_CONF)
        temp_paths_seen = []

        def fake_run(args, **kwargs):
            if args[:2] == ["wg", "setconf"]:
                temp_paths_seen.append(args[3])
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run), mock.patch(
            "sabnzbd.vpn.wireguard.wg_binary_available", return_value=True
        ):
            wireguard.create_interface("wg-sab-0", str(conf_path))

        assert len(temp_paths_seen) == 1
        assert not __import__("os").path.exists(temp_paths_seen[0])

    def test_create_interface_is_idempotent_and_reapplies_setconf(self, tmp_path):
        """The self-healing fix: create_interface() must re-run `wg setconf`
        even when the interface link already exists, so a tunnel that ended
        up half-configured (link up, no key/peer) can recover on retry."""
        conf_path = tmp_path / "profile.conf"
        conf_path.write_text(self.DUAL_STACK_CONF)
        setconf_call_count = 0

        def fake_run(args, **kwargs):
            nonlocal setconf_call_count
            if args[:2] == ["wg", "setconf"]:
                setconf_call_count += 1
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run), mock.patch(
            "sabnzbd.vpn.wireguard.interface_exists", return_value=True
        ), mock.patch("sabnzbd.vpn.wireguard.wg_binary_available", return_value=True):
            wireguard.create_interface("wg-sab-0", str(conf_path))
            wireguard.create_interface("wg-sab-0", str(conf_path))

        assert setconf_call_count == 2


class TestAssignTunnelAddressIdempotency:
    """Regression tests: different iproute2 versions report "address already
    present" with different stderr text for the exact same condition. Both
    forms must be treated as success, not a hard failure, or every bring-up
    after the first one fails even though the tunnel is actually fine."""

    def _run_with_stderr(self, stderr_text):
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            if args[:3] == ["ip", "address", "add"]:
                return mock.Mock(returncode=2, stdout="", stderr=stderr_text)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            wireguard.assign_tunnel_address("wg-sab-0", "10.68.155.86", 32)
        return calls

    def test_legacy_file_exists_message_is_idempotent(self):
        calls = self._run_with_stderr("RTNETLINK answers: File exists")
        assert ["ip", "link", "set", "wg-sab-0", "up"] in calls

    def test_modern_already_assigned_message_is_idempotent(self):
        calls = self._run_with_stderr("Error: ipv4: Address already assigned.")
        assert ["ip", "link", "set", "wg-sab-0", "up"] in calls

    def test_unrelated_error_still_raises(self):
        with pytest.raises(wireguard.VPNSubprocessError):
            self._run_with_stderr("Error: Nexthop has invalid gateway.")


class TestOutgoingIpBackwardCompat:
    @pytest.mark.config({"vpn_enabled": False, "outgoing_nntp_ip": "1.2.3.4"})
    def test_vpn_disabled_returns_plain_outgoing_ip(self, monkeypatch):
        monkeypatch.setattr(sabnzbd, "VPNManager", mock.Mock(killswitch_active=False), raising=False)
        assert manager.get_effective_outgoing_nntp_ip() == "1.2.3.4"

    @pytest.mark.config({"vpn_enabled": True, "outgoing_nntp_ip": "1.2.3.4"})
    def test_vpn_enabled_but_no_manager_falls_back(self, monkeypatch):
        monkeypatch.setattr(sabnzbd, "VPNManager", None, raising=False)
        assert manager.get_effective_outgoing_nntp_ip() == "1.2.3.4"

    @pytest.mark.config({"vpn_enabled": True, "outgoing_nntp_ip": "1.2.3.4"})
    def test_vpn_enabled_no_active_bind_ip_falls_back(self, monkeypatch):
        fake_manager = mock.Mock(killswitch_active=False)
        fake_manager.get_effective_bind_ip.return_value = None
        monkeypatch.setattr(sabnzbd, "VPNManager", fake_manager, raising=False)
        assert manager.get_effective_outgoing_nntp_ip() == "1.2.3.4"

    @pytest.mark.config({"vpn_enabled": True, "outgoing_nntp_ip": "1.2.3.4"})
    def test_vpn_enabled_with_active_bind_ip_takes_priority(self, monkeypatch):
        fake_manager = mock.Mock(killswitch_active=False)
        fake_manager.get_effective_bind_ip.return_value = "10.50.0.2"
        monkeypatch.setattr(sabnzbd, "VPNManager", fake_manager, raising=False)
        assert manager.get_effective_outgoing_nntp_ip() == "10.50.0.2"

    @pytest.mark.config({"vpn_enabled": True, "outgoing_nntp_ip": "1.2.3.4"})
    def test_killswitch_active_never_falls_back_to_wan(self, monkeypatch):
        fake_manager = mock.Mock(killswitch_active=True)
        monkeypatch.setattr(sabnzbd, "VPNManager", fake_manager, raising=False)
        with pytest.raises(ConnectionError):
            manager.get_effective_outgoing_nntp_ip()
