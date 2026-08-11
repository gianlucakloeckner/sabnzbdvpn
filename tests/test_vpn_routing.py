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
tests.test_vpn_routing - Tests of Linux source-based policy routing.
All subprocess calls are mocked - no real `ip`/root required.
"""

import subprocess
from unittest import mock

import sabnzbd.vpn.routing as routing
import sabnzbd.vpn.wireguard as wireguard


def make_completed(argv, stdout="", returncode=0):
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr="")


class TestRoutingSetup:
    def test_setup_routing_issues_expected_commands(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            if args[:2] == ["ip", "rule"] and "show" in args:
                return make_completed(args, stdout="")
            return make_completed(args)

        with mock.patch("subprocess.run", side_effect=fake_run):
            routing.setup_routing("wg-sab-0", "10.50.0.2", 51820)

        assert ["ip", "route", "replace", "default", "dev", "wg-sab-0", "table", "51820"] in calls
        assert ["ip", "rule", "add", "from", "10.50.0.2", "table", "51820"] in calls

    def test_never_uses_shell_true(self):
        recorded_kwargs = []

        def fake_run(args, **kwargs):
            recorded_kwargs.append(kwargs)
            return make_completed(args, stdout="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            routing.setup_routing("wg-sab-0", "10.50.0.2", 51820)

        assert recorded_kwargs
        for kwargs in recorded_kwargs:
            assert kwargs.get("shell", False) is False

    def test_skips_duplicate_rule(self):
        existing_rule_output = "32764:\tfrom 10.50.0.2 lookup 51820\n"
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            if args[:3] == ["ip", "rule", "show"]:
                return make_completed(args, stdout=existing_rule_output)
            return make_completed(args)

        with mock.patch("subprocess.run", side_effect=fake_run):
            routing.setup_routing("wg-sab-0", "10.50.0.2", 51820)

        assert ["ip", "rule", "add", "from", "10.50.0.2", "table", "51820"] not in calls


class TestRoutingCleanup:
    def test_teardown_is_idempotent_when_rule_missing(self):
        def fake_run(args, **kwargs):
            if args[:2] == ["ip", "rule"] and "del" in args:
                return make_completed(args, returncode=2, stdout="")
            return make_completed(args)

        with mock.patch("subprocess.run") as mocked:
            mocked.side_effect = [
                subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="RTNETLINK answers: No such file or directory"),
                make_completed([], stdout=""),
            ]
            # Should not raise despite the "del" failing
            routing.teardown_routing("10.50.0.2", 51820)

    def test_teardown_reraises_unexpected_errors(self):
        with mock.patch("subprocess.run") as mocked:
            mocked.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Operation not permitted")
            try:
                routing.teardown_routing("10.50.0.2", 51820)
                raised = False
            except wireguard.VPNPermissionError:
                raised = True
            assert raised


class TestReconciliation:
    def test_reconcile_removes_only_stale_owned_entries(self):
        rule_show_output = (
            "0:\tfrom all lookup local\n"
            "32764:\tfrom 10.50.0.2 lookup 51820\n"
            "32765:\tfrom 10.51.0.2 lookup 51821\n"
            "32766:\tfrom all lookup main\n"
        )
        teardown_calls = []

        def fake_run(args, **kwargs):
            if args[:3] == ["ip", "rule", "show"]:
                return make_completed(args, stdout=rule_show_output)
            teardown_calls.append(args)
            return make_completed(args)

        with mock.patch("subprocess.run", side_effect=fake_run):
            # Only table 51820 (10.50.0.2) is still expected; 51821 is stale and must be removed
            routing.reconcile_stale_rules({51820: "10.50.0.2"})

        # The stale table (51821) must have been torn down
        assert any("51821" in str(call) for call in teardown_calls)
        # The still-expected table (51820) must not have been touched
        assert not any("51820" in str(call) for call in teardown_calls)
        # Nothing outside the owned range (main/local, table not in TABLE_RANGE) is ever referenced
        for call in teardown_calls:
            assert "main" not in call
            assert "local" not in call

    def test_list_sabnzbd_rules_ignores_out_of_range_tables(self):
        rule_show_output = "0:\tfrom all lookup local\n99999:\tfrom 10.9.9.9 lookup 999999\n32764:\tfrom 10.50.0.2 lookup 51820\n"
        with mock.patch("subprocess.run", return_value=make_completed([], stdout=rule_show_output)):
            rules = routing.list_sabnzbd_rules()
        assert len(rules) == 1
        assert rules[0].table == 51820
        assert rules[0].source == "10.50.0.2"

    def test_never_touches_main_table(self):
        # A pathological "expected" mapping should still never cause main/default/local to be touched,
        # since list_sabnzbd_rules() only ever returns rules already inside the owned numeric range.
        rule_show_output = "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n"
        calls = []

        def fake_run(args, **kwargs):
            if args[:3] == ["ip", "rule", "show"]:
                return make_completed(args, stdout=rule_show_output)
            calls.append(args)
            return make_completed(args)

        with mock.patch("subprocess.run", side_effect=fake_run):
            routing.reconcile_stale_rules({})

        assert calls == []


class TestEndpointNotRecursivelyRouted:
    def test_generated_rule_is_scoped_to_tunnel_source_only(self):
        """Documentation-anchored regression test: the policy rule SABnzbd
        installs must always be `from <tunnel_ip> ...`, never an
        unconditional/default rule - this is what prevents WireGuard's own
        UDP endpoint traffic (sourced from the host's normal address, not
        the tunnel's) from ever being captured by the rule."""
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            if args[:3] == ["ip", "rule", "show"]:
                return make_completed(args, stdout="")
            return make_completed(args, stdout="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            routing.setup_routing("wg-sab-0", "10.50.0.2", 51820)

        rule_add_calls = [c for c in calls if c[:3] == ["ip", "rule", "add"]]
        assert len(rule_add_calls) == 1
        assert rule_add_calls[0] == ["ip", "rule", "add", "from", "10.50.0.2", "table", "51820"]
