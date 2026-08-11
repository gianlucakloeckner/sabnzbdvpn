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
tests.test_vpn_manager - Tests of the central VPNManager: selection,
hysteresis, kill switch, mid-download failover, startup reconciliation and
thread-safety. All OS-level operations (subprocess, sockets, Downloader,
Scheduler) are mocked - no real WireGuard tunnel or root required.
"""

import threading
from unittest import mock

import pytest

import sabnzbd
import sabnzbd.vpn.manager as manager
from sabnzbd.vpn.models import VPNBandwidthResult, VPNBenchmarkResult, WireGuardProfile


def make_profile(uid, name, tunnel_ip, index=0, enabled=True) -> WireGuardProfile:
    return WireGuardProfile(
        uuid=uid,
        name=name,
        interface=f"wg-sab-{index}",
        interface_index=index,
        conf_path=f"/tmp/{uid}.conf",
        enabled=enabled,
        endpoint_host="vpn.example.net",
        endpoint_port=51820,
        tunnel_ip=tunnel_ip,
        tunnel_prefix=32,
        routing_table=51820 + index,
    )


def healthy(uid, latency_ms):
    return VPNBenchmarkResult(
        profile_uuid=uid, healthy=True, latency_samples_ms=[latency_ms], median_latency_ms=latency_ms, error=None
    )


def unhealthy(uid, error="unreachable"):
    return VPNBenchmarkResult(profile_uuid=uid, healthy=False, latency_samples_ms=[], median_latency_ms=None, error=error)


@pytest.fixture
def vpn_manager(monkeypatch):
    """A VPNManager with all real OS/network/scheduler interaction stubbed
    out, so tests exercise only the selection/hysteresis/kill-switch logic."""
    monkeypatch.setattr(sabnzbd, "Downloader", mock.Mock(vpn_killswitch_paused=False), raising=False)
    monkeypatch.setattr(sabnzbd, "Scheduler", mock.Mock(), raising=False)
    monkeypatch.setattr(manager, "is_platform_supported", lambda: True)

    vpn_manager = manager.VPNManager()
    monkeypatch.setattr(vpn_manager, "_ensure_tunnel_up", lambda profile: True)
    monkeypatch.setattr(vpn_manager, "_teardown_profile", lambda profile: None)
    monkeypatch.setattr(vpn_manager, "_primary_nntp_server", lambda: ("news.example.net", 119))
    return vpn_manager


def add_profiles(vpn_manager, *profiles):
    vpn_manager.profiles = {profile.uuid: profile for profile in profiles}


class TestVPNSelection:
    def test_selects_lowest_latency(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
            make_profile("c", "Zurich", "10.52.0.2", index=2),
        )
        results = {"a": healthy("a", 18.0), "b": healthy("b", 24.0), "c": healthy("c", 9.0)}
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: results[profile.uuid])

        vpn_manager.select_best_vpn()

        assert vpn_manager.active_profile_uuid == "c"
        assert vpn_manager.active_bind_ip == "10.52.0.2"
        sabnzbd.Downloader.pause.assert_not_called()

    def test_unhealthy_vpn_ignored_even_if_it_would_otherwise_win(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        # "b" would be fastest by latency value, but it's unhealthy so must never be selected
        results = {"a": healthy("a", 30.0), "b": unhealthy("b")}
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: results[profile.uuid])

        vpn_manager.select_best_vpn()

        assert vpn_manager.active_profile_uuid == "a"

    def test_all_vpns_unavailable_killswitch_pauses_downloader(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: unhealthy("a"))
        monkeypatch.setattr(sabnzbd.cfg, "vpn_killswitch", mock.Mock(return_value=True))

        vpn_manager.select_best_vpn()

        assert vpn_manager.active_profile_uuid is None
        assert vpn_manager.active_bind_ip is None
        assert vpn_manager.killswitch_active is True
        sabnzbd.Downloader.pause.assert_called_once()
        assert sabnzbd.Downloader.vpn_killswitch_paused is True

    def test_all_vpns_unavailable_no_profiles_enabled(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2", enabled=False))
        monkeypatch.setattr(sabnzbd.cfg, "vpn_killswitch", mock.Mock(return_value=True))

        vpn_manager.select_best_vpn()

        assert vpn_manager.active_profile_uuid is None
        sabnzbd.Downloader.pause.assert_called_once()


class TestBandwidthTest:
    """Manual bandwidth test - separate from latency benchmarking, never
    changes the active VPN or selection results."""

    def test_healthy_bandwidth_result_stored_and_returned(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        result = VPNBandwidthResult(profile_uuid="a", healthy=True, mbps=87.3, error=None)
        monkeypatch.setattr(manager.benchmark, "measure_bandwidth", lambda profile: result)

        returned = vpn_manager.test_profile_bandwidth("a")

        assert returned is result
        assert vpn_manager.bandwidth_results["a"] is result

    def test_bandwidth_test_does_not_change_active_profile(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        monkeypatch.setattr(
            manager.benchmark, "measure_bandwidth", lambda profile: VPNBandwidthResult(profile_uuid="a", healthy=True, mbps=50.0, error=None)
        )

        vpn_manager.test_profile_bandwidth("a")

        assert vpn_manager.active_profile_uuid is None

    def test_tunnel_not_up_reports_unhealthy_without_raising(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        monkeypatch.setattr(vpn_manager, "_ensure_tunnel_up", lambda profile: False)

        result = vpn_manager.test_profile_bandwidth("a")

        assert not result.healthy
        assert result.mbps is None

    def test_unknown_profile_reports_not_found(self, vpn_manager):
        result = vpn_manager.test_profile_bandwidth("does-not-exist")
        assert not result.healthy
        assert result.mbps is None

    def test_test_all_profiles_bandwidth_covers_every_profile(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(
            manager.benchmark,
            "measure_bandwidth",
            lambda profile: VPNBandwidthResult(profile_uuid=profile.uuid, healthy=True, mbps=10.0, error=None),
        )

        results = vpn_manager.test_all_profiles_bandwidth()

        assert set(results.keys()) == {"a", "b"}

    def test_deleted_profile_bandwidth_result_is_cleared(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        vpn_manager.bandwidth_results["a"] = VPNBandwidthResult(profile_uuid="a", healthy=True, mbps=10.0, error=None)

        vpn_manager.delete_profile("a")

        assert "a" not in vpn_manager.bandwidth_results


class TestKillSwitch:
    def test_killswitch_disabled_allows_wan_fallback(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: unhealthy("a"))
        monkeypatch.setattr(sabnzbd.cfg, "vpn_killswitch", mock.Mock(return_value=False))

        vpn_manager.select_best_vpn()

        assert vpn_manager.killswitch_active is False
        sabnzbd.Downloader.pause.assert_not_called()
        # active_bind_ip stays None -> get_effective_outgoing_nntp_ip() falls through to plain outgoing_nntp_ip
        assert vpn_manager.get_effective_bind_ip() is None

    def test_recovery_releases_killswitch_and_resumes(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        monkeypatch.setattr(sabnzbd.cfg, "vpn_killswitch", mock.Mock(return_value=True))

        # First pass: unhealthy -> kill switch engages
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: unhealthy("a"))
        vpn_manager.select_best_vpn()
        assert vpn_manager.killswitch_active is True
        sabnzbd.Downloader.vpn_killswitch_paused = True

        # Second pass: healthy again -> kill switch must release and resume
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: healthy("a", 20.0))
        vpn_manager.select_best_vpn()

        assert vpn_manager.killswitch_active is False
        sabnzbd.Downloader.resume.assert_called_once()
        assert sabnzbd.Downloader.vpn_killswitch_paused is False

    def test_manual_pause_is_not_auto_resumed(self, vpn_manager, monkeypatch):
        """If the kill switch never engaged (vpn_killswitch_paused stays False,
        e.g. the user paused manually), a later healthy selection must not
        call resume() - only a kill-switch-triggered pause is auto-released."""
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        sabnzbd.Downloader.vpn_killswitch_paused = False
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: healthy("a", 20.0))

        vpn_manager.select_best_vpn()

        sabnzbd.Downloader.resume.assert_not_called()


class TestBalancedSelection:
    """BALANCED combines each round's fresh latency with the most recent
    manual bandwidth-test result (never a fresh bandwidth test itself - see
    VPNManager._compute_scores() docstring for why)."""

    def test_no_bandwidth_data_falls_back_to_latency_ordering(self, vpn_manager):
        results = {"a": healthy("a", 30.0), "b": healthy("b", 10.0)}
        scores = vpn_manager._compute_scores(results, manager.VPNSelectionStrategy.BALANCED)
        assert scores["b"] > scores["a"]

    def test_bandwidth_can_change_the_ranking(self, vpn_manager):
        # "a" has the best latency but no bandwidth data; "b" and "c" share
        # the same (worse) latency, but "c" has much better bandwidth.
        results = {"a": healthy("a", 20.0), "b": healthy("b", 25.0), "c": healthy("c", 25.0)}
        vpn_manager.bandwidth_results = {
            "b": VPNBandwidthResult(profile_uuid="b", healthy=True, mbps=50.0, error=None),
            "c": VPNBandwidthResult(profile_uuid="c", healthy=True, mbps=500.0, error=None),
        }
        scores = vpn_manager._compute_scores(results, manager.VPNSelectionStrategy.BALANCED)
        assert scores["c"] > scores["b"]
        assert scores["c"] > scores["a"]  # c's bandwidth advantage outweighs a's small latency edge

    def test_unhealthy_bandwidth_result_is_ignored(self, vpn_manager):
        results = {"a": healthy("a", 20.0), "b": healthy("b", 20.0)}
        vpn_manager.bandwidth_results = {
            "b": VPNBandwidthResult(profile_uuid="b", healthy=False, mbps=None, error="boom"),
        }
        scores = vpn_manager._compute_scores(results, manager.VPNSelectionStrategy.BALANCED)
        # Same latency, "b"'s failed bandwidth test must not count as data -> tied
        assert scores["a"] == scores["b"]

    def test_select_best_vpn_picks_balanced_winner(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(sabnzbd.cfg, "vpn_selection_mode", mock.Mock(return_value="balanced"))
        vpn_manager.bandwidth_results = {
            "b": VPNBandwidthResult(profile_uuid="b", healthy=True, mbps=500.0, error=None),
        }
        monkeypatch.setattr(
            manager.benchmark,
            "benchmark_profile",
            lambda profile, *a, **k: {"a": healthy("a", 15.0), "b": healthy("b", 25.0)}[profile.uuid],
        )

        vpn_manager.select_best_vpn()

        # "a" has the better raw latency, but "b"'s large bandwidth advantage wins under BALANCED
        assert vpn_manager.active_profile_uuid == "b"

    def test_hysteresis_prevents_flapping_on_marginal_latency_noise(self, vpn_manager, monkeypatch):
        """Regression test: scores must stay on an absolute scale so a tiny
        real-world latency fluctuation doesn't look like a full-scale swing
        (which per-round min-max normalization would cause with only two
        candidates - one is always pushed to the extreme)."""
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(sabnzbd.cfg, "vpn_selection_mode", mock.Mock(return_value="balanced"))
        monkeypatch.setattr(sabnzbd.cfg, "vpn_switch_threshold", mock.Mock(return_value=10))
        monkeypatch.setattr(
            manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 25.0)}[profile.uuid]
        )
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"

        # "b" edges ahead by a hair - not a meaningful improvement, must not flap
        monkeypatch.setattr(
            manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 19.5)}[profile.uuid]
        )
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"


class TestHysteresis:
    def test_no_switch_for_insignificant_difference(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(sabnzbd.cfg, "vpn_switch_threshold", mock.Mock(return_value=10))

        # First pass selects "a"
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 25.0)}[profile.uuid])
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"

        # Second pass: "b" is only marginally better (19ms vs 20ms, <10%) -> must not switch
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 19.0)}[profile.uuid])
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"

    def test_switches_when_candidate_clearly_better(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(sabnzbd.cfg, "vpn_switch_threshold", mock.Mock(return_value=10))

        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 25.0)}[profile.uuid])
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"

        # "b" is now clearly better (15ms vs 20ms, 25% improvement > 10% threshold) -> must switch
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 15.0)}[profile.uuid])
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "b"

    def test_always_switches_when_current_becomes_unhealthy(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(sabnzbd.cfg, "vpn_switch_threshold", mock.Mock(return_value=50))  # very strict threshold

        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 21.0)}[profile.uuid])
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"

        # "a" goes unhealthy - must switch to "b" regardless of the strict threshold
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": unhealthy("a"), "b": healthy("b", 21.0)}[profile.uuid])
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "b"


class TestMidDownloadFailover:
    @pytest.mark.config({"vpn_enabled": True})
    def test_active_vpn_down_triggers_disconnect_and_reselection(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 25.0)}[profile.uuid])
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"

        # Simulate "a"'s tunnel going down mid-download
        monkeypatch.setattr(manager.wireguard, "interface_is_up", lambda iface: False)
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": unhealthy("a"), "b": healthy("b", 21.0)}[profile.uuid])
        sabnzbd.Downloader.disconnect.reset_mock()

        vpn_manager._periodic_health_check()

        # Failure detection must immediately stop using the dead tunnel...
        assert sabnzbd.Downloader.disconnect.called
        # ...then fail over to the other healthy VPN
        assert vpn_manager.active_profile_uuid == "b"

    def test_no_healthy_failover_enforces_killswitch(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2"))
        monkeypatch.setattr(sabnzbd.cfg, "vpn_killswitch", mock.Mock(return_value=True))
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: healthy("a", 20.0))
        vpn_manager.select_best_vpn()
        assert vpn_manager.active_profile_uuid == "a"

        monkeypatch.setattr(manager.wireguard, "interface_is_up", lambda iface: False)
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: unhealthy("a"))

        vpn_manager._handle_active_vpn_down()

        assert vpn_manager.active_profile_uuid is None
        assert vpn_manager.killswitch_active is True
        sabnzbd.Downloader.pause.assert_called_once()


class TestStartupReconciliation:
    def test_only_stale_interfaces_are_removed(self, vpn_manager, monkeypatch):
        add_profiles(vpn_manager, make_profile("a", "Frankfurt", "10.50.0.2", index=0))

        removed = []
        monkeypatch.setattr(manager.wireguard, "list_sabnzbd_interfaces", lambda: ["wg-sab-0", "wg-sab-7"])
        monkeypatch.setattr(manager.wireguard, "remove_interface", lambda name: removed.append(name))
        monkeypatch.setattr(manager.routing, "reconcile_stale_rules", lambda expected: None)

        vpn_manager.reconcile_on_startup()

        assert removed == ["wg-sab-7"]

    def test_reconcile_stale_rules_called_with_expected_mapping(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2", index=0),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1, enabled=False),
        )
        monkeypatch.setattr(manager.wireguard, "list_sabnzbd_interfaces", lambda: [])
        captured = {}
        monkeypatch.setattr(manager.routing, "reconcile_stale_rules", lambda expected: captured.update(expected))

        vpn_manager.reconcile_on_startup()

        # Only the enabled profile ("a") should be in the expected mapping
        assert captured == {51820: "10.50.0.2"}


class TestThreadSafety:
    def test_concurrent_selection_does_not_corrupt_state(self, vpn_manager, monkeypatch):
        add_profiles(
            vpn_manager,
            make_profile("a", "Frankfurt", "10.50.0.2"),
            make_profile("b", "Amsterdam", "10.51.0.2", index=1),
        )
        monkeypatch.setattr(manager.benchmark, "benchmark_profile", lambda profile, *a, **k: {"a": healthy("a", 20.0), "b": healthy("b", 21.0)}[profile.uuid])

        barrier = threading.Barrier(5)

        def run():
            barrier.wait()
            vpn_manager.select_best_vpn()

        threads = [threading.Thread(target=run) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # Must land on a consistent, valid state - never a torn/partial combination
        assert vpn_manager.active_profile_uuid in ("a", None)
        if vpn_manager.active_profile_uuid == "a":
            assert vpn_manager.active_bind_ip == "10.50.0.2"
