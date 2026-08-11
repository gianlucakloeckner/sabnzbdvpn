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
tests.test_vpn_benchmark - Tests of VPN tunnel latency benchmarking.
All real networking is mocked - no actual WireGuard tunnel or root required.
"""

from unittest import mock

import sabnzbd.vpn.benchmark as benchmark
from sabnzbd.vpn.models import WireGuardProfile


def make_profile(tunnel_ip="10.50.0.2") -> WireGuardProfile:
    return WireGuardProfile(
        uuid="abc123",
        name="Frankfurt",
        interface="wg-sab-0",
        interface_index=0,
        conf_path="/tmp/abc123.conf",
        enabled=True,
        endpoint_host="vpn.example.net",
        endpoint_port=51820,
        tunnel_ip=tunnel_ip,
        tunnel_prefix=32,
        routing_table=51820,
    )


class FakeSocket:
    """Minimal socket stand-in; records bind() calls for assertions."""

    def __init__(self, connect_error=None):
        self.connect_error = connect_error
        self.bound_address = None
        self.closed = False

    def settimeout(self, timeout):
        pass

    def bind(self, address):
        self.bound_address = address

    def connect(self, address):
        if self.connect_error is not None:
            raise self.connect_error

    def close(self):
        self.closed = True


class TestBenchmarkProfile:
    def test_successful_samples_produce_median(self):
        profile = make_profile()
        clock = iter([0.0, 0.010, 0.010, 0.021, 0.021, 0.026])  # 10ms, 11ms, 5ms
        with mock.patch("socket.socket", return_value=FakeSocket()), mock.patch(
            "time.monotonic", side_effect=clock
        ):
            result = benchmark.benchmark_profile(profile, "news.example.net", 119, samples=3, timeout=5.0)

        assert result.healthy
        assert result.error is None
        assert len(result.latency_samples_ms) == 3
        assert result.median_latency_ms == sorted(result.latency_samples_ms)[1]

    def test_all_samples_timeout_never_raises_and_marks_unhealthy(self):
        profile = make_profile()
        with mock.patch("socket.socket", return_value=FakeSocket(connect_error=TimeoutError("timed out"))):
            result = benchmark.benchmark_profile(profile, "news.example.net", 119, samples=3, timeout=1.0)

        assert not result.healthy
        assert result.median_latency_ms is None
        assert result.latency_samples_ms == []
        assert result.error

    def test_connection_refused_never_raises(self):
        profile = make_profile()
        with mock.patch("socket.socket", return_value=FakeSocket(connect_error=ConnectionRefusedError("refused"))):
            result = benchmark.benchmark_profile(profile, "news.example.net", 119, samples=2, timeout=1.0)

        assert not result.healthy
        assert "refused" in result.error

    def test_partial_failure_computes_median_from_successes_only(self):
        profile = make_profile()
        sockets = [FakeSocket(), FakeSocket(connect_error=OSError("unreachable")), FakeSocket()]
        with mock.patch("socket.socket", side_effect=sockets), mock.patch(
            "time.monotonic", side_effect=[0.0, 0.01, 0.02, 0.02, 0.03, 0.05]
        ):
            result = benchmark.benchmark_profile(profile, "news.example.net", 119, samples=3, timeout=5.0)

        assert result.healthy
        assert len(result.latency_samples_ms) == 2

    def test_bind_failure_when_tunnel_not_up_is_caught(self):
        profile = make_profile()

        class BindFailsSocket(FakeSocket):
            def bind(self, address):
                raise OSError("Cannot assign requested address")

        with mock.patch("socket.socket", return_value=BindFailsSocket()):
            result = benchmark.benchmark_profile(profile, "news.example.net", 119, samples=2, timeout=1.0)

        assert not result.healthy
        assert "requested address" in result.error

    def test_binds_to_tunnel_source_address(self):
        profile = make_profile(tunnel_ip="10.51.0.7")
        fake_sock = FakeSocket()
        with mock.patch("socket.socket", return_value=fake_sock):
            benchmark.benchmark_profile(profile, "news.example.net", 119, samples=1, timeout=1.0)
        assert fake_sock.bound_address == ("10.51.0.7", 0)

    def test_respects_configured_sample_count(self):
        profile = make_profile()
        created_sockets = []

        def make_socket(*args, **kwargs):
            sock = FakeSocket()
            created_sockets.append(sock)
            return sock

        with mock.patch("socket.socket", side_effect=make_socket):
            benchmark.benchmark_profile(profile, "news.example.net", 119, samples=7, timeout=1.0)
        assert len(created_sockets) == 7

    def test_sockets_are_always_closed(self):
        profile = make_profile()
        fake_sock = FakeSocket(connect_error=OSError("boom"))
        with mock.patch("socket.socket", return_value=fake_sock):
            benchmark.benchmark_profile(profile, "news.example.net", 119, samples=1, timeout=1.0)
        assert fake_sock.closed


class TestMeasureBandwidth:
    """measure_bandwidth() is a manual, on-demand test that reuses
    sabnzbd.internetspeed - these tests mock that function entirely, no
    real test-download or network access happens here."""

    def test_binds_to_tunnel_source_address(self):
        profile = make_profile(tunnel_ip="10.51.0.7")
        with mock.patch("sabnzbd.internetspeed.internetspeed_interal", return_value=10.0) as mocked:
            benchmark.measure_bandwidth(profile)
        _, kwargs = mocked.call_args
        assert kwargs["bind_ip"] == "10.51.0.7"

    def test_healthy_result_converts_to_mbps(self):
        profile = make_profile()
        with mock.patch("sabnzbd.internetspeed.internetspeed_interal", return_value=10.0):
            result = benchmark.measure_bandwidth(profile)
        assert result.healthy
        assert result.error is None
        assert result.mbps == round(10.0 * benchmark._MB_TO_MBIT, 2)

    def test_zero_speed_is_unhealthy_never_raises(self):
        profile = make_profile()
        with mock.patch("sabnzbd.internetspeed.internetspeed_interal", return_value=0.0):
            result = benchmark.measure_bandwidth(profile)
        assert not result.healthy
        assert result.mbps is None
        assert result.error
