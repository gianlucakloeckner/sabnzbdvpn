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
tests.test_internetspeed - Testing SABnzbd internetspeed
"""

from unittest import mock

import pytest

import sabnzbd.internetspeed as internetspeed
from sabnzbd.internetspeed import internetspeed as internetspeed_live


@pytest.mark.usefixtures("clean_cache_dir")
class TestInternetSpeed:
    def test_internet_speed(self):
        curr_speed_mbps = internetspeed_live()

        assert isinstance(curr_speed_mbps, float)
        assert curr_speed_mbps > 0


class TestInternetSpeedBindIp:
    """Unit tests (fully mocked, no real network) for the `bind_ip`
    parameter added for the VPN subsystem's bandwidth test - verifies each
    test socket is bound to the given source address, and that omitting
    bind_ip preserves the original (no-bind) behavior exactly."""

    def _run(self, bind_ip, monkeypatch):
        fake_addrinfo = mock.Mock(family=0, type=0, sockaddr=("1.2.3.4", 443))
        created_sockets = []

        def fake_socket(*args, **kwargs):
            sock = mock.Mock()
            created_sockets.append(sock)
            return sock

        fake_context = mock.Mock()
        fake_context.verify_flags = 0
        fake_context.wrap_socket.return_value = mock.Mock()

        monkeypatch.setattr(internetspeed, "get_fastest_addrinfo", lambda *a, **k: fake_addrinfo)
        monkeypatch.setattr(internetspeed.ssl, "create_default_context", lambda *a, **k: fake_context)
        monkeypatch.setattr(internetspeed.socket, "socket", fake_socket)
        monkeypatch.setattr(internetspeed.threading, "Thread", lambda *a, **k: mock.Mock(start=lambda: None))
        monkeypatch.setattr(internetspeed.time, "sleep", lambda *a, **k: None)

        internetspeed.internetspeed_interal(bind_ip=bind_ip)
        return created_sockets

    def test_binds_when_bind_ip_given(self, monkeypatch):
        sockets = self._run("10.50.0.2", monkeypatch)
        assert sockets
        for sock in sockets:
            sock.bind.assert_called_once_with(("10.50.0.2", 0))

    def test_does_not_bind_when_bind_ip_omitted(self, monkeypatch):
        sockets = self._run(None, monkeypatch)
        assert sockets
        for sock in sockets:
            sock.bind.assert_not_called()
