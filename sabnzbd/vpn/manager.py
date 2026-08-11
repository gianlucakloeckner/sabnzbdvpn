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
sabnzbd.vpn.manager - Central VPN manager.

Owns all mutable VPN state (loaded profiles, which one is active, the last
benchmark results, kill-switch state) behind a single lock, and is the only
part of the VPN subsystem the rest of SABnzbd talks to:

- sabnzbd/__init__.py constructs/starts/stops it alongside Downloader/Scheduler.
- sabnzbd/nzbqueue.py calls notify_active_nzo() once per NZB activation.
- sabnzbd/newswrapper.py calls get_effective_outgoing_nntp_ip() (module-level,
  not a method - it must work even if no VPNManager exists yet).
- sabnzbd/api.py and sabnzbd/interface.py call the profile-CRUD and
  status/test methods for the Config > VPN page and API.

Everything OS-specific (subprocess calls, socket binds) lives in
wireguard.py/routing.py/benchmark.py; this module only coordinates them.
"""

import ipaddress
import logging
import os
import threading
import uuid
from contextlib import suppress
from typing import Optional

import sabnzbd
import sabnzbd.cfg as cfg
import sabnzbd.config as config
import sabnzbd.vpn.benchmark as benchmark
import sabnzbd.vpn.routing as routing
import sabnzbd.vpn.wireguard as wireguard
from sabnzbd.vpn import is_platform_supported
from sabnzbd.vpn.models import VPNBandwidthResult, VPNBenchmarkResult, VPNSelectionStrategy, VPNStatus, WireGuardProfile


class VPNManager:
    """Thread-safe coordinator for all configured WireGuard profiles."""

    def __init__(self):
        self._lock = threading.RLock()
        self.profiles: dict[str, WireGuardProfile] = {}
        self.active_profile_uuid: Optional[str] = None
        self.active_bind_ip: Optional[str] = None
        self.benchmark_results: dict[str, VPNBenchmarkResult] = {}
        self.bandwidth_results: dict[str, VPNBandwidthResult] = {}
        self.killswitch_active: bool = False
        self.status_reason: Optional[str] = None
        self._selecting: bool = False
        self._health_task = None
        # _loaded: profiles have been read from config at least once.
        # _active: tunnels are currently expected to be up (mirrors
        # cfg.vpn_enabled(), but only after actually applying it) - kept
        # separate from _loaded so toggling vpn_enabled from the Config >
        # VPN page after startup takes effect immediately via
        # refresh_enabled_state(), instead of being a one-shot decision
        # only made once at process start.
        self._loaded: bool = False
        self._active: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Called once at SABnzbd startup: load profiles and, if VPN routing
        is enabled, bring tunnels up. A VPN problem here is logged, never
        allowed to block SABnzbd startup."""
        if self._loaded:
            return
        self._loaded = True
        if not is_platform_supported():
            logging.info("VPN routing is only supported on Linux, VPN subsystem disabled")
            return

        self._load_profiles_from_config()
        self.refresh_enabled_state()

    def refresh_enabled_state(self) -> None:
        """Bring the manager's live state (tunnels up, health-check task
        scheduled) in line with the current vpn_enabled setting. Called from
        start() and again whenever the Config > VPN page changes vpn_enabled,
        so enabling/disabling VPN routing takes effect immediately instead of
        requiring a restart."""
        if not is_platform_supported():
            return

        if cfg.vpn_enabled():
            if self._active:
                return
            self._active = True
            self.reconcile_on_startup()
            for profile in list(self.profiles.values()):
                if profile.enabled:
                    try:
                        self._ensure_tunnel_up(profile)
                    except wireguard.VPNError as exc:
                        logging.warning("Could not bring up VPN profile %s: %s", profile.name, exc)
            try:
                self._health_task = sabnzbd.Scheduler.scheduler.add_interval_task(
                    self._periodic_health_check, "vpn_health_check", 60, 120, "threaded"
                )
            except Exception:
                logging.debug("Could not schedule VPN health-check task", exc_info=True)
            self.select_best_vpn()
        else:
            if not self._active:
                return
            self._deactivate()

    def _deactivate(self) -> None:
        """Tear down every interface/route this run owns and stop the
        health-check task. Used both by stop() and by refresh_enabled_state()
        when the user disables VPN routing without restarting SABnzbd."""
        if self._health_task is not None:
            with suppress(Exception):
                sabnzbd.Scheduler.scheduler.cancel(self._health_task)
            self._health_task = None

        for profile in list(self.profiles.values()):
            self._teardown_profile(profile)

        with self._lock:
            self.active_profile_uuid = None
            self.active_bind_ip = None
            self.killswitch_active = False
            self.status_reason = None
        self._active = False

    def stop(self) -> None:
        """Tear down every interface/route this run owns. Called after the
        Downloader has already stopped, so no NNTP socket can still be using
        a tunnel while it's removed."""
        if not self._active:
            return
        if is_platform_supported():
            self._deactivate()

    def _load_profiles_from_config(self) -> None:
        profiles: dict[str, WireGuardProfile] = {}
        for profile_id, cfg_profile in config.get_vpn_profiles().items():
            profiles[profile_id] = WireGuardProfile(
                uuid=profile_id,
                name=cfg_profile.display_name(),
                interface=cfg_profile.interface(),
                interface_index=cfg_profile.interface_index(),
                conf_path=cfg_profile.conf_path(),
                enabled=bool(cfg_profile.enabled()),
                endpoint_host=cfg_profile.endpoint_host(),
                endpoint_port=cfg_profile.endpoint_port(),
                tunnel_ip=cfg_profile.tunnel_ip(),
                tunnel_prefix=cfg_profile.tunnel_prefix(),
                routing_table=routing.table_for_index(cfg_profile.interface_index()),
                created=cfg_profile.created(),
            )
        with self._lock:
            self.profiles = profiles

    def reconcile_on_startup(self) -> None:
        """Adopt-or-remove pass: any wg-sab-* interface or owned routing
        rule that doesn't match a currently enabled profile is removed;
        nothing outside SABnzbd's naming/table-range ownership is touched."""
        expected_interfaces = {profile.interface for profile in self.profiles.values() if profile.enabled}
        for interface in wireguard.list_sabnzbd_interfaces():
            if interface not in expected_interfaces:
                try:
                    wireguard.remove_interface(interface)
                    logging.info("Removed stale VPN interface %s", interface)
                except wireguard.VPNError as exc:
                    logging.warning("Could not remove stale VPN interface %s: %s", interface, exc)

        expected_rules = {profile.routing_table: profile.tunnel_ip for profile in self.profiles.values() if profile.enabled}
        try:
            routing.reconcile_stale_rules(expected_rules)
        except wireguard.VPNError as exc:
            logging.warning("Could not reconcile stale VPN routing rules: %s", exc)

    # ------------------------------------------------------------------
    # Profile CRUD
    # ------------------------------------------------------------------
    def _lowest_unused_interface_index(self) -> int:
        used = {profile.interface_index for profile in self.profiles.values()}
        index = 0
        while index in used:
            index += 1
        return index

    def add_profile_from_upload(self, conf_bytes: bytes, display_name: str) -> tuple[bool, str, Optional[str]]:
        """Validate and store an uploaded WireGuard .conf as a new profile.
        Returns (ok, message, profile_id). Never raises - parse errors,
        semantic validation errors and filesystem errors are all reported
        back as a message instead."""
        try:
            conf_text = conf_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return False, T("Configuration file is not valid UTF-8 text"), None

        parsed, errors = wireguard.parse_conf(conf_text)
        if parsed is None:
            return False, "; ".join(errors), None

        with self._lock:
            existing_tunnel_ips = {profile.tunnel_ip for profile in self.profiles.values()}
        errors = wireguard.validate_conf(parsed, existing_tunnel_ips)
        if errors:
            return False, "; ".join(errors), None

        try:
            tunnel_interface = ipaddress.ip_interface(parsed.address)
        except ValueError:
            return False, T("Could not parse interface Address"), None

        profile_id = uuid.uuid4().hex[:8]
        with self._lock:
            while profile_id in self.profiles:
                profile_id = uuid.uuid4().hex[:8]
            interface_index = self._lowest_unused_interface_index()

        interface_name = f"{wireguard.IFACE_PREFIX}{interface_index}"
        routing_table = routing.table_for_index(interface_index)

        conf_dir = os.path.join(cfg.admin_dir.get_path(), "wireguard")
        try:
            os.makedirs(conf_dir, exist_ok=True)
            conf_path = os.path.join(conf_dir, f"{profile_id}.conf")
            wireguard.write_conf_file(conf_path, conf_bytes)
        except OSError as exc:
            return False, T("Could not store the configuration file: %s") % exc, None

        peer = parsed.peers[0]
        profile = WireGuardProfile(
            uuid=profile_id,
            name=(display_name or profile_id).strip() or profile_id,
            interface=interface_name,
            interface_index=interface_index,
            conf_path=conf_path,
            enabled=True,
            endpoint_host=peer.endpoint_host or "",
            endpoint_port=peer.endpoint_port or 0,
            tunnel_ip=str(tunnel_interface.ip),
            tunnel_prefix=tunnel_interface.network.prefixlen,
            routing_table=routing_table,
        )

        config.ConfigVPNProfile(
            profile_id,
            {
                "display_name": profile.name,
                "interface": profile.interface,
                "interface_index": profile.interface_index,
                "enabled": profile.enabled,
                "endpoint_host": profile.endpoint_host,
                "endpoint_port": profile.endpoint_port,
                "tunnel_ip": profile.tunnel_ip,
                "tunnel_prefix": profile.tunnel_prefix,
                "conf_path": profile.conf_path,
                "created": profile.created,
            },
        )
        config.save_config()

        with self._lock:
            self.profiles[profile_id] = profile

        logging.info("VPN profile %s initialized as %s", profile.name, profile.interface)

        if is_platform_supported() and cfg.vpn_enabled():
            try:
                self._ensure_tunnel_up(profile)
            except wireguard.VPNError as exc:
                logging.warning("Could not bring up VPN profile %s yet: %s", profile.name, exc)

        return True, T("VPN profile added"), profile_id

    def delete_profile(self, profile_id: str) -> tuple[bool, str]:
        with self._lock:
            profile = self.profiles.pop(profile_id, None)
            was_active = self.active_profile_uuid == profile_id
            if was_active:
                self.active_profile_uuid = None
                self.active_bind_ip = None
            self.benchmark_results.pop(profile_id, None)
            self.bandwidth_results.pop(profile_id, None)

        if profile is None:
            return False, T("VPN profile not found")

        if is_platform_supported():
            self._teardown_profile(profile)

        with suppress(OSError):
            os.remove(profile.conf_path)

        cfg_profile = config.get_config("vpn_profiles", profile_id)
        if cfg_profile:
            cfg_profile.delete()
            config.save_config()

        logging.info("VPN profile %s removed", profile.name)

        if was_active:
            self._trigger_background_selection()

        return True, T("VPN profile deleted")

    def enable_profile(self, profile_id: str, enabled: bool) -> tuple[bool, str]:
        with self._lock:
            profile = self.profiles.get(profile_id)
        if profile is None:
            return False, T("VPN profile not found")

        profile.enabled = enabled
        cfg_profile = config.get_config("vpn_profiles", profile_id)
        if cfg_profile:
            cfg_profile.enabled.set(enabled)
            config.save_config()

        if enabled:
            if is_platform_supported() and cfg.vpn_enabled():
                try:
                    self._ensure_tunnel_up(profile)
                except wireguard.VPNError as exc:
                    logging.warning("Could not bring up VPN profile %s: %s", profile.name, exc)
            return True, T("VPN profile enabled")

        was_active = False
        with self._lock:
            if self.active_profile_uuid == profile_id:
                was_active = True
                self.active_profile_uuid = None
                self.active_bind_ip = None
        if is_platform_supported():
            self._teardown_profile(profile)
        if was_active:
            self._trigger_background_selection()
        return True, T("VPN profile disabled")

    def get_profiles_public(self) -> list[dict]:
        """Safe metadata only - never conf_path content or the private key."""
        with self._lock:
            profiles = sorted(self.profiles.values(), key=lambda profile: profile.interface_index)
            active_uuid = self.active_profile_uuid
            results = dict(self.benchmark_results)
            bandwidth_results = dict(self.bandwidth_results)

        output = []
        for profile in profiles:
            result = results.get(profile.uuid)
            bandwidth_result = bandwidth_results.get(profile.uuid)
            output.append(
                {
                    "id": profile.uuid,
                    "name": profile.name,
                    "interface": profile.interface,
                    "endpoint": profile.endpoint,
                    "enabled": profile.enabled,
                    "healthy": bool(result.healthy) if result else None,
                    "latency_ms": (
                        round(result.median_latency_ms, 1)
                        if result and result.median_latency_ms is not None
                        else None
                    ),
                    "error": result.error if result and not result.healthy else None,
                    "bandwidth_mbps": bandwidth_result.mbps if bandwidth_result and bandwidth_result.healthy else None,
                    "selected": profile.uuid == active_uuid,
                }
            )
        return output

    # ------------------------------------------------------------------
    # Tunnel/routing bring-up and teardown
    # ------------------------------------------------------------------
    def _ensure_tunnel_up(self, profile: WireGuardProfile) -> bool:
        """Best-effort: create/refresh the interface, its crypto config, its
        address and its routing table. Returns whether the interface ended
        up UP. Never raises for expected failure modes (missing
        binary/capability) - logs and returns False.

        Deliberately unconditional (not "only on first creation"): every
        step here is idempotent, so always re-applying is what makes this
        self-healing against a tunnel that's stuck half-configured - e.g.
        the link exists and is administratively up but `wg setconf` never
        actually succeeded, so no key/peer is loaded and nothing can pass
        traffic even though interface_is_up() alone would say "fine".
        """
        try:
            wireguard.create_interface(profile.interface, profile.conf_path)
            wireguard.assign_tunnel_address(profile.interface, profile.tunnel_ip, profile.tunnel_prefix)
            routing.setup_routing(profile.interface, profile.tunnel_ip, profile.routing_table)
            return wireguard.interface_is_up(profile.interface)
        except wireguard.VPNBinaryMissingError as exc:
            logging.error("VPN profile %s could not be initialized: %s", profile.name, exc)
            return False
        except wireguard.VPNPermissionError as exc:
            logging.error("VPN profile %s could not be initialized: CAP_NET_ADMIN is unavailable (%s)", profile.name, exc)
            return False
        except wireguard.VPNError as exc:
            logging.error("VPN profile %s could not be initialized: %s", profile.name, exc)
            return False

    def _teardown_profile(self, profile: WireGuardProfile) -> None:
        try:
            routing.teardown_routing(profile.tunnel_ip, profile.routing_table)
            wireguard.remove_interface(profile.interface)
        except wireguard.VPNError as exc:
            logging.warning("Could not fully tear down VPN profile %s: %s", profile.name, exc)

    # ------------------------------------------------------------------
    # Selection, hysteresis, switching
    # ------------------------------------------------------------------
    def _trigger_background_selection(self) -> None:
        if not cfg.vpn_enabled() or not is_platform_supported():
            return
        with self._lock:
            if self._selecting:
                return
            self._selecting = True
        threading.Thread(target=self._run_selection, name="VPNSelection", daemon=True).start()

    def _run_selection(self) -> None:
        try:
            self.select_best_vpn()
        finally:
            with self._lock:
                self._selecting = False

    def notify_active_nzo(self, nzo) -> None:
        """Called once when a new NZB becomes the active download (see the
        cheap id-diff check in nzbqueue.py's get_articles()). Selection runs
        in a background thread so the downloader's hot loop is never blocked
        on benchmarking; `nzo` is currently unused but kept for a future
        per-job/per-category selection extension.

        Honours vpn_test_before_job: when disabled, only run a selection if
        there isn't an active VPN yet (first job still needs one pick), so a
        user who disabled per-job retesting keeps using the same tunnel
        across jobs instead of re-benchmarking on every NZB."""
        if not cfg.vpn_test_before_job() and self.active_profile_uuid is not None:
            return
        self._trigger_background_selection()

    def _primary_nntp_server(self) -> tuple[Optional[str], Optional[int]]:
        """The server benchmarks are measured against: the enabled server
        with the lowest priority number (SABnzbd's "most preferred" server)."""
        servers = [server for server in config.get_servers().values() if server.enable()]
        if not servers:
            return None, None
        primary = min(servers, key=lambda server: server.priority())
        return primary.host(), primary.port()

    # How many milliseconds of "equivalent latency benefit" one extra Mbps of
    # measured bandwidth is worth in the BALANCED score. Deliberately a
    # simple, fixed heuristic for V1 (not physically derived) rather than
    # per-round min-max normalization: normalizing scores to the current
    # round's candidate set makes hysteresis meaningless, because with only
    # two candidates one is *always* pushed to the extreme (0 or 1) no
    # matter how small the real difference is - a 20.0ms vs 20.1ms latency
    # gap would look identical to a 20ms vs 200ms gap. Using a fixed,
    # round-independent conversion keeps the score on the same absolute
    # "effective milliseconds" scale as plain latency, so the existing
    # percentage-of-current hysteresis formula below stays correct and
    # unmodified for both strategies. Not exposed as a setting in V1; the
    # constant is named/isolated so a future config option can replace it.
    _BALANCED_MS_PER_MBPS = 0.3

    def _compute_scores(
        self, results: dict[str, VPNBenchmarkResult], strategy: VPNSelectionStrategy
    ) -> dict[str, float]:
        """Return {profile_uuid: score} for this round's healthy candidates,
        on an absolute "effective milliseconds, higher (less negative) is
        better" scale - this is what lets _pick_candidate()/_should_switch()
        stay strategy-agnostic and keeps hysteresis meaningful regardless of
        strategy or which other candidates happen to be in the pool.

        LOWEST_LATENCY (and any reserved/unimplemented strategy, which
        VPNSelectionStrategy.from_value() already collapses to it before
        this is ever called): score = -latency_ms.

        BALANCED: score = -latency_ms + mbps * _BALANCED_MS_PER_MBPS,
        combining this round's fresh latency with the most recent bandwidth
        test result (from the manual "Bandwidth test" action - see
        benchmark.measure_bandwidth()/test_profile_bandwidth()). Running a
        real multi-second bandwidth test on every selection would violate
        the "never benchmark per job" requirement, so bandwidth is only ever
        as fresh as the user's last manual test; a profile with no bandwidth
        result yet gets no bonus/penalty rather than being penalized for
        missing data.
        """
        healthy = {
            profile_id: result
            for profile_id, result in results.items()
            if result.healthy and result.median_latency_ms is not None
        }
        if strategy != VPNSelectionStrategy.BALANCED:
            return {profile_id: -result.median_latency_ms for profile_id, result in healthy.items()}

        with self._lock:
            bandwidth_results = dict(self.bandwidth_results)

        scores: dict[str, float] = {}
        for profile_id, result in healthy.items():
            bandwidth_result = bandwidth_results.get(profile_id)
            mbps = bandwidth_result.mbps if bandwidth_result and bandwidth_result.healthy and bandwidth_result.mbps else 0.0
            scores[profile_id] = -result.median_latency_ms + mbps * self._BALANCED_MS_PER_MBPS
        return scores

    def _pick_candidate(
        self, results: dict[str, VPNBenchmarkResult], strategy: VPNSelectionStrategy
    ) -> Optional[str]:
        scores = self._compute_scores(results, strategy)
        if not scores:
            return None
        return max(scores, key=lambda profile_id: scores[profile_id])

    def _should_switch(
        self,
        current_uuid: Optional[str],
        candidate_uuid: str,
        results: dict[str, VPNBenchmarkResult],
        threshold_pct: float,
        strategy: VPNSelectionStrategy,
    ) -> bool:
        if current_uuid is None or current_uuid == candidate_uuid:
            return current_uuid != candidate_uuid
        scores = self._compute_scores(results, strategy)
        if current_uuid not in scores:
            return True  # current is unhealthy/missing this round
        candidate_score = scores.get(candidate_uuid)
        if candidate_score is None:
            return False
        current_score = scores[current_uuid]
        # Scores are negative by construction (-latency_ms, optionally offset
        # by a bandwidth bonus), so this only guards the division below
        # against the degenerate case of an exact-zero score, not against
        # "any negative score" - that would defeat hysteresis entirely.
        if current_score == 0:
            return candidate_score > current_score
        improvement = (candidate_score - current_score) / abs(current_score)
        return improvement > (threshold_pct / 100.0)

    def select_best_vpn(self) -> None:
        """Benchmark every enabled profile against the primary NNTP server
        and switch to the best one, subject to hysteresis. Called once per
        newly-active NZB (via notify_active_nzo), from the periodic health
        check on failure, and on-demand from profile CRUD. Never runs on a
        per-article/per-poll basis."""
        with self._lock:
            candidates = [profile for profile in self.profiles.values() if profile.enabled]

        if not candidates:
            self._handle_no_healthy_vpn(T("No VPN profiles are enabled"))
            return

        nntp_host, nntp_port = self._primary_nntp_server()
        if not nntp_host:
            logging.debug("VPN selection skipped: no enabled NNTP server is configured yet")
            return

        results: dict[str, VPNBenchmarkResult] = {}
        for profile in candidates:
            if self._ensure_tunnel_up(profile):
                result = benchmark.benchmark_profile(
                    profile, nntp_host, nntp_port, int(cfg.vpn_benchmark_samples()), float(cfg.vpn_benchmark_timeout())
                )
            else:
                result = VPNBenchmarkResult(
                    profile_uuid=profile.uuid,
                    healthy=False,
                    latency_samples_ms=[],
                    median_latency_ms=None,
                    error=T("Tunnel is not up"),
                )
            results[profile.uuid] = result
            if result.healthy:
                logging.info("VPN benchmark %s: %.1f ms", profile.name, result.median_latency_ms)
            else:
                logging.info("VPN benchmark %s: %s", profile.name, T("unreachable"))

        with self._lock:
            self.benchmark_results = results

        strategy = VPNSelectionStrategy.from_value(cfg.vpn_selection_mode())
        candidate_uuid = self._pick_candidate(results, strategy)

        if candidate_uuid is None:
            self._handle_no_healthy_vpn(T("No healthy WireGuard VPN is available"))
            return

        self._release_killswitch()

        if self._should_switch(self.active_profile_uuid, candidate_uuid, results, float(cfg.vpn_switch_threshold()), strategy):
            self._switch_to(candidate_uuid)

    def _switch_to(self, profile_id: str) -> None:
        """Atomically (from the downloader's perspective) move to a new
        active profile, then force existing NNTP connections to reconnect
        through the existing disconnect()/reset_nw() mechanism so nothing
        keeps using a stale bind IP."""
        with self._lock:
            profile = self.profiles.get(profile_id)
            if profile is None:
                return
            previous_uuid = self.active_profile_uuid
            previous_name = self.profiles[previous_uuid].name if previous_uuid in self.profiles else None
            self.active_profile_uuid = profile_id
            self.active_bind_ip = profile.tunnel_ip

        if previous_name and previous_name != profile.name:
            logging.info("Switching VPN %s -> %s", previous_name, profile.name)
        else:
            logging.info("Selected VPN %s", profile.name)

        if getattr(sabnzbd, "Downloader", None) is not None:
            sabnzbd.Downloader.disconnect()

    def activate_profile(self, profile_id: str) -> tuple[bool, str]:
        """Manual "Activate" - bypasses hysteresis entirely."""
        with self._lock:
            profile = self.profiles.get(profile_id)
        if profile is None:
            return False, T("VPN profile not found")
        if not profile.enabled:
            return False, T("Cannot activate a disabled VPN profile")
        if not is_platform_supported():
            return False, T("VPN routing is not available on this platform")
        if not self._ensure_tunnel_up(profile):
            return False, T("Tunnel is not up")

        self._release_killswitch()
        self._switch_to(profile_id)
        return True, T("VPN activated")

    def test_profile(self, profile_id: str) -> VPNBenchmarkResult:
        """Manual "Test" for one profile - never changes the active VPN."""
        with self._lock:
            profile = self.profiles.get(profile_id)
        if profile is None:
            return VPNBenchmarkResult(
                profile_uuid=profile_id, healthy=False, latency_samples_ms=[], median_latency_ms=None, error=T("VPN profile not found")
            )

        nntp_host, nntp_port = self._primary_nntp_server()
        if not nntp_host:
            result = VPNBenchmarkResult(
                profile_uuid=profile_id,
                healthy=False,
                latency_samples_ms=[],
                median_latency_ms=None,
                error=T("No enabled NNTP server is configured"),
            )
        elif not is_platform_supported() or not self._ensure_tunnel_up(profile):
            result = VPNBenchmarkResult(
                profile_uuid=profile_id, healthy=False, latency_samples_ms=[], median_latency_ms=None, error=T("Tunnel is not up")
            )
        else:
            result = benchmark.benchmark_profile(
                profile, nntp_host, nntp_port, int(cfg.vpn_benchmark_samples()), float(cfg.vpn_benchmark_timeout())
            )

        with self._lock:
            self.benchmark_results[profile_id] = result

        if result.healthy:
            logging.info("VPN benchmark %s: %.1f ms", profile.name, result.median_latency_ms)
        else:
            logging.info("VPN benchmark %s: %s", profile.name, T("unreachable"))
        return result

    def test_all_profiles(self) -> dict[str, VPNBenchmarkResult]:
        with self._lock:
            profile_ids = list(self.profiles.keys())
        return {profile_id: self.test_profile(profile_id) for profile_id in profile_ids}

    def test_profile_bandwidth(self, profile_id: str) -> VPNBandwidthResult:
        """Manual "Bandwidth test" for one profile - a real, multi-second
        test download through the tunnel via SABnzbd's own internetspeed
        mechanism. Never changes the active VPN or feeds selection in V1."""
        with self._lock:
            profile = self.profiles.get(profile_id)
        if profile is None:
            return VPNBandwidthResult(profile_uuid=profile_id, healthy=False, mbps=None, error=T("VPN profile not found"))

        if not is_platform_supported() or not self._ensure_tunnel_up(profile):
            result = VPNBandwidthResult(profile_uuid=profile_id, healthy=False, mbps=None, error=T("Tunnel is not up"))
        else:
            result = benchmark.measure_bandwidth(profile)

        with self._lock:
            self.bandwidth_results[profile_id] = result

        if result.healthy:
            logging.info("VPN bandwidth test %s: %.2f Mbps", profile.name, result.mbps)
        else:
            logging.info("VPN bandwidth test %s: %s", profile.name, T("unreachable"))
        return result

    def test_all_profiles_bandwidth(self) -> dict[str, VPNBandwidthResult]:
        with self._lock:
            profile_ids = list(self.profiles.keys())
        return {profile_id: self.test_profile_bandwidth(profile_id) for profile_id in profile_ids}

    # ------------------------------------------------------------------
    # Kill switch
    # ------------------------------------------------------------------
    def _handle_no_healthy_vpn(self, reason: str) -> None:
        with self._lock:
            self.active_profile_uuid = None
            self.active_bind_ip = None
        if cfg.vpn_killswitch():
            self._enforce_killswitch(reason)
        else:
            logging.warning("%s - VPN kill switch is disabled, falling back to normal outgoing connection", reason)
            with self._lock:
                self.status_reason = reason

    def _enforce_killswitch(self, reason: str) -> None:
        with self._lock:
            already_active = self.killswitch_active
            self.killswitch_active = True
            self.status_reason = reason
        if not already_active:
            logging.warning("%s - download paused", reason)
        if getattr(sabnzbd, "Downloader", None) is not None:
            sabnzbd.Downloader.vpn_killswitch_paused = True
            sabnzbd.Downloader.pause()

    def _release_killswitch(self) -> None:
        with self._lock:
            was_active = self.killswitch_active
            self.killswitch_active = False
            self.status_reason = None
        downloader = getattr(sabnzbd, "Downloader", None)
        if was_active and downloader is not None and getattr(downloader, "vpn_killswitch_paused", False):
            downloader.vpn_killswitch_paused = False
            downloader.resume()
            logging.info("Healthy VPN available again, resuming downloading")

    def _handle_active_vpn_down(self) -> None:
        """Active tunnel went down mid-download: stop using it immediately,
        then try to fail over to another healthy VPN (or enforce the kill
        switch if none is available)."""
        if getattr(sabnzbd, "Downloader", None) is not None:
            sabnzbd.Downloader.disconnect()
        self.select_best_vpn()

    def _periodic_health_check(self) -> None:
        """Cheap interface-up check only - never a full re-benchmark. Runs
        on the existing Scheduler, not a bespoke thread loop."""
        if not cfg.vpn_enabled() or not is_platform_supported():
            return

        with self._lock:
            active_uuid = self.active_profile_uuid
            active_profile = self.profiles.get(active_uuid) if active_uuid else None

        if active_profile is not None and not wireguard.interface_is_up(active_profile.interface):
            logging.warning("VPN %s is no longer up", active_profile.name)
            self._handle_active_vpn_down()
            return

        with self._lock:
            enabled_profiles = [profile for profile in self.profiles.values() if profile.enabled]
        for profile in enabled_profiles:
            if not wireguard.interface_is_up(profile.interface):
                self._ensure_tunnel_up(profile)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def get_effective_bind_ip(self) -> Optional[str]:
        with self._lock:
            return self.active_bind_ip

    def get_status(self) -> VPNStatus:
        with self._lock:
            active_uuid = self.active_profile_uuid
            active_profile = self.profiles.get(active_uuid) if active_uuid else None
            latency = None
            if active_uuid and active_uuid in self.benchmark_results:
                latency = self.benchmark_results[active_uuid].median_latency_ms
            return VPNStatus(
                platform_supported=is_platform_supported(),
                enabled=bool(cfg.vpn_enabled()),
                killswitch=bool(cfg.vpn_killswitch()),
                selection_mode=VPNSelectionStrategy.from_value(cfg.vpn_selection_mode()),
                active_profile_uuid=active_uuid,
                active_profile_name=active_profile.name if active_profile else None,
                active_latency_ms=latency,
                killswitch_active=self.killswitch_active,
                reason=self.status_reason,
            )


def get_effective_outgoing_nntp_ip() -> str:
    """The single integration point newswrapper.py uses instead of calling
    cfg.outgoing_nntp_ip() directly. When VPN routing is enabled and a VPN is
    active, use its tunnel IP; otherwise fall through unchanged to the
    existing outgoing_nntp_ip setting, so behaviour with VPN disabled is
    identical to before this feature existed.

    Raises ConnectionError while the kill switch is actively blocking, so a
    connection attempt fails cleanly (via newswrapper.py's existing OSError
    handling) instead of silently going out over the normal WAN interface.
    This matters even though Downloader.pause() is the primary kill-switch
    gate: FORCE_PRIORITY jobs bypass that pause and would otherwise still be
    able to open a new, unprotected connection.
    """
    if cfg.vpn_enabled():
        manager = getattr(sabnzbd, "VPNManager", None)
        if manager is not None:
            if manager.killswitch_active:
                raise ConnectionError(T("VPN kill switch is active: no healthy WireGuard VPN is available"))
            bind_ip = manager.get_effective_bind_ip()
            if bind_ip:
                return bind_ip
    return cfg.outgoing_nntp_ip()
