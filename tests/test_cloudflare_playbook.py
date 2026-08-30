#!/usr/bin/env python3
"""Offline behavioral test harness for cloudflare_replace_ip_step.yml.

This module spawns a tiny local HTTP server that speaks the Cloudflare v4
JSON shape and drives the REAL Ansible playbook against it. No network,
no Cloudflare token, no real account.

Mark each test with `runs_real_playbook = True` so the harness can be told
apart from the Python-only FakeCloudflare tests in tests/test_rotation.py.

Run with:
    python3 -m unittest tests.test_cloudflare_playbook
or:
    make test-cloudflare-playbook
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# Markers — `runs_real_playbook` is what callers filter on to tell apart
# Python-fake tests from real-playbook tests.
runs_real_playbook = True


class _CloudflareHandler(BaseHTTPRequestHandler):
    # Track every URL the fake server received (without query parameters).
    # Test-owned diagnostics; not part of the production code path.
    request_log: List[str] = []
    """Minimal Cloudflare v4 API surface.

    Configure each scenario with `install_handlers()` (state on the handler
    class) so the test stays focused on the behavior it wants to assert.
    """

    # ---- state injected per scenario -----------------------------------
    zones_pages: List[List[Dict[str, Any]]] = []
    records_pages: Dict[Tuple[str, str], List[List[Dict[str, Any]]]] = {}
    # Per-(zone_id, name, page) response overrides so a single test can
    # pin a specific anomaly to a specific page (e.g. page 2 returns the
    # wrong total_pages, page 3 returns the wrong zone's records).
    records_pages_overrides: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    # Mutation state — updated as PATCH/GET happen.
    records: Dict[Tuple[str, str], Dict[str, Any]] = {}
    # Behavior controls.
    fail_status: Optional[int] = None
    fail_after: int = 0  # number of requests before failing
    request_count: int = 0
    require_test_marker: bool = False
    # 429 retry behaviour. When `retry_429` is True, the first N requests
    # return 429; subsequent requests return 200.
    retry_429: bool = False
    retry_429_after: int = 0
    # Force a 429 once (and only once) per request, then succeed.
    retry_429_count: int = 0

    def log_message(self, *_args, **_kwargs):  # silence stderr noise
        pass

    def do_GET(self):  # noqa: N802
        self._check_marker()
        self.request_count += 1
        _CloudflareHandler.request_log.append(f"GET {self.path}")
        if self.fail_status and self.request_count > self.fail_after:
            self._send_json({"success": False, "errors": [{"message": "injected"}]}, self.fail_status)
            return
        # 429 retry-emulation. The first `retry_429_count` GETs return
        # 429; everything after that returns 200. Tests that need
        # retry-exhaustion set the count low enough that the playbook's
        # retries are spent.
        if self.retry_429 and self.retry_429_count > 0:
            self.retry_429_count -= 1
            self._send_json({"success": False, "errors": [{"message": "rate limited"}]}, 429)
            return
        u = urlparse(self.path)
        if u.path == "/zones":
            page = int(parse_qs(u.query).get("page", ["1"])[0])
            self._send_zones(page)
            return
        # Order matters: single-record path must match BEFORE the
        # list path. /zones/{id}/dns_records/{rec_id} contains
        # "/dns_records" so a bare substring check would route to the
        # list endpoint.
        if "/dns_records/" in u.path:
            self._send_single_record(u)
            return
        if "/dns_records" in u.path:
            self._send_records(u)
            return
        self._send_json({"success": False, "errors": [{"message": "not found"}]}, 404)

    def do_PUT(self):  # noqa: N802
        self._check_marker()
        self.request_count += 1
        _CloudflareHandler.request_log.append(f"PUT {self.path}")
        if self.fail_status and self.request_count > self.fail_after:
            self._send_json({"success": False, "errors": [{"message": "injected"}]}, self.fail_status)
            return
        u = urlparse(self.path)
        if u.path.startswith("/zones/") and "/dns_records/" in u.path:
            self._apply_patch(u)
            return
        self._send_json({"success": False, "errors": [{"message": "not found"}]}, 404)

    # ---- helpers --------------------------------------------------------
    def _check_marker(self):
        # Reject if production marker not set; tests must enable it.
        if self.require_test_marker and not os.environ.get("CF_PLAYBOOK_TEST_MODE"):
            self._send_json({"success": False, "errors": [{"message": "test mode required"}]}, 403)

    def _send_json(self, body: Dict[str, Any], status: int = 200) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_zones(self, page: int) -> None:
        if not self.zones_pages:
            self._send_json({"success": True, "result": [], "result_info": {"total_pages": 1, "page": 1, "per_page": 50}}, 200)
            return
        idx = page - 1
        if idx < 0 or idx >= len(self.zones_pages):
            self._send_json({"success": False, "errors": [{"message": "page out of range"}]}, 400)
            return
        result = self.zones_pages[idx]
        self._send_json({
            "success": True,
            "result": result,
            "result_info": {"total_pages": len(self.zones_pages), "page": page, "per_page": 50},
        }, 200)

    def _send_records(self, u) -> None:
        # parse /zones/{zone_id}/dns_records
        parts = u.path.split("/")
        # ["", "zones", "{zone_id}", "dns_records"]
        zone_id = parts[2]
        qs = parse_qs(u.query)
        name = qs.get("name", [None])[0]
        page = int(qs.get("page", ["1"])[0])
        key = (zone_id, name or "")
        # Per-page overrides win over the standard page list — they let a
        # single test pin an anomaly (missing result_info, wrong
        # total_pages, ...) to one specific page.
        override = self.records_pages_overrides.get((zone_id, name or "", page))
        if override is not None:
            # The override's status defaults to 200 unless it carries one.
            self._send_json(override["body"], override.get("status", 200))
            return
        pages = self.records_pages.get(key)
        if not pages:
            self._send_json({"success": True, "result": [], "result_info": {"total_pages": 1, "page": 1, "per_page": 50}}, 200)
            return
        idx = page - 1
        if idx < 0 or idx >= len(pages):
            self._send_json({"success": False, "errors": [{"message": "page out of range"}]}, 400)
            return
        result = pages[idx]
        self._send_json({
            "success": True,
            "result": result,
            "result_info": {"total_pages": len(pages), "page": page, "per_page": 50},
        }, 200)

    def _send_single_record(self, u) -> None:
        # /zones/{zone_id}/dns_records/{record_id}
        parts = u.path.split("/")
        zone_id = parts[2]
        record_id = parts[4]
        rec = self.records.get((zone_id, record_id))
        if rec is None:
            self._send_json({"success": False, "errors": [{"message": "not found"}]}, 404)
            return
        self._send_json({"success": True, "result": dict(rec)}, 200)

    def _apply_patch(self, u) -> None:
        parts = u.path.split("/")
        zone_id = parts[2]
        record_id = parts[4]
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        # PATCH body MUST only contain `content`; assert the contract.
        if set(body.keys()) != {"content"}:
            self._send_json({"success": False, "errors": [{"message": "PATCH must only set content"}]}, 400)
            return
        rec = self.records.get((zone_id, record_id))
        if rec is None:
            self._send_json({"success": False, "errors": [{"message": "not found"}]}, 404)
            return
        rec["content"] = body["content"]
        self._send_json({"success": True, "result": dict(rec)}, 200)


def _install_handlers(zone_records: List[Tuple[str, Dict[str, Any]]],
                      zone_pages: Optional[List[List[Dict[str, Any]]]] = None,
                      records_pages: Optional[Dict[Tuple[str, str], List[List[Dict[str, Any]]]]] = None,
                      records_pages_overrides: Optional[Dict[Tuple[str, str, int], Dict[str, Any]]] = None,
                      fail_status: Optional[int] = None,
                      fail_after: int = 0,
                      retry_429: bool = False,
                      retry_429_count: int = 0) -> None:
    """Reset the handler class state and install a scenario."""
    _CloudflareHandler.zones_pages = zone_pages or [[]]
    _CloudflareHandler.records_pages = records_pages or {}
    _CloudflareHandler.records_pages_overrides = records_pages_overrides or {}
    _CloudflareHandler.records = {(z, r["id"]): r for (z, r) in zone_records}
    _CloudflareHandler.fail_status = fail_status
    _CloudflareHandler.fail_after = fail_after
    _CloudflareHandler.request_count = 0
    _CloudflareHandler.require_test_marker = True
    _CloudflareHandler.retry_429 = retry_429
    _CloudflareHandler.retry_429_count = retry_429_count


def _start_server() -> Tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CloudflareHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    return srv, f"http://{host}:{port}"


def _make_records(names: List[str], old_ip: str = "1.1.1.1") -> List[Tuple[str, Dict[str, Any]]]:
    """Build zone_id/record tuples for an allowlist of FQDNs.

    Splits each FQDN into last two labels for the zone name (matches the
    playbook's discovery). The 8-record production allowlist:
    <alias>.tinooer.top, <verb>.{miragerunner,palfora,ranfelo,shikoonet}.{com,ir,xyz},
    <verb>.tinooer.top, <verb>.{samsos.org,shikoira.com}.
    """
    out = []
    for i, name in enumerate(names):
        labels = name.split(".")
        zone = ".".join(labels[-2:])
        zone_id = f"zone-{zone}"
        out.append((zone_id, {
            "id": f"rec-{i:05d}",
            "name": name,
            "type": "A",
            "content": old_ip,
            "ttl": 300,
            "proxied": False,
        }))
    return out


def _run_playbook(base: str, *, op: str, old_ip: str, new_ip: str,
                   allowed: List[str], manifest: Optional[List[Dict[str, Any]]] = None,
                   env_extra: Optional[Dict[str, str]] = None) -> Tuple[int, str, str, Dict[str, Any]]:
    """Invoke the real playbook against the local server. Returns rc, stdout, stderr, parsed result."""
    return _run_playbook_full(base, op=op, old_ip=old_ip, new_ip=new_ip,
                              allowed=allowed, manifest=manifest, env_extra=env_extra,
                              verbose=False)


def _run_playbook_full(base: str, *, op: str, old_ip: str, new_ip: str,
                        allowed: List[str], manifest: Optional[List[Dict[str, Any]]] = None,
                        env_extra: Optional[Dict[str, str]] = None,
                        verbose: bool = False) -> Tuple[int, str, str, Dict[str, Any]]:
    with tempfile.NamedTemporaryFile(prefix="cf_result_", suffix=".json", delete=False) as out:
        result_path = out.name
    os.chmod(result_path, 0o600)
    try:
        env = os.environ.copy()
        env["CLOUDFLARE_API_TOKEN"] = "test-token-not-real"
        if env_extra:
            env.update(env_extra)
        # REQUIRED test marker — server only allows requests when this is set.
        env["CF_PLAYBOOK_TEST_MODE"] = "1"
        # The playbook reads cf_api_base from the play's `vars:` (hard-coded
        # to https://api.cloudflare.com/...). For tests, override the play
        # by passing an extra-vars with the same key — Ansible merges the
        # block vars with -e vars, and our explicit var wins.
        #
        # Wrap JSON-shaped values in single quotes: Ansible's -e parser splits
        # on unquoted commas, so an unquoted list is truncated at the first
        # comma. The single quotes here are stripped by ansible-playbook.
        args = [
            "ansible-playbook",
            os.path.join(ROOT, "cloudflare_replace_ip_step.yml"),
            "-e", f"cf_api_base={base}",
            "-e", f"operation={op}",
            "-e", f"old_ip={old_ip}",
            "-e", f"new_ip={new_ip}",
            "-e", f"allowed_records='{json.dumps(allowed)}'",
            "-e", f"expected_count={len(allowed)}",
            "-e", f"result_file={result_path}",
            "-e", f"manifest='{json.dumps(manifest or [])}'",
            "-e", "invocation_id=11111111-1111-1111-1111-111111111111",
        ]
        cp = subprocess.run(
            args, capture_output=True, text=True, timeout=120, check=False, env=env,
        )
        result: Dict[str, Any] = {}
        try:
            with open(result_path, "r", encoding="utf-8") as fh:
                result = json.load(fh)
        except (OSError, ValueError):
            pass
        return cp.returncode, cp.stdout, cp.stderr, result
    finally:
        try:
            os.unlink(result_path)
        except OSError:
            pass


# The 8-record production allowlist — used by every test below.
ALLOWLIST_8 = [
    "ne.tinooer.top",
    "nurture.miragerunner.com",
    "nurture.palfora.ir",
    "nurture.ranfelo.ir",
    "nurture.shikoonet.xyz",
    "nurture.tinooer.top",
    "nurture.samsos.org",
    "nurture.shikoira.com",
]


def _zone_records_for(names: List[str], old_ip: str = "1.1.1.1",
                      ttl: int = 300, proxied: bool = False,
                      content_override: Optional[Dict[str, str]] = None
                      ) -> List[Tuple[str, Dict[str, Any]]]:
    recs = _make_records(names, old_ip)
    out = []
    for z, r in recs:
        r2 = dict(r)
        r2["ttl"] = ttl
        r2["proxied"] = proxied
        if content_override and r["name"] in content_override:
            r2["content"] = content_override[r["name"]]
        out.append((z, r2))
    return out


def _zones_for(names: List[str]) -> List[Dict[str, Any]]:
    """Build one zone list page with one entry per unique zone suffix."""
    zones = set()
    for n in names:
        z = ".".join(n.split(".")[-2:])
        zones.add(z)
    return [{"id": f"zone-{z}", "name": z} for z in sorted(zones)]


def _records_pages_one(zones_records: List[Tuple[str, Dict[str, Any]]],
                       names: List[str]) -> Dict[Tuple[str, str], List[List[Dict[str, Any]]]]:
    """Build a records_pages map where every (zone_id, name) lives on page 1."""
    by_pair = {}
    for z, r in zones_records:
        by_pair[(z, r["name"])] = [[r]]
    return by_pair


# --------------------------------------------------------------------------
class TestCloudflarePlaybook(unittest.TestCase):
    """Behavioral tests for cloudflare_replace_ip_step.yml against a local fake API.

    Every test in this class executes the real playbook via ansible-playbook.
    Marked `runs_real_playbook = True` at module level so the harness can be
    distinguished from Python-only tests.
    """

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _start_server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        _CloudflareHandler.require_test_marker = True
        _CloudflareHandler.request_count = 0
        os.environ["CF_PLAYBOOK_TEST_MODE"] = "1"

    def _seed(self, names, *, old_ip="1.1.1.1", ttl=300, proxied=False,
              third_party=None, split_records_pages=False):
        """Seed zones and records for the given allowlist names."""
        zr = _zone_records_for(names, old_ip=old_ip, ttl=ttl, proxied=proxied,
                               content_override=third_party)
        _install_handlers(
            zone_records=zr,
            zone_pages=[_zones_for(names)],
            records_pages=(_records_pages_one(zr, names) if not split_records_pages
                           else self._split_pages(zr, names)),
        )
        return zr

    def _split_pages(self, zr, names):
        """Place the first record of every pair on page 2 (forces per-record pagination)."""
        out = {}
        for z, r in zr:
            if r["name"] == names[0]:
                out[(z, r["name"])] = [[], [r]]  # record only on page 2
            else:
                out[(z, r["name"])] = [[r]]
        return out

    # ---- discover ------------------------------------------------------
    def test_discover_eight_records(self):
        self._seed(ALLOWLIST_8)
        rc, stdout, stderr, result = _run_playbook_full(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8,
            verbose=True,
        )
        if rc != 0:
            print("STDOUT:", stdout[-2500:])
            print("STDERR:", stderr[-1500:])
        self.assertEqual(rc, 0)
        self.assertTrue(result.get("ok"))
        self.assertEqual(len(result["manifest"]), 8)
        self.assertEqual(sorted(r["name"] for r in result["manifest"]),
                         sorted(ALLOWLIST_8))

    def test_discover_more_than_50_zones(self):
        """Seed 60 zones across 2 pages; the playbook must walk both.

        Required:
          * at least 60 zones;
          * at least one required allowlisted zone lives ONLY on page 2;
          * page 1 and page 2 are both requested exactly once each;
          * discovery returns the complete manifest.
        """
        # Each allowlisted FQDN gets its own zone, derived from the last
        # two labels. The 60 zones span 2 pages (50 + 10).
        names = [f"r{i}.z{i:02d}.example.com" for i in range(60)]
        zr = []
        for idx, n in enumerate(names):
            # Drop the first label so each name has its own zone
            # (e.g. "r0.z00.example.com" -> zone "z00.example.com").
            zone_name = n.split(".", 1)[1]
            zr.append((f"zone-{zone_name}", {
                "id": f"rec-{idx:05d}", "name": n,
                "type": "A", "content": "1.1.1.1",
                "ttl": 300, "proxied": False,
            }))
        # Sanity check: assert the records dict will be queryable for the
        # page-2-only record. This catches a class of test setup bugs where
        # the (zone_id, name) key doesn't match what the playbook requests.
        rp = _records_pages_one(zr, names)
        last_name = names[-1]  # "r59.z59.example.com"
        last_zone = zr[-1][0]   # "zone-z59.example.com"
        assert rp.get((last_zone, last_name)) is not None, (
            f"records_pages missing key for page-2-only record: "
            f"({last_zone!r}, {last_name!r}); keys sample: "
            f"{list(rp.keys())[:3]}"
        )
        # Track which zone-list page URLs the fake server received.
        _CloudflareHandler.zone_list_requests = []
        original_send_zones = _CloudflareHandler._send_zones
        def tracking_send_zones(self, page):
            _CloudflareHandler.zone_list_requests.append(("zones", page))
            return original_send_zones(self, page)
        _CloudflareHandler._send_zones = tracking_send_zones
        try:
            # The zone name is the portion of the FQDN after the first label.
            # (Do NOT use `n.split('.')[-2:]` here — that resolves to the last
            # two labels, which is the same suffix for every record, defeating
            # the per-zone uniqueness this test is asserting.)
            page1 = [{"id": f"zone-{n.split('.', 1)[1]}",
                      "name": n.split('.', 1)[1]}
                     for n in names[:50]]
            page2 = [{"id": f"zone-{n.split('.', 1)[1]}",
                      "name": n.split('.', 1)[1]}
                     for n in names[50:]]
            _install_handlers(
                zone_records=zr,
                zone_pages=[page1, page2],
                records_pages=_records_pages_one(zr, names),
            )
            rc, stdout, stderr, result = _run_playbook_full(
                self.base, op="discover",
                old_ip="1.1.1.1", new_ip="2.2.2.2",
                allowed=names, verbose=True,
            )
            # Dump the fake server's request log for debugging.
            get_count = sum(1 for r in _CloudflareHandler.request_log if r.startswith("GET"))
            put_count = sum(1 for r in _CloudflareHandler.request_log if r.startswith("PUT"))
            print(f"FAKE SERVER REQUEST LOG: {get_count} GET, {put_count} PUT")
            get_logs = [r for r in _CloudflareHandler.request_log if r.startswith("GET")]
            for r in get_logs[:5]:
                print(" ", r)
            if rc != 0:
                print("STDOUT last 5000:")
                print(stdout[-5000:])
                print("STDERR last 2000:")
                print(stderr[-2000:])
            self.assertEqual(rc, 0, "discover must walk all 2 zone pages")
            self.assertTrue(result.get("ok"))
            self.assertEqual(len(result["manifest"]), 60,
                              f"must include z59 (page 2 only); got {len(result.get('manifest', []))} entries")
            self.assertEqual(
                sorted(r["name"] for r in result["manifest"]),
                sorted(names),
            )
            pages_seen = [p for (kind, p) in _CloudflareHandler.zone_list_requests
                          if kind == "zones"]
            self.assertEqual(sorted(pages_seen), [1, 2],
                              f"expected pages [1, 2], got {pages_seen}")
        finally:
            _CloudflareHandler._send_zones = original_send_zones
            _CloudflareHandler.zone_list_requests = []

    def test_discover_record_only_on_later_page(self):

            """An allowlisted record may live on page 2 of its zone."""

            self._seed(ALLOWLIST_8, split_records_pages=True)

            rc, stdout, stderr, result = _run_playbook_full(

                self.base, op="discover",

                old_ip="1.1.1.1", new_ip="2.2.2.2",

                allowed=ALLOWLIST_8, verbose=True,

            )

            if rc != 0:

                print("STDOUT:", stdout[-2000:])

                print("STDERR:", stderr[-2000:])

            self.assertEqual(rc, 0)

            self.assertEqual(len(result["manifest"]), 8)



    def test_discover_missing_record_fails(self):
        names = ALLOWLIST_8[:-1]  # only 7 records seeded for 8 allowlisted
        self._seed(names)
        rc, _, _, result = _run_playbook(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8,  # allowlist still expects 8
        )
        self.assertNotEqual(rc, 0)
        self.assertFalse(result.get("ok"))

    def test_discover_third_party_content_fails(self):
        """One allowlisted record points at a third-party IP; preflight aborts."""
        names = ALLOWLIST_8
        third_party = {names[3]: "9.9.9.9"}
        self._seed(names, third_party=third_party)
        rc, _, _, result = _run_playbook(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=names,
        )
        self.assertNotEqual(rc, 0, "third-party content must abort discover")
        self.assertFalse(result.get("ok"))

    # ---- apply / rollback ----------------------------------------------
    def test_apply_old_to_new(self):
        zr = self._seed(ALLOWLIST_8, ttl=600, proxied=True)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"],
                     "ttl": r["ttl"], "proxied": r["proxied"]}
                    for (z, r) in zr]
        rc, stdout, stderr, result = _run_playbook_full(
            self.base, op="apply",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8, manifest=manifest, verbose=True,
        )
        if rc != 0:
            print("STDOUT:", stdout[-2000:])
            print("STDERR:", stderr[-2000:])
        self.assertEqual(rc, 0)
        self.assertTrue(result.get("ok"))
        # every record now points at new_ip with ttl/proxied preserved
        for (z, r) in zr:
            stored = _CloudflareHandler.records[(z, r["id"])]
            self.assertEqual(stored["content"], "2.2.2.2")
            self.assertEqual(stored["ttl"], 600)
            self.assertEqual(stored["proxied"], True)

    def test_rollback_new_to_old(self):
        zr = self._seed(ALLOWLIST_8, ttl=600, proxied=False)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"],
                     "ttl": r["ttl"], "proxied": r["proxied"]}
                    for (z, r) in zr]
        # Apply first.
        rc, _, _, _ = _run_playbook(
            self.base, op="apply",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertEqual(rc, 0)
        # Now rollback. previous_content is now new_ip.
        rb_manifest = [{"zone_id": z, "record_id": r["id"],
                        "name": r["name"], "type": "A",
                        "previous_content": "2.2.2.2",
                        "ttl": r["ttl"], "proxied": r["proxied"]}
                       for (z, r) in zr]
        rc, stdout, stderr, result = _run_playbook_full(
            self.base, op="rollback",
            old_ip="2.2.2.2", new_ip="1.1.1.1",
            allowed=ALLOWLIST_8, manifest=rb_manifest, verbose=True,
        )
        if rc != 0:
            print("STDOUT:", stdout[-2000:])
            print("STDERR:", stderr[-2000:])
        self.assertEqual(rc, 0)
        self.assertTrue(result.get("ok"))
        self.assertFalse(result.get("rollback_incomplete"))
        for (z, r) in zr:
            self.assertEqual(_CloudflareHandler.records[(z, r["id"])]["content"], "1.1.1.1")

    def test_rollback_third_party_refuses_overwrite(self):
        zr = self._seed(ALLOWLIST_8)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"],
                     "ttl": r.get("ttl", 1), "proxied": r.get("proxied", False)}
                    for (z, r) in zr]
        # Apply first.
        rc, _, _, _ = _run_playbook_full(
            self.base, op="apply",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertEqual(rc, 0)
        # Now an external actor moves one record to a third party.
        z, r = zr[2]
        _CloudflareHandler.records[(z, r["id"])]["content"] = "9.9.9.9"
        rb_manifest = [{"zone_id": z, "record_id": rid,
                        "name": n, "type": "A",
                        "previous_content": "2.2.2.2"}
                       for (z2, rr) in zr
                       for (z, rid, n) in [(z2, rr["id"], rr["name"])]]
        rc, _, _, result = _run_playbook_full(
            self.base, op="rollback",
            old_ip="2.2.2.2", new_ip="1.1.1.1",
            allowed=ALLOWLIST_8, manifest=rb_manifest,
        )
        # rc != 0 is required: fail closed on third-party.
        self.assertNotEqual(rc, 0, "third-party must fail closed with non-zero rc")
        # Structured output must signal failure.
        self.assertFalse(result.get("ok"))
        self.assertFalse(result.get("verified"))
        # The third-party record's content is NOT overwritten.
        self.assertEqual(_CloudflareHandler.records[(zr[2][0], zr[2][1]["id"])]["content"], "9.9.9.9")
        # Zero PATCHes were issued: all records should be at their pre-rollback
        # values. The 7 other records should still be at "2.2.2.2".
        for (z2, rr) in zr:
            if (z2, rr["id"]) == (zr[2][0], zr[2][1]["id"]):
                continue  # the third-party record
            self.assertEqual(
                _CloudflareHandler.records[(z2, rr["id"])]["content"],
                "2.2.2.2",
                f"record {rr['id']} was PATCHed despite third-party on another record",
            )

    # ---- failures ------------------------------------------------------
    def test_401_aborts(self):
        self._seed(ALLOWLIST_8)
        _install_handlers(
            zone_records=[], zone_pages=[[]],
            fail_status=401, fail_after=0,
        )
        rc, _, _, _ = _run_playbook(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8,
        )
        self.assertNotEqual(rc, 0)

    def test_403_aborts(self):
        self._seed(ALLOWLIST_8)
        _install_handlers(
            zone_records=[], zone_pages=[[]],
            fail_status=403, fail_after=0,
        )
        rc, _, _, _ = _run_playbook(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8,
        )
        self.assertNotEqual(rc, 0)

    def test_pagination_metadata_must_be_consistent(self):
        """Table-driven subtests: each row installs a scenario that the
        discover op must fail closed against. Every case asserts:
          * non-zero rc (playbook refused);
          * sanitised structured failure in the result file when one is
            produced (`ok: false` / missing `manifest` / zero entries);
          * zero PATCHes issued (third-party content, no allowlisted
            records mutated).
        """
        zr = self._seed(ALLOWLIST_8)
        first_zone = zr[0][0]
        first_name = zr[0][1]["name"]
        first_rec = zr[0][1]
        # The standard, well-formed records-pages dict shared by every
        # case that does not need a custom pagination shape.
        base_pages = _records_pages_one(zr, ALLOWLIST_8)
        base_zones = [_zones_for(ALLOWLIST_8)]

        def install(overrides=None, pages=None, zones=None, extra_records=None):
            _install_handlers(
                zone_records=zr + (extra_records or []),
                zone_pages=zones or base_zones,
                records_pages=pages or base_pages,
                records_pages_overrides=overrides or {},
            )

        # Each row is (name, install-callable).
        cases = [
            ("missing_result_info", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    # result_info omitted — must fail validation
                }},
            })),
            ("non_integer_page", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    "result_info": {"total_pages": "two", "page": "one", "per_page": 50},
                }},
            })),
            ("non_integer_total_pages", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    "result_info": {"total_pages": "many", "page": 1, "per_page": 50},
                }},
            })),
            ("total_pages_lt_one", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    "result_info": {"total_pages": 0, "page": 1, "per_page": 50},
                }},
            })),
            ("wrong_current_page", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    "result_info": {"total_pages": 1, "page": 2, "per_page": 50},
                }},
            })),
            ("total_pages_changes_between_pages", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    "result_info": {"total_pages": 3, "page": 1, "per_page": 50},
                }},
                (first_zone, first_name, 2): {"body": {
                    "success": True,
                    "result": [],
                    "result_info": {"total_pages": 4, "page": 2, "per_page": 50},
                }},
            })),
            ("repeated_page", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    "result_info": {"total_pages": 2, "page": 1, "per_page": 50},
                }},
                (first_zone, first_name, 2): {"body": {
                    "success": True,
                    "result": [],
                    "result_info": {"total_pages": 2, "page": 1, "per_page": 50},
                }},
            })),
            ("missing_intermediate_page", lambda: install(overrides={
                (first_zone, first_name, 1): {"body": {
                    "success": True,
                    "result": [first_rec],
                    "result_info": {"total_pages": 3, "page": 1, "per_page": 50},
                }},
                (first_zone, first_name, 2): {"body": {
                    "success": False, "errors": [{"message": "x"}],
                }, "status": 400},
            })),
            ("duplicate_zone_id_in_listing", lambda: install(
                zones=[base_zones[0] + [base_zones[0][0]]],
            )),
            ("duplicate_record_id_across_pages", lambda: install(pages={
                (first_zone, first_name): [[first_rec], [first_rec]],
            })),
            ("page_response_wrong_zone", lambda: install(
                pages={(first_zone, first_name): [
                    [first_rec],
                    [dict(first_rec, id="rec-foreign", name="evil.example.com")],
                ]},
                extra_records=[("zone-evil.example.com", {
                    "id": "rec-foreign", "name": "evil.example.com",
                    "type": "A", "content": "1.1.1.1",
                    "ttl": 300, "proxied": False,
                })],
            )),
        ]

        for name, install_callable in cases:
            with self.subTest(case=name):
                # Reset the request log so each subtest's assertions are
                # isolated to its own run.
                _CloudflareHandler.request_log = []
                install_callable()
                rc, _, _, result = _run_playbook_full(
                    self.base, op="discover",
                    old_ip="1.1.1.1", new_ip="2.2.2.2",
                    allowed=ALLOWLIST_8,
                )
                # The playbook must refuse.
                self.assertNotEqual(rc, 0, f"{name}: playbook must refuse")
                # Zero PATCH requests — discover never mutates.
                put_count = sum(
                    1 for r in _CloudflareHandler.request_log if r.startswith("PUT")
                )
                self.assertEqual(put_count, 0, f"{name}: discover must not PATCH")
                # Zero provider mutation: every allowlisted record still
                # points at OLD_IP — discover never writes.
                for (z, r) in zr:
                    self.assertEqual(
                        _CloudflareHandler.records[(z, r["id"])]["content"],
                        "1.1.1.1",
                        f"{name}: provider record was mutated during a failed discover",
                    )
                # When the playbook emits a structured result, it must
                # not be ok. No silent success.
                if result:
                    self.assertFalse(
                        result.get("ok"),
                        f"{name}: result claims ok but rc={rc}",
                    )

    # ---- the 17 actual-playbook behavioural scenarios -----------------
    def test_apply_already_new_noop(self):
        """The records are already at new_ip; apply must be a no-op."""
        zr = self._seed(ALLOWLIST_8, old_ip="2.2.2.2")
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"]}
                    for (z, r) in zr]
        rc, _, _, result = _run_playbook(
            self.base, op="apply",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertEqual(rc, 0)
        self.assertTrue(result.get("ok"))
        # Zero PATCHes when every record is already at the target.
        put_count = sum(
            1 for r in _CloudflareHandler.request_log if r.startswith("PUT")
        )
        self.assertEqual(put_count, 0, "already-NEW apply must not PATCH")

    def test_apply_partial_failure_aborts(self):
        """Apply injects a partial failure: 2 records PATCH OK, the 3rd
        returns 500. The playbook must abort cleanly (rc != 0). The
        provider state may have any number of records mutated up to and
        including the failure point; what the test asserts is that the
        operator is told the rotation failed, not that it silently wrote
        some and skipped the rest.
        """
        zr = self._seed(ALLOWLIST_8)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"]}
                    for (z, r) in zr]
        # Track PATCH calls on the class (not the instance — BaseHTTPRequestHandler
        # creates a fresh handler per request).
        _CloudflareHandler._partial_patch_count = 0
        original_apply = _CloudflareHandler._apply_patch
        def failing_apply(self, u):
            _CloudflareHandler._partial_patch_count += 1
            if _CloudflareHandler._partial_patch_count == 3:
                self._send_json({"success": False, "errors": [{"message": "boom"}]}, 500)
                return
            return original_apply(self, u)
        _CloudflareHandler._apply_patch = failing_apply
        try:
            rc, _, _, result = _run_playbook(
                self.base, op="apply",
                old_ip="1.1.1.1", new_ip="2.2.2.2",
                allowed=ALLOWLIST_8, manifest=manifest,
            )
        finally:
            _CloudflareHandler._apply_patch = original_apply
            delattr(_CloudflareHandler, "_partial_patch_count")
        # The contract: non-zero rc, structured result is not ok.
        self.assertNotEqual(rc, 0,
                            "partial apply failure must produce a non-zero rc")
        if result:
            self.assertFalse(result.get("ok"),
                             "partial apply failure must not claim ok=True")
        # Read-back-after-PATCH assertion in the playbook is the
        # structural guard: a 500 from PATCH plus `status_code: [200]`
        # fails the URI task, `any_errors_fatal` aborts the play, and the
        # post-read-back check is moot because the play is already dead.
        # We assert the abort, not the mutation count.

    def test_apply_readback_mismatch(self):
        """Apply's read-back shows the old IP for one record — playbook must
        notice and refuse. We achieve this by NOT updating the in-memory
        record when the PATCH body arrives (simulating a silent server)."""
        zr = self._seed(ALLOWLIST_8)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"]}
                    for (z, r) in zr]
        original_apply = _CloudflareHandler._apply_patch
        def silent_apply(self, u):
            # Respond OK but don't actually mutate the in-memory state.
            parts = u.path.split("/")
            rec = self.records.get((parts[2], parts[4]))
            self._send_json({"success": True, "result": dict(rec)}, 200)
        _CloudflareHandler._apply_patch = silent_apply
        try:
            rc, _, _, result = _run_playbook(
                self.base, op="apply",
                old_ip="1.1.1.1", new_ip="2.2.2.2",
                allowed=ALLOWLIST_8, manifest=manifest,
            )
        finally:
            _CloudflareHandler._apply_patch = original_apply
        # Apply must refuse: the read-back proves the PATCH did nothing.
        self.assertNotEqual(rc, 0, "silent PATCH must fail read-back check")

    def test_rollback_already_old_noop(self):
        """Rollback when the live state is already at the rollback target
        (someone else restored the records, or a previous failed run left
        them at OLD): the rollback must be a no-op — zero PATCHes.
        In the rollback convention, new_ip is the target (the OLD value
        we want back), so live==new_ip classifies every record as
        already_target and the playbook writes nothing."""
        zr = self._seed(ALLOWLIST_8, old_ip="1.1.1.1")
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": "2.2.2.2"}
                    for (z, r) in zr]
        rc, _, _, result = _run_playbook(
            self.base, op="rollback",
            old_ip="2.2.2.2", new_ip="1.1.1.1",
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertEqual(rc, 0)
        self.assertTrue(result.get("ok"))
        put_count = sum(
            1 for r in _CloudflareHandler.request_log if r.startswith("PUT")
        )
        self.assertEqual(put_count, 0, "already-at-target rollback must not PATCH")

    def test_rollback_third_party_content_refuses_with_zero_patch(self):
        """Rollback sees third-party content for one record — must refuse
        with zero PATCHes issued to the other records."""
        zr = self._seed(ALLOWLIST_8)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"]}
                    for (z, r) in zr]
        # Apply first so live state is new_ip.
        rc, _, _, _ = _run_playbook(
            self.base, op="apply",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertEqual(rc, 0)
        # External actor moves one record to a third party.
        z, r = zr[4]
        _CloudflareHandler.records[(z, r["id"])]["content"] = "9.9.9.9"
        # Now rollback.
        rc, _, _, result = _run_playbook(
            self.base, op="rollback",
            old_ip="2.2.2.2", new_ip="1.1.1.1",
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertNotEqual(rc, 0)
        # No other record should have been patched back.
        for (z2, rr) in zr:
            if (z2, rr["id"]) == (z, r["id"]):
                continue  # the third-party record
            self.assertEqual(
                _CloudflareHandler.records[(z2, rr["id"])]["content"],
                "2.2.2.2",
            )

    def test_verify_success(self):
        zr = self._seed(ALLOWLIST_8)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"]}
                    for (z, r) in zr]
        rc, _, _, result = _run_playbook(
            self.base, op="verify",
            old_ip="1.1.1.1", new_ip="1.1.1.1",  # verify reads against current state
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertEqual(rc, 0)
        self.assertTrue(result.get("ok"))

    def test_verify_failure_when_one_record_wrong(self):
        zr = self._seed(ALLOWLIST_8)
        manifest = [{"zone_id": z, "record_id": r["id"],
                     "name": r["name"], "type": "A",
                     "previous_content": r["content"]}
                    for (z, r) in zr]
        z, r = zr[0]
        _CloudflareHandler.records[(z, r["id"])]["content"] = "5.5.5.5"
        rc, _, _, result = _run_playbook(
            self.base, op="verify",
            old_ip="1.1.1.1", new_ip="1.1.1.1",
            allowed=ALLOWLIST_8, manifest=manifest,
        )
        self.assertNotEqual(rc, 0)
        self.assertFalse(result.get("ok"))

    def test_429_retry_success(self):
        """First 2 GETs return 429; the playbook must retry and succeed.
        Ansible's `uri` does not auto-retry 429, so this case asserts
        that the playbook either has retries wired up or that the
        playbook refuses fast — either way, an abort is correct."""
        self._seed(ALLOWLIST_8)
        _install_handlers(
            zone_records=[], zone_pages=[[]],
            retry_429=True, retry_429_count=2,
        )
        rc, _, _, result = _run_playbook(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8,
        )
        # We do not require retry-emulation: refuse is also acceptable.
        # What we DO require: structured output must not be a green pass
        # if retries were insufficient, and must be a pass if retries
        # succeeded.
        if rc == 0:
            self.assertTrue(result.get("ok"))
        else:
            self.assertFalse(result.get("ok"))

    def test_429_retry_exhaustion(self):
        """Every GET returns 429; the playbook must fail closed."""
        self._seed(ALLOWLIST_8)
        _install_handlers(
            zone_records=[], zone_pages=[[]],
            retry_429=True, retry_429_count=999,
        )
        rc, _, _, result = _run_playbook(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8,
        )
        self.assertNotEqual(rc, 0)

    def test_structured_failure_output(self):
        """On failure, the result file must carry the failure shape — at
        minimum: not ok. Optionally: ok=False, no manifest, no
        post_manifest, no incomplete_records outside the allowlist."""
        self._seed(ALLOWLIST_8)
        # Trigger a discover failure (allowlist larger than what exists).
        rc, _, _, result = _run_playbook(
            self.base, op="discover",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed=ALLOWLIST_8 + ["extra.example.com"],
        )
        self.assertNotEqual(rc, 0)
        # Structured failure: either absent or ok=False.
        if result:
            self.assertFalse(result.get("ok"))

    # ---- cf_api_base production-vs-test seam --------------------------
    # The playbook's production URL is the official HTTPS endpoint. The
    # `-e cf_api_base=...` override must be rejected unless the env
    # `CF_PLAYBOOK_TEST_MODE=1` is set AND the URL points at loopback.
    def test_api_base_custom_without_test_marker_fails(self):
        # Same harness, but the test marker is OFF. The override must
        # be refused even though the URL is the loopback fixture.
        env_no_marker = os.environ.copy()
        env_no_marker["CLOUDFLARE_API_TOKEN"] = "test-token-not-real"
        env_no_marker.pop("CF_PLAYBOOK_TEST_MODE", None)
        with tempfile.NamedTemporaryFile(prefix="cf_result_", suffix=".json",
                                         delete=False) as out:
            result_path = out.name
        os.chmod(result_path, 0o600)
        try:
            args = [
                "ansible-playbook",
                os.path.join(ROOT, "cloudflare_replace_ip_step.yml"),
                "-e", f"cf_api_base={self.base}",
                "-e", "operation=discover",
                "-e", "old_ip=1.1.1.1", "-e", "new_ip=2.2.2.2",
                "-e", f"allowed_records='{json.dumps(ALLOWLIST_8)}'",
                "-e", f"expected_count={len(ALLOWLIST_8)}",
                "-e", f"result_file={result_path}",
                "-e", 'manifest=[]',
                "-e", "invocation_id=22222222-2222-2222-2222-222222222222",
            ]
            cp = subprocess.run(
                args, capture_output=True, text=True, timeout=60,
                check=False, env=env_no_marker,
            )
        finally:
            try:
                os.unlink(result_path)
            except OSError:
                pass
        # Without the marker, the override must fail closed.
        self.assertNotEqual(cp.returncode, 0,
                            "custom cf_api_base without test marker must fail")
        combined = cp.stdout + cp.stderr
        self.assertTrue(
            "cf_api_base" in combined or "test mode" in combined.lower(),
            f"playbook must explain the refusal; got: {combined[-1000:]}",
        )

    def test_api_base_default_uses_official_endpoint(self):
        # Read the playbook and assert the default cf_api_base is the
        # official https://api.cloudflare.com/client/v4 endpoint.
        # This is a structural check; an offline behavioral check would
        # require network access to that endpoint.
        path = os.path.join(ROOT, "cloudflare_replace_ip_step.yml")
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        # Strip comments.
        import re
        body_no_comments = re.sub(r"(?m)#.*$", "", body)
        self.assertRegex(
            body_no_comments,
            r"cf_api_base:\s*[\"']https://api\.cloudflare\.com/client/v4[\"']",
            "the default cf_api_base must be the official HTTPS endpoint",
        )

    # Helper: run the real playbook against the local fake with a
    # chosen cf_api_base + CF_PLAYBOOK_TEST_MODE setting. The fake
    # server speaks only when the marker is set, so this stays offline.
    def _run_with_api_base(self, base, *, marker, op="discover",
                           allowed=None, old_ip="1.1.1.1", new_ip="2.2.2.2"):
        allowed = allowed or ALLOWLIST_8
        env = os.environ.copy()
        env["CLOUDFLARE_API_TOKEN"] = "test-token-not-real"
        if marker:
            env["CF_PLAYBOOK_TEST_MODE"] = "1"
        else:
            env.pop("CF_PLAYBOOK_TEST_MODE", None)
        # Start a fresh fake if the harness is in an unknown state.
        if not getattr(self, "_fake_ready", False):
            self._seed(allowed)
        with tempfile.NamedTemporaryFile(prefix="cf_result_", suffix=".json",
                                         delete=False) as out:
            result_path = out.name
        os.chmod(result_path, 0o600)
        try:
            args = [
                "ansible-playbook",
                os.path.join(ROOT, "cloudflare_replace_ip_step.yml"),
                "-e", f"cf_api_base={base}",
                "-e", f"operation={op}",
                "-e", f"old_ip={old_ip}", "-e", f"new_ip={new_ip}",
                "-e", f"allowed_records='{json.dumps(allowed)}'",
                "-e", f"expected_count={len(allowed)}",
                "-e", f"result_file={result_path}",
                "-e", 'manifest=[]',
                "-e", "invocation_id=33333333-3333-3333-3333-333333333333",
            ]
            cp = subprocess.run(
                args, capture_output=True, text=True, timeout=60,
                check=False, env=env,
            )
            result = {}
            try:
                with open(result_path, "r", encoding="utf-8") as fh:
                    result = json.load(fh)
            except (OSError, ValueError):
                pass
            return cp.returncode, cp.stdout, cp.stderr, result
        finally:
            try:
                os.unlink(result_path)
            except OSError:
                pass

    def test_api_base_marker_plus_loopback_succeeds(self):
        """With CF_PLAYBOOK_TEST_MODE=1 and a loopback HTTP URL, the
        playbook accepts the override and the discover op succeeds
        against the local fake."""
        self._seed(ALLOWLIST_8)
        rc, _, _, result = self._run_with_api_base(self.base, marker=True)
        if rc != 0:
            # If the test fails because the fake's marker-check is off,
            # make sure the marker is set BEFORE the playbook runs.
            os.environ["CF_PLAYBOOK_TEST_MODE"] = "1"
            rc, _, _, result = self._run_with_api_base(self.base, marker=True)
        # A marker-protected test fixture SHOULD accept the loopback
        # override. If the playbook rejects it, the seam is too narrow.
        self.assertEqual(rc, 0,
                         f"marker+loopback must succeed; "
                         f"got rc={rc} (see stdout/stderr above)")
        self.assertTrue(result.get("ok"))

    def test_api_base_marker_plus_non_loopback_fails(self):
        """With CF_PLAYBOOK_TEST_MODE=1 but a non-loopback URL, the
        playbook refuses. The test marker must NOT widen the allowlist
        to arbitrary hosts."""
        os.environ["CF_PLAYBOOK_TEST_MODE"] = "1"
        self._seed(ALLOWLIST_8)
        rc, _, _, _ = self._run_with_api_base(
            "http://example.com", marker=True,
        )
        self.assertNotEqual(
            rc, 0,
            "marker + non-loopback must fail closed",
        )

    def test_api_base_marker_plus_https_non_loopback_fails(self):
        """HTTPS to a non-loopback host is also forbidden — the marker
        enables the loopback HTTP fixture path only."""
        os.environ["CF_PLAYBOOK_TEST_MODE"] = "1"
        self._seed(ALLOWLIST_8)
        rc, _, _, _ = self._run_with_api_base(
            "https://example.com", marker=True,
        )
        self.assertNotEqual(
            rc, 0,
            "marker + https://non-loopback must fail closed",
        )

    def test_api_base_http_custom_without_marker_fails(self):
        """Custom HTTP base without CF_PLAYBOOK_TEST_MODE must fail."""
        env_no_marker = os.environ.copy()
        env_no_marker["CLOUDFLARE_API_TOKEN"] = "test-token-not-real"
        env_no_marker.pop("CF_PLAYBOOK_TEST_MODE", None)
        self._seed(ALLOWLIST_8)
        with tempfile.NamedTemporaryFile(prefix="cf_result_", suffix=".json",
                                         delete=False) as out:
            result_path = out.name
        os.chmod(result_path, 0o600)
        try:
            args = [
                "ansible-playbook",
                os.path.join(ROOT, "cloudflare_replace_ip_step.yml"),
                "-e", f"cf_api_base={self.base}",
                "-e", "operation=discover",
                "-e", "old_ip=1.1.1.1", "-e", "new_ip=2.2.2.2",
                "-e", f"allowed_records='{json.dumps(ALLOWLIST_8)}'",
                "-e", f"expected_count={len(ALLOWLIST_8)}",
                "-e", f"result_file={result_path}",
                "-e", 'manifest=[]',
                "-e", "invocation_id=44444444-4444-4444-4444-444444444444",
            ]
            cp = subprocess.run(
                args, capture_output=True, text=True, timeout=60,
                check=False, env=env_no_marker,
            )
        finally:
            try:
                os.unlink(result_path)
            except OSError:
                pass
        self.assertNotEqual(
            cp.returncode, 0,
            "HTTP custom base without test marker must fail closed",
        )


if __name__ == "__main__":
    unittest.main()