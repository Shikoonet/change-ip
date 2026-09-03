#!/usr/bin/env python3
"""Loopback Cloudflare API server for the multi-account test harness.

Speaks a strict subset of the real Cloudflare API surface that
`cloudflare_replace_ip_step.yml` uses:

  GET    /zones?per_page=N&page=P
  GET    /zones/{zone_id}/dns_records?type=A&name=FQDN&per_page=N&page=P
  GET    /zones/{zone_id}/dns_records/{record_id}
  PUT    /zones/{zone_id}/dns_records/{record_id}

Per-token zone ownership: the server is configured with
`{account_name: {token: str, zones: [zone_id, ...]}}`. A request
carrying a Bearer token is matched to an account; if the request
URL references a zone the account does not own, the server
returns 403 with `{"success": false, "errors": [{"code": 1004,
"message": "..."}]}`. Wrong / unknown tokens get 403. Missing
tokens get 401.

The data is seeded from a JSON file at startup so the test can
assert on a stable known world.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse


def _wire(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Return a Cloudflare-API-shaped record.

    The real Cloudflare API uses `id` for the record id; the
    playbook reads `rec.id`. Internally we use `record_id` (more
    descriptive), so this is the only place the translation happens.
    """
    return {**rec, "id": rec["record_id"]}


def _persist(state_path: str, state: Dict[str, Any],
             accounts: Dict[str, Dict[str, Any]]) -> None:
    """Atomic write of the canonical in-memory state to disk.

    The test harness spawns fresh processes between phases (apply,
    rollback, verify) and expects the on-disk state to reflect what
    earlier in-memory mutations did. We persist AFTER every mutation
    so a crash, a kill, or a fresh subprocess all see the same
    canonical record state.

    The test harness ALSO restarts the server mid-rotation (to
    inject a fail-after-N flag), and it needs the accounts map
    back to make any further API call. We persist `accounts` here
    with each token replaced by `[REDACTED]` — the server's
    in-memory `accounts` dict still holds the real tokens, but
    the on-disk view contains no Bearer material. A test that
    reads the on-disk file cannot exfiltrate a live token; it
    can only see the account/zone structure.
    """
    import os as _os
    import tempfile as _tempfile
    safe_accounts = {
        name: {"token": "[REDACTED]",
               "zones": list(acc.get("zones", []))}
        for name, acc in accounts.items()
    }
    payload = {
        "accounts": safe_accounts,
        "records": list(state.get("records", [])),
        "mutations": list(state.get("mutations", [])),
        "zones_by_account": state.get("zones_by_account", {}),
        "fail_after_n_mutations": state.get("fail_after_n_mutations"),
    }
    parent = _os.path.dirname(state_path) or "."
    fd, tmp = _tempfile.mkstemp(prefix=".cf_state.", dir=parent)
    try:
        with _os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.flush()
            _os.fsync(fh.fileno())
        _os.replace(tmp, state_path)
        try:
            _os.chmod(state_path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            _os.unlink(tmp)
        except OSError:
            pass
        raise


def make_handler(state: Dict[str, Any], accounts: Dict[str, Dict[str, Any]],
                  state_path: str = "", original_seed: Dict[str, Any] = None):
    """Return a request handler bound to a state dict + accounts map."""

    class _Handler(BaseHTTPRequestHandler):
        # Sanitized request log. NEVER prints:
        #   * the Authorization value
        #   * any other header value
        #   * request body contents
        #   * env, full URL with query value, complete headers
        # Safe keys: method, normalized path, query KEYS (not values),
        # header NAMES, body LENGTH, matched route, response
        # status, safe reason enum.
        def _log(self, method: str, path: str, query_keys: List[str],
                   header_names: List[str], body_length: int,
                   route: str, status: int, reason: str) -> None:
            import sys as _sys
            qkeys = ",".join(sorted(query_keys)) or "-"
            hnames = ",".join(sorted(header_names)) or "-"
            print(
                f"[loopback-cf] {method} path={path} qkeys=[{qkeys}] "
                f"hdrs=[{hnames}] body_len={body_length} "
                f"route={route} -> {status} ({reason})",
                file=_sys.stderr,
            )

        def _path(self) -> str:
            u = urlparse(self.path)
            p = u.path
            for prefix in ("/client/v4",):
                if p.startswith(prefix):
                    p = p[len(prefix):]
                    break
            return p or "/"

        def _send(self, status: int, body: Any,
                    reason: str = "ok",
                    route: str = "unknown",
                    method: str = "GET",
                    query_keys: Optional[List[str]] = None,
                    header_names: Optional[List[str]] = None,
                    body_length: int = 0) -> None:
            blob = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
            self._log(method, self.path,
                      query_keys if query_keys is not None else [],
                      header_names if header_names is not None else list(self.headers.keys()),
                      body_length, route, status, reason)

        def _auth(self) -> Tuple[str, Dict[str, Any]] | None:
            h = self.headers.get("Authorization", "")
            m = re.match(r"^Bearer\s+(.+)$", h)
            if not m:
                return None
            token = m.group(1)
            for name, acc in accounts.items():
                if acc.get("token") == token:
                    return name, acc
            return None

        def _read_body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {}

        def _check_zone(self, account: Dict[str, Any],
                          zone_id: str) -> bool:
            return zone_id in set(account.get("zones", []))

        # ---- routes ----
        def do_GET(self):  # noqa: N802
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            qkeys = sorted(qs.keys())
            auth = self._auth()
            p = self._path()
            method = "GET"
            if p == "/zones":
                if auth is None:
                    return self._send(401, _error(10000, "missing token"),
                                       reason="missing_token",
                                       route="/zones",
                                       method=method, query_keys=qkeys)
                zones = state["zones_by_account"].get(auth[0], [])
                return self._send(200, _ok(zones),
                                   reason="ok", route="/zones",
                                   method=method, query_keys=qkeys)
            m = re.match(r"^/zones/([^/]+)/dns_records(?:\?.*)?$", self._path())
            if m:
                if auth is None:
                    return self._send(401, _error(10000, "missing token"),
                                       reason="missing_token",
                                       route="/zones/{id}/dns_records",
                                       method=method, query_keys=qkeys)
                zone_id = m.group(1)
                if not self._check_zone(auth[1], zone_id):
                    return self._send(403, _error(1004,
                                                       f"zone {zone_id} not owned by account {auth[0]}"),
                                       reason="zone_not_owned",
                                       route="/zones/{id}/dns_records",
                                       method=method, query_keys=qkeys)
                rec_type = (qs.get("type") or [""])[0]
                name = (qs.get("name") or [""])[0]
                per_page = int((qs.get("per_page") or ["50"])[0])
                page = int((qs.get("page") or ["1"])[0])
                rs = [r for r in state["records"]
                      if r["zone_id"] == zone_id
                      and (not rec_type or r["type"] == rec_type)
                      and (not name or r["name"] == name)]
                return self._send(200, _page([_wire(r) for r in rs], per_page, page),
                                   reason="ok",
                                   route="/zones/{id}/dns_records",
                                   method=method, query_keys=qkeys)
            m = re.match(r"^/zones/([^/]+)/dns_records/([^/]+)$", self._path())
            if m:
                if auth is None:
                    return self._send(401, _error(10000, "missing token"),
                                       reason="missing_token",
                                       route="/zones/{id}/dns_records/{id}",
                                       method=method, query_keys=qkeys)
                zone_id, rec_id = m.group(1), m.group(2)
                if not self._check_zone(auth[1], zone_id):
                    return self._send(403, _error(1004, "zone not owned"),
                                       reason="zone_not_owned",
                                       route="/zones/{id}/dns_records/{id}",
                                       method=method, query_keys=qkeys)
                rec = next((r for r in state["records"]
                              if r["zone_id"] == zone_id
                              and r["record_id"] == rec_id), None)
                if rec is None:
                    return self._send(404, _error(81044, "record not found"),
                                       reason="record_not_found",
                                       route="/zones/{id}/dns_records/{id}",
                                       method=method, query_keys=qkeys)
                return self._send(200, _ok(_wire(rec)),
                                   reason="ok",
                                   route="/zones/{id}/dns_records/{id}",
                                   method=method, query_keys=qkeys)
            return self._send(404, _error(10000, "no such route"),
                               reason="no_route", route="<none>",
                               method=method, query_keys=qkeys)

        def do_PUT(self):  # noqa: N802
            method = "PUT"
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            qkeys = sorted(qs.keys())
            body_length = int(self.headers.get("Content-Length", "0") or "0")
            m = re.match(r"^/zones/([^/]+)/dns_records/([^/]+)$", self._path())
            if m:
                auth = self._auth()
                if auth is None:
                    return self._send(401, _error(10000, "missing token"),
                                       reason="missing_token",
                                       route="/zones/{id}/dns_records/{id}",
                                       method=method, query_keys=qkeys,
                                       body_length=body_length)
                zone_id, rec_id = m.group(1), m.group(2)
                if not self._check_zone(auth[1], zone_id):
                    return self._send(403, _error(1004, "zone not owned"),
                                       reason="zone_not_owned",
                                       route="/zones/{id}/dns_records/{id}",
                                       method=method, query_keys=qkeys,
                                       body_length=body_length)
                body = self._read_body()
                rec = next((r for r in state["records"]
                              if r["zone_id"] == zone_id
                              and r["record_id"] == rec_id), None)
                if rec is None:
                    return self._send(404, _error(81044, "record not found"),
                                       reason="record_not_found",
                                       route="/zones/{id}/dns_records/{id}",
                                       method=method, query_keys=qkeys,
                                       body_length=body_length)
                if state.get("fail_after_n_mutations") is not None:
                    n = state["fail_after_n_mutations"]
                    # "fail after n mutations" — once the live mutation
                    # count passes n, the next PATCH fails. Strictly
                    # greater than so the n-th mutation itself succeeds
                    # before the gate trips. Mutations survive a server
                    # restart (carried over from the persisted seed) so
                    # the test's restart-with-N-flag pattern reads the
                    # accumulated count, not a fresh zero.
                    if len(state.get("mutations", [])) > n:
                        # Trip-once: clear the gate so the FOLLOWING
                        # PATCH (the rollback that recovers the partial
                        # mutation) succeeds. Persist the cleared
                        # state so a later restart doesn't trip it
                        # again either.
                        state["fail_after_n_mutations"] = None
                        if state_path:
                            _persist(state_path, state, accounts)
                        return self._send(500, _error(10000,
                                                           "injected failure"),
                                           reason="fail_after_n_mutations",
                                           route="/zones/{id}/dns_records/{id}",
                                           method=method, query_keys=qkeys,
                                           body_length=body_length)
                if "content" in body:
                    rec["content"] = body["content"]
                state.setdefault("mutations", []).append({
                    "account": auth[0], "zone_id": zone_id,
                    "record_id": rec_id, "content": rec["content"],
                })
                if state_path:
                    _persist(state_path, state, accounts)
                return self._send(200, _ok(_wire(rec)), reason="ok",
                                   route="/zones/{id}/dns_records/{id}",
                                   method=method, query_keys=qkeys,
                                   body_length=body_length)
            return self._send(404, _error(10000, "no such route"),
                               reason="no_route", route="<none>",
                               method=method, query_keys=qkeys,
                               body_length=body_length)

    return _Handler


def _ok(result: Any) -> Dict[str, Any]:
    return {"success": True, "result": result, "result_info": {
        "page": "1", "per_page": "50", "total_pages": "1"}}


def _page(results: List[Any], per_page: int, page: int) -> Dict[str, Any]:
    total_pages = max(1, (len(results) + per_page - 1) // per_page)
    return {
        "success": True,
        "result": results,
        "result_info": {"page": str(page), "per_page": str(per_page),
                          "total_pages": str(total_pages)},
    }


def _error(code: int, message: str) -> Dict[str, Any]:
    return {"success": False, "errors": [{"code": code, "message": message}]}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--state", required=True,
                    help="JSON file with seeded state")
    args = p.parse_args()
    with open(args.state) as fh:
        seed = json.load(fh)
    # accounts: {account_name: {token, zones: [...]}}
    accounts = seed["accounts"]
    state = {
        "records": list(seed.get("records", [])),
        # Map account -> [{id, name}, ...] using REALISTIC zone
        # names that the playbook's FQDN suffix-match can resolve
        # against. The brief requires the rotation to move
        # `ne.tinooer.top`, `ne.miragerunner.com`, etc.; the
        # fictional zone names below cover exactly those suffixes
        # and nothing else.
        "zones_by_account": {
            "account_a": [
                {"id": "zone-aaaa", "name": "tinooer.top"},
                {"id": "zone-bbbb", "name": "miragerunner.com"},
            ],
            "account_b": [
                {"id": "zone-cccc", "name": "palfora.ir"},
                {"id": "zone-dddd", "name": "shikoonet.xyz"},
            ],
        },
        "mutations": [],
    }
    state = {
        "records": list(seed.get("records", [])),
        # Map account -> [{id, name}, ...] using REALISTIC zone
        # names that the playbook's FQDN suffix-match can resolve
        # against. The brief requires the rotation to move
        # `ne.tinooer.top`, `ne.miragerunner.com`, etc.; the
        # fictional zone names below cover exactly those suffixes
        # and nothing else.
        "zones_by_account": {
            "account_a": [
                {"id": "zone-aaaa", "name": "tinooer.top"},
                {"id": "zone-bbbb", "name": "miragerunner.com"},
            ],
            "account_b": [
                {"id": "zone-cccc", "name": "palfora.ir"},
                {"id": "zone-dddd", "name": "shikoonet.xyz"},
            ],
        },
        "mutations": list(seed.get("mutations", [])),
        # The test injects a fail-after-N gate by editing the
        # persisted state file before restarting. Persist it
        # across restarts so the gate takes effect on the next
        # server process without the test having to re-write it
        # to the seed.
        "fail_after_n_mutations": seed.get("fail_after_n_mutations"),
    }
    handler = make_handler(state, accounts, state_path=args.state)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    # Tell the parent our port (we know it already, but write it
    # to the state file so the test can read it without race).
    seed["_bound_port"] = args.port
    Path = __import__("pathlib").Path
    Path(args.state).write_text(json.dumps(seed))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
