#!/usr/bin/env python3
"""A real local HTTP server that models the DataForest public API.

The point of running a real socket rather than mocking `urllib.request`
is to exercise the adapter's transport (URL parsing, headers, JSON
parsing, timeouts) exactly the way production does. The DataForest
adapter is the seam; `DataForestProvider` consumes it; tests substitute
this server behind `urllib.request.urlopen`.

Bind only to an OS-assigned loopback port. No fixed port, no external
hostname, no `time.sleep`-based eventual consistency that the test could
not race against.

Documented behaviour modelled:
  * `GET /team` — team identity, status, resource_limits
  * `GET /seeds/{seedId}` — Seed payload incl. ipv4[], active_action
  * `GET /seeds/{seedId}/actions` — list
  * `GET /seeds/{seedId}/actions/{actionId}` — single action
  * `POST /seeds/{seedId}/actions` — add / remove IPv4
  * Immediate 200 (sync) and async 202 (poll-until-completed)
  * Configurable 401/403/409/410/422/429/500/503 with Retry-After
  * Action statuses: new, pending, running, retry, completed, failed
  * Mutation-counting so tests can assert "no mutating call before X"
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

DEFAULT_TOKEN = "dataforest-fake-pat-0123456789abcdef"
DEFAULT_SEED_ID = "11111111-2222-3333-4444-555555555555"
DEFAULT_TEAM_ID = "team-abcdef"
DEFAULT_LOCATION = "fra1"
DEFAULT_PROJECT = "default"

DEFAULT_OLD_IP = "198.51.100.10"
DEFAULT_NEW_IP = "198.51.100.20"


def _make_ipv4_entry(
    address: str,
    *,
    cidr: Optional[str] = None,
    gateway: Optional[str] = None,
    primary: bool = True,
    ptr: Optional[str] = None,
    ptr_record_id: Optional[str] = None,
) -> Dict[str, Any]:
    """An IPResponse-shaped entry. Fields beyond address are optional."""
    entry: Dict[str, Any] = {"address": address}
    if cidr:
        entry["cidr"] = cidr
    if gateway:
        entry["gateway"] = gateway
    entry["primary_ip"] = primary
    if ptr:
        entry["ptr_hostname"] = ptr
    if ptr_record_id:
        entry["ptr_record_id"] = ptr_record_id
    return entry


def default_seed(
    *,
    seed_id: str = DEFAULT_SEED_ID,
    name: str = "seed-default",
    location: str = DEFAULT_LOCATION,
    project: str = DEFAULT_PROJECT,
    ipv4: Optional[List[Dict[str, Any]]] = None,
    state: str = "running",
    available_actions: Optional[List[str]] = None,
    is_clone_source: bool = False,
    active_action: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """A canonical Seed payload. `ipv4` defaults to a single OLD_IP entry.

    `state` follows the documented schema (running / stopped / unknown /
    processing / suspended / error / deleted). `available_actions` defaults
    to both rotation ops so tests can drive add and remove without
    further setup.
    """
    if ipv4 is None:
        ipv4 = [_make_ipv4_entry(
            DEFAULT_OLD_IP,
            cidr=f"{DEFAULT_OLD_IP}/32",
            gateway="198.51.100.1",
            primary=True,
            ptr=f"old.example.test",
            ptr_record_id=f"ptr-{uuid.uuid4().hex[:12]}",
        )]
    if available_actions is None:
        available_actions = ["seed.add-ipv4", "seed.remove-ipv4"]
    return {
        "id": seed_id,
        "name": name,
        "project": project,
        "location": location,
        "state": state,
        "available_actions": available_actions,
        "ipv4": ipv4,
        "active_action": active_action,
        "is_clone_source": is_clone_source,
    }


def default_team(
    *,
    team_id: str = DEFAULT_TEAM_ID,
    status: str = "ready",
    max_ipv4_per_seed: int = 8,
) -> Dict[str, Any]:
    return {
        "id": team_id,
        "name": "Default Team",
        "status": status,
        "resource_limits": {
            "max_ipv4_per_seed": max_ipv4_per_seed,
            "max_seeds": 100,
        },
    }


class FakeDataForest:
    """Stateful fake. Bound to a loopback port on start().

    Usage:
        fake = FakeDataForest()
        fake.start()
        try:
            base = fake.base_url
            ...
        finally:
            fake.stop()

    All mutating endpoints increment `mutate_count`; tests can assert
    "no POST before checkpoint" via that counter rather than timestamps.
    """

    def __init__(
        self,
        *,
        seed_payload: Optional[Dict[str, Any]] = None,
        team_payload: Optional[Dict[str, Any]] = None,
        token: str = DEFAULT_TOKEN,
        immediate_add: bool = True,
        immediate_remove: bool = True,
        add_action_latency: float = 0.0,
        max_ipv4_per_seed: int = 8,
    ):
        self.token = token
        self._seed_payload = seed_payload or default_seed()
        self._team_payload = team_payload or default_team(
            max_ipv4_per_seed=max_ipv4_per_seed
        )
        self.immediate_add = bool(immediate_add)
        self.immediate_remove = bool(immediate_remove)
        self.add_action_latency = float(add_action_latency)
        self._lock = threading.RLock()

        # Mutable state.
        self._actions: Dict[str, Dict[str, Any]] = {}  # action id -> action
        self._next_action_seq = 1
        self.mutate_count = 0
        self.requests: List[Dict[str, Any]] = []
        # Ordered event log of significant state transitions. Tests
        # assert the EXACT ordering of DNS / inventory / guest /
        # provider during rollback. Append-only; never cleared between
        # test cases (each test creates a fresh fake via start()).
        self.event_log: List[str] = []
        self._seed_snapshot = copy.deepcopy(self._seed_payload)

        # Injected behaviour — one-shot then cleared.
        self._inject: Dict[str, List[Dict[str, Any]]] = {}
        # Per-method quota deltas for testing.
        self.forced_add_failure: Optional[str] = None

        # Server handle, set on start().
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.base_url: str = ""

    # -- test controls -----------------------------------------------------
    def inject(self, op: str, response: Dict[str, Any], times: int = 1) -> None:
        """Queue a one-shot response for an op (POST /seeds/.../actions)."""
        self._inject.setdefault(op, []).extend([copy.deepcopy(response)] * times)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "seed": copy.deepcopy(self._seed_snapshot),
                "actions": copy.deepcopy(self._actions),
                "mutate_count": self.mutate_count,
            }

    def restore(self, snap: Dict[str, Any]) -> None:
        with self._lock:
            self._seed_snapshot = copy.deepcopy(snap["seed"])
            self._actions = copy.deepcopy(snap["actions"])
            self.mutate_count = int(snap["mutate_count"])

    def add_action(
        self,
        *,
        action_type: str,
        target_status: str = "completed",
        address: Optional[str] = None,
        poll_count_to_complete: int = 1,
        seed_id: Optional[str] = None,
    ) -> str:
        """Insert an action as if the API did it. Returns the action id."""
        with self._lock:
            aid = f"act-{self._next_action_seq:08d}"
            self._next_action_seq += 1
            action = {
                "id": aid,
                "type": action_type,
                "status": "new",
                "poll_count_to_complete": int(poll_count_to_complete),
                "target_status": target_status,
                "seed_id": seed_id or self._seed_snapshot["id"],
            }
            if address:
                action["address"] = address
            self._actions[aid] = action
            return aid

    def force_action_status(self, action_id: str, status: str) -> None:
        with self._lock:
            if action_id in self._actions:
                self._actions[action_id]["status"] = status
                self._actions[action_id]["target_status"] = status

    # -- server lifecycle --------------------------------------------------
    def start(self) -> None:
        if self._server is not None:
            return
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):  # noqa: A002 - silence stdlib noise
                return

            def _bad(self, status: int, message: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _json(self, status: int, body: Any) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _record(self, method: str, path: str, body: bytes) -> None:
                outer.requests.append({
                    "method": method,
                    "path": path,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body": body.decode("utf-8", "replace"),
                })

            def _auth(self) -> bool:
                h = self.headers.get("Authorization", "")
                return h.strip().lower() == f"bearer {outer.token}".lower()

            def do_GET(self):  # noqa: N802 - stdlib override
                self._record("GET", self.path, b"")
                if not self._auth():
                    return self._json(401, {
                        "code": "unauthorized",
                        "message": "token rejected",
                    })
                parsed = urlparse(self.path)
                path = parsed.path
                # Strip /api/v1/public prefix if present.
                if path.startswith("/api/v1/public"):
                    path = path[len("/api/v1/public"):]
                if path == "/team":
                    return self._json(200, outer._team_payload)
                if path.startswith("/seeds/") and path.endswith("/actions"):
                    parts = path.split("/")
                    # /seeds/{seed_id}/actions -> ['', 'seeds', '{seed_id}', 'actions']
                    if len(parts) == 4 and parts[3] == "actions":
                        seed_id = parts[2]
                        if seed_id != outer._seed_snapshot["id"]:
                            return self._json(404, {
                                "code": "seed_not_found",
                                "message": f"seed {seed_id} not found",
                            })
                        return self._json(200, {
                            "actions": list(outer._actions.values()),
                        })
                if path.startswith("/seeds/") and "/actions/" in path:
                    # /seeds/{seed_id}/actions/{action_id}
                    parts = path.split("/")
                    if len(parts) == 5 and parts[3] == "actions":
                        seed_id, action_id = parts[2], parts[4]
                        with outer._lock:
                            action = outer._actions.get(action_id)
                            if not action:
                                return self._json(404, {
                                    "code": "action_not_found",
                                    "message": f"action {action_id} not found",
                                })
                            if action["seed_id"] != seed_id:
                                return self._json(409, {
                                    "code": "seed_id_mismatch",
                                    "message": "action belongs to a different seed",
                                })
                            # Drive the action: increment poll_count, and
                            # once polls_to_complete is reached, transition
                            # to completed (and apply the side effect).
                            action["poll_count"] = action.get("poll_count", 0) + 1
                            if (action["status"] in ("pending", "running", "new")
                                    and action.get("polls_to_complete", 0) > 0
                                    and action["poll_count"] >= action["polls_to_complete"]):
                                action["status"] = "completed"
                                outer._apply_action_side_effects(action)
                            return self._json(200, dict(action))
                if path.startswith("/seeds/"):
                    parts = path.split("/")
                    if len(parts) == 3:
                        seed_id = parts[2]
                        if seed_id != outer._seed_snapshot["id"]:
                            return self._json(404, {
                                "code": "seed_not_found",
                                "message": f"seed {seed_id} not found",
                            })
                        with outer._lock:
                            # Bump active_action if there is a non-terminal action.
                            active = None
                            for a in outer._actions.values():
                                if a.get("status") not in ("completed", "failed"):
                                    active = dict(a)
                                    break
                            payload = copy.deepcopy(outer._seed_snapshot)
                            payload["active_action"] = active
                            return self._json(200, payload)
                return self._json(404, {"code": "not_found", "message": path})

            def do_POST(self):  # noqa: N802 - stdlib override
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                self._record("POST", self.path, raw)
                if not self._auth():
                    return self._json(401, {
                        "code": "unauthorized",
                        "message": "token rejected",
                    })
                parsed = urlparse(self.path)
                path = parsed.path
                if path.startswith("/api/v1/public"):
                    path = path[len("/api/v1/public"):]
                if not (path.startswith("/seeds/") and path.endswith("/actions")):
                    return self._json(404, {"code": "not_found", "message": path})

                try:
                    body = json.loads(raw.decode("utf-8") or "{}")
                except (ValueError, UnicodeDecodeError):
                    return self._json(422, {"code": "malformed_json"})

                if not isinstance(body, dict):
                    return self._json(422, {"code": "malformed_json"})

                parts = path.split("/")
                if len(parts) != 4 or parts[3] != "actions":
                    return self._json(404, {"code": "not_found"})
                seed_id = parts[2]
                if seed_id != outer._seed_snapshot["id"]:
                    return self._json(404, {"code": "seed_not_found"})

                op_type = body.get("type")

                # Honour queued injected responses BEFORE mutate_count.
                queued = outer._inject.get("post")
                if queued:
                    payload = queued.pop(0)
                    code = int(payload.get("status", 200))
                    return self._json(code, payload.get("body", {}))

                with outer._lock:
                    outer.mutate_count += 1
                    current_count = outer.mutate_count
                    # Record the structured event BEFORE side effects, so
                    # tests asserting ordering see the call as soon as
                    # the fake commits to it.
                    op_label = "add" if op_type == "seed.add-ipv4" else "remove"
                    addr = body.get("address", "")
                    outer.event_log.append(
                        f"post:{op_label}:{op_type}:{addr}"
                    )

                if op_type == "seed.add-ipv4":
                    code, payload = outer._handle_add(body)
                    return self._json(code, payload)
                if op_type == "seed.remove-ipv4":
                    code, payload = outer._handle_remove(body)
                    return self._json(code, payload)
                return self._json(422, {"code": "unknown_action_type",
                                          "message": f"op {op_type!r} not supported"})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        self._server = server
        self.base_url = f"http://127.0.0.1:{server.server_port}/api/v1/public"
        thread = threading.Thread(target=server.serve_forever, name="fake-df", daemon=True)
        thread.start()
        self._thread = thread

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None
        self.base_url = ""

    # -- mutation handlers -------------------------------------------------
    def _handle_add(self, body: Dict[str, Any]) -> "Tuple[int, Dict[str, Any]]":
        with self._lock:
            current = self._seed_snapshot.get("ipv4") or []
            seed_state = self._seed_snapshot.get("state") or "unknown"
            if seed_state not in ("running", "stopped"):
                return self._mutation_response(409, {
                    "code": "seed_state_unsupported",
                    "message": f"seed state is {seed_state!r}",
                })
            available = self._seed_snapshot.get("available_actions") or []
            if "seed.add-ipv4" not in available:
                return self._mutation_response(409, {
                    "code": "action_not_available",
                    "message": "seed.add-ipv4 is not in available_actions",
                })
            active = self._seed_snapshot.get("active_action")
            if active:
                return self._mutation_response(409, {
                    "code": "active_action_present",
                    "message": "another action is in flight",
                })
            limit = (self._team_payload.get("resource_limits") or {}).get(
                "max_ipv4_per_seed", 8
            )
            if len(current) >= int(limit):
                return self._mutation_response(409, {
                    "code": "quota_exceeded",
                    "message": f"max_ipv4_per_seed={limit} reached",
                })
            if self.forced_add_failure:
                return self._mutation_response(422, {
                    "code": self.forced_add_failure,
                    "message": "forced failure",
                })
            # Allocate an address.
            new_addr = _next_address(current)
            action_id = self._record_action(
                "seed.add-ipv4", address=new_addr, async_=not self.immediate_add,
            )
            if self.immediate_add:
                # Apply the address synchronously.
                self._seed_snapshot["ipv4"] = current + [_make_ipv4_entry(
                    new_addr, primary=False,
                )]
            return self._mutation_response(
                200 if self.immediate_add else 202,
                {"action_id": action_id, "status": "completed" if self.immediate_add else "pending"},
            )

    def _handle_remove(self, body: Dict[str, Any]) -> "Tuple[int, Dict[str, Any]]":
        with self._lock:
            target = body.get("address")
            if not isinstance(target, str):
                return self._mutation_response(422, {
                    "code": "address_required",
                    "message": "remove-ipv4 requires an address",
                })
            available = self._seed_snapshot.get("available_actions") or []
            if "seed.remove-ipv4" not in available:
                return self._mutation_response(409, {
                    "code": "action_not_available",
                    "message": "seed.remove-ipv4 is not in available_actions",
                })
            current = self._seed_snapshot.get("ipv4") or []
            addresses = [e.get("address") for e in current if isinstance(e, dict)]
            if target not in addresses:
                return self._mutation_response(409, {
                    "code": "address_not_present",
                    "message": f"address {target} is not on the seed",
                })
            # Two ipv4 remaining? Then we'd leave the Seed ipv4-only-empty.
            # If removing the LAST ipv4, refuse.
            if len(addresses) <= 1:
                return self._mutation_response(409, {
                    "code": "cannot_remove_last_ipv4",
                    "message": "removing the last IPv4 would leave the Seed without one",
                })
            action_id = self._record_action(
                "seed.remove-ipv4", address=target, async_=not self.immediate_remove,
            )
            if self.immediate_remove:
                self._seed_snapshot["ipv4"] = [
                    e for e in current if e.get("address") != target
                ]
            return self._mutation_response(
                200 if self.immediate_remove else 202,
                {"action_id": action_id, "status": "completed" if self.immediate_remove else "pending"},
            )

    def _mutation_response(self, status: int, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        # The handler is the one that writes — we just return the tuple.
        return (status, body)

    def _record_action(
        self,
        action_type: str,
        *,
        address: Optional[str],
        async_: bool,
    ) -> str:
        aid = f"act-{self._next_action_seq:08d}"
        self._next_action_seq += 1
        action = {
            "id": aid,
            "type": action_type,
            "status": "completed" if not async_ else "pending",
            "seed_id": self._seed_snapshot["id"],
            "poll_count": 0,
            "polls_to_complete": 1 if async_ else 0,
            "address": address,
        }
        self._actions[aid] = action
        return aid

    def _apply_action_side_effects(self, action: Dict[str, Any]) -> None:
        """When an async action transitions to completed, apply its effect.

        For add-ipv4, allocate the address and add to ipv4[]. For
        remove-ipv4, drop the entry. Caller holds the lock.
        """
        if action.get("type") == "seed.add-ipv4":
            current = self._seed_snapshot.get("ipv4") or []
            addresses = [e.get("address") for e in current if isinstance(e, dict)]
            if not addresses or addresses[-1] not in (action.get("address"),):
                new_addr = action.get("address") or _next_address(current)
                if new_addr not in addresses:
                    self._seed_snapshot["ipv4"] = current + [
                        _make_ipv4_entry(new_addr, primary=False)
                    ]
        elif action.get("type") == "seed.remove-ipv4":
            target = action.get("address")
            current = self._seed_snapshot.get("ipv4") or []
            self._seed_snapshot["ipv4"] = [
                e for e in current
                if not (isinstance(e, dict) and e.get("address") == target)
            ]

    def __enter__(self) -> "FakeDataForest":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _next_address(current: List[Dict[str, Any]]) -> str:
    """Pick an IPv4 not already on the Seed. Last octet increments."""
    used = {ipaddress.IPv4Address(e["address"]) for e in current if isinstance(e, dict) and e.get("address")}
    base = ipaddress.IPv4Address(DEFAULT_NEW_IP)
    for delta in range(1, 255):
        cand = ipaddress.IPv4Address(int(base) + delta)
        if cand not in used:
            return str(cand)
    # Very unlikely fallback.
    return DEFAULT_NEW_IP


# ---------------------------------------------------------------------------
# bootstrap: server can also be run standalone for ad-hoc curl exercises
# ---------------------------------------------------------------------------
def main() -> None:
    fake = FakeDataForest()
    fake.start()
    print(f"fake dataforest listening at {fake.base_url}")
    print("press enter to stop")
    try:
        input()
    finally:
        fake.stop()


if __name__ == "__main__":
    main()