#!/usr/bin/env python3
"""An in-memory Hetzner Cloud, sitting exactly where hcloud_step.yml sits.

The fake IS the runner: `FakeHcloud()` is callable as `(op, params) -> dict`,
the same contract providers.HcloudProvider drives in production. That is the
whole point of the seam — every line of normalisation, error mapping and the
assignee quirk runs in every test, because the only thing replaced is the
subprocess.

It really applies mutations rather than recording intentions, so a test can ask
the state machine to do something and then look at the resulting world. Three
things it deliberately mimics from the real modules, read from the PINNED
7.0.0 source:

  * every datacenter field is called `location`, and a server payload carries
    no `datacenter` at all. 6.x said `home_location` / `datacenter`; modelling
    6.x here while CI installed 7.0.0 is what let three live failures through
    a green suite. The fake tracks the pin, and the pin is in
    .github/actions/setup — change them together.
  * the `server` module's result carries NO Primary IP id — only
    `ipv4_address`. Only `read_server` correlates the id, because only
    hcloud_step.yml's read_server block makes the second call that finds it.
  * an unknown server id is `not_found`, not an exception. `touched_ids`
    records every id a MUTATING op was aimed at, so a test can assert that no
    other server was ever addressed.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

DEFAULT_SERVER_ID = 12345678
DEFAULT_OLD_IP_ID = 900001

WRITE_OPS = ("protect_ip", "stop", "unassign", "allocate", "assign", "start")


class FakeHcloud:
    """Callable runner over a two-resource world: one server, some Primary IPs."""

    def __init__(
        self,
        server_id: int = DEFAULT_SERVER_ID,
        name: str = "Hetzner-DE",
        location: str = "nbg1",
        old_ip: str = "46.224.67.245",
        stop_delay: int = 0,
    ):
        self.server: Dict[str, Any] = {
            "id": server_id,
            "name": name,
            "status": "running",
            "location": location,
            "ipv4_address": old_ip,
        }
        self.ips: Dict[int, Dict[str, Any]] = {
            DEFAULT_OLD_IP_ID: {
                "id": DEFAULT_OLD_IP_ID,
                "name": "hetzner-de-primary",
                "ip": old_ip,
                "type": "ipv4",
                "location": location,
                "assignee_id": server_id,
                "assignee_type": "server",
                "auto_delete": True,  # the state the tool must turn OFF first
            }
        }
        self._next_ip_id = 900100
        self._next_octet = 10

        #: how many `stop` calls report "still running" before the box is off
        self.stop_delay = stop_delay
        self._stop_seen = 0

        self.write_count = 0
        self.calls: List[Dict[str, Any]] = []
        self.touched_ids: set = set()
        self._injected: Dict[str, List[Dict[str, Any]]] = {}

    # -- test controls -----------------------------------------------------
    def inject(self, op: str, error: str = "boom", kind: str = "retryable", times: int = 1) -> None:
        """Queue `times` one-shot failures for `op`, consumed in order."""
        self._injected.setdefault(op, []).extend(
            [{"ok": False, "error": f"{op}: {error}", "error_kind": kind}] * times
        )

    def snapshot(self) -> Dict[str, Any]:
        return copy.deepcopy(
            {
                "server": self.server,
                "ips": self.ips,
                "next_ip_id": self._next_ip_id,
                "next_octet": self._next_octet,
                "write_count": self.write_count,
                "stop_seen": self._stop_seen,
            }
        )

    def restore(self, snap: Dict[str, Any]) -> None:
        snap = copy.deepcopy(snap)
        self.server = snap["server"]
        self.ips = snap["ips"]
        self._next_ip_id = snap["next_ip_id"]
        self._next_octet = snap["next_octet"]
        self.write_count = snap["write_count"]
        self._stop_seen = snap["stop_seen"]

    # -- the runner contract ----------------------------------------------
    def __call__(self, op: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append({"op": op, "params": dict(params)})

        queued = self._injected.get(op)
        if queued:
            return queued.pop(0)

        server_id = params.get("server_id")
        if server_id is not None:
            if op in WRITE_OPS:
                self.touched_ids.add(int(server_id))
            if int(server_id) != self.server["id"]:
                return self._err(f"server {server_id} not found", "not_found")

        handler = getattr(self, f"_op_{op}", None)
        if handler is None:
            return self._err(f"unknown op {op}", "validation")
        if op in WRITE_OPS:
            self.write_count += 1
        return handler(params)

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _ok(data: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": True, "data": copy.deepcopy(data)}

    @staticmethod
    def _err(message: str, kind: str = "retryable") -> Dict[str, Any]:
        return {"ok": False, "error": message, "error_kind": kind}

    def _attached_ipv4_id(self) -> Optional[int]:
        for ip in self.ips.values():
            if ip["type"] == "ipv4" and ip["assignee_id"] == self.server["id"]:
                return ip["id"]
        return None

    def _server_result(self) -> Dict[str, Any]:
        """What the `server` module returns: no Primary IP id, ever."""
        return {k: v for k, v in self.server.items()}

    # -- ops ---------------------------------------------------------------
    def _op_read_server(self, params: Dict[str, Any]) -> Dict[str, Any]:
        data = self._server_result()
        data["ipv4_id"] = self._attached_ipv4_id()
        return self._ok(data)

    def _op_read_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if params.get("ip_id") is not None:
            found = self.ips.get(int(params["ip_id"]))
        else:
            found = next(
                (ip for ip in self.ips.values() if ip["name"] == params.get("ip_name")), None
            )
        if found is None:
            return self._err("No Primary IP matched", "not_found")
        return self._ok(found)

    def _op_find_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        matches = [ip for ip in self.ips.values() if ip["name"] == params.get("ip_name")]
        return self._ok({"matches": matches})

    def _op_protect_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ip = self.ips.get(int(params["ip_id"]))
        if ip is None:
            return self._err("No Primary IP matched", "not_found")
        ip["auto_delete"] = False
        return self._ok(dict(ip))

    def _op_stop(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self._stop_seen += 1
        if self._stop_seen > self.stop_delay:
            self.server["status"] = "off"
        return self._ok(self._server_result())

    def _op_unassign(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ip = self.ips.get(int(params["ip_id"]))
        if ip is None:
            return self._err("No Primary IP matched", "not_found")
        ip["assignee_id"] = None
        ip["assignee_type"] = None
        self.server["ipv4_address"] = None
        return self._ok(self._server_result())

    def _op_allocate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params["ip_name"]
        existing = next((ip for ip in self.ips.values() if ip["name"] == name), None)
        if existing is not None:
            return self._ok(dict(existing))
        new_id = self._next_ip_id
        self._next_ip_id += 1
        self._next_octet += 1
        record = {
            "id": new_id,
            "name": name,
            "ip": f"91.99.{self._next_octet}.7",
            "type": "ipv4",
            "location": params["location"],
            "assignee_id": None,
            "assignee_type": None,
            "auto_delete": False,
        }
        self.ips[new_id] = record
        return self._ok(dict(record))

    def _op_assign(self, params: Dict[str, Any]) -> Dict[str, Any]:
        wanted = next(
            (ip for ip in self.ips.values() if ip["name"] == params.get("ip_name")), None
        )
        if wanted is None:
            return self._err("No Primary IP matched", "not_found")
        # the real module detaches whatever is there before attaching
        for ip in self.ips.values():
            if ip["assignee_id"] == self.server["id"]:
                ip["assignee_id"] = None
                ip["assignee_type"] = None
        wanted["assignee_id"] = self.server["id"]
        wanted["assignee_type"] = "server"
        self.server["ipv4_address"] = wanted["ip"]
        return self._ok(self._server_result())

    def _op_start(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.server["status"] = "running"
        return self._ok(self._server_result())


def example_config(fake: FakeHcloud, alias: str = "Hetzner-DE") -> Dict[str, Any]:
    """A config that matches whatever world `fake` currently holds."""
    return {
        "provider": "hcloud",
        "server": {
            "id": fake.server["id"],
            "expected_name": fake.server["name"],
            "expected_ipv4": fake.server["ipv4_address"],
            "expected_location": fake.server["location"],
        },
        "ansible": {
            "host_alias": alias,
            "inventory": "inventory/hosts.yml",
            "repo_dir": "..",
            "auto_edit_inventory": False,
        },
        "dns": {
            "node_record_zone": "tinooer.top",
            "allowed_records": [f"{alias}.tinooer.top"],
        },
        "cloudflare": {
            "expected_record_count": 4,
            "allowed_records": [
                f"{alias}.tinooer.top",
                f"verb-{alias}.miragerunner.com",
                f"verb-{alias}.palfora.ir",
                f"verb-{alias}.shikoonet.xyz",
            ],
        },
        "timeouts": {"power_off": 180, "power_on": 300, "ssh": 10},
        "retries": {"provider": 2, "provider_delay": 0, "health": 3, "health_delay": 0},
        "old_ip": {"retention": "keep"},
        "health": {"ssh_port": 22},
        "state_dir": "state",
    }
