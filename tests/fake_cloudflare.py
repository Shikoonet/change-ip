#!/usr/bin/env python3
"""An in-memory Cloudflare, sitting exactly where cloudflare_replace_ip_step.yml sits.

Mirror of `fake_hcloud.py` for the Cloudflare half of the rotation. The fake
IS the runner callable: takes `(op, **kwargs)` and returns the same shape
`cloudflare_adapter.run_cloudflare_op()` returns. A test can therefore
substitute this for the real subprocess without touching rotate.py.

What this fake actually mutates: a tiny `records` dict keyed by
`(zone_id, record_id)`. discover writes the manifest into it; apply and
rollback assert and patch; verify reads. The mutations are real so a
sequence "discover then apply then verify" sees the expected deltas.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional


class FakeCloudflare:
    """Callable runner for run_cloudflare_op().

    Maintains a world of A records across (zone, record_id) pairs and answers
    the four ops with the same dict shape the real playbook writes:

      {
        "ok": True, "result": {...}     # or
        "ok": False, "error_kind": ...
      }

    The token NEVER enters this object; in tests we set
    CLOUDFLARE_API_TOKEN in the environment.
    """

    def __init__(
        self,
        records: Optional[List[Dict[str, Any]]] = None,
        old_ip: str = "46.224.67.245",
    ):
        # `records` is a list of dicts, each: {zone_id, record_id, name, content}
        self.records: List[Dict[str, Any]] = []
        if records:
            for rec in records:
                self.records.append(dict(rec))
        # If no manifest was supplied, seed eight allowlisted names — the
        # production default — all pointing at old_ip, on three zones.
        if not self.records:
            z = ["zone-aaaa", "zone-bbbb", "zone-cccc", "zone-dddd"]
            for i, name in enumerate(("alpha", "bravo", "charlie", "delta",
                                       "echo", "foxtrot", "golf", "hotel")):
                self.records.append({
                    "zone_id": z[i % len(z)],
                    "record_id": f"rec-{i:05d}",
                    "name": f"ne.{['tinooer.top','miragerunner.com','palfora.ir','shikoonet.xyz'][i % 4]}",
                    "content": old_ip,
                    "ttl": 1,
                    "proxied": False,
                })
        self.calls: List[Dict[str, Any]] = []
        self.write_count = 0
        self._injected: Dict[str, List[Dict[str, Any]]] = {}

    def snapshot(self) -> Dict[str, Any]:
        return copy.deepcopy({"records": self.records, "write_count": self.write_count})

    def restore(self, snap: Dict[str, Any]) -> None:
        snap = copy.deepcopy(snap)
        self.records = snap["records"]
        self.write_count = snap["write_count"]

    def inject(self, op: str, error: str = "boom", kind: str = "retryable", times: int = 1) -> None:
        self._injected.setdefault(op, []).extend(
            [{"ok": False, "error": error, "error_kind": kind}] * times
        )

    # -- the runner contract ----------------------------------------------
    def __call__(self, op: str, **params: Any) -> Dict[str, Any]:
        self.calls.append({"op": op, "params": {k: v for k, v in params.items() if k != "manifest"}})

        queued = self._injected.get(op)
        if queued:
            failure = queued.pop(0)
            # Raise the same exception the real adapter would raise on a
            # failure result, so the rotation's `with_retries` path engages.
            from providers import RetryableError, NonRetryableError
            kind = failure.get("error_kind", "retryable")
            if kind in ("not_found",):
                raise NonRetryableError(failure.get("error") or f"{op}: not found")
            raise RetryableError(failure.get("error") or f"{op}: injected failure")
        rc = 0  # default for the success path

        if op == "discover":
            manifest = []
            for rec in self.records:
                if rec["content"] != (params.get("old_ip") or "").strip():
                    # Honor the preflight invariant: do not put drifted records into
                    # the manifest. The real playbook would assert this and abort.
                    continue
                manifest.append({
                    "zone_id": rec["zone_id"],
                    "record_id": rec["record_id"],
                    "name": rec["name"],
                    "previous_content": rec["content"],
                    "ttl": rec.get("ttl", 1),
                    "proxied": rec.get("proxied", False),
                })
            return {
                "ok": True,
                "rc": 0,
                "result": {
                    "ok": True,
                    "operation": "discover",
                    "invocation_id": params.get("invocation_id", ""),
                    "manifest": manifest,
                },
            }

        if op == "apply":
            manifest = params.get("manifest") or []
            old_ip = (params.get("old_ip") or "").strip()
            new_ip = (params.get("new_ip") or "").strip()
            patches = 0
            post_manifest = []
            for wanted in manifest:
                rec = self._find(wanted)
                if rec is None:
                    return {"ok": False, "error": "record not found",
                            "error_kind": "not_found"}
                if rec["content"] == new_ip:
                    # already at target — no-op
                    pass
                elif rec["content"] == old_ip:
                    rec["content"] = new_ip
                    self.write_count += 1
                    patches += 1
                else:
                    # third-party content — the real playbook aborts here.
                    return {"ok": False, "error": "drift", "error_kind": "validation"}
                post_manifest.append({
                    "zone_id": rec["zone_id"],
                    "record_id": rec["record_id"],
                    "name": rec["name"],
                    "content": rec["content"],
                })
            return {
                "ok": True,
                "rc": 0,
                "result": {
                    "ok": True,
                    "operation": "apply",
                    "invocation_id": params.get("invocation_id", ""),
                    "post_manifest": post_manifest,
                    "patches": patches,
                },
            }

        if op == "rollback":
            manifest = params.get("manifest") or []
            old_ip = (params.get("old_ip") or "").strip()
            new_ip = (params.get("new_ip") or "").strip()
            incomplete = []
            for wanted in manifest:
                rec = self._find(wanted)
                if rec is None:
                    incomplete.append({"name": wanted.get("name"), "reason": "missing"})
                    continue
                if rec["content"] == old_ip:
                    pass
                elif rec["content"] == new_ip:
                    rec["content"] = old_ip
                    self.write_count += 1
                else:
                    incomplete.append({
                        "name": rec["name"], "content": rec["content"],
                        "expected": old_ip,
                    })
            return {
                "ok": True,
                "rc": 0,
                "result": {
                    "ok": not incomplete,
                    "operation": "rollback",
                    "invocation_id": params.get("invocation_id", ""),
                    "incomplete_records": incomplete,
                    "rollback_incomplete": bool(incomplete),
                },
            }

        if op == "verify":
            manifest = params.get("manifest") or []
            new_ip = (params.get("new_ip") or "").strip()
            for wanted in manifest:
                rec = self._find(wanted)
                if rec is None or rec["content"] != new_ip:
                    return {"ok": False, "error": "drift", "error_kind": "validation"}
            return {
                "ok": True,
                "rc": 0,
                "result": {
                    "ok": True,
                    "operation": "verify",
                    "invocation_id": params.get("invocation_id", ""),
                },
            }

        return {"ok": False, "error": f"unknown op {op}", "error_kind": "validation"}

    def _find(self, wanted: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for rec in self.records:
            if (
                rec["zone_id"] == wanted.get("zone_id")
                and rec["record_id"] == wanted.get("record_id")
            ):
                return rec
        return None
