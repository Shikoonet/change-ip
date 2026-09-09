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

Multi-account mode: pass `account_zones={"account_a": ["zone-aaaa", ...],
"account_b": [...]}` to enforce per-token zone ownership. A discover /
apply / rollback invoked with `token_env` of account A will only see
account A's zones; anything outside that set returns a 403-shaped
validation error. The whole point is that token B is structurally
unable to touch token A's records — even if a manifest was hand-
constructed to include them.
"""

from __future__ import annotations

import copy
import os
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
        account_zones: Optional[Dict[str, List[str]]] = None,
    ):
        # `records` is a list of dicts, each: {zone_id, record_id, name, content}
        # The empty-list case historically seeded defaults too (the same
        # tests called `records=[]` to mean "give me the standard eight"),
        # and the rotation refuses a zero-record config outright — empty
        # `allowed_records` and `expected_record_count=0` are config
        # errors (`rotate.py` lines 596-602, 718-731). Keeping the
        # single-branch behaviour so existing tests that pass `records=[]`
        # continue to get the seeded default.
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
        # account_zones: {account_name: [zone_id, ...]}. When set, every
        # discover / apply / rollback call is filtered through the token
        # ownership check: a record whose zone_id is not in the calling
        # account's allowed zones is treated as 403, regardless of what
        # the manifest says.
        self.account_zones: Dict[str, List[str]] = account_zones or {}
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
        # Per-token ownership check: when account_zones is configured and
        # the call came in with a token_env, the resolved token's
        # associated account owns a fixed zone set. Records outside that
        # set are unreachable — even if the manifest lists them.
        if self.account_zones:
            token_env = params.get("token_env")
            credential_ref = params.get("credential_ref")
            if not token_env or not credential_ref:
                return {
                    "ok": False, "rc": 1,
                    "error": "token_env and credential_ref required when "
                             "account_zones is set",
                    "error_kind": "validation",
                }
            allowed_zones = set(self.account_zones.get(credential_ref, []))
            if not allowed_zones:
                return {
                    "ok": False, "rc": 1,
                    "error": f"account {credential_ref!r} owns no zones; "
                             "refusing to serve an op against an unknown "
                             "credential",
                    "error_kind": "validation",
                }
            # Discover: filter the records by the account's zones.
            # Apply / rollback / verify: refuse if the manifest names a
            # record outside the account's zones.
            if op == "discover":
                pass  # filtered below
            else:
                manifest = params.get("manifest") or []
                for wanted in manifest:
                    zid = wanted.get("zone_id")
                    if zid is not None and zid not in allowed_zones:
                        return {
                            "ok": False, "rc": 1,
                            "error": (f"zone {zid!r} is not owned by account "
                                      f"{credential_ref!r}; this token has no "
                                      "access to it"),
                            "error_kind": "validation",
                            "http_status": 403,
                        }
        rc = 0  # default for the success path

        if op == "discover":
            manifest = []
            for rec in self.records:
                if rec["content"] != (params.get("old_ip") or "").strip():
                    # Honor the preflight invariant: do not put drifted records into
                    # the manifest. The real playbook would assert this and abort.
                    continue
                if self.account_zones and params.get("credential_ref"):
                    allowed = set(self.account_zones.get(
                        params["credential_ref"], []))
                    if rec["zone_id"] not in allowed:
                        # Wrong account for this zone — as if 403.
                        continue
                manifest.append({
                    "zone_id": rec["zone_id"],
                    "record_id": rec["record_id"],
                    "name": rec["name"],
                    "previous_content": rec["content"],
                    "ttl": rec.get("ttl", 1),
                    "proxied": rec.get("proxied", False),
                })
            if self.account_zones and params.get("credential_ref"):
                visible_zones = set(self.account_zones.get(
                    params["credential_ref"], []))
            else:
                visible_zones = {r["zone_id"] for r in self.records}
            return {
                "ok": True,
                "rc": 0,
                "result": {
                    "ok": True,
                    "operation": "discover",
                    "invocation_id": params.get("invocation_id", ""),
                    # Production discovery reports every zone visible to the
                    # selected credential, independently of how many matching
                    # records it found. Keep the fake's contract identical so
                    # the fail-closed zone-coverage checks are exercised.
                    "zones_seen": len(visible_zones),
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
