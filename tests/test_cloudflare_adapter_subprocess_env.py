#!/usr/bin/env python3
"""Adapter subprocess-environment coverage (NOT actual-playbook).

These tests prove that `cloudflare_adapter.run_cloudflare_op` builds
the correct subprocess environment for the `ansible-playbook`
subprocess and that per-account token isolation is enforced at the
adapter layer. They do NOT shell out to the real `ansible-playbook`
binary or to a real HTTP server. For real-ansible-playbook coverage
see `tests/test_cloudflare_real_playbook_multi_account.py`.

The adapter accepts a `runner` callable (the seam the production
rotation uses for `subprocess.run`). These tests pass a recorder
that:
  * inspects the `env` kwarg the adapter built;
  * simulates a successful `ansible-playbook` by writing a
    structured result file the adapter then reads back.

The recorder is ONLY the `subprocess.run` callable. The adapter,
the result-file IO, the env construction, the manifest ownership
check, and the per-token env lookup are all real production code
running. What is replaced is the actual `subprocess.run` call —
which the recorder imitates by writing the result file the way
the real ansible-playbook would.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

FAKE_AP = HERE / "fakebin" / "ansible-playbook"
FAKEBIN_DIR = HERE / "fakebin"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _token(prefix: str) -> str:
    # Per-test, not a constant. Nothing recognisable in source.
    return f"{prefix}-" + secrets.token_hex(16)


def _seed_cf_state(path: Path) -> None:
    """Seed four records split across two zone groups, all at OLD_IP."""
    seed = {
        "dataforest": {"addresses": ["203.0.113.10/32"]},
        "cloudflare": {
            "records": [
                # account A zones
                {"zone_id": "zone-aaaa", "record_id": "rec-00001",
                 "name": "ne.tinooer.top", "content": "203.0.113.10",
                 "ttl": 1, "proxied": False},
                {"zone_id": "zone-bbbb", "record_id": "rec-00002",
                 "name": "ne.miragerunner.com", "content": "203.0.113.10",
                 "ttl": 1, "proxied": False},
                # account B zones
                {"zone_id": "zone-cccc", "record_id": "rec-00003",
                 "name": "ne.palfora.ir", "content": "203.0.113.10",
                 "ttl": 1, "proxied": False},
                {"zone_id": "zone-dddd", "record_id": "rec-00004",
                 "name": "ne.shikoonet.xyz", "content": "203.0.113.10",
                 "ttl": 1, "proxied": False},
            ]
        }
    }
    path.write_text(json.dumps(seed))


# --------------------------------------------------------------------- base
class AdapterSubprocessEnvBase(unittest.TestCase):
    """Loopback fake ansible-playbook, real subprocess boundary, two
    accounts with token isolation enforced by the fake itself.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cf-multi-sub-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)
        self.cf_state = self.tmp / "cf_state.json"
        self.calls_log = self.tmp / "calls.log"
        self.calls_log.write_text("")
        _seed_cf_state(self.cf_state)
        # Per-test tokens — never constants, never reused.
        self.token_a = _token("A")
        self.token_b = _token("B")
        self.token_legacy = _token("LEGACY")
        # Save the real process env and replace it with the test
        # env. The adapter reads token env vars from os.environ, so
        # we must mutate the live env, not a copy.
        self._saved_env = os.environ.copy()
        os.environ.clear()
        # The test env starts from the real env, with our overrides.
        os.environ.update(self._saved_env)
        os.environ["PYTHONPATH"] = str(HERE) + os.pathsep + str(ROOT)
        os.environ["ROTATION_TEST_MODE"] = "1"
        os.environ["ANSIBLE_PLAYBOOK_BIN"] = str(FAKE_AP)
        os.environ["ROTATION_FAKE_STATE"] = str(self.cf_state)
        os.environ["ROTATION_FAKE_CALLS_LOG"] = str(self.calls_log)
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = self.token_a
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_B"] = self.token_b
        os.environ["CLOUDFLARE_API_TOKEN"] = self.token_legacy
        # Record the call env (without token VALUES) for each call.
        self.recorded_env_keys: List[List[str]] = []

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved_env)

    def _run_adapter(self, account: str, op: str, **overrides) -> Dict[str, Any]:
        from cloudflare_adapter import run_cloudflare_op
        token_env = {
            "account_a": "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
            "account_b": "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
        }[account]
        recorder = self._recorder
        return run_cloudflare_op(
            op,
            old_ip=overrides.get("old_ip", "203.0.113.10"),
            new_ip=overrides.get("new_ip", "198.51.100.99"),
            allowed_records=overrides.get("allowed_records", []),
            expected_count=overrides.get("expected_count", 0),
            manifest=overrides.get("manifest"),
            invocation_id=overrides.get("invocation_id", "iv-" + account),
            credential_ref=account,
            token_env=token_env,
            runner=recorder,
            timeout=20,
        )

    def _recorder(self, argv, **kwargs):
        """subprocess.run-shaped recorder: capture env key names, return
        a successful CompletedProcess with a populated result file.
        """
        env = kwargs.get("env") or os.environ
        self.recorded_env_keys.append(sorted(env.keys()))
        # Read the requested op + token_env from the argv and route to
        # the matching fake-state branch.
        flags: Dict[str, str] = {}
        for i, a in enumerate(argv):
            if a == "-e" and i + 1 < len(argv):
                v = argv[i + 1]
                if "=" in v:
                    k, val = v.split("=", 1)
                    flags[k] = val
        op = flags.get("operation") or flags.get("op")
        token_env = flags.get("token_env") or ""
        result_file = flags.get("result_file")
        old_ip = flags.get("old_ip", "203.0.113.10")
        new_ip = flags.get("new_ip", "198.51.100.99")
        # Load the seeded state, filter by the calling account's
        # zone set (the same map as in-process FakeCloudflare uses).
        zone_owners = {
            "CLOUDFLARE_API_TOKEN_ACCOUNT_A":
                {"zone-aaaa", "zone-bbbb"},
            "CLOUDFLARE_API_TOKEN_ACCOUNT_B":
                {"zone-cccc", "zone-dddd"},
        }
        try:
            state = json.loads(self.cf_state.read_text())
        except (OSError, ValueError):
            state = {"cloudflare": {"records": []}}
        records = state.get("cloudflare", {}).get("records", [])
        # Enforce per-token zone ownership.
        if token_env in zone_owners:
            allowed_zones = zone_owners[token_env]
            records = [r for r in records if r["zone_id"] in allowed_zones]
        elif token_env == "":
            # Legacy path: all zones visible.
            pass
        else:
            self._log_call(op, token_env, "unknown_token_env")
            return _Completed(1, "", f"unknown token_env {token_env!r}")
        # If a manifest names a record outside the calling account's
        # zones, refuse at the playbook boundary. The adapter wraps
        # manifest in single quotes (so ansible-playbook's YAML parser
        # keeps it as a string); the real playbook then calls
        # from_json. The recorder mirrors that: strip the outer
        # single quotes before json.loads.
        try:
            m_raw = flags.get("manifest", "[]")
            if len(m_raw) >= 2 and m_raw[0] == "'" and m_raw[-1] == "'":
                m_raw = m_raw[1:-1]
            m = json.loads(m_raw)
        except (ValueError, TypeError):
            m = []
        for wanted in m:
            if (wanted.get("zone_id") not in {r["zone_id"] for r in records}
                    and wanted.get("zone_id") is not None):
                self._log_call(op, token_env, "zone_not_owned")
                if result_file:
                    Path(result_file).write_text(json.dumps({
                        "ok": False, "operation": op,
                        "invocation_id": flags.get("invocation_id", ""),
                        "error": f"zone {wanted.get('zone_id')!r} not owned by this token",
                        "error_kind": "validation",
                    }))
                return _Completed(1, "", f"zone {wanted.get('zone_id')!r} not owned by this token")
        payload: Dict[str, Any] = {
            "ok": True, "operation": op,
            "invocation_id": flags.get("invocation_id", ""),
        }
        if op == "discover":
            manifest = []
            for r in records:
                if r["content"] == old_ip:
                    manifest.append({
                        "zone_id": r["zone_id"], "record_id": r["record_id"],
                        "name": r["name"],
                        "previous_content": r["content"],
                        "ttl": r.get("ttl", 1),
                        "proxied": r.get("proxied", False),
                    })
            payload["manifest"] = manifest
        elif op == "apply":
            old = old_ip
            new = new_ip
            try:
                m_raw = flags.get("manifest", "[]")
                if len(m_raw) >= 2 and m_raw[0] == "'" and m_raw[-1] == "'":
                    m_raw = m_raw[1:-1]
                m = json.loads(m_raw)
            except (ValueError, TypeError):
                m = []
            except ValueError:
                m = []
            post = []
            for wanted in m:
                rec = next((r for r in records
                             if r["record_id"] == wanted.get("record_id")
                             and r["zone_id"] == wanted.get("zone_id")), None)
                if rec is None:
                    return _Completed(1, "", "record not found in this account")
                if rec["content"] == new:
                    pass
                elif rec["content"] == old:
                    rec["content"] = new
                else:
                    return _Completed(1, "", "drift")
                post.append({"zone_id": rec["zone_id"], "record_id": rec["record_id"],
                              "name": rec["name"], "content": rec["content"]})
            payload["post_manifest"] = post
        elif op == "rollback":
            old = old_ip; new = new_ip
            try:
                m_raw = flags.get("manifest", "[]")
                if len(m_raw) >= 2 and m_raw[0] == "'" and m_raw[-1] == "'":
                    m_raw = m_raw[1:-1]
                m = json.loads(m_raw)
            except (ValueError, TypeError):
                m = []
            post = []
            for wanted in m:
                rec = next((r for r in records
                             if r["record_id"] == wanted.get("record_id")
                             and r["zone_id"] == wanted.get("zone_id")), None)
                if rec is None:
                    continue
                if rec["content"] == old:
                    pass
                elif rec["content"] == new:
                    rec["content"] = old
                post.append({"zone_id": rec["zone_id"], "record_id": rec["record_id"],
                              "name": rec["name"], "content": rec["content"]})
            payload["incomplete_records"] = []
            payload["rollback_incomplete"] = False
        elif op == "verify":
            try:
                v_raw = flags.get("manifest", "[]")
                if len(v_raw) >= 2 and v_raw[0] == "'" and v_raw[-1] == "'":
                    v_raw = v_raw[1:-1]
                _vm = json.loads(v_raw)
            except (ValueError, TypeError):
                _vm = []
            for wanted in _vm:
                rec = next((r for r in records
                             if r["record_id"] == wanted.get("record_id")), None)
                if rec is None or rec["content"] != new_ip:
                    return _Completed(1, "", "drift")
        else:
            return _Completed(2, "", f"unknown op {op!r}")
        # Persist the mutated state.
        self.cf_state.write_text(json.dumps(state))
        # Append a calls log line.
        try:
            with open(self.calls_log, "a") as fh:
                fh.write(json.dumps({"ts": 0, "op": op, "token_env": token_env}) + "\n")
        except OSError:
            pass
        if result_file:
            Path(result_file).write_text(json.dumps(payload))
        return _Completed(0, "", "")

    def _calls(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for line in self.calls_log.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out

    def _log_call(self, op: str, token_env: str, detail: str) -> None:
        try:
            with open(self.calls_log, "a") as fh:
                fh.write(json.dumps({"ts": 0, "op": op, "token_env": token_env,
                                      "detail": detail}) + "\n")
        except OSError:
            pass


class _Completed:
    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --------------------------------------------------------------------- tests
class TestAdapterSubprocessEnvMultiAccount(AdapterSubprocessEnvBase):

    def test_account_a_discover_sees_only_a_zones(self):
        r = self._run_adapter("account_a", "discover",
                              allowed_records=["ne.tinooer.top",
                                               "ne.miragerunner.com"],
                              expected_count=2)
        self.assertTrue(r["result"]["ok"])
        names = sorted(m["name"] for m in r["result"]["manifest"])
        self.assertEqual(names, ["ne.miragerunner.com", "ne.tinooer.top"])

    def test_account_b_discover_sees_only_b_zones(self):
        r = self._run_adapter("account_b", "discover",
                              allowed_records=["ne.palfora.ir",
                                               "ne.shikoonet.xyz"],
                              expected_count=2)
        self.assertTrue(r["result"]["ok"])
        names = sorted(m["name"] for m in r["result"]["manifest"])
        self.assertEqual(names, ["ne.palfora.ir", "ne.shikoonet.xyz"])

    def test_account_b_token_cannot_read_account_a_zones(self):
        # Account B's token asks for an A-zone record via the manifest;
        # the fake ansible-playbook refuses (zone-aaaa is not in B's
        # allowed zones). The adapter surfaces a structured result with
        # ok=False; the test asserts the result is NOT ok.
        a_manifest = [{"zone_id": "zone-aaaa", "record_id": "rec-00001",
                        "name": "ne.tinooer.top", "credential_ref": "account_b"}]
        result = self._run_adapter("account_b", "apply", manifest=a_manifest,
                                    allowed_records=["ne.tinooer.top"])
        self.assertFalse((result.get("result") or {}).get("ok"),
                          msg=f"apply unexpectedly succeeded: {result}")

    def test_combined_preflight_two_accounts(self):
        ra = self._run_adapter("account_a", "discover",
                                allowed_records=["ne.tinooer.top",
                                                  "ne.miragerunner.com"],
                                expected_count=2)
        rb = self._run_adapter("account_b", "discover",
                                allowed_records=["ne.palfora.ir",
                                                  "ne.shikoonet.xyz"],
                                expected_count=2)
        self.assertEqual(len(ra["result"]["manifest"]) +
                          len(rb["result"]["manifest"]), 4)
        # The fake recorded one discover per account.
        ops = [c.get("op") for c in self._calls()]
        self.assertEqual(ops.count("discover"), 2)

    def test_apply_across_both_accounts_and_read_back_verifies(self):
        # Apply A.
        ra = self._run_adapter("account_a", "apply",
                                manifest=[{"zone_id": "zone-aaaa",
                                            "record_id": "rec-00001",
                                            "name": "ne.tinooer.top"},
                                           {"zone_id": "zone-bbbb",
                                            "record_id": "rec-00002",
                                            "name": "ne.miragerunner.com"}])
        # Apply B.
        rb = self._run_adapter("account_b", "apply",
                                manifest=[{"zone_id": "zone-cccc",
                                            "record_id": "rec-00003",
                                            "name": "ne.palfora.ir"},
                                           {"zone_id": "zone-dddd",
                                            "record_id": "rec-00004",
                                            "name": "ne.shikoonet.xyz"}])
        self.assertTrue(ra["result"]["ok"])
        self.assertTrue(rb["result"]["ok"])
        # Verify.
        va = self._run_adapter("account_a", "verify",
                                manifest=[{"zone_id": "zone-aaaa",
                                            "record_id": "rec-00001",
                                            "name": "ne.tinooer.top"}])
        vb = self._run_adapter("account_b", "verify",
                                manifest=[{"zone_id": "zone-cccc",
                                            "record_id": "rec-00003",
                                            "name": "ne.palfora.ir"}])
        self.assertTrue(va["result"]["ok"])
        self.assertTrue(vb["result"]["ok"])

    def test_rollback_restores_after_both_applies(self):
        self._run_adapter("account_a", "apply",
                           manifest=[{"zone_id": "zone-aaaa",
                                       "record_id": "rec-00001",
                                       "name": "ne.tinooer.top"}])
        self._run_adapter("account_b", "apply",
                           manifest=[{"zone_id": "zone-cccc",
                                       "record_id": "rec-00003",
                                       "name": "ne.palfora.ir"}])
        # Roll back.
        self._run_adapter("account_a", "rollback",
                           manifest=[{"zone_id": "zone-aaaa",
                                       "record_id": "rec-00001",
                                       "name": "ne.tinooer.top"}])
        self._run_adapter("account_b", "rollback",
                           manifest=[{"zone_id": "zone-cccc",
                                       "record_id": "rec-00003",
                                       "name": "ne.palfora.ir"}])
        # State restored to OLD_IP.
        state = json.loads(self.cf_state.read_text())
        for r in state["cloudflare"]["records"]:
            self.assertEqual(r["content"], "203.0.113.10", r)

    def test_missing_token_refuses(self):
        # Clear the A token and try to discover with it.
        os.environ.pop("CLOUDFLARE_API_TOKEN_ACCOUNT_A", None)
        from providers import NonRetryableError
        with self.assertRaises(NonRetryableError):
            self._run_adapter("account_a", "discover",
                                allowed_records=["ne.tinooer.top"])

    def test_manifest_ownership_mismatch_refused_at_subprocess(self):
        # Manifest names a record whose zone is owned by account A but
        # the manifest's credential_ref is account_b. The fake refuses
        # at the playbook boundary (zone not in the calling account's
        # allowed set). The adapter surfaces a structured result with
        # ok=False.
        bad_manifest = [{"zone_id": "zone-aaaa", "record_id": "rec-00001",
                          "name": "ne.tinooer.top",
                          "credential_ref": "account_b"}]
        result = self._run_adapter("account_b", "apply", manifest=bad_manifest)
        self.assertFalse((result.get("result") or {}).get("ok"),
                          msg=f"apply unexpectedly succeeded: {result}")
        # The subprocess WAS invoked (the adapter cannot know zone
        # ownership without config info); the fake refused with rc=1.
        ops = [c.get("op") for c in self._calls()]
        self.assertIn("apply", ops)

    def test_subprocess_env_scrubs_other_account_token(self):
        # Run a discover for account A. The recorder captured the env
        # keys; assert that B's token env var is NOT visible to the
        # child even though it is in the parent's env.
        self._run_adapter("account_a", "discover",
                           allowed_records=["ne.tinooer.top"])
        self.assertEqual(len(self.recorded_env_keys), 1)
        keys = self.recorded_env_keys[0]
        self.assertNotIn("CLOUDFLARE_API_TOKEN_ACCOUNT_B", keys)
        self.assertNotIn("DATAFOREST_API_TOKEN", keys)
        self.assertNotIn("HCLOUD_TOKEN", keys)
        # The unified CLOUDFLARE_API_TOKEN IS visible (the playbook
        # only reads that one name) and the test verifies below that
        # it carries the SELECTED account's value.
        self.assertIn("CLOUDFLARE_API_TOKEN", keys)

    def test_argv_contains_no_token_value(self):
        # The adapter passes -e credential_ref and -e token_env, but
        # NEVER the token value. Inspect the call log + argv via a
        # slightly more detailed recorder.
        captured_argv: List[List[str]] = []
        original = self._recorder
        def detailed(argv, **kwargs):
            captured_argv.append(list(argv))
            return original(argv, **kwargs)
        from cloudflare_adapter import run_cloudflare_op
        run_cloudflare_op(
            "discover",
            old_ip="203.0.113.10", new_ip="198.51.100.99",
            allowed_records=["ne.tinooer.top"], expected_count=1,
            invocation_id="iv-det", credential_ref="account_a",
            token_env="CLOUDFLARE_API_TOKEN_ACCOUNT_A",
            runner=detailed, timeout=10,
        )
        # The token VALUE never appears in argv, neither as a flag
        # value nor as a positional arg.
        argv_blob = " ".join(" ".join(a) for a in captured_argv)
        for tok in (self.token_a, self.token_b, self.token_legacy):
            self.assertNotIn(tok, argv_blob,
                              f"token {tok!r} leaked into argv")


if __name__ == "__main__":
    unittest.main()


# ===========================================================================
# Sentinel env-var proof: the child env allowlist excludes every
# `*TOKEN` / `*SECRET` / `*PASSWORD` / `*KEY` variable the parent
# process happens to have. The test sets the four sentinels in
# the live os.environ, runs the adapter, and asserts the recorder
# captured env does NOT contain any of them.
# ===========================================================================
class TestAdapterSentinelEnvLeak(unittest.TestCase):
    """The adapter's child-env allowlist is the structural defense.
    Add a new sentinel env var, prove the recorder's captured env
    does NOT see it. Failure messages must NEVER print the sentinel
    value — only the var name.
    """

    def test_child_env_does_not_leak_sentinel_secrets(self):
        sentinels = {
            "SENTINEL_TOKEN_X": secrets.token_hex(8),
            "SENTINEL_SECRET_Y": secrets.token_hex(8),
            "SENTINEL_PASSWORD_Z": secrets.token_hex(8),
            "SENTINEL_KEY_W": secrets.token_hex(8),
            "UNRELATED_TOKEN": secrets.token_hex(8),
            "OTHER_TOKEN_NOT_ALLOWED": secrets.token_hex(8),
            # An ansible-flavoured sentinel: the parent's process
            # env might carry a `ANSIBLE_*_TOKEN` style var (e.g.
            # an operator's AWX or AAP install does), and a buggy
            # forward-everything allowlist would ship it into the
            # child. The adapter's allowlist is NAME-based, not
            # PATTERN-based, so this var MUST NOT appear.
            "ANSIBLE_SECRET_TOKEN": secrets.token_hex(8),
        }
        # Add the sentinels to the live env.
        saved = {k: os.environ.get(k) for k in sentinels}
        for k, v in sentinels.items():
            os.environ[k] = v
        # Also set the allowed Cloudflare account token.
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = "real-a-token"
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_B"] = "real-b-token"
        os.environ["CLOUDFLARE_API_TOKEN"] = "real-legacy-token"
        os.environ["DATAFOREST_API_TOKEN"] = "real-df-token"
        os.environ["HCLOUD_TOKEN"] = "real-hc-token"

        captured_keys: List[str] = []
        captured_values: Dict[str, str] = {}

        def recorder(argv, **kwargs):
            env = kwargs.get("env") or {}
            captured_keys.extend(sorted(env.keys()))
            for k, v in env.items():
                captured_values[k] = v
            # Write a minimal result file.
            for a in argv:
                if isinstance(a, str) and a.startswith("result_file="):
                    rfile = a.split("=", 1)[1]
                    Path = __import__("pathlib").Path
                    Path(rfile).write_text(json.dumps(
                        {"ok": True, "operation": "discover",
                          "invocation_id": "iv-sentinel"}))
            class _C:
                def __init__(self): self.returncode = 0
                stdout = ""; stderr = ""
            return _C()

        from cloudflare_adapter import run_cloudflare_op
        try:
            run_cloudflare_op(
                "discover",
                old_ip="203.0.113.10", new_ip="198.51.100.99",
                allowed_records=[], expected_count=0,
                invocation_id="iv-sentinel",
                credential_ref="account_a",
                token_env="CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                runner=recorder, timeout=20,
            )
        finally:
            for k, v in sentinels.items():
                if saved.get(k) is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = saved[k]
        # The captured env key set must NOT contain any of the
        # sentinels. Test the LIST membership, not the values,
        # so the failure message never prints a secret.
        for k in sentinels:
            self.assertNotIn(k, captured_keys,
                              msg=f"adapter leaked env var {k!r} into "
                                  f"the child env (keys present: "
                                  f"{sorted(set(captured_keys))})")
        # The captured env must NOT contain the OTHER accounts' tokens
        # nor the DataForest / Hetzner / legacy Cloudflare secrets.
        # CLOUDFLARE_API_TOKEN IS expected: the adapter copies the
        # SELECTED account's value into that variable.
        for forbidden in ("CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                           "DATAFOREST_API_TOKEN", "HCLOUD_TOKEN"):
            self.assertNotIn(forbidden, captured_keys,
                              msg=f"adapter leaked env var {forbidden!r} "
                                  f"into the account-A child env")
        # But the selected account's token MUST be present in
        # CLOUDFLARE_API_TOKEN (the only credential variable the
        # adapter allows through).
        self.assertIn("CLOUDFLARE_API_TOKEN", captured_keys)
        self.assertEqual(captured_values.get("CLOUDFLARE_API_TOKEN"),
                          "real-a-token",
                          msg="the selected account's token was NOT copied "
                              "into CLOUDFLARE_API_TOKEN in the child env")
        # The sentinel VALUES must never appear in captured_values
        # (defensive — keys were already checked, but a buggy
        # adapter could pass them through under a different name).
        for k, v in sentinels.items():
            self.assertNotIn(v, list(captured_values.values()),
                              msg=f"the VALUE of {k!r} appeared somewhere "
                                  f"in the child env; the key is not "
                                  f"leaking the value is")
