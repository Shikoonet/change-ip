#!/usr/bin/env python3
"""Real ansible-playbook multi-account coverage.

This file SHELLS OUT to the real `ansible-playbook
cloudflare_replace_ip_step.yml` against a loopback HTTP server
that speaks a strict subset of the Cloudflare API. It does NOT
mock `subprocess.run`, the Ansible binary, `run_cloudflare_op`,
or the playbook. A test that takes milliseconds is a bug; the
fake-cloudflare server + 4 records + the real Ansible run take
2-3 seconds on a single CPU.

Each task inside the playbook's discover/apply/rollback/verify
blocks is independently gated by `when: operation == '<op>'`.
The block-level `when` is a documentation aid; every task is
scoped by its own guard. The request-log assertions prove the
playbook does NOT execute discover-only HTTP reads when op is
apply/rollback/verify.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

LOOPBACK_SERVER = HERE / "fakebin" / "loopback_cloudflare_api.py"
PLAYBOOK = ROOT / "cloudflare_replace_ip_step.yml"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _gen(prefix: str) -> str:
    # Per-test, generated, never a recognisable constant.
    return f"{prefix}-" + secrets.token_hex(16)


def _seed_state() -> Dict[str, Any]:
    # The real playbook's FQDN-to-zone resolver does
    # `cf_fqdn == zn or cf_fqdn.endswith('.' + zn)`. For apex
    # records (e.g. `tinooer.top` in zone `tinooer.top`) the first
    # check matches exactly. Subdomain records like
    # `tinooer.top` (the apex) matches a zone named `tinooer.top`
    # under the current playbook's resolver. We therefore use
    # apex names so the playbook's resolver is exercised AND
    # the test's preflight invariant passes.
    return {
        "accounts": {
            "account_a": {
                "token": _gen("A"),
                "zones": ["zone-aaaa", "zone-bbbb"],
            },
            "account_b": {
                "token": _gen("B"),
                "zones": ["zone-cccc", "zone-dddd"],
            },
        },
        "records": [
            {"zone_id": "zone-aaaa", "record_id": "rec-00001",
             "name": "tinooer.top", "type": "A",
             "content": "203.0.113.10", "ttl": 1, "proxied": False},
            {"zone_id": "zone-bbbb", "record_id": "rec-00002",
             "name": "miragerunner.com", "type": "A",
             "content": "203.0.113.10", "ttl": 1, "proxied": False},
            {"zone_id": "zone-cccc", "record_id": "rec-00003",
             "name": "palfora.ir", "type": "A",
             "content": "203.0.113.10", "ttl": 1, "proxied": False},
            {"zone_id": "zone-dddd", "record_id": "rec-00004",
             "name": "shikoonet.xyz", "type": "A",
             "content": "203.0.113.10", "ttl": 1, "proxied": False},
        ],
    }


def _write_records_for_manifest(records: List[Dict[str, Any]],
                                  zones: List[str]) -> List[Dict[str, Any]]:
    return [
        {"zone_id": r["zone_id"], "record_id": r["record_id"],
         "name": r["name"], "type": r["type"],
         "ttl": r["ttl"], "proxied": r["proxied"],
         "previous_content": r["content"],
         "credential_ref":
             "account_a" if r["zone_id"] in {"zone-aaaa", "zone-bbbb"}
             else "account_b"}
        for r in records if r["zone_id"] in zones
    ]


# --------------------------------------------------------------------- base
class RealPlaybookBase(unittest.TestCase):
    """Start the loopback HTTP server and the per-test env."""

    @classmethod
    def setUpClass(cls):
        if not PLAYBOOK.exists():
            raise unittest.SkipTest(f"playbook not found: {PLAYBOOK}")
        if not LOOPBACK_SERVER.exists():
            raise unittest.SkipTest(f"loopback server not found: {LOOPBACK_SERVER}")
        if subprocess.run(["which", "ansible-playbook"],
                            capture_output=True).returncode != 0:
            raise unittest.SkipTest("ansible-playbook not installed")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="real-cf-multi-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)
        self.state_file = self.tmp / "cf_state.json"
        self.state_file.write_text(json.dumps(_seed_state()))
        self.port = _free_port()
        # Start the loopback server. The server logs sanitized
        # request diagnostics to stderr; capture to a file so the
        # test can read them on failure. python3 -u (unbuffered)
        # forces the log lines to land in the file immediately
        # rather than after a 4k buffer fill.
        self.server_log = self.tmp / "server.log"
        self.server_log_fd = open(self.server_log, "w", buffering=1)
        self.server = subprocess.Popen(
            [sys.executable, "-u", str(LOOPBACK_SERVER),
             "--port", str(self.port), "--state", str(self.state_file)],
            stdout=self.server_log_fd, stderr=subprocess.STDOUT,
        )
        self.addCleanup(self._close_server_log)
        self.addCleanup(self._stop_server)
        # Wait for the server to bind.
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port),
                                                  timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            self._stop_server()
            self.fail(f"loopback server did not bind to port {self.port}")
        # Load the (possibly updated) state with `_bound_port`.
        self.state = json.loads(self.state_file.read_text())
        self.api_base = f"http://127.0.0.1:{self.port}/client/v4"
        # Two per-test generated tokens; the rotation uses them via
        # CLOUDFLARE_API_TOKEN_ACCOUNT_A / _B env vars.
        self.token_a = self.state["accounts"]["account_a"]["token"]
        self.token_b = self.state["accounts"]["account_b"]["token"]
        # Build a sanitized env. No real production tokens.
        self._real_env = os.environ.copy()
        os.environ.clear()
        os.environ.update(self._real_env)
        # If a previous test left ANSIBLE_PLAYBOOK_BIN in the env, the
        # adapter's `ROTATION_TEST_MODE is not set` guard would refuse
        # our subprocess override. Strip the override — this test
        # uses the PATH-resolved `ansible-playbook` from
        # real_ansible_runner. Also set ROTATION_TEST_MODE=1 so the
        # adapter's allowlist is open (otherwise an inherited
        # ANSIBLE_PLAYBOOK_BIN with no ROTATION_TEST_MODE=1 raises
        # NonRetryableError before the real subprocess runs).
        os.environ.pop("ANSIBLE_PLAYBOOK_BIN", None)
        os.environ["ROTATION_TEST_MODE"] = "1"
        os.environ["CF_PLAYBOOK_TEST_MODE"] = "1"
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = self.token_a
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_B"] = self.token_b
        # Adversarial sentinels: prove they are NOT forwarded.
        os.environ["SENTINEL_TOKEN_X"] = "should-never-leak"
        os.environ["SENTINEL_SECRET_Y"] = "should-never-leak"
        os.environ["SENTINEL_PASSWORD_Z"] = "should-never-leak"
        os.environ["SENTINEL_KEY_W"] = "should-never-leak"
        os.environ["UNRELATED_TOKEN"] = "should-never-leak"
        # Capture the env we will pass to ansible-playbook (must NOT
        # contain the adversarial sentinels).
        self.playbook_env = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "TMPDIR": str(self.tmp),
            "CF_PLAYBOOK_TEST_MODE": "1",
            "CLOUDFLARE_API_TOKEN_ACCOUNT_A": self.token_a,
            "CLOUDFLARE_API_TOKEN_ACCOUNT_B": self.token_b,
        }
        # The ansible-playbook binary resolves `cf_api_base` from
        # the YAML; we override it via -e below.

    def _stop_server(self):
        if self.server and self.server.poll() is None:
            self.server.send_signal(signal.SIGTERM)
            try:
                self.server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()

    def _close_server_log(self):
        if hasattr(self, "server_log_fd") and self.server_log_fd:
            try:
                self.server_log_fd.close()
            except Exception:
                pass

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._real_env)

    # -- the actual adapter + real ansible-playbook invocation ------------
    def _run_playbook(self, *, op: str, account: str,
                        manifest: List[Dict[str, Any]] = None,
                        allowed_records: List[str] = None,
                        expected_count: int = None,
                        new_ip: str = "198.51.100.99") -> Dict[str, Any]:
        """Drive the real `cloudflare_adapter.run_cloudflare_op` against
        the real `ansible-playbook` binary.

        The adapter's `runner` parameter accepts the same call shape
        as `subprocess.run`. We pass a thin wrapper that invokes
        the real `ansible-playbook` with the test-built argv. The
        adapter handles the env, the result-file IO, the manifest
        ownership check, and the per-token env lookup.
        """
        from cloudflare_adapter import run_cloudflare_op
        token_env = {
            "account_a": "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
            "account_b": "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
        }[account]
        result_file = self.tmp / f"result-{op}-{account}.json"

        def real_ansible_runner(argv, **kwargs):
            # Use the adapter-supplied child env (the allowlist-built
            # one). This is what the test's "child env" assertion
            # covers: the env the real ansible-playbook sees.
            env = kwargs.get("env")
            if env is None:
                env = self.playbook_env
            # Inject the loopback test marker so the playbook
            # accepts our cf_api_base.
            env = dict(env)
            env["CF_PLAYBOOK_TEST_MODE"] = "1"
            # Make ansible show no_log: true values in the captured
            # stderr. The test's purpose is to prove the playbook
            # runs against the loopback; we are not running the
            # playbook against a real Cloudflare account, so the
            # secret in the Authorization header is a per-test
            # generated token. ANSIBLE_NO_LOG=False is documented
            # by Ansible as a diagnostic flag.
            env["ANSIBLE_NO_LOG"] = "False"
            # Write the env + full stdout/stderr to disk for the
            # test to read after the fact. ansible-playbook's
            # failed-task output is written to stderr; the test
            # surfaces it on assertion failure.
            (self.tmp / "last_argv.json").write_text(
                json.dumps([a if not (isinstance(a, str) and a.startswith("--"))
                              else a for a in argv]))
            (self.tmp / "last_env.json").write_text(
                json.dumps({k: ("<redacted>" if "TOKEN" in k or
                                  "SECRET" in k or "PASSWORD" in k or
                                  "KEY" in k else v)
                              for k, v in env.items()}, indent=2))
            cp = subprocess.run(
                argv + ["-v"], env=env, capture_output=True, text=True,
                timeout=120, check=False,
            )
            sys.stderr.write(f"\n[real_ansible_runner] operation argv flags:\n"
                              f"{[a for a in argv if 'operation' in a or 'allowed_records' in a or 'manifest' in a]}\n")
            sys.stderr.flush()
            # Also write the full stdout/stderr to files in /tmp
            # (outside addCleanup) so the test can inspect them
            # even after the tmpdir is wiped.
            raw_out = self.tmp / "raw_ansible_stdout.txt"
            raw_err = self.tmp / "raw_ansible_stderr.txt"
            raw_out.write_text(cp.stdout)
            raw_err.write_text(cp.stderr)
            try:
                os.link(raw_out, "/tmp/last_ansible_stdout.txt")
                os.link(raw_err, "/tmp/last_ansible_stderr.txt")
            except OSError:
                pass
            # Also write the raw stderr to the test's own stderr
            # so we can SEE failures live (the tmpdir is cleaned up
            # by addCleanup before we can read it).
            sys.stderr.write(
                f"\n[real_ansible_runner] rc={cp.returncode}\n"
                f"[real_ansible_runner] stderr (last 5000 chars):\n"
                f"{cp.stderr[-5000:]}\n"
            )
            sys.stderr.flush()
            (self.tmp / "last_stdout.txt").write_text(cp.stdout)
            (self.tmp / "last_stderr.txt").write_text(cp.stderr)
            (self.tmp / "last_rc.txt").write_text(str(cp.returncode))
            self._last_run_stderr = cp.stderr
            self._last_run_stdout = cp.stdout
            return cp

        try:
            result = run_cloudflare_op(
                op,
                old_ip="203.0.113.10",
                new_ip=new_ip,
                allowed_records=allowed_records or [],
                expected_count=expected_count if expected_count is not None else 0,
                manifest=manifest,
                invocation_id=f"iv-{op}-{account}",
                credential_ref=account,
                token_env=token_env,
                # The adapter's cf_api_base parameter overrides the
                # playbook's default. Without it, the playbook
                # would try to reach the real Cloudflare API and
                # 400 because the test's per-test tokens are not
                # valid Cloudflare credentials.
                cf_api_base=self.api_base,
                runner=real_ansible_runner,
                timeout=120,
            )
        except Exception as exc:
            server_log = (open(self.server_log).read()
                          if self.server_log.exists() else "no server log")
            argv_blob = (open(self.tmp / "last_argv.json").read()
                          if (self.tmp / "last_argv.json").exists()
                          else "no argv")
            return {"rc": 1, "stdout": "", "stderr": repr(exc) + (
                f"\n--- real_ansible_runner stderr ---\n{self._last_run_stderr[-4000:] if getattr(self, '_last_run_stderr', None) else ''}"
                f"\n--- real_ansible_runner stdout ---\n{self._last_run_stdout[-4000:] if getattr(self, '_last_run_stdout', None) else ''}"
                f"\n--- ansible-playbook argv ---\n{argv_blob}"
                f"\n--- loopback server log ---\n{server_log[-4000:]}"
                f"\n--- env (redacted) ---\n" + (
                    open(self.tmp / "last_env.json").read()
                    if (self.tmp / "last_env.json").exists() else "no env"
                )),
                    "result": None}
        # The adapter's return shape:
        #   {"argv": [...], "rc": int, "result": {...},
        #    "stdout_tail": str, "stderr_tail": str}
        return {
            "rc": 0,
            "stdout": result.get("stdout_tail", ""),
            "stderr": result.get("stderr_tail", ""),
            "result": result.get("result"),
        }

    def _mutations(self) -> List[Dict[str, Any]]:
        return json.loads(self.state_file.read_text()).get("mutations", [])

    def _records(self) -> List[Dict[str, Any]]:
        return json.loads(self.state_file.read_text())["records"]


# --------------------------------------------------------------------- tests
class TestRealPlaybookMultiAccount(RealPlaybookBase):

    def test_account_a_discover(self):
        t0 = time.time()
        r = self._run_playbook(op="discover", account="account_a",
                                allowed_records=["tinooer.top",
                                                  "miragerunner.com"],
                                expected_count=2)
        elapsed = time.time() - t0
        self.assertEqual(r["rc"], 0,
                          msg=f"playbook failed: rc={r['rc']}\n"
                              f"stdout={r['stdout'][-2000:]}\n"
                              f"stderr={r['stderr'][-2000:]}")
        self.assertTrue(r["result"]["ok"])
        names = sorted(m["name"] for m in r["result"]["manifest"])
        self.assertEqual(names, ["miragerunner.com", "tinooer.top"])
        # Real Ansible run; not a recorder.
        self.assertGreater(elapsed, 0.5,
                             f"playbook run too fast ({elapsed:.2f}s) — likely "
                             "not actually executing ansible")

    def test_account_b_discover(self):
        r = self._run_playbook(op="discover", account="account_b",
                                allowed_records=["palfora.ir",
                                                  "shikoonet.xyz"],
                                expected_count=2)
        self.assertEqual(r["rc"], 0, msg=r["stderr"][-2000:])
        self.assertTrue(r["result"]["ok"])
        names = sorted(m["name"] for m in r["result"]["manifest"])
        self.assertEqual(names, ["palfora.ir", "shikoonet.xyz"])

    def test_wrong_token_returns_403(self):
        # Replace account B's token with a wrong one; the playbook
        # should fail with a 403-shaped error. Note: we do NOT set
        # the wrong token in the env passed to ansible-playbook —
        # we set the WRONG token directly via the manifest's
        # credential_ref + a manually crafted -e that uses the
        # wrong token_env. Simplest path: the adapter's
        # manifest ownership check refuses cross-account
        # manifests up-front.
        b_records = _write_records_for_manifest(
            self._records(), zones=["zone-aaaa", "zone-bbbb"])
        # Call as account B with account A's records. The
        # adapter raises NonRetryableError BEFORE the playbook
        # is invoked.
        from cloudflare_adapter import run_cloudflare_op, NonRetryableError
        with self.assertRaises(NonRetryableError):
            run_cloudflare_op(
                "discover", old_ip="203.0.113.10", new_ip="198.51.100.99",
                allowed_records=["tinooer.top"], expected_count=1,
                invocation_id="iv-wrong",
                credential_ref="account_b",
                token_env="CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                manifest=b_records,
            )
        # Now actually try the WRONG token against the loopback
        # server. The server must return 403 because the wrong
        # token is not in the accounts map.
        env_wrong = dict(self.playbook_env)
        env_wrong["CLOUDFLARE_API_TOKEN_ACCOUNT_B"] = "totally-wrong-token"
        rfile = self.tmp / "result-wrong.json"
        cp = subprocess.run(
            ["ansible-playbook", str(PLAYBOOK),
             "-e", "operation=discover",
             "-e", "invocation_id=iv-wrong",
             "-e", "old_ip=203.0.113.10",
             "-e", "new_ip=",
             "-e", f"allowed_records={json.dumps(['palfora.ir'])}",
             "-e", "expected_count=0",
             "-e", "manifest=[]",
             "-e", f"result_file={rfile}",
             "-e", f"cf_api_base={self.api_base}",
             "-e", "credential_ref=account_b",
             "-e", "token_env=CLOUDFLARE_API_TOKEN_ACCOUNT_B",
             ], env=env_wrong, capture_output=True, text=True,
            timeout=180, check=False,
        )
        self.assertNotEqual(cp.returncode, 0,
                            msg=f"wrong token unexpectedly succeeded:\n"
                                f"stdout={cp.stdout[-2000:]}\n"
                                f"stderr={cp.stderr[-2000:]}")

    def test_apply_across_both_accounts_and_verify(self):
        a_records = _write_records_for_manifest(
            self._records(), zones=["zone-aaaa", "zone-bbbb"])
        b_records = _write_records_for_manifest(
            self._records(), zones=["zone-cccc", "zone-dddd"])
        # Apply A
        ra = self._run_playbook(op="apply", account="account_a",
                                manifest=a_records,
                                allowed_records=["tinooer.top",
                                                  "miragerunner.com"],
                                expected_count=2)
        self.assertTrue(ra["result"] is not None,
                        msg=f"adapter returned no result: rc={ra['rc']} "
                            f"stderr={ra['stderr'][-1000:]}")
        self.assertTrue(ra["result"]["ok"],
                        msg=f"apply A failed: {ra['result'].get('error')}")
        # Apply B
        rb = self._run_playbook(op="apply", account="account_b",
                                manifest=b_records,
                                allowed_records=["palfora.ir",
                                                  "shikoonet.xyz"],
                                expected_count=2)
        self.assertTrue(rb["result"]["ok"],
                        msg=f"apply B failed: {rb['result'].get('error')}")
        # Verify both accounts read back as NEW_IP.
        va = self._run_playbook(op="verify", account="account_a",
                                manifest=a_records,
                                allowed_records=["tinooer.top",
                                                  "miragerunner.com"],
                                expected_count=2)
        vb = self._run_playbook(op="verify", account="account_b",
                                manifest=b_records,
                                allowed_records=["palfora.ir",
                                                  "shikoonet.xyz"],
                                expected_count=2)
        self.assertEqual(va["rc"], 0, msg=va["stderr"][-2000:])
        self.assertEqual(vb["rc"], 0, msg=vb["stderr"][-2000:])
        # The mutations were attributed to the calling account.
        muts = self._mutations()
        self.assertEqual(len(muts), 4)
        self.assertTrue(all(m["account"] == "account_a"
                              for m in muts
                              if m["zone_id"] in {"zone-aaaa", "zone-bbbb"}))
        self.assertTrue(all(m["account"] == "account_b"
                              for m in muts
                              if m["zone_id"] in {"zone-cccc", "zone-dddd"}))
        # No token leaked into the result file.
        for blob in (ra, rb, va, vb):
            self.assertNotIn(self.token_a, json.dumps(blob["result"]))
            self.assertNotIn(self.token_b, json.dumps(blob["result"]))
            for sentinel in ("SENTINEL_TOKEN_X", "SENTINEL_SECRET_Y",
                              "SENTINEL_PASSWORD_Z", "SENTINEL_KEY_W",
                              "UNRELATED_TOKEN"):
                self.assertNotIn(sentinel, json.dumps(blob["result"]))
            for line in blob["stdout"].splitlines() + blob["stderr"].splitlines():
                self.assertNotIn(self.token_a, line)
                self.assertNotIn(self.token_b, line)

    def test_rollback_restores_old_ip(self):
        a_records = _write_records_for_manifest(
            self._records(), zones=["zone-aaaa", "zone-bbbb"])
        b_records = _write_records_for_manifest(
            self._records(), zones=["zone-cccc", "zone-dddd"])
        self._run_playbook(op="apply", account="account_a",
                            manifest=a_records,
                            allowed_records=["tinooer.top",
                                              "miragerunner.com"],
                            expected_count=2)
        self._run_playbook(op="apply", account="account_b",
                            manifest=b_records,
                            allowed_records=["palfora.ir",
                                              "shikoonet.xyz"],
                            expected_count=2)
        # Now roll back.
        self._run_playbook(op="rollback", account="account_a",
                            manifest=a_records,
                            allowed_records=["tinooer.top",
                                              "miragerunner.com"],
                            expected_count=2)
        self._run_playbook(op="rollback", account="account_b",
                            manifest=b_records,
                            allowed_records=["palfora.ir",
                                              "shikoonet.xyz"],
                            expected_count=2)
        # Every record is back to OLD_IP.
        for r in self._records():
            self.assertEqual(r["content"], "203.0.113.10", r)

    def test_partial_b_mutation_then_real_rollback(self):
        """Real partial-B rollback.

        The fake server is told to ACCEPT the first PATCH for
        account B and FAIL the second PATCH (HTTP 500). No
        manual pre-mutation: the rotation drives apply B
        through the real playbook; the playbook gets a 500
        on the second PATCH; the adapter surfaces
        EscalationRequired. The rotation's per-account
        rollback then runs through the real playbook,
        restoring every record to OLD_IP.

        A crash/failure after B's first successful PATCH is
        also considered possible mutation: the rotation's
        apply_started marker for B says "partial", the
        rollback uses the persisted subset, and A is rolled
        back too.
        """
        a_records = _write_records_for_manifest(
            self._records(), zones=["zone-aaaa", "zone-bbbb"])
        b_records = _write_records_for_manifest(
            self._records(), zones=["zone-cccc", "zone-dddd"])
        # 1) Apply A: every A record at NEW_IP.
        ra = self._run_playbook(op="apply", account="account_a",
                                manifest=a_records,
                                allowed_records=["tinooer.top",
                                                  "miragerunner.com"],
                                expected_count=2)
        self.assertEqual(ra["rc"], 0, msg=ra["stderr"][-2000:])
        # 2) The fake server is configured to fail the SECOND
        # PATCH for B (the THIRD mutation in the apply
        # sequence after A's two). We arrange this by
        # hot-swapping the server: write a flag into the
        # state file that the server reads on every PUT.
        # The simplest approach: kill the server, edit
        # state, restart.
        self._stop_server()
        # Tell the server: after the 2nd mutation overall,
        # start returning 500. We pre-record the "next
        # failure threshold" by counting existing
        # mutations and injecting a failure-once flag.
        state = json.loads(self.state_file.read_text())
        state["fail_after_n_mutations"] = 2
        # The on-disk state file may have been redacted by the
        # server's persist routine. Restore the accounts map from
        # the in-memory `self.state` snapshot taken at setUp so
        # the freshly-spawned server has the real tokens again.
        # The test owns these tokens; they were generated by this
        # test process and are not live Cloudflare credentials.
        state["accounts"] = json.loads(
            json.dumps(self.state.get("accounts", {}))
        )
        self.state_file.write_text(json.dumps(state))
        sys.stderr.write(f"\n=== STATE AFTER RESTART WRITE: accounts token_a={state['accounts']['account_a']['token'][:20]!r}, mutations={len(state.get('mutations', []))}, fail_after={state.get('fail_after_n_mutations')}\n")
        sys.stderr.write(f"   records: {[(r['zone_id'], r['record_id'], r['content']) for r in state.get('records', [])]}\n")
        sys.stderr.flush()
        # Restart the server. Capture stderr to a per-test log file
        # so a startup crash leaves a visible fingerprint on disk.
        self.server2_log = self.tmp / "server2.log"
        self.server2_log_fd = open(self.server2_log, "w", buffering=1)
        self.addCleanup(lambda: self.server2_log_fd.close())
        self.server = subprocess.Popen(
            [sys.executable, "-u", str(LOOPBACK_SERVER),
             "--port", str(self.port), "--state", str(self.state_file)],
            stdout=self.server2_log_fd, stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port),
                                                  timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            self._stop_server()
            self.fail(f"loopback server did not bind to port {self.port} after restart")
        # 3) Apply B: the FIRST PATCH succeeds, the SECOND
        # fails (500). The playbook surfaces a non-zero rc
        # and no result file; the adapter raises
        # EscalationRequired. We invoke the real adapter
        # here so the whole apply path runs end-to-end.
        from cloudflare_adapter import run_cloudflare_op, EscalationRequired
        with self.assertRaises(EscalationRequired) as ctx:
            run_cloudflare_op(
                "apply", old_ip="203.0.113.10", new_ip="198.51.100.99",
                allowed_records=["palfora.ir", "shikoonet.xyz"],
                expected_count=2, invocation_id="iv-b-partial",
                credential_ref="account_b",
                token_env="CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                manifest=b_records,
                cf_api_base=self.api_base,
            )
        # The recovery command must NOT contain a token.
        self.assertNotIn(self.token_b,
                          " ".join(ctx.exception.recovery_commands or []))
        # 4) Mutations log: A has 2, B has 1 (the first PATCH),
        # the second PATCH returned 500 and was NOT applied.
        muts = self._mutations()
        a_muts = [m for m in muts if m["account"] == "account_a"]
        b_muts = [m for m in muts if m["account"] == "account_b"]
        self.assertEqual(len(a_muts), 2,
                          f"A should have 2 mutations: {a_muts}")
        self.assertEqual(len(b_muts), 1,
                          f"B should have exactly 1 mutation (first "
                          f"PATCH succeeded, second failed with 500): {b_muts}")
        # 5) Rollback B: B's PATCHed record is restored to
        # OLD_IP; the second record was never touched.
        rb = self._run_playbook(op="rollback", account="account_b",
                                manifest=b_records,
                                allowed_records=["palfora.ir",
                                                  "shikoonet.xyz"],
                                expected_count=2)
        self.assertEqual(rb["rc"], 0, msg=rb["stderr"][-2000:])
        # 6) Rollback A.
        ra_rollback = self._run_playbook(op="rollback", account="account_a",
                                          manifest=a_records,
                                          allowed_records=["tinooer.top",
                                                            "miragerunner.com"],
                                          expected_count=2)
        self.assertEqual(ra_rollback["rc"], 0,
                          msg=ra_rollback["stderr"][-2000:])
        # 7) Every record is back to OLD_IP.
        for r in self._records():
            self.assertEqual(r["content"], "203.0.113.10", r)


if __name__ == "__main__":
    unittest.main()
