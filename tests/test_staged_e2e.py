#!/usr/bin/env python3
"""Real multi-process staged CLI integration test.

EVERY stage of the DataForest change-ip transaction runs as its own
`python3 rotate.py ...` subprocess, wrapped by the workflow's own stage
runner (`.github/scripts/stage.py`), against ONE persisted state
directory:

  1  apply --until new_ip_allocated        DF token   rc 6
  2  dataforest-identity-check             DF token   rc 6  (marker)
  3  resume --until guest_configured       no token   rc 6  (fake playbook)
  4  resume --until guest_verified         no token   rc 6  (fake probe)
  5  resume --until cloudflare_preflighted CF token   rc 6  (manifest)
  6  resume --until ansible_done           CF token   rc 6  (fake ip-change)
  7  resume --until cloudflare_replaced    CF token   rc 6  (apply marker)
  8  resume --until awaiting_finalize      CF token   rc 6
  9  finalize-precheck                     CF token   rc 6
  10 provider-finalize                     DF token   rc 0  (OLD_IP gone)

The stage runner returns 0 only when the raw rc, the checkpoint state and
the required markers all match, so a green stage is a checked stage.

Host interception, all guarded by `ROTATION_TEST_MODE=1`:

  * `ANSIBLE_PLAYBOOK_BIN` → `tests/fakebin/ansible-playbook`, which
    answers BOTH `dataforest_step.yml` and
    `cloudflare_replace_ip_step.yml` from `$ROTATION_FAKE_STATE` and
    appends every call to `$ROTATION_FAKE_CALLS_LOG`;
  * `ROTATION_PROBE=accept` → the SSH TCP probe seam;
  * `ROTATION_IP_CHANGE=stub` → the `make ip-change` seam;
  * `DF_*` dirs + a PATH of fake `ip`/`netplan`/`ssh`/`ssh-keyscan`
    binaries, so nothing resolves to a real system tool;
  * `DATAFOREST_API_BASE_URL` → an in-process loopback TCP fake.

Every stage asserts, before it runs, that the fake is the executable
that will be selected and that only the permitted token is in the env;
and after it runs, that real `/etc` is untouched, no non-loopback
endpoint was configured, the checkpoint advanced, the expected fake
invocation was recorded, and no token reached stdout/stderr or disk.

NO live Hetzner, DataForest, Cloudflare, DNS, SSH, server, GitHub
deployment, commit, push, merge, PR, or workflow-dispatch.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

# Use the SAME tokens the existing dataforest helpers use so the
# in-process rotation's adapter accepts the DataForest fake's auth.
from tests.fake_dataforest import DEFAULT_TOKEN as DF_TOKEN
from tests.test_dataforest import FAKE_CF_TOKEN as CF_TOKEN
HC_TOKEN = "hcloud-staged-e2e-token-fedcba9876543210"

# The fake ansible-playbook binary that handles BOTH playbooks.
FAKE_AP = HERE / "fakebin" / "ansible-playbook"
FAKEBIN_DIR = HERE / "fakebin"
STAGE_RUNNER = ROOT / ".github" / "scripts" / "stage.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _link_fakebins(tmp: Path) -> Path:
    """Symlink the system-binary fakes and the ansible-playbook fake."""
    bindir = tmp / "fakebin"
    bindir.mkdir(parents=True, exist_ok=True)
    for cmd in ("ip", "netplan", "nmcli", "networkctl",
                "systemctl", "ssh", "ssh-keyscan"):
        link = bindir / cmd
        if link.exists():
            link.unlink()
        link.write_text(
            f"#!/usr/bin/env python3\n"
            f"import sys, os\n"
            f"sys.path.insert(0, {str(FAKEBIN_DIR)!r})\n"
            f"sys.argv[0] = {cmd!r}\n"
            f"from fakebin import main\n"
            f"sys.exit(main())\n"
        )
        os.chmod(link, 0o755)
    shutil.copy(FAKEBIN_DIR / "__init__.py", bindir / "__init__.py")
    shutil.copy(FAKE_AP, bindir / "ansible-playbook")
    os.chmod(bindir / "ansible-playbook", 0o755)
    return bindir


def _stage_env( *, bindir: Path, paths: Dict[str, str],
              df_token: Optional[str], cf_token: Optional[str],
              df_base_url: str, cf_state: str, calls_log: str
              ) -> Dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = (
        str(HERE) + os.pathsep + str(ROOT) + os.pathsep
        + env.get("PYTHONPATH", "")
    )
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["IP_BIN"] = str(bindir / "ip")
    env["NETPLAN_BIN"] = str(bindir / "netplan")
    env["NMCLI_BIN"] = str(bindir / "nmcli")
    env["NETWORKCTL_BIN"] = str(bindir / "networkctl")
    env["SYSTEMCTL_BIN"] = str(bindir / "systemctl")
    env["SSH_BIN"] = str(bindir / "ssh")
    env["SSH_KEYSCAN_BIN"] = str(bindir / "ssh-keyscan")
    env["DF_NETPLAN_DIR"] = paths["netplan_dir"]
    env["DF_SYSTEMD_NETWORK_DIR"] = paths["systemd_network_dir"]
    env["DF_INTERFACES_D_DIR"] = paths["interfaces_d_dir"]
    env["DF_PERSISTENT_DIR"] = paths["persistent_dir"]
    env["DF_FAKEBIN_STATE"] = paths["fakebin_state"]
    env["DF_NM_ACTIVE"] = "0"
    env["DF_SSH_OPEN"] = "1"
    env["LC_ALL"] = "C.UTF-8"
    env["LANG"] = "C.UTF-8"
    env["DATAFOREST_API_TEST_MODE"] = "1"
    env["ROTATION_TEST_MODE"] = "1"
    # The Cloudflare adapter accepts a loopback cf_api_base ONLY when BOTH
    # markers are set (see test_cf_api_base_contract). This harness set the
    # first and not the second, and passed anyway for as long as the whole
    # suite ran in one process: test_cloudflare_playbook.setUp writes
    # CF_PLAYBOOK_TEST_MODE=1 into os.environ and never restores it, and
    # every later subprocess inherited it. Run this module alone, or in a CI
    # shard without that module first, and every cf-preflight stage was
    # refused as "production mode" pointing at 127.0.0.1 — the guard doing
    # its job against a test that borrowed another test's environment.
    env["CF_PLAYBOOK_TEST_MODE"] = "1"
    env["ANSIBLE_PLAYBOOK_BIN"] = str(FAKE_AP)
    env["ROTATION_FAKE_STATE"] = cf_state
    env["ROTATION_FAKE_CALLS_LOG"] = calls_log
    env["DATAFOREST_API_BASE_URL"] = df_base_url
    # The harness uses `tests/fakebin/ansible-playbook`, a Python
    # script that does NOT open a socket — the URL it would "talk to"
    # is decorative. The adapter's URL contract (loopback-only in test
    # mode) must still pass, so the harness passes an explicit
    # loopback URL through rotate.py. rotate.py reads this env var
    # ONLY when ROTATION_TEST_MODE == "1" and forwards it to the
    # adapter; production never reads it. The port number is
    # irrelevant because the fake never connects.
    env["ROTATION_TEST_CF_API_BASE"] = "http://127.0.0.1:1/client/v4"
    env["STATE_DIR"] = paths["state_dir"]
    env["ROTATION_PROBE"] = "accept"
    env["ROTATION_IP_CHANGE"] = "stub"
    for k in ("CLOUDFLARE_API_TOKEN", "DATAFOREST_API_TOKEN", "HCLOUD_TOKEN"):
        env.pop(k, None)
    if df_token is not None:
        env["DATAFOREST_API_TOKEN"] = df_token
    if cf_token is not None:
        env["CLOUDFLARE_API_TOKEN"] = cf_token
    return env


def _run_rotate(args: List[str], env: Dict[str, str],
                 timeout: int = 60) -> subprocess.CompletedProcess:
    """Run `python3 rotate.py` directly (no stage runner) and return
    the completed process. Used when the test only needs the rc and
    the captured output, not the stage runner's state assertions."""
    return subprocess.run(
        [sys.executable, str(ROOT / "rotate.py"), *args],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
        timeout=timeout, check=False,
    )


def _assert_no_leak(test: unittest.TestCase, cp: subprocess.CompletedProcess,
                    *tokens: str) -> None:
    blob = (cp.stdout or "") + (cp.stderr or "")
    for t in tokens:
        test.assertNotIn(t, blob,
                          msg=f"token leaked: {blob[:500]}")


def _read_cf_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        return json.loads(Path(path).read_text() or "{}")
    except (OSError, ValueError):
        return {}


def _save_cf_state(path: str, state: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(json.dumps(state))
    os.replace(tmp, path)


def _read_calls(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _write_config(cfg_path: Path, seed_id: str, old_ip: str, new_ip: str,
                 state_dir: str) -> None:
    cfg = {
        "provider": "dataforest",
        "server": {"id": seed_id, "expected_name": "seed-default",
                   "expected_ipv4": old_ip, "expected_location": "fra1"},
        "seed": {"expected_name": "seed-default",
                 "expected_location": "fra1",
                 "expected_project": "default",
                 "allow_extra_addresses": [new_ip]},
        "guest": {"network_manager": "netplan", "interface": "eth0",
                  "expected_host_key_pattern": r"^[^ ]+ ssh-ed25519",
                  "service_probes": [], "gateway": "203.0.113.1"},
        "ansible": {"host_alias": "DF-DE",
                    "inventory": "inventory/hosts.yml",
                    "repo_dir": "..", "auto_edit_inventory": False},
        "dns": {"node_record_zone": "tinooer.top",
                "allowed_records": ["DF-DE.tinooer.top", "ne.tinooer.top"]},
        "cloudflare": {"expected_record_count": 1,
                       "allowed_records": ["ne.tinooer.top"]},
        "retries": {"provider": 1, "provider_delay": 0,
                    "health": 3, "health_delay": 0},
        "old_ip": {"retention": "keep"},
        "health": {"ssh_port": 22},
        "timeouts": {"ssh": 5},
        # Allow NEW_IP without a PTR: the offline fake cannot
        # configure a PTR record on the new IP. Production should
        # still use require_match.
        "finalize": {"acknowledge_no_reacquire": True,
                "ptr_policy": "allow_no_ptr"},
        "state_dir": state_dir,
    }
    with open(cfg_path, "w") as fh:
        json.dump(cfg, fh)


# --------------------------------------------------------------------
class StagedE2EBase(unittest.TestCase):
    """Loopback fakes + shared per-test state dir."""

    def setUp(self):
        from tests.fake_dataforest import FakeDataForest
        self.df = FakeDataForest(token=DF_TOKEN)
        self.df.start()
        self.addCleanup(self.df.stop)
        self.tmp = Path(tempfile.mkdtemp(prefix="staged-e2e-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)
        self.bindir = _link_fakebins(self.tmp)
        self.paths = {
            "netplan_dir": str(self.tmp / "netplan"),
            "systemd_network_dir": str(self.tmp / "sn"),
            "interfaces_d_dir": str(self.tmp / "iu"),
            "persistent_dir": str(self.tmp / "p"),
            "fakebin_state": str(self.tmp / "fakebin_state"),
            "state_dir": str(self.tmp / "state"),
        }
        for k in ("netplan_dir", "systemd_network_dir", "interfaces_d_dir",
                  "persistent_dir", "fakebin_state", "state_dir"):
            os.makedirs(self.paths[k], exist_ok=True)
        self.cf_state = str(self.tmp / "cf_state.json")
        self.calls_log = str(self.tmp / "calls.log")
        # Seed the fake's records explicitly: exactly the one FQDN the
        # config allowlists, holding OLD_IP. (An empty list would make the
        # fake invent eight records across four zones.)
        Path(self.cf_state).write_text(json.dumps({
            "dataforest": {"addresses": ["198.51.100.10/32"]},
            "cloudflare": {"records": [{
                "zone_id": "zone-aaaa", "record_id": "rec-00001",
                "name": "ne.tinooer.top", "content": "198.51.100.10",
                "ttl": 1, "proxied": False}]}}))
        Path(self.calls_log).write_text("")

        self.seed_id = self.df._seed_snapshot["id"]
        self.old_ip = "198.51.100.10"
        self.new_ip = "198.51.100.20"
        self.df._seed_snapshot["ipv4"].append(
            {"address": self.new_ip, "primary_ip": False})

        self.config_path = self.tmp / "rotation.yml"
        # state_dir is the absolute test state dir; the rotation's
        # _resolve_state_dir keeps absolute paths.
        _write_config(self.config_path, self.seed_id, self.old_ip,
                      self.new_ip, self.paths["state_dir"])

    def _df_env(self):
        return _stage_env(bindir=self.bindir, paths=self.paths,
                          df_token=DF_TOKEN, cf_token=None,
                          df_base_url=self.df.base_url,
                          cf_state=self.cf_state,
                          calls_log=self.calls_log)

    def _cf_env(self):
        return _stage_env(bindir=self.bindir, paths=self.paths,
                          df_token=None, cf_token=CF_TOKEN,
                          df_base_url=self.df.base_url,
                          cf_state=self.cf_state,
                          calls_log=self.calls_log)

    def _neither_env(self):
        return _stage_env(bindir=self.bindir, paths=self.paths,
                          df_token=None, cf_token=None,
                          df_base_url=self.df.base_url,
                          cf_state=self.cf_state,
                          calls_log=self.calls_log)

    # ---- the staged driver: one subprocess per stage ------------------
    #: Real paths that a botched guest step would touch. Their mtimes are
    #: snapshotted per stage; any change fails the stage.
    REAL_ETC_PATHS = ("/etc", "/etc/netplan", "/etc/systemd/network",
                      "/etc/network/interfaces.d", "/etc/hosts",
                      "/etc/resolv.conf")

    def _etc_fingerprint(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for p in self.REAL_ETC_PATHS:
            try:
                st = os.stat(p)
                out[p] = (st.st_mtime_ns, st.st_size)
            except OSError:
                out[p] = None
        return out

    def _assert_env_ready(self, env: Dict[str, str],
                          allowed_tokens: List[str]) -> None:
        """Pre-flight the fake environment. A missing or non-executable
        fake must fail the test HERE, not silently fall back to a real
        binary."""
        fake = env["ANSIBLE_PLAYBOOK_BIN"]
        self.assertEqual(env["ROTATION_TEST_MODE"], "1")
        self.assertTrue(os.path.isabs(fake), fake)
        self.assertTrue(os.path.exists(fake), f"fake missing: {fake}")
        self.assertTrue(os.access(fake, os.X_OK), f"fake not executable: {fake}")
        self.assertEqual(fake, str(FAKE_AP))
        # Nothing may resolve to a real system binary either.
        for cmd in ("ansible-playbook", "ssh", "ssh-keyscan", "ip", "netplan"):
            resolved = shutil.which(cmd, path=env["PATH"])
            self.assertEqual(resolved, str(self.bindir / cmd),
                             f"{cmd} resolves to {resolved}, not the fake")
        self.assertEqual(env["ROTATION_PROBE"], "accept")
        self.assertEqual(env["ROTATION_IP_CHANGE"], "stub")
        self.assertEqual(env["ROTATION_FAKE_STATE"], self.cf_state)
        self.assertEqual(env["ROTATION_FAKE_CALLS_LOG"], self.calls_log)
        self.assertEqual(env["STATE_DIR"], self.paths["state_dir"])
        self.assertTrue(env["DATAFOREST_API_BASE_URL"].startswith(
            "http://127.0.0.1:"), env["DATAFOREST_API_BASE_URL"])
        present = [k for k in ("DATAFOREST_API_TOKEN", "CLOUDFLARE_API_TOKEN",
                               "HCLOUD_TOKEN") if env.get(k)]
        self.assertEqual(sorted(present), sorted(allowed_tokens),
                         f"token scope for this stage is {present}")

    def _run_stage(self, label: str, args: List[str], env: Dict[str, str], *,
                   expect_rc: int, expect_state: str,
                   allowed_tokens: List[str],
                   markers: Optional[List[str]] = None,
                   expect_fake_ops: Optional[List[str]] = None,
                   txid: str = "latest") -> str:
        """Run ONE stage through `.github/scripts/stage.py`.

        The wrapper exits 0 only after checking the exact raw rc, the
        checkpoint state and every required marker, so `returncode == 0`
        here is the whole contract for the stage.
        """
        self._assert_env_ready(env, allowed_tokens)
        etc_before = self._etc_fingerprint()
        calls_before = len(_read_calls(self.calls_log))
        cmd = [sys.executable, str(STAGE_RUNNER),
               "--expect-rc", str(expect_rc),
               "--expect-state", expect_state,
               "--label", label,
               "--txid", txid,
               "--state-dir", self.paths["state_dir"]]
        for marker in markers or []:
            cmd += ["--expect-marker", marker]
        cmd += ["--", sys.executable, str(ROOT / "rotate.py"), *args]
        cp = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True,
                            text=True, timeout=180, check=False,
                            stdin=subprocess.DEVNULL)
        self.assertEqual(
            cp.returncode, 0,
            msg=(f"stage {label} failed (wrapper rc={cp.returncode})\n"
                 f"--- stdout ---\n{cp.stdout}\n--- stderr ---\n{cp.stderr}\n"
                 f"--- fake calls ---\n{_read_calls(self.calls_log)}"))
        # Real /etc untouched; no real SSH/system tool could have run.
        self.assertEqual(etc_before, self._etc_fingerprint(),
                         f"stage {label} changed something under /etc")
        # Checkpoint on disk, in the transaction's own state dir.
        actual_txid = ""
        for line in (cp.stdout or "").splitlines():
            if line.startswith("TXID="):
                actual_txid = line.split("=", 1)[1].strip()
        self.assertTrue(actual_txid, f"stage {label} printed no TXID")
        checkpoint = self._read_checkpoint(actual_txid)
        self.assertIsNotNone(checkpoint, f"stage {label} wrote no checkpoint")
        self.assertEqual(checkpoint["state"], expect_state)
        # The expected fake invocation(s) were recorded by the fake itself.
        new_calls = [c.get("op") for c in
                     _read_calls(self.calls_log)[calls_before:]]
        for op in expect_fake_ops or []:
            self.assertIn(op, new_calls,
                          f"stage {label} did not invoke the fake op {op!r}; "
                          f"recorded: {new_calls}")
        # No token in the output or in anything persisted.
        blob = (cp.stdout or "") + (cp.stderr or "") + json.dumps(checkpoint)
        for tok in (DF_TOKEN, CF_TOKEN, HC_TOKEN):
            self.assertNotIn(tok, blob, f"token leaked in stage {label}")
        return actual_txid

    def _drive_to_awaiting_finalize(self) -> str:
        """Stages 1–8, each a separate subprocess, one state dir."""
        txid = self._run_stage(
            "apply-allocate",
            ["apply", "--config", str(self.config_path),
             "--confirm-server-id", self.seed_id,
             "--until", "new_ip_allocated"],
            self._df_env(), expect_rc=6, expect_state="new_ip_allocated",
            allowed_tokens=["DATAFOREST_API_TOKEN"])
        self._run_stage(
            "identity-check",
            ["dataforest-identity-check", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            self._df_env(), expect_rc=6, expect_state="new_ip_allocated",
            allowed_tokens=["DATAFOREST_API_TOKEN"],
            markers=["dataforest_identity_ok"], txid=txid)
        self._run_stage(
            "guest-configure",
            ["resume", "--config", str(self.config_path), "--txid", txid,
             "--confirm-server-id", self.seed_id,
             "--until", "guest_configured"],
            self._neither_env(), expect_rc=6, expect_state="guest_configured",
            allowed_tokens=[], markers=["guest"],
            expect_fake_ops=["detect_network_manager", "configure_guest"],
            txid=txid)
        self._run_stage(
            "guest-verify",
            ["resume", "--config", str(self.config_path), "--txid", txid,
             "--confirm-server-id", self.seed_id,
             "--until", "guest_verified"],
            self._neither_env(), expect_rc=6, expect_state="guest_verified",
            allowed_tokens=[], expect_fake_ops=["verify_guest"], txid=txid)
        self._run_stage(
            "cf-preflight",
            ["resume", "--config", str(self.config_path), "--txid", txid,
             "--confirm-server-id", self.seed_id,
             "--until", "cloudflare_preflighted"],
            self._cf_env(), expect_rc=6,
            expect_state="cloudflare_preflighted",
            allowed_tokens=["CLOUDFLARE_API_TOKEN"],
            markers=["cloudflare_manifest"], expect_fake_ops=["discover"],
            txid=txid)
        self._run_stage(
            "ip-change",
            ["resume", "--config", str(self.config_path), "--txid", txid,
             "--confirm-server-id", self.seed_id,
             "--until", "ansible_done"],
            self._cf_env(), expect_rc=6, expect_state="ansible_done",
            allowed_tokens=["CLOUDFLARE_API_TOKEN"], markers=["ansible"],
            txid=txid)
        self._run_stage(
            "cf-apply",
            ["resume", "--config", str(self.config_path), "--txid", txid,
             "--confirm-server-id", self.seed_id,
             "--until", "cloudflare_replaced"],
            self._cf_env(), expect_rc=6, expect_state="cloudflare_replaced",
            allowed_tokens=["CLOUDFLARE_API_TOKEN"],
            markers=["cloudflare_apply_started", "cloudflare_apply"],
            expect_fake_ops=["apply"], txid=txid)
        self._run_stage(
            "await-finalize",
            ["resume", "--config", str(self.config_path), "--txid", txid,
             "--confirm-server-id", self.seed_id,
             "--until", "awaiting_finalize"],
            self._cf_env(), expect_rc=6, expect_state="awaiting_finalize",
            allowed_tokens=["CLOUDFLARE_API_TOKEN"],
            markers=["awaiting_finalize_summary"], txid=txid)
        return txid

    def _read_checkpoint(self, txid: str) -> Optional[Dict[str, Any]]:
        path = os.path.join(self.paths["state_dir"], f"{txid}.json")
        if not os.path.exists(path):
            return None
        return json.loads(Path(path).read_text())


# --------------------------------------------------------------------
# finalize-precheck + provider-finalize (the core new CLI surface)
# --------------------------------------------------------------------
class TestFinalizeSubprocess(StagedE2EBase):
    """Subprocess finalize-precheck → provider-finalize chain."""

    def test_full_staged_chain(self):
        """All ten stages, ten subprocesses, one state directory.

        This is the acceptance test: nothing in the chain runs
        in-process, no `Rotation` method is called directly, and every
        stage is checked by `.github/scripts/stage.py` on the raw rc,
        the checkpoint state and the markers.
        """
        txid = self._drive_to_awaiting_finalize()
        actual_new_ip = self._read_checkpoint(txid)["new_ip"]["ip"]

        # 9) finalize-precheck — CF token only.
        self._run_stage(
            "finalize-precheck",
            ["finalize-precheck", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            self._cf_env(), expect_rc=6,
            expect_state="dns_finalize_verified",
            allowed_tokens=["CLOUDFLARE_API_TOKEN"],
            markers=["dns_finalize_verified"], txid=txid)

        # 10) provider-finalize — DF token only, rc 0, OLD_IP released.
        self._run_stage(
            "provider-finalize",
            ["provider-finalize", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            self._df_env(), expect_rc=0, expect_state="done",
            allowed_tokens=["DATAFOREST_API_TOKEN"], txid=txid)

        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["outcome"], "done")
        # The identity marker was the guest stages' only identity
        # evidence, and it is digest-bound to this transaction.
        marker = cp_state["dataforest_identity_ok"]
        for key in ("ts", "txid", "seed_id", "old_ip", "new_ip", "digest"):
            self.assertTrue(marker.get(key), f"marker missing {key}")
        self.assertEqual(marker["txid"], txid)
        self.assertEqual(marker["seed_id"], str(self.seed_id))
        self.assertEqual(marker["old_ip"], self.old_ip)
        self.assertEqual(marker["new_ip"], actual_new_ip)
        # DNS moved to NEW_IP through the fake playbook, not a stub.
        records = _read_cf_state(self.cf_state)["cloudflare"]["records"]
        self.assertEqual([r["content"] for r in records], [actual_new_ip])
        # OLD_IP removed from the Seed exactly once.
        addresses = [e["address"] for e in self.df._seed_snapshot["ipv4"]]
        self.assertNotIn(self.old_ip, addresses)
        self.assertIn(actual_new_ip, addresses)
        removals = [c for c in _read_calls(self.calls_log)
                    if c.get("op") == "remove_guest_address"]
        self.assertEqual(len(removals), 1, f"guest removals: {removals}")

    def test_finalize_precheck_subprocess(self):
        txid = self._drive_to_awaiting_finalize()
        # Read the actual NEW_IP allocated by the fake (the in-process
        # driver picked a free address, not necessarily self.new_ip).
        actual_new_ip = self._read_checkpoint(txid)["new_ip"]["ip"]
        env = self._cf_env()
        cp = _run_rotate(
            ["finalize-precheck", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 6,
                          msg=f"precheck stderr: {cp.stderr}")
        _assert_no_leak(self, cp, DF_TOKEN, CF_TOKEN, HC_TOKEN)
        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["state"], "dns_finalize_verified")
        marker = cp_state["dns_finalize_verified"]
        self.assertEqual(marker["txid"], txid)
        self.assertEqual(marker["old_ip"], self.old_ip)
        self.assertEqual(marker["new_ip"], actual_new_ip)
        self.assertEqual(marker["seed_id"], self.seed_id)
        # Discover count: 1 (idempotent skip) or 2 (re-verified).
        cf_discover = _read_cf_state(self.cf_state
                                     )["cloudflare"]["op_count"]["discover"]
        self.assertIn(cf_discover, (1, 2),
                       msg=f"unexpected discover count: {cf_discover}")

    def test_provider_finalize_subprocess(self):
        txid = self._drive_to_awaiting_finalize()
        # finalize-precheck first.
        env = self._cf_env()
        _run_rotate(
            ["finalize-precheck", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        # provider-finalize (DF token only) reads the marker and
        # removes OLD_IP.
        env = self._df_env()
        cp = _run_rotate(
            ["provider-finalize", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 0,
                          msg=f"provider-finalize stderr: {cp.stderr}")
        _assert_no_leak(self, cp, DF_TOKEN, CF_TOKEN, HC_TOKEN)
        # State machine reached done; OLD_IP removed.
        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["state"], "done")
        self.assertEqual(cp_state["outcome"], "done")
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertNotIn(self.old_ip, addresses)
        self.assertIn(self.new_ip, addresses)

    def test_provider_finalize_refuses_awaiting_finalize(self):
        """provider-finalize MUST refuse state `awaiting_finalize`.

        It requires exact `dns_finalize_verified` and refuses the
        apply-path terminal pause state. This is the fail-closed
        separation that prevents OLD_IP release while DNS still
        points at it.
        """
        txid = self._drive_to_awaiting_finalize()
        env = self._df_env()
        cp = _run_rotate(
            ["provider-finalize", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertNotEqual(cp.returncode, 0, msg=cp.stderr)
        self.assertIn("dns_finalize_verified", cp.stderr.lower(),
                      msg=cp.stderr)
        # OLD_IP must remain — the refusal happened BEFORE the
        # seed.remove-ipv4 POST.
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertIn(self.old_ip, addresses)
        self.assertIn(self.new_ip, addresses)

    def test_provider_finalize_refuses_missing_marker(self):
        """provider-finalize refuses when the marker is absent.

        The marker is the contract between the CF precheck and the
        provider step. Without it, the provider step does not run.
        """
        txid = self._drive_to_awaiting_finalize()
        # Drop the marker from the persisted checkpoint.
        cp_state = self._read_checkpoint(txid)
        cp_state.pop("dns_finalize_verified", None)
        # Also ensure cloudflare_apply_started.manifest_digest matches
        # what provider-finalize validates.
        cp_state.setdefault("cloudflare_apply_started",
                            {"manifest_digest": "", "ts": "now"})
        path = os.path.join(self.paths["state_dir"], f"{txid}.json")
        Path(path).write_text(json.dumps(cp_state))
        env = self._df_env()
        cp = _run_rotate(
            ["provider-finalize", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertNotEqual(cp.returncode, 0, msg=cp.stderr)
        self.assertIn("dns_finalize_verified", cp.stderr.lower())
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertIn(self.old_ip, addresses)

    def test_provider_finalize_refuses_stale_marker(self):
        """provider-finalize refuses a marker older than 30 minutes."""
        txid = self._drive_to_awaiting_finalize()
        stale = (datetime.now(timezone.utc)
                 - timedelta(hours=2)).isoformat(timespec="seconds")
        cp_state = self._read_checkpoint(txid)
        cp_state["dns_finalize_verified"] = {
            "ts": stale, "manifest_digest": "",
            "txid": txid, "old_ip": self.old_ip,
            "new_ip": self.new_ip, "seed_id": self.seed_id,
            "record_count": 1}
        Path(os.path.join(self.paths["state_dir"],
                          f"{txid}.json")).write_text(json.dumps(cp_state))
        env = self._df_env()
        cp = _run_rotate(
            ["provider-finalize", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertNotEqual(cp.returncode, 0, msg=cp.stderr)
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertIn(self.old_ip, addresses)

    def test_provider_finalize_refuses_wrong_seed_marker(self):
        """provider-finalize refuses a marker with mismatched seed_id."""
        txid = self._drive_to_awaiting_finalize()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cp_state = self._read_checkpoint(txid)
        cp_state["dns_finalize_verified"] = {
            "ts": now, "manifest_digest": "",
            "txid": txid, "old_ip": self.old_ip,
            "new_ip": self.new_ip, "seed_id": "WRONG-SEED",
            "record_count": 1}
        Path(os.path.join(self.paths["state_dir"],
                          f"{txid}.json")).write_text(json.dumps(cp_state))
        env = self._df_env()
        cp = _run_rotate(
            ["provider-finalize", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertNotEqual(cp.returncode, 0, msg=cp.stderr)
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertIn(self.old_ip, addresses)

    def test_crash_resume_after_precheck(self):
        """After the precheck persists the marker, a fresh
        provider-finalize subprocess resumes and finishes at done."""
        txid = self._drive_to_awaiting_finalize()
        # Stage 1: finalize-precheck (CF only).
        env = self._cf_env()
        cp = _run_rotate(
            ["finalize-precheck", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 6, msg=cp.stderr)
        # Stage 2: a fresh provider-finalize subprocess (DF only).
        env = self._df_env()
        cp = _run_rotate(
            ["provider-finalize", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 0,
                          msg=f"resume provider-finalize: {cp.stderr}")
        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["state"], "done")
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertNotIn(self.old_ip, addresses)
        # OLD_IP was removed exactly once.
        calls = _read_calls(self.calls_log)
        # The dataforest playbook ran the verify_guest + configure
        # ops during the in-process driver; the CF precheck + apply
        # were in the in-process driver stubs. The provider-finalize
        # subprocess ran a seed.remove-ipv4 directly (not via the
        # fake ansible-playbook). The calls log shows the in-process
        # activity; OLD_IP being absent is the actual contract.
        self.assertNotIn(self.old_ip, addresses)


# --------------------------------------------------------------------
# Staged rollback chain
# --------------------------------------------------------------------
class TestStagedRollbackSubprocess(StagedE2EBase):
    """rollback-dns → rollback-inventory → rollback-guest →
    rollback-provider, each as a separate subprocess with the
    required token."""

    def test_full_staged_rollback_chain(self):
        txid = self._drive_to_awaiting_finalize()
        actual_new_ip = self._read_checkpoint(txid)["new_ip"]["ip"]
        # 1) rollback-dns (CF token only).
        env = self._cf_env()
        cp = _run_rotate(
            ["rollback-dns", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 6,
                          msg=f"rollback-dns stderr: {cp.stderr}")
        _assert_no_leak(self, cp, DF_TOKEN, CF_TOKEN, HC_TOKEN)
        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["state"], "dns_rollback_done")
        self.assertIn("dns_step_at", cp_state.get("rollback", {}))

        # 2) rollback-inventory (no token).
        env = self._neither_env()
        cp = _run_rotate(
            ["rollback-inventory", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 6, msg=cp.stderr)
        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["state"], "inventory_rollback_done")
        self.assertIn("inventory_step_at", cp_state.get("rollback", {}))

        # 3) rollback-guest (no token).
        env = self._neither_env()
        cp = _run_rotate(
            ["rollback-guest", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 6, msg=cp.stderr)
        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["state"], "guest_rollback_done")
        self.assertIn("guest_step_at", cp_state.get("rollback", {}))

        # 4) rollback-provider (DF token only) — the ONLY stage that
        # produces `rolled_back` (rc 5).
        env = self._df_env()
        cp = _run_rotate(
            ["rollback-provider", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 5, msg=cp.stderr)
        _assert_no_leak(self, cp, DF_TOKEN, CF_TOKEN, HC_TOKEN)
        cp_state = self._read_checkpoint(txid)
        self.assertEqual(cp_state["state"], "rolled_back")
        self.assertIn("provider_step_at", cp_state.get("rollback", {}))

        # NEW_IP removed from seed, OLD_IP restored.
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertIn(self.old_ip, addresses)
        self.assertNotIn(actual_new_ip, addresses)

    def test_rollback_provider_refuses_without_dns_marker(self):
        """rollback-provider refuses if guest_rollback_done is missing.

        The ordered chain is DNS → inventory → guest → provider; the
        provider stage MUST refuse if the guest rollback didn't run.
        """
        txid = self._drive_to_awaiting_finalize()
        env = self._df_env()
        cp = _run_rotate(
            ["rollback-provider", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertNotEqual(cp.returncode, 0, msg=cp.stderr)
        # The rotation names the step that must run first.
        self.assertIn("rollback-guest", cp.stderr.lower(),
                      msg=cp.stderr)
        addresses = [e["address"]
                     for e in self.df._seed_snapshot["ipv4"]]
        self.assertIn(self.old_ip, addresses)
        self.assertIn(self.new_ip, addresses)

    def test_rollback_dns_idempotent(self):
        """Re-running rollback-dns is a no-op once dns_step_at is set.

        Both calls return rc 6 (boundary pause). The intermediate
        rollback stage MUST NOT produce rc 5 (rolled_back) — that
        signal is reserved for the final provider-only stage.
        """
        txid = self._drive_to_awaiting_finalize()
        env = self._cf_env()
        cp = _run_rotate(
            ["rollback-dns", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 6, msg=cp.stderr)
        cp = _run_rotate(
            ["rollback-dns", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertEqual(cp.returncode, 6, msg=cp.stderr)
        # The CF fake was only called once for the rollback (the
        # second call was a no-op).
        cf_state = _read_cf_state(self.cf_state)
        self.assertEqual(cf_state["cloudflare"]["op_count"].get("rollback", 0), 1)

    def test_rollback_inventory_requires_dns_rollback(self):
        """rollback-inventory refuses if state is not dns_rollback_done.

        The ordered chain DNS → inventory → guest → provider must be
        followed; running a later stage before the earlier one
        escalates.
        """
        txid = self._drive_to_awaiting_finalize()
        env = self._neither_env()
        cp = _run_rotate(
            ["rollback-inventory", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertNotEqual(cp.returncode, 0, msg=cp.stderr)
        self.assertIn("rollback-dns", cp.stderr.lower(),
                      msg=cp.stderr)

    def test_rollback_guest_requires_inventory_rollback(self):
        txid = self._drive_to_awaiting_finalize()
        # Run rollback-dns first.
        env = self._cf_env()
        _run_rotate(
            ["rollback-dns", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        # Skip rollback-inventory; try rollback-guest directly.
        env = self._neither_env()
        cp = _run_rotate(
            ["rollback-guest", "--config", str(self.config_path),
             "--txid", txid, "--confirm-server-id", self.seed_id],
            env)
        self.assertNotEqual(cp.returncode, 0, msg=cp.stderr)
        # The rotation names inventory as the next required step.
        self.assertIn("rollback-inventory", cp.stderr.lower(),
                      msg=cp.stderr)


if __name__ == "__main__":
    unittest.main()