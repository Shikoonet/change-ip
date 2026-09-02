#!/usr/bin/env python3
"""Tests for `.github/scripts/stage.py`.

The stage runner is the contract that maps subprocess exit codes to
GitHub Actions step outcomes. Its job is to NEVER silently accept a
loose exit code, and to ALWAYS verify the persisted checkpoint matches
the expected boundary.

Coverage:
  * expected_rc + expected_state → runner exits 0 (success)
  * expected_rc + wrong state   → runner exits 2
  * unexpected_rc              → runner propagates rc
  * missing checkpoint          → runner exits 3 (when state was required)
  * no-state-required terminal → runner exits 0 on bare done (rc=0)
  * token redaction             → captured stdout/stderr carry no token
  * negative tests: stage never treats 4 (escalated) as success
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent
STAGE_PY = ROOT / ".github" / "scripts" / "stage.py"

CF_TOKEN = "stage-runner-cf-token-staged-0987654321fedcba"
DF_TOKEN = "stage-runner-df-token-staged-0123456789abcdef"


def _run_stage(*args, env_extra=None, stdin=None):
    """Invoke the stage runner. Returns CompletedProcess."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(STAGE_PY), *args],
        cwd=str(ROOT), env=env,
        capture_output=True, text=True, timeout=60,
        check=False, input=stdin,
    )


def _write_checkpoint(tmpdir: str, txid: str, state: str,
                     extra: Dict = None) -> None:
    state_dir = os.path.join(tmpdir, "state")
    os.makedirs(state_dir, exist_ok=True)
    cp = {"txid": txid, "state": state, "version": 1,
          "server": {"id": "x"}, "old_ip": {"ip": "1.1.1.1"},
          "new_ip": {"ip": "2.2.2.2"}, "alias": "x"}
    if extra:
        cp.update(extra)
    with open(os.path.join(state_dir, f"{txid}.json"), "w") as fh:
        json.dump(cp, fh)


class TestStageRunner(unittest.TestCase):
    """Prove each stage runner rule."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="stage-runner-")
        # Symlink state into cwd for the runner. We chdir to ROOT to
        # import providers, so point ROOT/state at our checkpoint.
        self.root_state = ROOT / "state"
        self._remove_root_state_on_cleanup = False
        if self.root_state.exists():
            self._root_state_was_present = True
        else:
            self._root_state_was_present = False
            self.root_state.mkdir(parents=True, exist_ok=True)
            self._remove_root_state_on_cleanup = True
        # Wipe any leftover checkpoints so the runner sees a clean slate.
        for f in self.root_state.glob("*.json"):
            f.unlink()

    def tearDown(self):
        for f in self.root_state.glob("*.json"):
            f.unlink()
        if self._remove_root_state_on_cleanup:
            self.root_state.rmdir()

    def _stage_script(self, rc: int, state: str = "planned",
                     stderr_text: str = "") -> str:
        """Write a tiny Python script that mimics a rotate.py call.

        The script writes a checkpoint with the requested state then
        exits with the requested rc.
        """
        script = (
            f"import json, os\n"
            f"cp = {{'txid': 'T', 'state': '{state}', "
            f"'server': {{'id': 'x'}}, "
            f"'old_ip': {{'ip': '1.1.1.1'}}, "
            f"'new_ip': {{'ip': '2.2.2.2'}}, "
            f"'alias': 'x', 'version': 1}}\n"
            f"os.makedirs('state', exist_ok=True)\n"
            f"with open('state/T.json', 'w') as f: json.dump(cp, f)\n"
            f"import sys\n"
            f"sys.stderr.write({stderr_text!r})\n"
            f"sys.exit({rc})\n"
        )
        script_path = os.path.join(self.tmp, "fake_rotate.py")
        with open(script_path, "w") as fh:
            fh.write(script)
        return script_path

    # -- 1. expected_rc + expected_state → success --------------------------
    def test_expected_rc_and_state_succeed(self):
        self._stage_script(rc=6, state="new_ip_allocated")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 0,
                         msg=f"stderr: {cp.stderr}\nstdout: {cp.stdout}")

    def test_expected_rc_no_state_required(self):
        # rc=0 (done) with no --expect-state: still allowed.
        self._stage_script(rc=0, state="done")
        cp = _run_stage(
            "--expect-rc", "0",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 0, msg=cp.stderr)

    def test_rolled_back_rc5_succeeds(self):
        self._stage_script(rc=5, state="rolled_back")
        cp = _run_stage(
            "--expect-rc", "5",
            "--expect-state", "rolled_back",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 0, msg=cp.stderr)

    def test_rollback_incomplete_rc7_succeeds(self):
        self._stage_script(rc=7, state="rollback_incomplete")
        cp = _run_stage(
            "--expect-rc", "7",
            "--expect-state", "rollback_incomplete",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 0, msg=cp.stderr)

    # -- 2. expected_rc + wrong state → runner exits 2 ---------------------
    def test_wrong_state_fails(self):
        self._stage_script(rc=6, state="awaiting_finalize")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",  # wrong
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 2, msg=cp.stderr)
        self.assertIn("awaiting_finalize", cp.stderr)
        self.assertIn("new_ip_allocated", cp.stderr)

    # -- 3. unexpected_rc → runner propagates rc ----------------------------
    def test_escalated_rc4_propagates(self):
        self._stage_script(rc=4, state="escalated")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        # rc=4 is not in EXPECTED_EXIT_CODES, so it must be preserved.
        self.assertEqual(cp.returncode, 4, msg=cp.stderr)

    def test_usage_error_rc1_propagates(self):
        self._stage_script(rc=1, state="planned")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 1, msg=cp.stderr)

    def test_provider_error_rc3_propagates(self):
        self._stage_script(rc=3, state="planned")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 3, msg=cp.stderr)

    def test_right_rc_but_also_propagates_when_unexpected(self):
        # rc=6 is expected, but the script ran with rc=0 (a clean
        # exit). The runner MUST refuse: rc=0 is a valid stage exit
        # (for `done`) but not THIS stage's expected boundary. The
        # runner returns rc=8 (wrong boundary) to mark this.
        self._stage_script(rc=0, state="new_ip_allocated")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        self.assertEqual(cp.returncode, 8,
                         msg=f"expected 8 (wrong boundary); got "
                             f"{cp.returncode}: {cp.stderr}")

    # -- 4. missing/corrupt checkpoint → runner exits 3 -----------------
    def test_missing_checkpoint_fails(self):
        # No checkpoint on disk. rc=6 expected with --expect-state.
        # The fake script below writes nothing.
        script_path = os.path.join(self.tmp, "no_write.py")
        with open(script_path, "w") as fh:
            fh.write("import sys; sys.exit(6)\n")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, script_path,
        )
        self.assertEqual(cp.returncode, 3, msg=cp.stderr)

    def test_corrupt_checkpoint_fails(self):
        # Pre-write a corrupt JSON; the fake script below writes
        # nothing on success so the corrupt file survives the run.
        with open(self.root_state / "T.json", "w") as fh:
            fh.write("not json {{{")
        script_path = os.path.join(self.tmp, "no_write.py")
        with open(script_path, "w") as fh:
            fh.write("import sys; sys.exit(6)\n")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, script_path,
        )
        # Corrupt → _read_state returns None → treated as missing.
        self.assertEqual(cp.returncode, 3, msg=cp.stderr)

    # -- 5. token values never appear in output ---------------------------
    def test_token_redacted_in_captured_output(self):
        script_path = os.path.join(self.tmp, "fake_with_token.py")
        with open(script_path, "w") as fh:
            fh.write(
                f"import sys\n"
                f"sys.stderr.write('boom: {CF_TOKEN} {DF_TOKEN}\\n')\n"
                f"import json, os\n"
                f"cp = {{'txid': 'T', 'state': 'new_ip_allocated', "
                f"'server': {{'id': 'x'}}, "
                f"'old_ip': {{'ip': '1.1.1.1'}}, "
                f"'new_ip': {{'ip': '2.2.2.2'}}, "
                f"'alias': 'x', 'version': 1}}\n"
                f"os.makedirs('state', exist_ok=True)\n"
                f"with open('state/T.json', 'w') as f: json.dump(cp, f)\n"
                f"sys.exit(6)\n"
            )
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, script_path,
            env_extra={CF: CF_TOKEN} if False else {"CLOUDFLARE_API_TOKEN": CF_TOKEN,
                                                "DATAFOREST_API_TOKEN": DF_TOKEN},
        )
        # The runner returns 0; the captured output (re-emitted to
        # stderr on failure) must NOT contain the tokens.
        blob = cp.stdout + cp.stderr
        self.assertNotIn(CF_TOKEN, blob)
        self.assertNotIn(DF_TOKEN, blob)

    # -- 6. --expect-marker requires it to be present -----------------
    def test_expected_marker_must_be_present(self):
        self._stage_script(rc=6, state="new_ip_allocated")
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--expect-marker", "provider_allocation_started",
            "--txid", "T",
            "--", sys.executable, os.path.join(self.tmp, "fake_rotate.py"),
        )
        # Marker missing → runner exits 4.
        self.assertEqual(cp.returncode, 4, msg=cp.stderr)

    def test_expected_marker_present_succeeds(self):
        # Write a richer checkpoint with the marker present.
        script_path = os.path.join(self.tmp, "fake_with_marker.py")
        with open(script_path, "w") as fh:
            fh.write(
                "import json, os, uuid\n"
                "cp = {'txid': 'T', 'state': 'new_ip_allocated', "
                "'server': {'id': 'x'}, 'old_ip': {'ip': '1.1.1.1'}, "
                "'new_ip': {'ip': '2.2.2.2'}, 'alias': 'x', 'version': 1, "
                "'provider_allocation_started': {'ts': 'now'}}\n"
                "os.makedirs('state', exist_ok=True)\n"
                "with open('state/T.json', 'w') as f: json.dump(cp, f)\n"
                "import sys; sys.exit(6)\n"
            )
        cp = _run_stage(
            "--expect-rc", "6",
            "--expect-state", "new_ip_allocated",
            "--expect-marker", "provider_allocation_started",
            "--txid", "T",
            "--", sys.executable, script_path,
        )
        self.assertEqual(cp.returncode, 0, msg=cp.stderr)

    # -- 7. workflow failure: NEVER accept rc=4 (escalated) -------
    def test_escalated_never_treated_as_success(self):
        """The single failure that matters most: rc=4 (escalated) MUST
        propagate to GitHub Actions as a failure. A loose 'one of' in
        the runner would mark the step green and hide the escalation
        — exactly the failure mode the spec forbids."""
        script_path = os.path.join(self.tmp, "fake_escalate.py")
        with open(script_path, "w") as fh:
            fh.write(
                "import json, os\n"
                "cp = {'txid': 'T', 'state': 'escalated', "
                "'server': {'id': 'x'}, 'old_ip': {'ip': '1.1.1.1'}, "
                "'new_ip': {'ip': '2.2.2.2'}, 'alias': 'x', 'version': 1}\n"
                "os.makedirs('state', exist_ok=True)\n"
                "with open('state/T.json', 'w') as f: json.dump(cp, f)\n"
                "import sys; sys.exit(4)\n"
            )
        # Even if we accidentally passed --expect-rc=4 (which the
        # runner rejects via choices={0,5,6,7}), the test makes it
        # explicit: rc=4 is NEVER a boundary.
        cp = _run_stage(
            "--expect-rc", "6",  # we expect paused; got escalated
            "--expect-state", "new_ip_allocated",
            "--txid", "T",
            "--", sys.executable, script_path,
        )
        self.assertNotEqual(cp.returncode, 0,
                            msg=f"escalated treated as success: rc={cp.returncode}")


if __name__ == "__main__":
    unittest.main()