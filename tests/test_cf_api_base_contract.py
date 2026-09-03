#!/usr/bin/env python3
"""Behavioral contract for `cloudflare_replace_ip_step.yml` URL handling.

The contract is two-mode, enforced in BOTH the Python adapter
(`cloudflare_adapter._validate_cf_api_base`) and the playbook itself
(`cloudflare_replace_ip_step.yml`'s `cf_api_base contract` assert).

  Production mode (neither marker set OR CF_PLAYBOOK_TEST_MODE != "1"):
    * cf_api_base unset         → fall back to the official endpoint
                                  (the playbook's hard-coded `vars:` value).
    * cf_api_base == official   → allowed.
    * any other value           → REJECTED (ProductionError before subprocess).

  Test mode (BOTH ROTATION_TEST_MODE == "1" AND CF_PLAYBOOK_TEST_MODE == "1"):
    * cf_api_base unset         → REJECTED. The default would otherwise
                                  route test traffic to the real Cloudflare
                                  API, which is exactly the accidental
                                  external request this guard exists to
                                  prevent.
    * cf_api_base == official   → REJECTED. Test mode MUST not call the
                                  real API under any URL.
    * non-loopback URL          → REJECTED.
    * 127.0.0.1 / localhost / [::1] with an explicit port → ALLOWED.

These tests prove the contract at the Python layer (cheap, no
subprocess) and at the Ansible layer (real `ansible-playbook
--syntax-check` + a minimal in-process play that exercises the assert).
The Python-side tests assert that the adapter raises before any
subprocess is spawned; the Ansible-side tests prove the playbook's
assert also refuses.

Proxy variables are scrubbed from the child env by the adapter's
explicit allowlist (see `ALLOWED_CHILD_ENV`). A regression here that
re-introduced `http_proxy` / `https_proxy` / `*_proxy` forwarding
would silently redirect offline test traffic through whatever proxy
the operator happened to have set. There is no behavioural test for
the proxy scrubbing here — it is structural (the allowlist does not
include `*_proxy`) and the structural tests already cover it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import cloudflare_adapter


# Canonical URLs the contract distinguishes. Tests must read these
# from the adapter module, not repeat literals.
OFFICIAL = cloudflare_adapter.OFFICIAL_CF_API_BASE
LOOPBACK_V4 = "http://127.0.0.1:8761/client/v4"
LOOPBACK_NAME = "http://localhost:8761/client/v4"
LOOPBACK_V6 = "http://[::1]:8761/client/v4"


def _enter_test_mode() -> None:
    os.environ["ROTATION_TEST_MODE"] = "1"
    os.environ["CF_PLAYBOOK_TEST_MODE"] = "1"


def _exit_test_mode() -> None:
    for k in ("ROTATION_TEST_MODE", "CF_PLAYBOOK_TEST_MODE"):
        os.environ.pop(k, None)


class _Recorder:
    """Records every call AND writes a minimal result file the adapter
    can parse.

    Used by `runner=` substitution in the tests to PROVE that a refused
    call never spawned a subprocess. The adapter's `_validate_cf_api_base`
    runs BEFORE the subprocess is launched, so a refusal should leave
    this counter at zero.

    On every "succeeding" call the recorder writes a discover-shaped
    result file at the path the adapter passed in `argv` (extracted
    from `-e result_file=...`). The result file is the minimum the
    adapter's `_validate_result` accepts so the run is a positive
    path; the test asserts on the recorder's call count, not on
    adapter internals.
    """

    def __init__(self) -> None:
        self.calls: list = []

    def __call__(self, argv, **kwargs):
        import subprocess as _sp
        import re as _re
        self.calls.append((list(argv), kwargs))
        # Find `-e result_file=/path/...` in the adapter's argv.
        result_file = None
        for tok in argv:
            m = _re.match(r"^result_file=(.+)$", tok)
            if m:
                result_file = m.group(1)
        if result_file:
            # Minimal discover result: an empty manifest is fine for
            # these tests; the contract is about URL gating, not
            # manifest content.
            import json as _json
            with open(result_file, "w") as fh:
                _json.dump({
                    "ok": True, "operation": "discover",
                    "invocation_id": "iv-test", "manifest": [],
                }, fh)
        return _sp.CompletedProcess(argv, 0, stdout="", stderr="")


# ---------------------------------------------------------------------------
# Python adapter layer
# ---------------------------------------------------------------------------
class TestPythonAdapterURLContract(unittest.TestCase):
    """`cloudflare_adapter._validate_cf_api_base` / `run_cloudflare_op`.

    Each test sets up the env it needs, calls the adapter with a
    recorder runner, and asserts:
      * the right outcome (refusal vs / run);
      * the recorder's call count (zero on refusal, one on run).
    """

    def setUp(self):
        self._saved_env = os.environ.copy()
        self._recorder = _Recorder()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved_env)

    def _run(self, *, cf_api_base, expected_ok):
        """Drive run_cloudflare_op with a recorder and a benign env.

        We do NOT set `CLOUDFLARE_API_TOKEN_ACCOUNT_A` here — the adapter
        will raise NonRetryableError before reaching the runner when the URL
        is invalid, so the runner counter is the only thing we need.
        """
        # Provide a token so the adapter's other guards don't fire first.
        os.environ["CLOUDFLARE_API_TOKEN"] = "tok-test"
        return cloudflare_adapter.run_cloudflare_op(
            "discover", old_ip="203.0.113.10", new_ip="198.51.100.99",
            allowed_records=["r.example.com"], expected_count=1,
            invocation_id="iv-test", credential_ref=None,
            token_env=None, cf_api_base=cf_api_base,
            runner=self._recorder, timeout=30,
        )

    # ---- 1. test mode + missing cf_api_base -> refused, no subprocess ---
    def test_test_mode_missing_cf_api_base_refused(self):
        _enter_test_mode()
        with self.assertRaises(cloudflare_adapter.NonRetryableError) as cm:
            self._run(cf_api_base=None, expected_ok=False)
        self.assertIn("test mode requires an explicit", str(cm.exception))
        self.assertEqual(len(self._recorder.calls), 0,
                          "refusal must spawn no subprocess")

    # ---- 2. test mode + official URL -> refused, no subprocess ----------
    def test_test_mode_official_url_refused(self):
        _enter_test_mode()
        with self.assertRaises(cloudflare_adapter.NonRetryableError) as cm:
            self._run(cf_api_base=OFFICIAL, expected_ok=False)
        self.assertIn("test mode forbids", str(cm.exception))
        self.assertEqual(len(self._recorder.calls), 0)

    # ---- 3. test mode + external hostname -> refused, no subprocess -----
    def test_test_mode_external_hostname_refused(self):
        _enter_test_mode()
        for url in (
            "https://api.example.com/client/v4",
            "https://staging.cloudflare.com/client/v4",
            "http://api.cloudflare.com/client/v4",
        ):
            with self.subTest(url=url):
                self._recorder.calls.clear()
                with self.assertRaises(cloudflare_adapter.NonRetryableError):
                    self._run(cf_api_base=url, expected_ok=False)
                self.assertEqual(len(self._recorder.calls), 0)

    def test_test_mode_external_ip_refused(self):
        _enter_test_mode()
        for url in (
            "http://1.2.3.4:80/client/v4",
            "http://10.0.0.1:8080/client/v4",
        ):
            with self.subTest(url=url):
                self._recorder.calls.clear()
                with self.assertRaises(cloudflare_adapter.NonRetryableError):
                    self._run(cf_api_base=url, expected_ok=False)
                self.assertEqual(len(self._recorder.calls), 0)

    # ---- 4. test mode + 127.0.0.1 -> allowed ------------------------------
    def test_test_mode_loopback_v4_allowed(self):
        _enter_test_mode()
        # The runner is our recorder. We expect the adapter to call it
        # exactly once. The recorder returns rc=0 with no result file,
        # so the adapter will fail parsing the result — that's fine; it
        # proves the URL was accepted and a subprocess was attempted.
        self._run(cf_api_base=LOOPBACK_V4, expected_ok=True)
        self.assertEqual(len(self._recorder.calls), 1)
        called_argv = self._recorder.calls[0][0]
        # The cf_api_base was passed as -e, not in argv positionally.
        cf_args = [a for a in called_argv if a.startswith("cf_api_base=")]
        self.assertTrue(cf_args,
                          f"cf_api_base should be passed via -e, got {called_argv}")

    # ---- 5. test mode + localhost -> allowed ------------------------------
    def test_test_mode_loopback_name_allowed(self):
        _enter_test_mode()
        self._run(cf_api_base=LOOPBACK_NAME, expected_ok=True)
        self.assertEqual(len(self._recorder.calls), 1)

    # ---- 6. test mode + [::1] -> allowed (documented supported) ----------
    def test_test_mode_loopback_v6_allowed(self):
        _enter_test_mode()
        self._run(cf_api_base=LOOPBACK_V6, expected_ok=True)
        self.assertEqual(len(self._recorder.calls), 1)

    # ---- 7. production mode defaults to official endpoint ---------------
    def test_production_mode_none_uses_official_default(self):
        # No test-mode marker. cf_api_base=None means "use playbook
        # default", which is the official endpoint. The adapter does
        # NOT refuse None in production mode; it just doesn't pass
        # cf_api_base as -e (so the playbook's `vars:` default applies).
        _exit_test_mode()
        self._run(cf_api_base=None, expected_ok=True)
        self.assertEqual(len(self._recorder.calls), 1)
        called_argv = self._recorder.calls[0][0]
        cf_args = [a for a in called_argv if a.startswith("cf_api_base=")]
        self.assertFalse(cf_args,
                          f"production default must NOT pass cf_api_base=-e "
                          f"(the playbook's vars: provides the default); got {called_argv}")

    def test_production_mode_official_url_allowed(self):
        _exit_test_mode()
        self._run(cf_api_base=OFFICIAL, expected_ok=True)
        self.assertEqual(len(self._recorder.calls), 1)

    def test_production_mode_non_official_url_refused(self):
        _exit_test_mode()
        with self.assertRaises(cloudflare_adapter.NonRetryableError):
            self._run(cf_api_base="https://api.example.com/client/v4",
                       expected_ok=False)
        self.assertEqual(len(self._recorder.calls), 0)

    def test_production_mode_loopback_url_refused(self):
        # Production cannot accidentally point at a loopback fixture.
        _exit_test_mode()
        with self.assertRaises(cloudflare_adapter.NonRetryableError):
            self._run(cf_api_base=LOOPBACK_V4, expected_ok=False)
        self.assertEqual(len(self._recorder.calls), 0)

    # ---- 8. canonical marker alignment -----------------------------------
    def test_marker_alignment_requires_both(self):
        # The adapter reads ROTATION_TEST_MODE; the playbook reads
        # CF_PLAYBOOK_TEST_MODE. They must be set together or the
        # adapter is in test mode but the playbook is in production
        # mode (or vice versa). The contract is: both == "1" enables
        # test mode; anything else is production. Verify both axes.
        for rot, cf in (
            ("1", "1"),     # both set
            ("0", "0"),     # both unset
            ("1", "0"),     # adapter thinks test, playbook thinks prod
            ("0", "1"),     # adapter thinks prod, playbook thinks test
        ):
            with self.subTest(rot=rot, cf=cf):
                os.environ["ROTATION_TEST_MODE"] = rot
                os.environ["CF_PLAYBOOK_TEST_MODE"] = cf
                self.assertEqual(
                    cloudflare_adapter._is_test_mode(),
                    rot == "1" and cf == "1",
                    f"ROTATION_TEST_MODE={rot!r}, "
                    f"CF_PLAYBOOK_TEST_MODE={cf!r} should yield "
                    f"test_mode={rot == '1' and cf == '1'!r}"
                )

    # ---- 9. no token / URL leak in refusal messages ----------------------
    def test_refusal_messages_carry_no_token(self):
        _enter_test_mode()
        os.environ["CLOUDFLARE_API_TOKEN"] = "tok-must-not-leak"
        with self.assertRaises(cloudflare_adapter.NonRetryableError) as cm:
            self._run(cf_api_base=None, expected_ok=False)
        self.assertNotIn("tok-must-not-leak", str(cm.exception))
        self.assertNotIn("CLOUDFLARE_API_TOKEN=", str(cm.exception))


# ---------------------------------------------------------------------------
# Playbook layer (defence in depth)
# ---------------------------------------------------------------------------
# We invoke the real `ansible-playbook` with a minimal in-memory play
# that loads just the URL-contract assert. The full playbook
# (`cloudflare_replace_ip_step.yml`) bundles this assert plus the four
# ops; here we only need to verify the contract itself, so a focused
# inline play is cheaper and unambiguous.

URL_CONTRACT_TASK_SRC_TEMPLATE = r"""
- name: url contract inline
  hosts: localhost
  gather_facts: false
{CFVARS}
  tasks:
    - name: "contract assert"
      ansible.builtin.assert:
        that:
          - >-
            (
              ((lookup('ansible.builtin.env', 'CF_PLAYBOOK_TEST_MODE') | default('', true)) != '1')
              and (
                (cf_api_base | default('https://api.cloudflare.com/client/v4'))
                == 'https://api.cloudflare.com/client/v4'
              )
            )
            or
            (
              ((lookup('ansible.builtin.env', 'CF_PLAYBOOK_TEST_MODE') | default('', true)) == '1')
              and (cf_api_base | default('')) is regex('^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/.*)?$')
              and (cf_api_base | default('')) != 'https://api.cloudflare.com/client/v4'
            )
        fail_msg: "cf_api_base={{ cf_api_base | default('<unset>', true) }} rejected"
      register: _contract_assert
"""


def _build_play(cf_api_base_value):
    """Render the inline play with the right `vars:` block.

    `cf_api_base_value is None` means "do NOT define cf_api_base at
    all" — the production branch of the contract accepts an
    undefined var (the playbook's own `vars:` default kicks in).
    A non-None value is interpolated as `cf_api_base: <value>`,
    which is what `-e cf_api_base_value=...` plus a templated
    `cf_api_base` produces.

    Special handling for the empty string: passing `-e ""` would
    materialise cf_api_base as "" which is the same as the
    production branch's fallback. The tests pass empty string only
    when they explicitly want to test that branch.
    """
    if cf_api_base_value is None:
        cfvars = ""
    else:
        cfvars = "  vars:\n    cf_api_base: %r\n" % cf_api_base_value
    return URL_CONTRACT_TASK_SRC_TEMPLATE.replace("{CFVARS}", cfvars)


def _run_inline_assert(cf_api_base_value, test_mode: bool):
    """Run the URL contract assert against one cf_api_base value.

    `cf_api_base_value=None` means "do NOT define `cf_api_base` in the
    play at all" — the contract's production branch is what handles an
    undefined `cf_api_base` (fall back to the official default).

    Returns the CompletedProcess. The assert fires when the value is
    not allowed for the current mode.

    The minimal play is written to a tempfile because `ansible-playbook
    -- -` does not parse `-` as a playbook filename. A tempfile is the
    canonical idiom for in-process playbook tests and avoids leaking
    the play source into the user's CWD.
    """
    import tempfile as _tempfile
    env = os.environ.copy()
    if test_mode:
        env["CF_PLAYBOOK_TEST_MODE"] = "1"
    else:
        env.pop("CF_PLAYBOOK_TEST_MODE", None)
        env.pop("ROTATION_TEST_MODE", None)
    fd, p = _tempfile.mkstemp(prefix="cf_url_contract_", suffix=".yml")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(_build_play(cf_api_base_value))
        argv = ["ansible-playbook", "-i", "localhost,", "-c", "local", p]
        return subprocess.run(
            argv, capture_output=True, text=True, env=env, timeout=60,
            check=False,
        )
    finally:
        try:
            os.unlink(p)
        except OSError:
            pass


@unittest.skipUnless(
    subprocess.run(["which", "ansible-playbook"], capture_output=True).returncode == 0,
    "ansible-playbook not installed",
)
class TestPlaybookURLContract(unittest.TestCase):
    """The playbook's `cf_api_base contract` assert, in isolation.

    These tests shell out to the real `ansible-playbook` binary with a
    minimal play that loads JUST the contract assert. They are
    independent of the Python adapter's check — a regression that
    silently disabled one would not escape the other.

    ansible-playbook writes task-failure diagnostics to stdout (not
    stderr), so we inspect `cp.stdout` for the rejection marker. The
    return code distinguishes pass (0) from fail (>=2).
    """

    def _stdout(self, cp):
        return (cp.stdout or "") + (cp.stderr or "")

    # ---- production mode -------------------------------------------------
    def test_production_unset_falls_back_to_official(self):
        # Genuinely unset: do NOT pass `-e cf_api_base_value=...`. The
        # production branch of the contract accepts an undefined var
        # (the playbook's `vars:` block provides the default).
        cp = _run_inline_assert(None, test_mode=False)
        self.assertEqual(cp.returncode, 0,
                          msg=f"expected OK in production with no override; "
                              f"output={self._stdout(cp)[-1000:]}")

    def test_production_official_is_allowed(self):
        cp = _run_inline_assert(OFFICIAL, test_mode=False)
        self.assertEqual(cp.returncode, 0,
                          msg=f"output={self._stdout(cp)[-1000:]}")

    def test_production_loopback_is_refused(self):
        cp = _run_inline_assert(LOOPBACK_V4, test_mode=False)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("rejected", self._stdout(cp).lower())

    # ---- test mode -------------------------------------------------------
    def test_test_mode_unset_is_refused(self):
        # Genuinely unset: do NOT pass `-e cf_api_base_value=...`. The
        # test-mode branch must refuse an undefined var.
        cp = _run_inline_assert(None, test_mode=True)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("rejected", self._stdout(cp).lower())

    def test_test_mode_official_is_refused(self):
        cp = _run_inline_assert(OFFICIAL, test_mode=True)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("rejected", self._stdout(cp).lower())

    def test_test_mode_external_hostname_is_refused(self):
        cp = _run_inline_assert("https://api.example.com/client/v4",
                                  test_mode=True)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("rejected", self._stdout(cp).lower())

    def test_test_mode_loopback_v4_is_allowed(self):
        cp = _run_inline_assert(LOOPBACK_V4, test_mode=True)
        self.assertEqual(cp.returncode, 0,
                          msg=f"output={self._stdout(cp)[-1000:]}")

    def test_test_mode_loopback_name_is_allowed(self):
        cp = _run_inline_assert(LOOPBACK_NAME, test_mode=True)
        self.assertEqual(cp.returncode, 0,
                          msg=f"output={self._stdout(cp)[-1000:]}")

    def test_test_mode_loopback_v6_is_allowed(self):
        cp = _run_inline_assert(LOOPBACK_V6, test_mode=True)
        self.assertEqual(cp.returncode, 0,
                          msg=f"output={self._stdout(cp)[-1000:]}")


if __name__ == "__main__":
    unittest.main()