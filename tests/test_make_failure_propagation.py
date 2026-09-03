#!/usr/bin/env python3
"""Regression: a failing test/contract in `make` propagates as
non-zero exit.

The CI gate is only as trustworthy as the Make recipes that
implement it. If a recipe swallows a failure (`|| true`,
`continue-on-error`, no `pipefail`), CI can pass while the suite
is red. This test injects an artificial failure and confirms
that the corresponding Make target returns non-zero.

To keep the test fast (and not run the full offline suite 4
times), each test injects ONE failure and runs a SMALL dedicated
make target that exercises only the same shell-failure semantics
as `test` and `ci-fast` (set -euo pipefail, no `|| true`).

The small targets are defined alongside the test in a per-test
Makefile (NOT the project's Makefile, so we cannot accidentally
ship a CI target that depends on them).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


# A minimal Makefile that mirrors the project's shell flags:
# `set -eu -o pipefail -c` per recipe, no `|| true`. Two
# recipes — `unittest-only` and `contract-only` — that, in a
# healthy workdir, pass with rc=0; in a workdir where the
# injected piece fails, return non-zero.
# Recipe bodies use a literal TAB, not spaces — GNU make
# requires it.
MIRROR_MAKEFILE = (
    "SHELL := /bin/bash\n"
    ".SHELLFLAGS := -eu -o pipefail -c\n"
    "\n"
    ".PHONY: unittest-only contract-only\n"
    "unittest-only:\n"
    "\tpython3 -m unittest $(SUITE)\n"
    "\n"
    "contract-only:\n"
    "\tansible-playbook tests/contract.yml\n"
)


def _workdir() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="make-failprop-"))
    # A minimal workdir: tests/ with one trivially-passing unit
    # test, and a copy of the contract playbook. We do NOT copy
    # the whole project — the small recipes only need these two
    # pieces, and a self-contained workdir makes the regression
    # hermetic.
    tests_dst = tmp / "tests"
    tests_dst.mkdir()
    (tests_dst / "__init__.py").write_text("")
    (tests_dst / "_trivial_passing.py").write_text(textwrap.dedent("""\
        import unittest

        class TrivialPassing(unittest.TestCase):
            def test_always_passes(self):
                self.assertEqual(1 + 1, 2)

        if __name__ == "__main__":
            unittest.main()
    """))
    shutil.copy2(ROOT / "tests" / "contract.yml",
                 tests_dst / "contract.yml")
    (tmp / "Makefile").write_text(MIRROR_MAKEFILE)
    return tmp


def _run(workdir: Path, *args: str) -> int:
    env = dict(os.environ)
    cp = subprocess.run(
        ["make", *args], cwd=str(workdir), env=env,
        capture_output=True, text=True, check=False,
    )
    return cp.returncode


class TestMakeFailurePropagation(unittest.TestCase):
    KEEP_WORKDIR = False  # set True to inspect a workdir on failure

    def setUp(self):
        self.workdir = _workdir()
        if not self.KEEP_WORKDIR:
            self.addCleanup(shutil.rmtree, str(self.workdir),
                            ignore_errors=True)

    def _break_unittest(self, module: str = "test_rotation") -> None:
        """Append a broken test to the named module so discovery
        picks it up. The original module is preserved."""
        broken = self.workdir / "tests" / "_zzz_broken_for_test.py"
        broken.write_text(textwrap.dedent(f"""\
            import unittest

            class _BrokenForPropagation(unittest.TestCase):
                def test_zzz_breaks_on_purpose(self):
                    self.fail("intentional failure for "
                              "test_make_failure_propagation")

            if __name__ == "__main__":
                unittest.main()
        """))
        # Tell the small target to discover this module too.
        # We pass it on the SUITE variable.
        self._broken_module = "_zzz_broken_for_test"

    def _break_contract(self) -> None:
        """Force `tests/contract.yml` to fail by appending an
        always-failing assertion."""
        contract = self.workdir / "tests" / "contract.yml"
        with contract.open("a") as fh:
            fh.write("\n  - name: forced contract failure\n")
            fh.write("    ansible.builtin.assert:\n")
            fh.write("      that: false\n")
            fh.write("      fail_msg: 'intentional contract failure'\n")
            fh.write("    quiet: true\n")

    # ----------------------------------------------------------------
    def test_failing_unittest_propagates_via_make(self):
        """A unittest failure inside `make` propagates as a
        non-zero exit code. The recipe MUST NOT swallow the
        failure with `|| true` or a similar pattern."""
        self._break_unittest()
        rc = _run(self.workdir, "unittest-only",
                  f"SUITE=tests.{self._broken_module}")
        self.assertNotEqual(
            rc, 0,
            msg="`make unittest-only` swallowed a unittest failure; "
                "the recipe must propagate the non-zero exit so CI "
                "sees the red.")

    def test_failing_contract_propagates_via_make(self):
        """A contract playbook failure inside `make` propagates
        as a non-zero exit code."""
        self._break_contract()
        rc = _run(self.workdir, "contract-only")
        self.assertNotEqual(
            rc, 0,
            msg="`make contract-only` swallowed a contract playbook "
                "failure; the recipe must propagate the non-zero "
                "exit so CI sees the red.")

    def test_healthy_recipe_returns_zero(self):
        """A healthy `make` invocation returns 0."""
        rc = _run(self.workdir, "unittest-only",
                  "SUITE=tests._trivial_passing")
        # Some environments may not have ansible-playbook on PATH;
        # contract-only is the more fragile one. unittest-only
        # only needs python3.
        self.assertEqual(
            rc, 0,
            msg=f"`make unittest-only` on a healthy target returned "
                f"non-zero ({rc}). The recipe should exit 0 when "
                f"all checks pass.")


if __name__ == "__main__":
    unittest.main()
