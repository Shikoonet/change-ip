#!/usr/bin/env python3
"""Tests for `.github/scripts/classify_change.py`.

The classifier is invoked from `ci.yml` to pick `ci-fast` vs
`ci-full`. The decisions are small but load-bearing:
  * a docs-only PR must run ci-fast (cheap)
  * any PR that touches code, tests, contracts, or CI config
    must run ci-full (expensive but exhaustive)
  * an indeterminate diff (missing SHA, shallow clone, all-zero
    SHA) MUST escalate to ci-full — failing closed is the whole
    point of the gate

A bug here means either:
  * docs-only PRs run a five-minute suite (cost)
  * code-touching PRs run only the cheap gate (CI can pass while
    the suite is red — exactly the regression the brief is
    closing).
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / ".github" / "scripts"))

import classify_change  # noqa: E402


class TestClassify(unittest.TestCase):
    # -- exact-match / prefix / substring coverage ---------------------
    def test_single_commit_pr_docs_only(self):
        """A PR whose ONLY change is a docs/ file picks ci-fast."""
        self.assertEqual(
            classify_change.classify(["docs/notes.md"]),
            "ci-fast",
        )

    def test_single_commit_pr_root_md_only(self):
        """A top-level README change with no other edits picks ci-fast."""
        self.assertEqual(
            classify_change.classify(["README.md"]),
            "ci-fast",
        )

    def test_pr_with_latest_commit_docs_only_but_earlier_commit_touches_rotate_py(self):
        """Multi-commit PR where the LATEST commit is docs-only but
        an EARLIER commit changed `rotate.py`. Must select ci-full."""
        self.assertEqual(
            classify_change.classify(["docs/notes.md"]),
            "ci-fast",
        )
        # Now include the earlier commit's touched file too — the
        # whole PR diff matters, not just the latest commit.
        self.assertEqual(
            classify_change.classify(
                ["docs/notes.md", "rotate.py"]
            ),
            "ci-full",
        )

    def test_push_to_main_changing_makefile_only(self):
        """A push to main changing Makefile picks ci-full."""
        self.assertEqual(
            classify_change.classify(["Makefile"]),
            "ci-full",
        )

    def test_push_to_main_changing_only_claude_md_is_ci_fast(self):
        """A push to main changing only CLAUDE.md picks ci-fast."""
        self.assertEqual(
            classify_change.classify(["CLAUDE.md"]),
            "ci-fast",
        )

    def test_pr_changing_rotate_py_picks_ci_full(self):
        """A PR changing rotate.py picks ci-full."""
        self.assertEqual(
            classify_change.classify(["rotate.py"]),
            "ci-full",
        )

    def test_pr_changing_providers_py_picks_ci_full(self):
        self.assertEqual(
            classify_change.classify(["providers.py"]),
            "ci-full",
        )

    def test_pr_changing_an_adapter_picks_ci_full(self):
        """`_adapter.py` substring catches every adapter filename."""
        self.assertEqual(
            classify_change.classify(["cloudflare_adapter.py"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["dataforest_adapter.py"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["dataforest_guest_adapter.py"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["ansible_adapter.py"]),
            "ci-full",
        )

    def test_pr_changing_a_step_yml_picks_ci_full(self):
        """`_step.yml` substring catches every step playbook."""
        self.assertEqual(
            classify_change.classify(["hcloud_step.yml"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["cloudflare_replace_ip_step.yml"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["dataforest_step.yml"]),
            "ci-full",
        )

    def test_pr_changing_cf_record_pages_yml_picks_ci_full(self):
        self.assertEqual(
            classify_change.classify(["cf_record_pages.yml"]),
            "ci-full",
        )

    def test_pr_changing_a_workflow_picks_ci_full(self):
        """Anything under `.github/` is a CI control surface."""
        self.assertEqual(
            classify_change.classify([".github/workflows/ci.yml"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(
                [".github/scripts/classify_change.py"]
            ),
            "ci-full",
        )

    def test_pr_changing_tests_picks_ci_full(self):
        """`tests/` prefix is always relevant."""
        self.assertEqual(
            classify_change.classify(["tests/test_rotation.py"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["tests/contract.yml"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["tests/onboard_contract.yml"]),
            "ci-full",
        )

    def test_pr_changing_rotation_yml_picks_ci_full(self):
        """Both rotation.yml and rotation.example.yml are config — they
        pin real server IDs and project fingerprints, so a PR touching
        them MUST run the full suite."""
        self.assertEqual(
            classify_change.classify(["rotation.yml"]),
            "ci-full",
        )
        self.assertEqual(
            classify_change.classify(["rotation.example.yml"]),
            "ci-full",
        )

    # -- mixed + edge cases --------------------------------------------
    def test_mixed_docs_and_provider_files(self):
        """A PR that touches both docs and provider files picks
        ci-full (the provider touch dominates)."""
        self.assertEqual(
            classify_change.classify(
                ["docs/notes.md", "rotate.py"]
            ),
            "ci-full",
        )

    def test_unknown_path_picks_ci_full(self):
        """A path that matches neither docs nor relevant defaults to
        the heavier tier. We do not assume a path is docs-only
        just because we haven't enumerated it."""
        self.assertEqual(
            classify_change.classify(["some_random_new_file.py"]),
            "ci-full",
        )

    def test_empty_file_list_picks_ci_full(self):
        """An empty diff has no signal — fail safe to ci-full."""
        self.assertEqual(
            classify_change.classify([]),
            "ci-full",
        )

    def test_graphify_out_alone_picks_ci_full(self):
        """`graphify-out/` is generated content; it is NOT docs and
        NOT relevant. With only graphify-out files in the diff,
        the classifier has no docs to lean on → ci-full."""
        self.assertEqual(
            classify_change.classify(["graphify-out/GRAPH_REPORT.md"]),
            "ci-full",
        )

    # -- diff_files helper ---------------------------------------------
    def test_diff_files_empty_for_zero_sha(self):
        """All-zero SHA is the GitHub Actions sentinel for "no
        previous commit". diff_files returns None so the caller
        can fail safe."""
        self.assertIsNone(
            classify_change.diff_files("0" * 40, "abcdef" * 7),
        )

    def test_diff_files_empty_for_empty_sha(self):
        """Empty base or head SHA is also indeterminate."""
        self.assertIsNone(classify_change.diff_files("", "abc"))
        self.assertIsNone(classify_change.diff_files("abc", ""))

    def test_diff_files_none_for_missing_repo(self):
        """Outside a real git repo, diff_files returns None (no
        crash — a missing git context is an indeterminate diff)."""
        # Run from a temp directory with no .git folder.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            old_cwd = os.getcwd()
            try:
                os.chdir(td)
                self.assertIsNone(
                    classify_change.diff_files(
                        "a" * 40, "b" * 40
                    )
                )
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
