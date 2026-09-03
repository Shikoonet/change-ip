#!/usr/bin/env python3
"""Classify a GitHub push or pull-request change into a CI tier
(`ci-fast` or `ci-full`) and write the result to $GITHUB_OUTPUT.

This script is invoked from `.github/workflows/ci.yml`. It
deliberately has NO third-party deps so it runs on a fresh
ubuntu-latest runner without `pip install` ceremony.

WHY A SCRIPT (not a heredoc):
  * testable in isolation (`tests/test_classify_change.py`)
  * the CI tier decision lives in ONE place; adding a path is
    a single-line edit here, not a workflow diff
  * `git diff ... | classify` works locally for dry-run

WHY A FAIL-SAFE:
  * missing base SHA, all-zero SHA, shallow clone — anything that
    would make the diff comparison indeterminate — must escalate
    to `ci-full`. The brief forbids `ci-fast` running when we
    cannot prove the change is docs-only.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple


# Paths that force `ci-full` regardless of the docs-only check.
# A change touching ANY of these is treated as relevant.
# Listed in alphabetical order; keep it that way for review.
# `docs/` is NOT here on purpose: docs files are docs-only and
# must run the cheap ci-fast tier. The `_is_docs_only` helper
# matches the docs/ prefix.
RELEVANT_PATH_PREFIXES: Tuple[str, ...] = (
    ".github/",
    "roles/",
    "tests/",
)
RELEVANT_PATH_EXACT: frozenset = frozenset({
    "Makefile",
    "ansible.cfg",
    "cf_record_pages.yml",
    "hcloud_step.yml",
    "cloudflare_replace_ip_step.yml",
    "dataforest_step.yml",
    "node-onboard.yml",
    "monitoring-doctor.yml",
    "onboard.py",
    "providers.py",
    "rotate.py",
    "ansible_adapter.py",
    "cloudflare_adapter.py",
    "dataforest_adapter.py",
    "dataforest_guest_adapter.py",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "tests/contract.yml",
    "tests/onboard_contract.yml",
    "rotation.example.yml",
    "rotation.yml",
    ".yamllint.yml",
})
# Substrings: any file whose name contains one of these is relevant.
# This catches e.g. `cloudflare_adapter.py` matched on `_adapter.py`
# without enumerating every adapter filename.
RELEVANT_PATH_SUBSTRINGS: Tuple[str, ...] = (
    "_adapter.py",
    "_step.yml",
)


def _is_relevant(path: str) -> bool:
    """A path is RELEVANT if any prefix / exact / substring matches.

    Returns True when the path touches code, tests, contracts,
    CI configuration, or anything else that can break the gate.
    Docs and graphify-out are not relevant on their own.
    """
    if path in RELEVANT_PATH_EXACT:
        return True
    for prefix in RELEVANT_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    for needle in RELEVANT_PATH_SUBSTRINGS:
        if needle in path:
            return True
    return False


def _is_docs_only(path: str) -> bool:
    """A path is DOCS if it lives under `docs/` or ends in `.md`.

    Used for the docs-only fast path. `graphify-out/` is generated
    and never relevant to the build, but also never docs in the
    sense the brief means — it falls into "neither" and triggers
    the fail-safe `ci-full`.
    """
    if path.startswith("graphify-out/"):
        return False
    if path.startswith("docs/"):
        return True
    if path.endswith(".md"):
        return True
    return False


def classify(files: List[str]) -> str:
    """Return "ci-fast" iff every file is docs-only AND at least
    one file is recognised as docs. Otherwise "ci-full".

    Empty file list → ci-full (no evidence either way).
    Unknown non-docs path → ci-full (fail safe).
    """
    if not files:
        return "ci-full"
    docs = sum(1 for f in files if _is_docs_only(f))
    relevant = sum(1 for f in files if _is_relevant(f))
    other = len(files) - docs - relevant
    # Anything not classified as docs or relevant pushes to full.
    if other > 0:
        return "ci-full"
    if relevant > 0:
        return "ci-full"
    if docs == 0:
        # No relevant, no docs: only meaningful if file list was
        # empty (handled above). Pure unknown → fail safe.
        return "ci-full"
    return "ci-fast"


def diff_files(base_sha: str, head_sha: str) -> Optional[List[str]]:
    """Run `git diff --name-only <base>..<head>` and return the list.

    Returns None when the diff cannot be computed (empty output,
    git error, missing SHA). A None result means "indeterminate"
    and the caller must fail safe to `ci-full`.
    """
    if not base_sha or not head_sha:
        return None
    if base_sha == "0" * 40 or head_sha == "0" * 40:
        return None
    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-only",
             f"{base_sha}..{head_sha}"],
            stderr=subprocess.DEVNULL, text=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    files = [line.strip() for line in out.splitlines() if line.strip()]
    if not files:
        # Empty diff = nothing to test = fail safe.
        return None
    return files


def main() -> int:
    base = os.environ.get("CI_BASE_SHA", "")
    head = os.environ.get("CI_HEAD_SHA", "")
    files_env = os.environ.get("CI_CHANGED_FILES", "").strip()
    if files_env:
        files = [f.strip() for f in files_env.splitlines() if f.strip()]
        indeterminable = False
    else:
        files = diff_files(base, head) or []
        indeterminable = (diff_files(base, head) is None)
    tier = classify(files)
    if indeterminable:
        tier = "ci-full"
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        print(f"tier={tier}", file=sys.stderr)
        return 0
    with open(out, "a", encoding="utf-8") as fh:
        fh.write(f"tier={tier}\n")
        fh.write(f"changed_count={len(files)}\n")
        fh.write(f"base_sha={base}\n")
        fh.write(f"head_sha={head}\n")
    print(f"tier={tier}", file=sys.stderr)
    print(f"changed_count={len(files)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
