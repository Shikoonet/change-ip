#!/usr/bin/env python3
"""Stage runner for `.github/workflows/run.yml`.

Runs a `rotate.py` command as a subprocess, captures its exit code, and
verifies the persisted checkpoint state. Used by every staged job so
GitHub Actions does NOT treat a normal `EXIT_PAUSED (6)` boundary as
a job failure.

Exit semantics:
  expected_rc + expected_state match (and expected marker present when
   required)  →  runner exits 0, the step is green.
  expected_rc but state mismatch → exits 2, the step is red (caller
    reads the message — wrong checkpoint transition).
  unexpected_rc → exits <rc>, the step is red and propagates the rc
    so the caller can see what happened.
  no checkpoint on disk where one is required → exits 3.

Usage:
    python3 .github/scripts/stage.py \
        --expect-rc 6 \
        --expect-state new_ip_allocated \
        --txid 20260826-101500-a3f1 \
        -- python3 rotate.py apply --config rotation.yml ...

The runner never silently accepts an exit code. The list of acceptable
rc values is bounded:

    0  EXIT_OK              state == "done"
    5  EXIT_ROLLED_BACK     state == "rolled_back"
    6  EXIT_PAUSED          state in PAUSABLE
    7  EXIT_ROLLBACK_INCOMPLETE  state == "rollback_incomplete"

Anything else is preserved as-is.

Tokens: the runner takes the secrets it needs to scrub from the
output. It redacts both `CLOUDFLARE_API_TOKEN` and `DATAFOREST_API_TOKEN`
from the captured output before writing to its own stdout/stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import List, Optional

HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

try:
    from providers import CLOUDFLARE_TOKEN_ENV, DATAFOREST_TOKEN_ENV, register_secret, redact
except ImportError:
    CLOUDFLARE_TOKEN_ENV = "CLOUDFLARE_API_TOKEN"
    DATAFOREST_TOKEN_ENV = "DATAFOREST_API_TOKEN"
    register_secret = lambda v: None  # noqa: E731
    redact = lambda s: s  # noqa: E731

# State machine vocabulary. These names match `rotate.py` exactly.
PAUSABLE_STATES = frozenset({
    "connectivity_ok",
    "new_ip_allocated",
    "guest_configured",
    "guest_verified",
    "cloudflare_preflighted",
    "ansible_done",
    "cloudflare_replaced",
    "awaiting_finalize",
})
TERMINAL_STATES = frozenset({
    "done",
    "planned",
    "rolled_back",
    "rollback_incomplete",
    "escalated",
    "paused",
    "awaiting_finalize",  # reachable as a stop but not a final
})
# A staged command is allowed to exit with one of:
#   0 done / 5 rolled_back / 6 paused / 7 rollback_incomplete
# Anything else (1 usage / 2 identity / 3 provider / 4 escalated) is a
# failure of the staged path and must propagate.
EXPECTED_EXIT_CODES = frozenset({0, 5, 6, 7})


def _register_token_secrets() -> None:
    """Register whatever tokens are in scope so redaction works."""
    for var in (CLOUDFLARE_TOKEN_ENV, DATAFOREST_TOKEN_ENV,
                "HCLOUD_TOKEN", "ANSIBLE_VAULT_PASSWORD",
                "SSH_PRIVATE_KEY"):
        val = os.environ.get(var)
        if val:
            register_secret(val)


_STATE_DIR: Optional[str] = None


def _read_state(txid: str) -> Optional[dict]:
    state_dir = _STATE_DIR or "state"
    state_path = os.path.join(state_dir, f"{txid}.json")
    if not os.path.exists(state_path):
        return None
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _state_matches(cp: Optional[dict], expected_state: Optional[str]) -> bool:
    """`cp["state"] == expected_state`. None means "don't care"."""
    if expected_state is None:
        return True
    if cp is None:
        return False
    return cp.get("state") == expected_state


def _marker_present(cp: Optional[dict], marker_key: str) -> bool:
    """Whether `cp[marker_key]` is present and non-empty."""
    if cp is None:
        return False
    val = cp.get(marker_key)
    return bool(val)


def _expected_outcome(rc: int) -> Optional[str]:
    return {
        0: "done",
        5: "rolled_back",
        6: "paused",
        7: "rollback_incomplete",
    }.get(rc)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-rc", type=int, required=True,
                        choices=sorted(EXPECTED_EXIT_CODES),
                        help="the exact exit code this stage must return")
    parser.add_argument("--expect-state", default=None,
                        help="the state the checkpoint must be in after this stage")
    parser.add_argument("--expect-marker", action="append",
                        default=[],
                        help="a key that must be present in the checkpoint "
                             "(may be repeated)")
    parser.add_argument("--txid", default="latest",
                        help="the transaction ID whose checkpoint must "
                             "match the expected state. Default 'latest' "
                             "uses the newest state/*.json file.")
    parser.add_argument("--label", default="stage",
                        help="short label for log lines")
    parser.add_argument("--max-output-bytes", type=int, default=8192,
                        help="truncate captured subprocess output")
    parser.add_argument("--state-dir", default=None,
                        help="absolute or relative path to the state "
                             "directory (default: ./state relative to the "
                             "subprocess's cwd)")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="the rotate.py command (after `--`)")
    args = parser.parse_args()

    if not args.command or args.command[0] != "--":
        print(f"[{args.label}] usage: stage.py --expect-rc N --expect-state S "
              f"--txid T -- <command...>", file=sys.stderr)
        return 64
    args.command = args.command[1:]

    _register_token_secrets()

    # Run the subprocess.
    print(f"[{args.label}] running: {' '.join(args.command[:6])}", file=sys.stderr)
    try:
        cp_run = subprocess.run(
            args.command,
            cwd=HERE, capture_output=True, text=True, timeout=1800,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[{args.label}] TIMEOUT after 1800s", file=sys.stderr)
        return 124

    rc = cp_run.returncode
    out = (cp_run.stdout or "")[: args.max_output_bytes]
    err = (cp_run.stderr or "")[: args.max_output_bytes]

    expected_outcome = _expected_outcome(args.expect_rc)
    if rc not in EXPECTED_EXIT_CODES:
        # Unexpected exit code (one of 1/2/3/4). Preserve it as a
        # failure so the workflow surfaces the message. Multiplying
        # by a sentinel keeps it distinguishable from a clean stage
        # exit while still being a non-zero rc.
        print(f"[{args.label}] unexpected rc={rc}; expected "
              f"{args.expect_rc} ({expected_outcome})", file=sys.stderr)
        print(redact(err or out), file=sys.stderr)
        # rc=4 (escalated) and rc=3 (provider error) are the cases the
        # spec calls out — preserve them EXACTLY so the workflow can
        # surface them. Other unexpected codes also propagate.
        return rc

    if rc != args.expect_rc:
        # The subprocess exited cleanly but with the WRONG boundary
        # code. The runner MUST NOT accept this silently — it would
        # mask the case where a downstream `apply --until X` actually
        # ran past X (e.g. ran to `done`) while the workflow expected
        # to pause at X. Return a distinct failure rc=8 so the
        # caller can tell "wrong boundary" apart from "right boundary,
        # wrong state" (rc=2) and "no checkpoint" (rc=3).
        print(f"[{args.label}] rc={rc} != expected {args.expect_rc} "
              f"({expected_outcome})", file=sys.stderr)
        print(redact(err or out), file=sys.stderr)
        return 8

    # rc matches. Now verify the checkpoint state.
    txid = args.txid
    state_dir = args.state_dir or "state"
    global _STATE_DIR
    _STATE_DIR = state_dir  # for _read_state
    if not txid or txid == "latest":
        # Find the newest state/*.json.
        print(f"[{args.label}] looking in state_dir={state_dir!r} "
              f"(exists={os.path.isdir(state_dir)})", file=sys.stderr)
        if os.path.isdir(state_dir):
            files = sorted(
                (os.path.join(state_dir, f) for f in os.listdir(state_dir)
                 if f.endswith(".json")),
                key=os.path.getmtime,
            )
            if files:
                txid = os.path.basename(files[-1]).removesuffix(".json")
    cp = _read_state(txid)
    if cp is None:
        if args.expect_state is not None:
            print(f"[{args.label}] rc={rc} matched but no checkpoint on "
                  f"disk for txid={txid}", file=sys.stderr)
            print(redact(err or out), file=sys.stderr)
            return 3
        return 0

    if not _state_matches(cp, args.expect_state):
        actual = cp.get("state")
        print(f"[{args.label}] rc={rc} matched but state={actual!r} != "
              f"expected {args.expect_state!r}", file=sys.stderr)
        print(redact(err or out), file=sys.stderr)
        return 2

    for marker in args.expect_marker:
        if not _marker_present(cp, marker):
            print(f"[{args.label}] rc={rc} and state={args.expect_state!r} "
                  f"matched but marker {marker!r} missing", file=sys.stderr)
            print(redact(err or out), file=sys.stderr)
            return 4

    print(f"[{args.label}] rc={rc} state={cp.get('state')!r} OK",
          file=sys.stderr)
    # Echo the actual txid on its own line so callers can pipe it.
    print(f"TXID={cp.get('txid', txid)}", file=sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())