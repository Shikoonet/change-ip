#!/usr/bin/env python3
"""The Cloudflare half of the rotation — discover / apply / rollback / verify.

Models `ansible_adapter.run_ip_change()`'s structure because rotate.py already
adopts that seam for `make ip-change`. The Cloudflare side has the same
sharing: production shells
`ansible-playbook cloudflare_replace_ip_step.yml`, tests fake it. The test
fake in `tests/cloudflare_fake.py` is the same pattern as `fake_hcloud.py`.

The token follows the same rule as HCLOUD_TOKEN:

  * never on argv, never in -e blob, never inside the result JSON
  * registered with `register_secret()` so a producer-side forget still cannot
    leak: redact() at the sink scrubs the literal token, the Authorization
    header value, and any `Bearer <...>` shape the upstream happened to print

argv composition is strict — the only values that can reach it are:

  * the op name (`discover|apply|rollback|verify`)
  * the tmpfile path (output sink)
  * path-style values like inventory paths
  * the JSON blobs the playbook requires as `-e` parameters

The actual FQDN strings, the manifest, and the IP addresses travel as JSON in
`-e`, which is fine: they contain no secret. The token never does, and that
is asserted by the contract test.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional

from providers import (
    EscalationRequired,
    NonRetryableError,
    RetryableError,
    redact,
)


PLAYBOOK = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cloudflare_replace_ip_step.yml",
)


# ponytail: this stays a flat list — every entry is a non-secret path or
# scalar that the contract test greps for in argv. add a field here and you
# also add an -e below; do not pass secrets.
def _ansible_playbook_argv(playbook_filename: str, extra_blobs: List[str]) -> List[str]:
    """Return the argv list for invoking the playbook.

    Production uses the literal `ansible-playbook` (PATH-resolved). Tests
    may set `ANSIBLE_PLAYBOOK_BIN` to an absolute path of a fake binary
    when `ROTATION_TEST_MODE=1` is also set. The override is rejected
    outside the test marker so a non-test run cannot point at an
    arbitrary binary.
    """
    override = os.environ.get("ANSIBLE_PLAYBOOK_BIN")
    test_mode = os.environ.get("ROTATION_TEST_MODE") == "1"
    if override:
        if not test_mode:
            raise NonRetryableError(
                "ANSIBLE_PLAYBOOK_BIN override refused: "
                "ROTATION_TEST_MODE is not set; production must use the "
                "PATH-resolved `ansible-playbook`."
            )
        if not os.path.isabs(override):
            raise NonRetryableError(
                f"ANSIBLE_PLAYBOOK_BIN must be an absolute path, got {override!r}"
            )
        if not (os.path.exists(override) and os.access(override, os.X_OK)):
            raise NonRetryableError(
                f"ANSIBLE_PLAYBOOK_BIN does not point to an executable: "
                f"{override!r}"
            )
        return [override, playbook_filename, *extra_blobs]
    return ["ansible-playbook", playbook_filename, *extra_blobs]


def cf_op_argv(op: str, result_file: str, invocation_id: str) -> List[str]:
    extra = [
        "-e", f"operation={op}",
        "-e", f"result_file={result_file}",
        "-e", f"invocation_id={invocation_id}",
    ]
    return _ansible_playbook_argv(os.path.basename(PLAYBOOK), extra)


def _serialisable(value: Any) -> Any:
    """Path/string-ify before argv. json.dumps handles dicts/lists cleanly."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def run_cloudflare_op(
    operation: str,
    *,
    old_ip: str,
    new_ip: str,
    allowed_records: List[str],
    expected_count: int,
    manifest: Optional[List[Dict[str, Any]]] = None,
    invocation_id: Optional[str] = None,
    runner: Callable[..., Any] = subprocess.run,
    timeout: int = 900,
) -> Dict[str, Any]:
    """Run one Cloudflare op and return its structured result.

    The return shape mirrors `run_ip_change()` so rotate.py can consume both
    without separate code paths:

      {
        "argv": [..., "-e", "manifest=...", ...],
        "rc": int,
        "result": {...},              # the playbook's JSON file, parsed
        "stdout_tail": "...",
        "stderr_tail": "...",
      }

    A malformed or missing result file is `RetryableError` (transient: a
    half-written tmpfile is reasonably worth one more try) unless the playbook
    rc is non-zero AND the file does not exist, which is the normal "it failed
    and aborted" shape — that raises `EscalationRequired` with a recovery
    command naming the playbook and op.
    """
    if operation not in ("discover", "apply", "rollback", "verify"):
        raise NonRetryableError(f"unknown cloudflare op {operation!r}")
    if not invocation_id:
        raise NonRetryableError(
            "cloudflare op requires an invocation_id; pass a UUID to bind "
            "the result file to this call."
        )

    # Atomic result file: mkstemp, chmod 0o600, cleaned up in finally.
    fd, result_file_path = tempfile.mkstemp(prefix="cloudflare_result_", suffix=".json")
    os.close(fd)
    os.chmod(result_file_path, 0o600)
    argv = cf_op_argv(operation, result_file_path, invocation_id)

    blob_args: Dict[str, Any] = {
        "old_ip": old_ip,
        "new_ip": new_ip,
        "allowed_records": json.dumps([_serialisable(x) for x in allowed_records]),
        "expected_count": int(expected_count),
        "manifest": json.dumps(manifest or []),
        "invocation_id": _serialisable(invocation_id),
    }
    for key, value in blob_args.items():
        argv.extend(["-e", f"{key}={value}"])

    completed = runner(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )

    try:
        result: Optional[Dict[str, Any]] = None
        try:
            with open(result_file_path, "r", encoding="utf-8") as handle:
                result = json.load(handle)
        except (OSError, ValueError) as exc:
            rc = int(getattr(completed, "returncode", 1))
            stdout_tail = redact(getattr(completed, "stdout", "") or "")[-4000:]
            stderr_tail = redact(getattr(completed, "stderr", "") or "")[-4000:]
            if rc != 0:
                raise EscalationRequired(
                    f"cloudflare {operation} exited {rc} with no result JSON; "
                    f"see stdout/stderr tails.",
                    [
                        "ansible-playbook cloudflare_replace_ip_step.yml "
                        f"-e operation={operation} -e result_file=/tmp/cf.json "
                        "(re-run with full -e blobs to see the actual failure)",
                    ],
                ) from exc
            raise RetryableError(
                f"cloudflare {operation}: result file unreadable ({exc!r})"
            ) from exc

        rc = int(getattr(completed, "returncode", 1))

        # Validate the structured result BEFORE trusting it. Missing fields,
        # extra record ids outside the manifest, duplicate record ids, or an
        # ok/rc mismatch are all "the playbook produced something we cannot
        # rely on" — refuse rather than report success.
        if not isinstance(result, dict):
            raise NonRetryableError(
                f"cloudflare {operation}: result JSON is not an object "
                f"(got {type(result).__name__})"
            )
        _validate_result(operation, result, manifest, rc, invocation_id)

        if not isinstance(result, dict) or not result.get("ok"):
            return {
                "argv": argv,
                "rc": rc,
                "result": redact_tree(result or {}),
                "stdout_tail": redact(getattr(completed, "stdout", "") or "")[-4000:],
                "stderr_tail": redact(getattr(completed, "stderr", "") or "")[-4000:],
            }
        return {
            "argv": argv,
            "rc": rc,
            "result": redact_tree(result),
            "stdout_tail": redact(getattr(completed, "stdout", "") or "")[-4000:],
            "stderr_tail": redact(getattr(completed, "stderr", "") or "")[-4000:],
        }
    finally:
        try:
            os.remove(result_file_path)
        except OSError:
            pass


def _validate_result(
    operation: str,
    result: Dict[str, Any],
    manifest: Optional[List[Dict[str, Any]]],
    rc: int,
    invocation_id: str,
) -> None:
    """Reject malformed or untrustworthy structured results.

    Failure modes caught here:
      * missing required fields (`operation`, `ok`, `invocation_id`)
      * invocation_id mismatch — stale file from a previous op
      * operation mismatch
      * record ids that were never on the manifest
      * duplicate record ids in the post-state
      * rc != 0 while the result claims `ok: true` (or vice versa)
      * a non-boolean `verified` if the playbook provided one

    A failure here is a structural problem with the playbook output, not a
    transient API hiccup — `NonRetryableError` keeps it out of the retry
    loop. The caller sees the same path it would for any other stop and
    the operator reads the recovery command.
    """
    if "operation" not in result:
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON missing required 'operation' field"
        )
    if str(result["operation"]) != operation:
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON claims operation="
            f"{result['operation']!r}, not {operation!r}"
        )
    if "invocation_id" not in result:
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON missing required 'invocation_id'"
        )
    if str(result["invocation_id"]) != invocation_id:
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON invocation_id="
            f"{result['invocation_id']!r} != our invocation_id="
            f"{invocation_id!r}. Refusing to accept a stale or wrong-invocation file."
        )
    if "ok" not in result:
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON missing required 'ok' field"
        )
    if not isinstance(result["ok"], bool):
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON 'ok' is not a boolean "
            f"(got {type(result['ok']).__name__})"
        )
    if result["ok"] is True and rc != 0:
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON claims ok=true but the "
            f"playbook exited {rc}. Refusing to trust a green result from "
            "a non-zero process."
        )
    if result["ok"] is False and rc == 0:
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON claims ok=false but the "
            "playbook exited 0. Refusing to trust a failing result from a "
            "green process."
        )
    if manifest is not None:
        manifest_ids = {str(r.get("record_id")) for r in manifest if r.get("record_id")}
        seen_in_post: List[str] = []
        for key in ("post_manifest", "manifest", "incomplete_records"):
            entries = result.get(key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                rid = str(entry.get("record_id"))
                if rid in seen_in_post:
                    raise NonRetryableError(
                        f"cloudflare {operation}: duplicate record_id {rid!r} "
                        "in result JSON; refusing ambiguous state."
                    )
                seen_in_post.append(rid)
                if manifest_ids and rid not in manifest_ids:
                    raise NonRetryableError(
                        f"cloudflare {operation}: result record_id {rid!r} "
                        "is not in the supplied manifest — refusing to "
                        "trust a result that PATCHed something else."
                    )
    if "verified" in result and not isinstance(result["verified"], bool):
        raise NonRetryableError(
            f"cloudflare {operation}: result JSON 'verified' is not a "
            f"boolean (got {type(result['verified']).__name__})"
        )


def redact_tree(value: Any) -> Any:
    """Same shape as providers.redact_tree; kept here so this file does not
    import private helpers."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_tree(v) for key, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(v) for v in value]
    return value
