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
import re
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


# Canonical Cloudflare API endpoints and the loopback regex the test
# harness uses. Centralised here so the adapter and the playbook read
# the SAME values. Changing one of these without the other is a
# regression — the playbook's `vars:` block imports the constants by
# string match, and the adapter imports them as Python constants.
OFFICIAL_CF_API_BASE = "https://api.cloudflare.com/client/v4"
LOOPBACK_URL_RE = (
    r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/.*)?$"
)


def _is_test_mode() -> bool:
    """Canonical test-mode probe.

    Two markers exist for one purpose:
      * `ROTATION_TEST_MODE` — the Python adapter's switch.
      * `CF_PLAYBOOK_TEST_MODE` — the Ansible playbook's switch.

    The adapter sets BOTH before spawning `ansible-playbook` so the
    playbook reads the same state the Python caller sees. Reading
    only one of them silently lets the Python side accept a test
    invocation that the Ansible side then refuses (or vice versa),
    and the mismatch is what the earlier accidental external request
    rode on: the Python side thought it was talking to a loopback
    and never set the playbook's marker, so the playbook fell back
    to the production endpoint.
    """
    return (
        os.environ.get("ROTATION_TEST_MODE") == "1"
        and os.environ.get("CF_PLAYBOOK_TEST_MODE") == "1"
    )


def _validate_cf_api_base(cf_api_base: Optional[str]) -> None:
    """Reject unsafe `cf_api_base` BEFORE the subprocess is spawned.

    Rules — the same rules the playbook enforces as defence in depth:

      production mode (ROTATION_TEST_MODE != "1"):
        * `cf_api_base is None`        → fall back to OFFICIAL_CF_API_BASE
                                         (the playbook's hard-coded default)
        * `cf_api_base == official`   → allowed
        * any other value             → NonRetryableError

      test mode (ROTATION_TEST_MODE == "1"):
        * `cf_api_base is None`        → NonRetryableError
                                         (must be explicit in test mode)
        * `cf_api_base == official`   → NonRetryableError
                                         (the whole point of test mode is
                                         NOT to call the real API)
        * non-loopback hostname/IP    → NonRetryableError
        * 127.0.0.1 / localhost / [::1] with explicit port → allowed

    The check is deliberately in the adapter so a test or operator
    that forgets to pass `cf_api_base` in test mode fails HERE rather
    than after a subprocess is spawned (which would surface only when
    the playbook reads the result file).
    """
    test_mode = _is_test_mode()
    if cf_api_base is None:
        if test_mode:
            raise NonRetryableError(
                "cloudflare: test mode requires an explicit `cf_api_base` "
                "pointing at a loopback fixture (127.0.0.1, localhost, "
                "or [::1] with an explicit port). Refusing to spawn "
                "ansible-playbook without one — the playbook's default "
                "is the official Cloudflare endpoint and would route "
                "test traffic to the real API."
            )
        # Production: None means "use the playbook default", which is
        # the official endpoint. Pass nothing; the playbook falls back.
        return
    # An explicit URL was supplied. Reject anything that does not match
    # the contract for the current mode.
    if test_mode:
        if cf_api_base == OFFICIAL_CF_API_BASE:
            raise NonRetryableError(
                "cloudflare: test mode forbids cf_api_base="
                f"{OFFICIAL_CF_API_BASE!r}. Pointing test traffic at "
                "the production API is the failure mode this guard "
                "exists to prevent."
            )
        if not re.match(LOOPBACK_URL_RE, cf_api_base):
            raise NonRetryableError(
                f"cloudflare: test mode requires cf_api_base to match "
                f"{LOOPBACK_URL_RE!r}; got {cf_api_base!r}. Loopback "
                "fixtures only."
            )
        return
    # Production with an explicit URL: must it is the official endpoint.
    if cf_api_base != OFFICIAL_CF_API_BASE:
        raise NonRetryableError(
            f"cloudflare: production mode only accepts cf_api_base="
            f"{OFFICIAL_CF_API_BASE!r} or the playbook default. "
            f"Got {cf_api_base!r}. Refusing to point a live rotation "
            "at any other endpoint."
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
    credential_ref: Optional[str] = None,
    token_env: Optional[str] = None,
    cf_api_base: Optional[str] = None,
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

    Multi-account support: pass `credential_ref` (the account's logical
    name from the config) and `token_env` (the env var name that holds
    the token for this account). When the per-account path is in use,
    the adapter:
      * sets `CLOUDFLARE_API_TOKEN` in the subprocess env to the value
        of `token_env` ONLY (no value crosses the process boundary as
        an argv value, log line, manifest field, or checkpoint field);
      * asserts every record in `manifest` carries the same
        `credential_ref` it was given.

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
    # Test-mode URL guard. Runs BEFORE the subprocess is spawned so a
    # missing or unsafe URL is refused without touching the network.
    # The playbook enforces the same rule; both must agree.
    _validate_cf_api_base(cf_api_base)

    # Manifest ownership check (only when a credential_ref is in scope).
    if credential_ref is not None and manifest:
        for entry in manifest:
            entry_ref = entry.get("credential_ref")
            if entry_ref is None and len(manifest) and all(
                e.get("credential_ref") is None for e in manifest
            ):
                # Legacy single-account manifests are allowed through;
                # the legacy path uses the global CLOUDFLARE_API_TOKEN.
                break
            if entry_ref != credential_ref:
                raise NonRetryableError(
                    f"manifest entry {entry.get('name')!r} has "
                    f"credential_ref={entry_ref!r} but the adapter was "
                    f"called with credential_ref={credential_ref!r}; "
                    "refusing to let one account's token PATCH another "
                    "account's record set."
                )

    # Atomic result file: mkstemp, chmod 0o600, cleaned up in finally.
    fd, result_file_path = tempfile.mkstemp(prefix="cloudflare_result_", suffix=".json")
    os.close(fd)
    os.chmod(result_file_path, 0o600)
    argv = cf_op_argv(operation, result_file_path, invocation_id)

    # NOTE: `allowed_records` is a JSON string wrapped in single
    # quotes so ansible-playbook's YAML parser keeps it as a string.
    # Without the quotes, the YAML parser turns it into a Python
    # list and the playbook's `from_json` filter then fails
    # (from_json expects a string, gets a list). Same applies to
    # `manifest`.
    blob_args: Dict[str, Any] = {
        "old_ip": old_ip,
        "new_ip": new_ip,
        "allowed_records": f"'{json.dumps([_serialisable(x) for x in allowed_records])}'",
        "expected_count": int(expected_count),
        "manifest": f"'{json.dumps(manifest or [])}'",
        "invocation_id": _serialisable(invocation_id),
    }
    if credential_ref is not None:
        blob_args["credential_ref"] = _serialisable(credential_ref)
    if token_env is not None:
        blob_args["token_env"] = _serialisable(token_env)
    if cf_api_base is not None:
        # Explicit override of the playbook's default cf_api_base.
        # Production never sets this; tests do. The playbook
        # requires this to be a loopback URL when
        # CF_PLAYBOOK_TEST_MODE=1.
        blob_args["cf_api_base"] = _serialisable(cf_api_base)
    for key, value in blob_args.items():
        argv.extend(["-e", f"{key}={value}"])

    # Build the per-call env as an EXPLICIT ALLOWLIST. Only the
    # process settings the playbook subprocess has proven it needs
    # are forwarded; every other variable in os.environ is dropped
    # on the floor, including any *TOKEN / *SECRET / *PASSWORD / *KEY
    # the parent process happened to have. A leak path that adds a new
    # env var to the parent cannot leak to the child unless this
    # allowlist is also extended.
    #
    # `PATH` is required for `ansible-playbook` to find `python3`,
    # `ssh`, and the modules. `HOME` is required for `~/.ansible.cfg`
    # and `~/.ssh/`. `LANG` / `LC_ALL` / `TMPDIR` keep stdout parsing
    # deterministic. `CF_PLAYBOOK_TEST_MODE` flips the test marker
    # inside the playbook so it accepts a loopback cf_api_base.
    # `CLOUDFLARE_API_TOKEN` carries ONLY the selected account's
    # token; the per-account env vars and the other token are
    # dropped.
    #
    # The allowlist is the structural defense. The structural test
    # in `tests/test_workflow_structure.py` proves no other env var
    # is in the child. Adding a new env var here requires both a
    # code change AND a test update.
    ALLOWED_CHILD_ENV = (
        # Process settings the ansible-playbook subprocess needs.
        # All credentials (Cloudflare, DataForest, Hetzner, SSH) are
        # scrubbed by the absence of the credential env vars from
        # this list. The allowlist IS the secret-scrubbing policy.
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "LC_MESSAGES",
        "LANGUAGE", "TZ", "TMPDIR", "TMP", "TEMP",
        # ansible-playbook reads these; ansible modules read these.
        "ANSIBLE_LOCALHOST_WARNING", "ANSIBLE_INVENTORY",
        "ANSIBLE_HOST_KEY_CHECKING", "ANSIBLE_FORCE_COLOR",
        "ANSIBLE_STDOUT_CALLBACK", "ANSIBLE_LOAD_CALLBACK_PLUGINS",
        "ANSIBLE_COLLECTIONS_PATH", "ANSIBLE_ROLES_PATH",
        "ANSIBLE_LOOKUP_PLUGINS", "ANSIBLE_FILTER_PLUGINS",
        "ANSIBLE_TEST_PLUGINS", "ANSIBLE_CALLBACK_PLUGINS",
        "ANSIBLE_ACTION_PLUGINS", "ANSIBLE_CACHE_PLUGINS",
        "ANSIBLE_STRATEGY_PLUGINS", "ANSIBLE_INVENTORY_PLUGINS",
        "ANSIBLE_NETWORK_OS_PLUGINS", "ANSIBLE_CLI_INVENTORY",
        "ANSIBLE_TRANSFORM_INVALID_GROUP_CHARS",
        "ANSIBLE_PYTHON_INTERPRETER", "ANSIBLE_DEPRECATION_WARNINGS",
        "ANSIBLE_JINJA2_NATIVE", "ANSIBLE_COW_USAGE",
        "ANSIBLE_STDOUT_FORMATTER_TYPE",
        "ANSIBLE_DISPLAY_OK_HOSTS", "ANSIBLE_DISPLAY_SKIPPED_HOSTS",
        "ANSIBLE_DISPLAY_FAILED_HOSTS",
        # Test marker: the playbook's `cf_api_base` assertion
        # accepts a loopback URL only when this is "1".
        "CF_PLAYBOOK_TEST_MODE",
        # The selected account's token (CLOUDFLARE_API_TOKEN only).
        "CLOUDFLARE_API_TOKEN",
        # Diagnostic reference; never a secret.
        "CLOUDFLARE_CREDENTIAL_REF",
        # Test infrastructure paths. The fake ansible-playbook
        # reads ROTATION_FAKE_STATE and ROTATION_FAKE_CALLS_LOG to
        # know where to load seeded records and write its call log.
        # These are absolute paths to test temp dirs, never secrets.
        "ROTATION_FAKE_STATE", "ROTATION_FAKE_CALLS_LOG",
        "ROTATION_TEST_FAKE_BIN", "ROTATION_TEST_MODE",
    )
    child_env: Optional[Dict[str, str]] = None
    if token_env:
        # Hard-coded allowlist. Any other token_env is rejected so
        # the config cannot point at an arbitrary env var the
        # caller happens to have set. The PlayBook only ever reads
        # CLOUDFLARE_API_TOKEN from the child env; the
        # account-name → env-var mapping is structural, not
        # configured.
        if token_env not in ("CLOUDFLARE_API_TOKEN",
                              "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                              "CLOUDFLARE_API_TOKEN_ACCOUNT_B"):
            raise NonRetryableError(
                f"cloudflare {operation}: token_env={token_env!r} is not "
                "an allowed account token name. Allowed: "
                "CLOUDFLARE_API_TOKEN, "
                "CLOUDFLARE_API_TOKEN_ACCOUNT_A, "
                "CLOUDFLARE_API_TOKEN_ACCOUNT_B."
            )
        token_value = os.environ.get(token_env, "")
        if not token_value:
            raise NonRetryableError(
                f"cloudflare {operation}: token_env={token_env!r} is not "
                f"set in the calling process. The token must be exported; "
                "the adapter will not invent a value or fall back to a "
                "different account."
            )
        from providers import register_secret
        register_secret(token_value)
        # Build the child env from the explicit allowlist. The token
        # is the only credential that crosses the boundary; it lands
        # in `CLOUDFLARE_API_TOKEN` for the playbook's one entrypoint.
        child_env = {k: os.environ[k] for k in ALLOWED_CHILD_ENV
                      if k in os.environ}
        child_env["CLOUDFLARE_API_TOKEN"] = token_value
        if credential_ref is not None:
            child_env["CLOUDFLARE_CREDENTIAL_REF"] = credential_ref
    else:
        # Legacy single-account path: the calling process already
        # carries CLOUDFLARE_API_TOKEN in its own env. We do NOT
        # silently fall back to any account token in this branch; the
        # two modes are mutually exclusive and the validator rejects
        # the legacy `allowed_records` block when `accounts:` is also
        # present.
        if not os.environ.get("CLOUDFLARE_API_TOKEN"):
            raise NonRetryableError(
                f"cloudflare {operation}: CLOUDFLARE_API_TOKEN is not set "
                "in the calling process. For the per-account path pass "
                "token_env='CLOUDFLARE_API_TOKEN_ACCOUNT_A' or "
                "'CLOUDFLARE_API_TOKEN_ACCOUNT_B' instead."
            )
        from providers import register_secret
        register_secret(os.environ["CLOUDFLARE_API_TOKEN"])
        # Legacy path: same allowlist. The per-account vars are NOT
        # in the allowlist, so they cannot reach the child.
        child_env = {k: os.environ[k] for k in ALLOWED_CHILD_ENV
                      if k in os.environ}

    try:
        # `runner(...)` is INSIDE this try/finally on purpose: if the
        # subprocess raises (TimeoutExpired, FileNotFoundError when the
        # binary is missing, etc.), `result_file_path` would leak on disk
        # otherwise — `tempfile.mkstemp` makes a 0o600 file that nothing
        # else cleans up. Putting the runner call here guarantees the
        # `finally:` removes the tmpfile on every exit path.
        completed = runner(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            env=child_env,
        )

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
