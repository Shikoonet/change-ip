#!/usr/bin/env python3
"""The guest-network adapter for a DataForest rotation.

Models `ansible_adapter.run_ip_change()` and `cloudflare_adapter.run_cloudflare_op()`
because the rest of this repo already adopts the seam "production shells
ansible-playbook, tests substitute a callable". The same pattern fits here:

  * `dataforest_step.yml` is the only file that mutates the guest OS
  * `DataForestGuestAdapter` shells it as a subprocess and validates
    the result JSON before returning it
  * tests use a fake that returns the same shape

Supported ops:
  * detect_network_manager — read which manager is in play
  * configure_guest        — runtime add NEW_IP, persist, capture checksums
  * verify_guest           — TCP probe, ssh-keyscan, service probes
  * remove_guest_address   — temporarily drop OLD_IP during finalize prep
  * restore_guest          — checksum-verified rollback of persistent files

NO SECRETS in argv. The only values passed on -e are interface names,
addresses, and the txid — every one of them is already public. Any
flag the playbook later needs that involves a secret gets its own
adapter.
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

HERE = os.path.dirname(os.path.abspath(__file__))
PLAYBOOK = os.path.join(HERE, "dataforest_step.yml")

OPS = (
    "detect_network_manager",
    "configure_guest",
    "verify_guest",
    "remove_guest_address",
    "restore_guest",
)


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


def guest_op_argv(op: str, result_file: str, invocation_id: str) -> List[str]:
    extra = [
        "-e", f"op={op}",
        "-e", f"step_out={result_file}",
        "-e", f"invocation_id={invocation_id}",
    ]
    return _ansible_playbook_argv(os.path.basename(PLAYBOOK), extra)


def _serialisable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


# Interface / CIDR / address sanitisation. We refuse to pass anything
# that isn't already a strict-validated value — the adapter is the seam
# between rotate.py (which validates) and the playbook argv.
_INTERFACE = re.compile(r"^[A-Za-z0-9_:\-.]{1,15}$")
_ADDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")


def _check_interface(name: str) -> str:
    if not isinstance(name, str) or not _INTERFACE.match(name):
        raise NonRetryableError(f"guest adapter: interface name {name!r} is invalid")
    return name


def _check_address(value: str) -> str:
    if not isinstance(value, str) or not _ADDR.match(value.strip()):
        raise NonRetryableError(f"guest adapter: address {value!r} is invalid")
    return value.strip()


def run_guest_op(
    op: str,
    *,
    txid: str,
    invocation_id: str,
    interface: Optional[str] = None,
    snapshot: Optional[Dict[str, Any]] = None,
    new_address: Optional[str] = None,
    old_address: Optional[str] = None,
    gateway: Optional[str] = None,
    expected_host_key_pattern: Optional[str] = None,
    service_probes: Optional[List[Dict[str, Any]]] = None,
    backup_files: Optional[List[str]] = None,
    expected_checksums: Optional[Dict[str, str]] = None,
    ssh_keyscan_timeout: int = 5,
    runner: Callable[..., Any] = subprocess.run,
    timeout: int = 600,
) -> Dict[str, Any]:
    """Run one guest op and return its structured result.

    Returned shape mirrors the other adapters so rotate.py does not need
    a separate code path:
      {
        "argv": [...],
        "rc": int,
        "result": {...},                # the playbook's JSON file
        "stdout_tail": "...",
        "stderr_tail": "...",
      }
    """
    if op not in OPS:
        raise NonRetryableError(f"guest adapter: unknown op {op!r}")
    if not invocation_id:
        raise NonRetryableError("guest adapter: invocation_id is required")
    if not txid:
        raise NonRetryableError("guest adapter: txid is required")

    # mkstemp + chmod 0600 so a tmpfile does not leak on disk. The
    # playbook atomically writes its result there.
    fd, result_file = tempfile.mkstemp(prefix="df_guest_result_", suffix=".json")
    os.close(fd)
    os.chmod(result_file, 0o600)

    argv = guest_op_argv(op, result_file, invocation_id)

    blob_args: Dict[str, Any] = {
        "txid": _serialisable(txid),
        "invocation_id": _serialisable(invocation_id),
    }
    if interface is not None:
        blob_args["interface"] = _check_interface(interface)
    if snapshot is not None:
        blob_args["snapshot"] = json.dumps(snapshot)
    if new_address is not None:
        blob_args["new_address"] = _check_address(new_address)
    if old_address is not None:
        blob_args["old_address"] = _check_address(old_address)
    if gateway is not None:
        blob_args["gateway"] = _check_address(gateway)
    if expected_host_key_pattern is not None:
        if not isinstance(expected_host_key_pattern, str):
            raise NonRetryableError(
                "guest adapter: expected_host_key_pattern must be a string"
            )
        blob_args["expected_host_key_pattern"] = expected_host_key_pattern
    if service_probes is not None:
        blob_args["service_probes"] = json.dumps(service_probes)
    if backup_files is not None:
        blob_args["backup_files"] = json.dumps(backup_files)
    if expected_checksums is not None:
        blob_args["expected_checksums"] = json.dumps(expected_checksums)
    if ssh_keyscan_timeout:
        blob_args["ssh_keyscan_timeout"] = int(ssh_keyscan_timeout)

    for k, v in blob_args.items():
        argv.extend(["-e", f"{k}={v}"])

    completed = runner(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )

    try:
        result: Optional[Dict[str, Any]] = None
        try:
            with open(result_file, "r", encoding="utf-8") as handle:
                result = json.load(handle)
        except (OSError, ValueError) as exc:
            rc = int(getattr(completed, "returncode", 1))
            stdout_tail = redact(getattr(completed, "stdout", "") or "")[-4000:]
            stderr_tail = redact(getattr(completed, "stderr", "") or "")[-4000:]
            if rc != 0:
                raise EscalationRequired(
                    f"guest {op} exited {rc} with no result JSON",
                    [
                        f"ansible-playbook dataforest_step.yml -e op={op} "
                        f"-e step_out=/tmp/df.json -e invocation_id={invocation_id} "
                        "(re-run with full -e blobs)"
                    ],
                ) from exc
            raise RetryableError(
                f"guest {op}: result file unreadable ({exc!r})"
            ) from exc

        rc = int(getattr(completed, "returncode", 1))
        if not isinstance(result, dict):
            raise NonRetryableError(
                f"guest {op}: result JSON is not an object "
                f"(got {type(result).__name__})"
            )
        if "op" in result and str(result["op"]) != op:
            raise NonRetryableError(
                f"guest {op}: result JSON claims op={result['op']!r}"
            )
        if "invocation_id" in result and str(result["invocation_id"]) != invocation_id:
            raise NonRetryableError(
                f"guest {op}: result JSON invocation_id mismatch"
            )

        return {
            "argv": argv,
            "rc": rc,
            "result": redact_tree(result),
            "stdout_tail": redact(getattr(completed, "stdout", "") or "")[-4000:],
            "stderr_tail": redact(getattr(completed, "stderr", "") or "")[-4000:],
        }
    finally:
        try:
            os.remove(result_file)
        except OSError:
            pass


def redact_tree(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(v) for v in value]
    return value