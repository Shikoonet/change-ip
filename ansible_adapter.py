#!/usr/bin/env python3
"""The three places a rotation touches the rest of this repo.

Deliberately thin. The DNS move is already solved by `make ip-change` (an
in-place Cloudflare PATCH, an API read-back as a gate, a dig report, an SSH
check, then monitoring-doctor), so nothing here re-implements any of it. What
is here is the safety collar around calling it.

WHY `make ip-change HOST=<alias>` AND NOT `ansible-playbook ... -l <alias>`.
ip-change.yml documents the reason in its own header: the last thing it does is
import monitoring-doctor.yml, whose plays run on monitoring_jumphost and
localhost. A `-l` filters those out and turns the health check into a no-op
that still prints a header. The Makefile target passes the alias as
`-e ip_change_host=`, which is also the value ip-change.yml gates on twice. So
the target IS the safety, and the offline test asserts the argv literally.

WHY THE INVENTORY EDIT IS PRINT-AND-WAIT AND NOT AUTOMATIC.
inventory/hosts.yml is this project's single source of truth (CLAUDE.md), and
`ansible_host` is the value every other playbook resolves through. A tool that
rewrites it mid-rotation would be editing the definition of "the node" while
the node is halfway between two addresses. `auto_edit_inventory` exists in the
config, defaults to false, and this MVP has no other value implemented — the
operator makes the edit, the tool waits.
"""

from __future__ import annotations

import subprocess
from typing import Any, Callable, Dict, List, Optional, Sequence

from providers import EscalationRequired, redact

IP_CHANGE_ARGV_TEMPLATE = ["make", "ip-change", "HOST={alias}"]


def ip_change_argv(alias: str) -> List[str]:
    return [part.format(alias=alias) for part in IP_CHANGE_ARGV_TEMPLATE]


def dns_records_touched(alias: str, node_record_zone: str) -> List[str]:
    """The record `make ip-change` will move — exactly one, by construction.

    ip-change.yml touches `<alias>.<cf_node_record_zone>` and nothing else; the
    public verb name in cf_zone is not in its scope. Derived rather than
    configured so the allow-list check cannot be passed by mistyping the thing
    being allowed.
    """
    return [f"{alias}.{node_record_zone}"]


def check_dns_allowlist(touched: Sequence[str], allowed: Sequence[str]) -> List[str]:
    """Return the records that are NOT on the allow-list. Empty means proceed.

    A run stops at `validated` when this is non-empty. The point is not to
    catch a typo in this file — it is to make "which live DNS name may this
    change" a value the operator wrote down once, in the config, rather than
    something inferred from an inventory that may have been edited an hour ago
    for an unrelated reason.
    """
    allowed_set = {str(a).strip().lower() for a in allowed}
    return [r for r in touched if str(r).strip().lower() not in allowed_set]


def inventory_step(
    alias: str,
    inventory: str,
    old_ip: str,
    new_ip: str,
    auto_edit: bool = False,
    prompt: Callable[[str], str] = input,
    out: Callable[[str], None] = print,
) -> None:
    """Print the edit the operator must make, then block until they confirm.

    Raises EscalationRequired if auto_edit is on: the MVP has no implementation
    for it, and silently ignoring a config flag that says "write to my source
    of truth" is worse than refusing.
    """
    if auto_edit:
        raise EscalationRequired(
            "auto_edit_inventory: true is not implemented. inventory/hosts.yml is "
            "this project's single source of truth and nothing writes to it "
            "automatically. Set it back to false and make the edit by hand.",
            [f"$EDITOR {inventory}   # {alias}: ansible_host: {old_ip} -> {new_ip}"],
        )

    out("")
    out("=" * 72)
    out(f"  EDIT THE INVENTORY NOW — {inventory}")
    out("")
    out(f"    {alias}:")
    out(f"      ansible_host: {old_ip}      <-- change this")
    out(f"      ansible_host: {new_ip}      <-- to this")
    out("")
    out("  Inventory is the source of truth; the DNS step below makes Cloudflare")
    out("  agree with it, not the other way round. Nothing continues until the")
    out("  file on disk says the new address.")
    out("=" * 72)

    while True:
        answer = prompt(f"Typed the new address into {inventory}? [yes/abort] ").strip().lower()
        if answer == "yes":
            return
        if answer == "abort":
            raise EscalationRequired(
                "Operator aborted at the inventory step. The new address is already "
                "on the server; the inventory and DNS still point at the old one.",
                [
                    f"$EDITOR {inventory}   # set {alias}.ansible_host: {new_ip}",
                    f"make ip-change HOST={alias}",
                ],
            )


def run_ip_change(
    alias: str,
    cwd: str,
    runner: Callable[..., Any] = subprocess.run,
    timeout: Optional[int] = 1800,
) -> Dict[str, Any]:
    """Shell `make ip-change HOST=<alias>` in the repo root and report the rc.

    A non-zero rc does NOT roll the IP back. ip-change.yml is idempotent and
    the address is already correct on the box at this point; swapping the IP
    back to fix a Cloudflare hiccup would take a working node offline to undo a
    DNS record. The caller escalates with `resume` as the remedy instead.
    """
    argv = ip_change_argv(alias)
    completed = runner(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "argv": argv,
        "rc": int(getattr(completed, "returncode", 1)),
        "stdout_tail": redact(getattr(completed, "stdout", "") or "")[-4000:],
        "stderr_tail": redact(getattr(completed, "stderr", "") or "")[-4000:],
    }
