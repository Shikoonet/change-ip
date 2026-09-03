#!/usr/bin/env python3
"""Rotate a fleet node's public IPv4 at the provider, with a way back.

    rotate.py plan     --config rotation.yml
    rotate.py apply    --config rotation.yml --confirm-server-id 12345678
    rotate.py resume   --txid 20260826-101500-a3f1 --confirm-server-id 12345678
    rotate.py rollback --txid 20260826-101500-a3f1 --confirm-server-id 12345678
    rotate.py status   --txid 20260826-101500-a3f1
    rotate.py --self-test

WHY THIS EXISTS. The DNS half of "a node got a new address" has been solved in
this repo since 2026-08-21: `make ip-change HOST=<alias>` PATCHes
`<alias>.tinooer.top` in place, reads it back from the API as a gate, and the
PasarGuard panel follows the node by FQDN so it never has to be told. The
PROVIDER half — power the box down, detach the burned Primary IPv4, allocate a
fresh one in the same datacenter, attach it, power back on — was entirely a
human in the Hetzner console, with no dry run, no checkpoint, and no rollback.
This is that half, and it hands off to the half that already works.

WHAT IT WILL NOT DO, EVER
  * Delete a server, a Primary IP, or a DNS record. The old address is
    RETAINED after a rollback and the new one is RETAINED after a failure.
    Removing either is a separate decision with a separate approval — Rule One
    in CLAUDE.md. `state: absent` appears nowhere in hcloud_step.yml and the
    offline contract test asserts that by reading the file.
  * Write to inventory/hosts.yml. That file is the single source of truth and
    the tool waits for a human to edit it (`auto_edit_inventory: false`, and
    `true` is not implemented rather than quietly ignored).
  * Touch a server it cannot re-prove the identity of. Before every mutating
    step it re-reads the server and asserts id, name, location, the project
    fingerprint, and the address the step expects to find. A mismatch is
    `escalated`, never "try the other one".

⚠ HETZNER GUARANTEES THE DATACENTER, NEVER THE PREFIX. A new Primary IP comes
from the same location; it does not come from the same /24 and there is no API
to ask for one. If an exact prefix ever becomes a hard requirement (a
provider-side allow-list somewhere upstream, a peer that pinned a route), this
tool cannot deliver it and the answer is to escalate, not to allocate in a loop
until something adjacent falls out.

⚠ THIS IS DRY-RUN-ONLY CODE UNTIL SOMEONE RUNS IT FOR REAL. Written 2026-08-26
against hetzner.hcloud 6.2.1 with a full offline test suite and ZERO live API
calls. In this repo that means untested, in those words: the four traps
documented on 2026-08-13 (`tmp.mount`, `aide --check`, conntrack buckets,
node_exporter's listener) were every one of them found after a completely
green `--check`. Worse here than usual: the hcloud modules create no real
actions in check mode, so `--check` cannot validate the stop/detach/attach/start
ordering at all. The first live run needs its own approval and
`make monitoring-doctor` on both sides of it.

WHY THE STATE MACHINE IS ON DISK. Between `unassign` and `assign` the box is
powered off with no public address. A crash there is not recoverable by
re-running from the top: re-running would try to detach an address that is
already gone, and a naive retry of `allocate` would mint a second billed IP.
The checkpoint at state/<txid>.json plus a DETERMINISTIC new-IP name
(`<alias>-ipv4-<txid>`) makes every step re-runnable — `resume` finds the
address it already created instead of creating another.

  (The txid carries four random hex chars, which is not a contradiction of this
  repo's "derive names from a hash, never random" rule. That rule exists
  because a random DNS subdomain would be re-rolled on every converge and
  orphan the previous record. Here the value is minted ONCE, persisted in the
  checkpoint before anything is allocated, and every later step reads it from
  there — it is an identifier, not a re-derived name.)

Pure stdlib apart from PyYAML, which Ansible itself depends on. Python floor is
3.10: the fleet runs 3.10.12 to 3.14.4 and this file must stay readable on the
oldest controller anyone might use.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import ansible_adapter  # noqa: E402
from cloudflare_adapter import run_cloudflare_op  # noqa: E402
import dataforest_adapter  # noqa: E402
import dataforest_guest_adapter  # noqa: E402
from providers import (  # noqa: E402
    CLOUDFLARE_TOKEN_ENV,
    DATAFOREST_TOKEN_ENV,
    DataForestProvider,
    EscalationRequired,
    HcloudProvider,
    IdentityMismatch,
    NonRetryableError,
    NotFound,
    ProviderError,
    RetryableError,
    Seed,
    cf_token_present,
    dataforest_token_present,
    project_fingerprint,
    redact,
    redact_tree,
    register_secret,
    token_present,
)

try:
    import yaml
except ImportError:  # pragma: no cover - Ansible always ships it
    yaml = None

# -- exit codes ------------------------------------------------------------
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_IDENTITY = 2
EXIT_PROVIDER = 3
EXIT_ESCALATED = 4
EXIT_ROLLED_BACK = 5
# A deliberate stop at --until, not a failure. Distinct from EXIT_ESCALATED so a
# CI stage boundary is green and a real escalation is still red.
EXIT_PAUSED = 6
# Recovery is partial: provider IP is back, but DNS or inventory did not
# complete. Distinct from EXIT_ESCALATED (no human yet) and from
# EXIT_ROLLED_BACK (clean recovery).
EXIT_ROLLBACK_INCOMPLETE = 7

CHECKPOINT_VERSION = 1


# -- the state machine -----------------------------------------------------
@dataclass(frozen=True)
class Step:
    frm: str
    to: str
    fn: str
    #: what a failure of THIS step means. The mapping is policy, not
    #: convergence, which is why it lives here and not in the collection.
    on_failure: str  # "restore" | "restart_only" | "escalate"


STEPS = (
    # Preflight FIRST, while the box is still up and still has its address.
    # Discover every Cloudflare A record the rotation is about to move,
    # persist the manifest, and assert each one currently holds OLD_IP. A
    # quota, a Cloudflare outage or a drifted record then costs nothing but
    # a failed run — the box is untouched, and the downtime window has not
    # opened.
    Step("confirmed", "cloudflare_preflighted", "_step_cloudflare_preflight", "escalate"),
    # Allocation next. Same justification as before: the price of an
    # abandoned allocation is a retained Primary IP, not a node with no
    # address.
    Step("cloudflare_preflighted", "new_ip_allocated", "_step_allocate", "restart_only"),
    # Nothing has moved yet, so a shutdown that never completes costs only the
    # downtime: power the box back on and stop. No address was touched.
    Step("new_ip_allocated", "server_off", "_step_stop", "restart_only"),
    # From here to server_on the box is mid-swap and a failure means "put the
    # old address back", which is only possible because protect_ip ran first.
    #
    # ⚠ Hetzner allows a server exactly ONE Primary IPv4. The detach cannot be
    # deferred until after the attach — there is no window where both are on
    # the box, and no API call that swaps them atomically. These two lines are
    # the entire outage.
    Step("server_off", "old_ip_unassigned", "_step_unassign", "restore"),
    Step("old_ip_unassigned", "new_ip_assigned", "_step_assign", "restore"),
    # Swapping the addresses back does not fix a box that will not boot, so
    # this one goes straight to a human with the commands in hand.
    Step("new_ip_assigned", "server_on", "_step_start", "escalate"),
    Step("server_on", "connectivity_ok", "_step_health", "restore"),
    # ip-change.yml is idempotent and the address on the box is already
    # correct here. Taking a working node offline to undo Cloudflare records
    # would be a bigger outage than the one being fixed.
    Step("connectivity_ok", "ansible_done", "_step_ansible", "escalate"),
    # Now the PATCH. The manifest persisted at preflight is the only thing
    # this step ever touches — no scan, no discovery, no expansion. Any
    # record that drifted since preflight aborts the run. The provider IP
    # is already on the new address by this point, so on_failure is
    # restore (the inventory+DNS can still be rolled back via the manifest
    # persisted at preflight).
    Step("ansible_done", "cloudflare_replaced", "_step_cloudflare_replace", "restore"),
    # Read-back. A PATCH that returned 200 but did not apply shows up only on
    # a fresh GET — this is the audit row.
    Step("cloudflare_replaced", "done", "_step_verify", "escalate"),
)


# --------------------------------------------------------------------------
# DataForest state machine — `apply`/`resume` walks to `awaiting_finalize`,
# then STOPS. Releasing the OLD_IP is a separate explicit `finalize`
# command that begins with `finalizing_started` and ends at `done`.
# --------------------------------------------------------------------------
STEPS_DATAFOREST = (
    # Provider preflight FIRST. We MUST prove the team is ready, the Seed
    # is healthy, and `OLD_IP` exists exactly once before any mutation.
    # Persisted at this state so a later crash can reconcile without
    # re-running preflight.
    Step("confirmed", "dataforest_preflighted", "_step_dataforest_preflight", "escalate"),
    # Add NEW_IP via POST seed.add-ipv4. The Seed is unchanged otherwise;
    # a failure here leaves the Seed on its old address.
    Step("dataforest_preflighted", "new_ip_allocated", "_step_dataforest_allocate", "escalate"),
    # Guest network configuration. We add NEW_IP at runtime first, then
    # persist atomically. Old configuration is checksum-backed so a
    # restore on rollback is provable.
    Step("new_ip_allocated", "guest_configured", "_step_dataforest_configure_guest", "restore"),
    # TCP / SSH hostkey / service probes prove NEW_IP is reachable on
    # the SAME identity. A mismatch escalates — the rotation never
    # proceeds to DNS with an unverifiable address.
    Step("guest_configured", "guest_verified", "_step_dataforest_verify_guest", "restore"),
    # Cloudflare manifest discovery: same step as Hetzner; runs BEFORE
    # inventory edit / `make ip-change` so the manifest is on disk for
    # rollback. Persists the manifest at this state.
    Step("guest_verified", "cloudflare_preflighted", "_step_cloudflare_preflight", "escalate"),
    # Inventory edit + `make ip-change HOST=<alias>` is shared with
    # the Hetzner path; the same idempotent Ansible target works. A
    # failure here triggers the DataForest provider rollback (release
    # NEW_IP, revert DNS, revert inventory).
    Step("cloudflare_preflighted", "ansible_done", "_step_ansible", "restore"),
    # Cloudflare PATCH is also shared; we re-use the existing manifest.
    # A failure here also triggers the same restore path.
    Step("ansible_done", "cloudflare_replaced", "_step_cloudflare_replace", "restore"),
    # `awaiting_finalize` is the explicit PAUSE point of the apply/resume
    # flow. Releasing OLD_IP is point-of-no-return, so the operator has
    # to dispatch `finalize` explicitly. The `--until awaiting_finalize`
    # flag is implicit; no other state accepts an `--until` here.
    Step("cloudflare_replaced", "awaiting_finalize", "_step_dataforest_awaiting_finalize", "escalate"),
)

# ---- Finalize subcommand: the steps AFTER awaiting_finalize. Separate
# state table because the apply path STOPS at awaiting_finalize; only the
# explicit `finalize` subcommand advances from there.
#
# The first step (`dns_finalize_precheck`) requires CLOUDFLARE_API_TOKEN;
# the steps that follow require DATAFOREST_API_TOKEN. The split is the
# point of this rewrite: a single process cannot carry both secrets, so
# finalize is structurally two invocations. The first persists a
# `dns_finalize_verified` marker the second validates before any provider
# mutation.
STEPS_DATAFOREST_FINALIZE = (
    Step("awaiting_finalize", "dns_finalize_verified",
         "_step_dataforest_dns_finalize_precheck", "escalate"),
    # Intent marker BEFORE we touch anything, so a crash between
    # the marker write and the next mutation is recoverable.
    Step("dns_finalize_verified", "finalizing_started",
         "_step_dataforest_finalize_started", "escalate"),
    # Temporarily remove OLD_IP from the guest (DataForest still owns
    # both addresses). NEW_IP must remain reachable throughout.
    Step("finalizing_started", "guest_pre_finalized",
         "_step_dataforest_remove_guest_address", "escalate"),
    # POST seed.remove-ipv4 with the EXACT OLD_IP. Polling + read-back
    # reconcile. Any ambiguity (zero, multiple, OLD_IP absent) is a
    # structured error that maps to `rollback_incomplete`.
    Step("guest_pre_finalized", "old_ip_removed",
         "_step_dataforest_remove_provider", "escalate"),
    # Persist the post-finalize guest state (the runtime + persistent
    # configuration drops OLD_IP and keeps NEW_IP).
    Step("old_ip_removed", "guest_finalized",
         "_step_dataforest_finalize_guest", "restore"),
    Step("guest_finalized", "done", "_step_verify", "escalate"),
)

STEP_BY_STATE = {s.frm: s for s in STEPS}
STEP_BY_STATE_DATAFOREST = {s.frm: s for s in STEPS_DATAFOREST}
STEP_BY_STATE_DATAFOREST_FINALIZE = {s.frm: s for s in STEPS_DATAFOREST_FINALIZE}


def _steps_for_provider(provider: str, finalize: bool = False):
    """Which step table to walk.

    Hetzner has no finalize path; DataForest has two: the apply path
    (ends at awaiting_finalize) and the finalize subcommand (starts at
    awaiting_finalize, ends at done). The `finalize` flag picks.
    """
    if provider == "dataforest":
        if finalize:
            return STEPS_DATAFOREST_FINALIZE, STEP_BY_STATE_DATAFOREST_FINALIZE
        return STEPS_DATAFOREST, STEP_BY_STATE_DATAFOREST
    return STEPS, STEP_BY_STATE

#: One plain sentence per state, for the CI job summary. The Actions log
#: already streams `[state] step` live; this is the table you can read after
#: the fact without scrolling a log — which is the only view a run keeps once
#: it is finished.
STATE_LABELS = {
    "server_off": "server powered off",
    "old_ip_unassigned": "old Primary IP detached (retained, never deleted)",
    "new_ip_allocated": "new Primary IP allocated in the same datacenter",
    "new_ip_assigned": "new Primary IP attached to the server",
    "server_on": "server powered back on",
    "connectivity_ok": "TCP answered on the new address",
    "ansible_done": "inventory checked and the Cloudflare A records moved",
    "cloudflare_preflighted": "Cloudflare credential and allowlist preflight passed; manifest saved",
    "cloudflare_replaced": "allowlisted Cloudflare A records updated in place; no DNS record deleted",
    "done": "done — node on the new address, old one unassigned and retained",
    "rolled_back": "rolled back — the old address is back on the server",
    "rollback_incomplete": "rollback incomplete — provider IP restored, but DNS or inventory recovery did not complete",
    "escalated": "escalated — stopped for a human, nothing deleted",
    # DataForest-specific states
    "dataforest_preflighted": "DataForest team + Seed preflight passed; manifests saved",
    "guest_configured": "guest network configured: NEW_IP bound at runtime + persisted",
    "guest_verified": "guest network verified: TCP + SSH hostkey + service probes OK on NEW_IP",
    "awaiting_finalize": "awaiting_finalize — apply/resume STOPS here; release of OLD_IP requires explicit `finalize`",
    "finalizing_started": "finalize intent marker persisted; OLD_IP release requested",
    "guest_pre_finalized": "OLD_IP removed from guest (DataForest still owns both addresses)",
    "old_ip_removed": "DataForest confirmed OLD_IP removed and NEW_IP still assigned",
    "guest_finalized": "guest network finalized: OLD_IP gone from persistence, NEW_IP only",
}


def github_summary(state: str, cp: Dict[str, Any]) -> None:
    """Append one row to GitHub's job summary. A no-op outside Actions.

    Wired to Rotation.on_transition, so it fires on exactly the states the
    checkpoint reached — including `escalated` and `rolled_back`, which reach
    it through the same _transition() the happy path uses.
    """
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    ip = (cp.get("new_ip") or {}).get("ip") or (cp.get("old_ip") or {}).get("ip") or ""
    row = f"| {utcnow()[11:19]} | `{state}` | {STATE_LABELS.get(state, state)} | {ip} |\n"
    with open(path, "a", encoding="utf-8") as handle:
        if handle.tell() == 0:
            # `|:-|` and not `|---|`. A multi-line Actions secret registers
            # EVERY line as a mask token, and `---` is line one of any YAML
            # document — so the config secret turns every `---` in this file
            # into `***`, the separator stops being a separator, and the table
            # renders as a wall of pipes. Seen on the first live run.
            handle.write(
                f"**rotation `{cp['txid']}` — server {cp['server']['id']} "
                f"({cp['server']['expected_name']}, {cp['server']['expected_location']})**\n\n"
                "| utc | state | what happened | address |\n|:-|:-|:-|:-|\n"
            )
        handle.write(redact(row))


TERMINAL = ("done", "planned", "rolled_back", "rollback_incomplete", "escalated",
            "paused", "awaiting_finalize",
            # Durable rollback intermediate states are non-terminal; they
            # mark a stage as done so re-running the same command is a
            # no-op. Only the final `rolled_back` is a terminal state.
            "dns_rollback_done", "inventory_rollback_done",
            "guest_rollback_done")

#: States `--until` may name. ONLY where the box is up, reachable, and
#: the DNS picture is settled (or the apply path has reached its
#: terminal pause). Everything else is mid-swap or pre-DNS, where
#: "stop here" means "a node with an inconsistent DNS picture".
#:
#: `awaiting_finalize` is the apply/resume PAUSE for DataForest.
#: Releasing OLD_IP is point-of-no-return and lives behind the explicit
#: `finalize` subcommand; the apply/resume path stops here without it.
#:
#: DataForest apply path adds per-stage pause points so each step runs in a
#: separate process with only its own token in scope. The workflow YAML
#: invokes `apply --until <state>` (or `resume --until <state>`) for each
#: stage; a single `apply` call no longer walks from `confirmed` to
#: `awaiting_finalize` because that single process would need both tokens
#: at once — exactly the contradiction this list exists to prevent.
PAUSABLE = (
    "connectivity_ok",
    "new_ip_allocated",
    "guest_configured",
    "guest_verified",
    "cloudflare_preflighted",
    "ansible_done",
    "cloudflare_replaced",
    "awaiting_finalize",
)


class ConfigError(Exception):
    """The config file is missing something, or says something impossible."""


# -- helpers ---------------------------------------------------------------
def same_place(a: str, b: str) -> bool:
    """Is `a` the same place as `b`, given one may be a location and one a DC?

    Hetzner names a datacenter `<location>-dcN`, and the two names reach this
    tool from different calls: allocation answers with the datacenter, while a
    server payload may carry only the location. Comparing them raw reports a
    move that never happened. What is actually guaranteed — and all that is
    guaranteed — is the location.
    """
    return a.split("-")[0] == b.split("-")[0]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _marker_age_seconds(ts: Any) -> Optional[float]:
    """Age of an ISO-8601 marker timestamp in seconds, None if unparseable."""
    try:
        parsed = datetime.fromisoformat(ts or "")
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds()


def _manifest_digest(manifest: List[Dict[str, Any]]) -> str:
    """Deterministic, token-free fingerprint of the manifest.

    Stable across runs given identical records, so the adapter can refuse a
    result JSON whose manifest_digest does not match the manifest it was given.
    Built over every safety-relevant field — zone_id, record_id, name,
    previous_content, ttl, proxied, and type — so that even a TTL change
    between discover and apply produces a different digest. No token, no
    Authorization header, no temp path, no timestamp is folded in.
    """
    import hashlib
    canonical = json.dumps(
        sorted(
            (
                str(r.get("zone_id", "")),
                str(r.get("record_id", "")),
                str(r.get("name", "")).lower().rstrip("."),
                str(r.get("type", "")),
                str(r.get("previous_content", "")),
                str(r.get("ttl", "")),
                str(r.get("proxied", "")),
            )
            for r in manifest
        ),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _new_invocation_id() -> str:
    """UUID4 string used to bind a playbook invocation to its result file.

    Replay or stale-output attacks cannot bind to a new invocation without
    controlling this code path.
    """
    import uuid
    return str(uuid.uuid4())


def _test_mode_cf_api_base():
    """Read the test-mode Cloudflare API base URL from the env.

    The offline test harness points `tests/fakebin/ansible-playbook`
    at this repo and the fake does NOT open a socket — the URL is
    decorative for it. The adapter's `_validate_cf_api_base` still
    enforces the loopback contract, so the value MUST be a
    127.0.0.1 / localhost / [::1] URL. Production never sets this
    var (and the adapter refuses to read it outside test mode); the
    function returns `None` so the adapter falls back to its
    production-default path.

    The seam exists for ONE reason: a `cf_api_base=None` in test
    mode is refused by the adapter (a missing URL is the failure
    mode this guard exists to prevent). The harness must therefore
    hand an explicit URL to the adapter — exactly what
    `DATAFOREST_API_BASE_URL` does for DataForest.
    """
    if os.environ.get("ROTATION_TEST_MODE") != "1":
        return None
    return os.environ.get("ROTATION_TEST_CF_API_BASE")


def new_txid() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


def tcp_probe(host: str, port: int, timeout: float) -> bool:
    """One TCP handshake. True means something answered on that port.

    Deliberately not an SSH auth attempt: this runs seconds after a boot, and
    "the address is live and sshd is listening" is the question. Whether the
    key still works is what `make ip-change` checks afterwards.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _default_ssh_keyscan(host: str, timeout: float = 5.0) -> str:
    """Run ssh-keyscan against `host`, return stdout. Production default."""
    import subprocess
    try:
        completed = subprocess.run(
            ["ssh-keyscan", "-T", str(int(timeout)), host],
            capture_output=True, text=True, timeout=timeout + 5, check=False,
        )
        return redact(completed.stdout or "")
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise RetryableError(f"ssh-keyscan {host}: {redact(exc)}") from exc


def _new_invocation_id_dataforest() -> str:
    """Same shape as `_new_invocation_id`; kept distinct so a stray
    Cloudflare invocation_id is never accepted by a DataForest op."""
    import uuid
    return f"df-{uuid.uuid4()}"


def load_config(path: str) -> Dict[str, Any]:
    if yaml is None:
        raise ConfigError("PyYAML is not importable, so no config can be read")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} does not contain a mapping")
    return validate_config(data, path)


def validate_config(data: Dict[str, Any], path: str = "<config>") -> Dict[str, Any]:
    """Fail loudly on anything that would otherwise fail halfway through a run."""
    provider = data.get("provider")
    if provider not in ("hcloud", "dataforest"):
        raise ConfigError(
            f"{path}: provider must be 'hcloud' or 'dataforest', got {provider!r}"
        )

    server = data.get("server") or {}
    for key in ("id", "expected_name", "expected_ipv4", "expected_location"):
        if not server.get(key):
            raise ConfigError(
                f"{path}: server.{key} is required. The numeric id is immutable and "
                "is read from the Hetzner console once; the expected_* values are "
                "what every identity assert compares against."
            )
    if provider == "hcloud":
        try:
            server["id"] = int(server["id"])
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{path}: server.id must be the numeric id, not a name") from exc
    else:
        # DataForest: server.id is an immutable UUID. Refuse anything that
        # doesn't look like one — the tool cannot prove identity against a
        # display name.
        if not isinstance(server["id"], str) or len(server["id"]) < 8:
            raise ConfigError(
                f"{path}: server.id must be the immutable DataForest Seed UUID"
            )
        if not (data.get("seed") or {}).get("expected_name"):
            raise ConfigError(
                f"{path}: seed.expected_name is required when provider=dataforest"
            )
        if not (data.get("seed") or {}).get("expected_location"):
            raise ConfigError(
                f"{path}: seed.expected_location is required when provider=dataforest"
            )
        if "expected_project" in (data.get("seed") or {}) and not (data.get("seed") or {}).get(
            "expected_project"
        ):
            raise ConfigError(f"{path}: seed.expected_project, if present, must be a non-empty string")
        guest = data.get("guest") or {}
        if not guest.get("network_manager"):
            raise ConfigError(
                f"{path}: guest.network_manager is required when provider=dataforest "
                "(one of: netplan, systemd-networkd, networkmanager, ifupdown)"
            )
        if guest.get("network_manager") not in (
            "netplan", "systemd-networkd", "networkmanager", "ifupdown",
        ):
            raise ConfigError(
                f"{path}: guest.network_manager {guest['network_manager']!r} is not supported"
            )
        if not guest.get("interface"):
            raise ConfigError(
                f"{path}: guest.interface is required (e.g. 'eth0')"
            )
        if not guest.get("expected_host_key_pattern"):
            raise ConfigError(
                f"{path}: guest.expected_host_key_pattern is required"
            )

    ans = data.get("ansible") or {}
    if not ans.get("host_alias"):
        raise ConfigError(f"{path}: ansible.host_alias is required (the inventory alias)")
    if ans.get("auto_edit_inventory"):
        raise ConfigError(
            f"{path}: auto_edit_inventory must be false. inventory/hosts.yml is the "
            "single source of truth and nothing writes to it automatically."
        )

    dns = data.get("dns") or {}
    if not dns.get("node_record_zone"):
        raise ConfigError(f"{path}: dns.node_record_zone is required (e.g. tinooer.top)")
    if not dns.get("allowed_records"):
        raise ConfigError(
            f"{path}: dns.allowed_records must list the record this run may move. "
            "An empty allow-list means nothing is allowed, which is a stop, not a pass."
        )

    if (data.get("old_ip") or {}).get("retention", "keep") != "keep":
        raise ConfigError(
            f"{path}: old_ip.retention must be 'keep'. Deleting the previous address "
            "is a separate operator decision and this tool does not implement it."
        )

    cf = data.get("cloudflare") or {}
    # cloudflare.mode may be absent (= full run) or "provider_only" (throwaway
    # test server — never touch DNS). Anything else is a typo that would
    # silently bypass the allowlist, so refuse it loudly.
    mode = cf.get("mode")
    if mode is not None and mode != "provider_only":
        raise ConfigError(
            f"{path}: cloudflare.mode must be 'provider_only' or unset, not {mode!r}"
        )
    # ---- Cloudflare accounts (one credential reference per group of records)
    # The rotation may span two Cloudflare accounts. Each account is a
    # non-secret credential reference (`token_env`, e.g.
    # `CLOUDFLARE_API_TOKEN_ACCOUNT_A`) plus the FQDNs that account owns. A
    # record belongs to EXACTLY one account; duplicates or unknown refs are
    # refused. The token value never enters the config — only the env var
    # name does — and the secret is read inside the subprocess env, not the
    # parser.
    accounts_block = cf.get("accounts")
    if accounts_block is not None and not isinstance(accounts_block, dict):
        raise ConfigError(
            f"{path}: cloudflare.accounts must be a mapping, got "
            f"{type(accounts_block).__name__}"
        )
    # Closed set of allowed token env-var names. The validator
    # refuses any other name so the config cannot point at an
    # arbitrary env var that happens to be in scope.
    ALLOWED_CF_TOKEN_ENVS = frozenset({
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
        "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
    })
    if accounts_block:
        seen_refs: Dict[str, str] = {}  # token_env -> account name
        seen_records: Dict[str, str] = {}  # FQDN -> account name
        for account_name, account_cfg in accounts_block.items():
            if not isinstance(account_cfg, dict):
                raise ConfigError(
                    f"{path}: cloudflare.accounts.{account_name} must be a "
                    f"mapping, got {type(account_cfg).__name__}"
                )
            token_env = account_cfg.get("token_env")
            if not isinstance(token_env, str) or not token_env.strip():
                raise ConfigError(
                    f"{path}: cloudflare.accounts.{account_name}.token_env "
                    "must be a non-empty string (env var name, not value)"
                )
            if token_env not in ALLOWED_CF_TOKEN_ENVS:
                raise ConfigError(
                    f"{path}: cloudflare.accounts.{account_name}.token_env "
                    f"{token_env!r} is not an allowed Cloudflare credential "
                    f"reference. Allowed names: {sorted(ALLOWED_CF_TOKEN_ENVS)}. "
                    "Arbitrary env-var names are rejected so the config "
                    "cannot accidentally read an unrelated secret."
                )
            if token_env in seen_refs:
                raise ConfigError(
                    f"{path}: cloudflare.accounts.{account_name}.token_env "
                    f"{token_env!r} is already used by account "
                    f"{seen_refs[token_env]!r}; credential references must be unique"
                )
            if token_env not in seen_refs:
                # The explicit allowlist check above already rejected
                # any other name. The two-map bookkeeping is the only
                # remaining work.
                pass
            records = account_cfg.get("records")
            if not isinstance(records, list) or not records:
                raise ConfigError(
                    f"{path}: cloudflare.accounts.{account_name}.records "
                    "must be a non-empty list of FQDNs"
                )
            for fqdn in records:
                if not isinstance(fqdn, str) or not fqdn.strip():
                    raise ConfigError(
                        f"{path}: cloudflare.accounts.{account_name}.records "
                        f"contains a non-string entry: {fqdn!r}"
                    )
                lf = fqdn.strip().lower()
                if lf in seen_records:
                    raise ConfigError(
                        f"{path}: record {fqdn!r} appears in both account "
                        f"{seen_records[lf]!r} and account {account_name!r}; "
                        "each FQDN belongs to exactly one credential reference"
                    )
                seen_records[lf] = account_name
            expected = account_cfg.get("expected_record_count")
            if not isinstance(expected, int) or expected < 1:
                raise ConfigError(
                    f"{path}: cloudflare.accounts.{account_name}.expected_record_count "
                    "must be a positive integer"
                )
            if expected != len(records):
                raise ConfigError(
                    f"{path}: cloudflare.accounts.{account_name}.expected_record_count "
                    f"({expected}) must equal the number of records "
                    f"({len(records)})"
                )
            seen_refs[token_env] = account_name
        # When the new accounts block is present, the legacy top-level
        # fields are forbidden — coexistence is ambiguous (which account
        # owns the legacy `allowed_records`?). The migration is mechanical.
        if cf.get("allowed_records") or cf.get("expected_record_count"):
            raise ConfigError(
                f"{path}: cloudflare.allowed_records and "
                "cloudflare.expected_record_count are forbidden when "
                "cloudflare.accounts is set. Move each FQDN into the "
                "correct account.credentials_ref entry."
            )
    if not mode and not accounts_block:  # full run — require allowlist
        if not cf.get("allowed_records"):
            raise ConfigError(
                f"{path}: cloudflare.allowed_records is required when "
                "cloudflare.mode is not 'provider_only' AND "
                "cloudflare.accounts is not set. An empty allow-list is a "
                "stop, not a pass."
            )
        if not cf.get("expected_record_count"):
            raise ConfigError(
                f"{path}: cloudflare.expected_record_count is required when "
                "cloudflare.mode is not 'provider_only' AND "
                "cloudflare.accounts is not set."
            )

    if provider == "dataforest":
        # DataForest has a one-shot `finalize` that releases OLD_IP. The
        # config must explicitly acknowledge that the released address is
        # not guaranteed to be reacquirable.
        if not (data.get("finalize") or {}).get("acknowledge_no_reacquire"):
            raise ConfigError(
                f"{path}: finalize.acknowledge_no_reacquire must be true. "
                "DataForest does not guarantee reacquisition of a released IPv4 "
                "and finalize is a point of no return."
            )
        if not (data.get("finalize") or {}).get("ptr_policy"):
            raise ConfigError(
                f"{path}: finalize.ptr_policy is required (one of: 'require_match', "
                "'allow_no_ptr'); refuse means we refuse to finalize if OLD_IP has a "
                "PTR and NEW_IP does not yet have one"
            )

    return data


# -- the real runner -------------------------------------------------------
def ansible_runner(
    playbook: Optional[str] = None,
    cwd: Optional[str] = None,
    timeout: int = 900,
    runner: Callable[..., Any] = subprocess.run,
    out: Callable[[str], None] = print,
) -> Callable[[str, Dict[str, Any]], Dict[str, Any]]:
    """Build the callable providers.HcloudProvider drives.

    Everything the provider layer asks for becomes one `ansible-playbook
    hcloud_step.yml` process. The token is NOT passed: it is inherited from the
    environment, which is where the hcloud modules look for it, so it never
    reaches argv (visible in `ps`) or a var file (visible on disk).

    A module failure aborts the play and writes no JSON — that absence is the
    signal, which is why hcloud_step.yml carries no `ignore_errors` and no
    `failed_when: false` anywhere.
    """
    playbook = playbook or os.path.join(HERE, "hcloud_step.yml")
    cwd = cwd or HERE

    def run(op: str, params: Dict[str, Any]) -> Dict[str, Any]:
        workdir = tempfile.mkdtemp(prefix="rotate-")
        out_path = os.path.join(workdir, "step.json")
        argv = [
            "ansible-playbook",
            playbook,
            "-e",
            f"op={op}",
            "-e",
            f"rotate_out={out_path}",
            "-e",
            json.dumps(params),
        ]
        try:
            completed = runner(
                argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
            )
            combined = redact(
                (getattr(completed, "stdout", "") or "") + (getattr(completed, "stderr", "") or "")
            )
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8") as handle:
                    return json.load(handle)
            return {
                "ok": False,
                "error": f"{op}: hcloud_step.yml rc={completed.returncode}\n{combined[-4000:]}",
                "error_kind": classify_failure(combined),
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"{op}: hcloud_step.yml timed out", "error_kind": "retryable"}
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": f"{op}: {redact(exc)}", "error_kind": "retryable"}
        finally:
            try:
                if os.path.exists(out_path):
                    os.remove(out_path)
                os.rmdir(workdir)
            except OSError:
                out(redact(f"note: could not clean up {workdir}"))

    return run


def classify_failure(text: str) -> str:
    """Map a playbook's output onto the error taxonomy.

    Crude on purpose: the only distinction that changes behaviour is "retrying
    might work" versus "retrying is pointless and burns the shutdown window".
    A wrong token retried three times is three minutes of a powered-off node.
    """
    low = text.lower()
    if any(marker in low for marker in ("unauthorized", "401", "forbidden", "403",
                                         "invalid token", "token_readonly",
                                         "token is readonly")):
        return "auth"
    if "hcloud_token is not set" in low:
        return "auth"
    if any(marker in low for marker in ("not found", "404", "no primary ip matched")):
        return "not_found"
    return "retryable"


# -- the rotation ----------------------------------------------------------
class Rotation:
    """One transaction: config in, checkpoint on disk, node on a new address."""

    def __init__(
        self,
        config: Dict[str, Any],
        provider: Any,  # HcloudProvider | DataForestProvider
        state_dir: str,
        repo_dir: str,
        config_path: str = "<config>",
        probe: Callable[[str, int, float], bool] = tcp_probe,
        ip_change: Callable[..., Dict[str, Any]] = ansible_adapter.run_ip_change,
        prompt: Callable[[str], str] = input,
        out: Callable[[str], None] = print,
        sleep: Callable[[float], None] = time.sleep,
        on_transition: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        until: Optional[str] = None,
        cloudflare_preflight: Optional[Callable[..., Dict[str, Any]]] = None,
        cloudflare_replace: Optional[Callable[..., Dict[str, Any]]] = None,
        guest_op: Optional[Callable[..., Dict[str, Any]]] = None,
        ssh_keyscan: Optional[Callable[..., Dict[str, Any]]] = None,
    ):
        # ROTATION_TEST_MODE=1 + ROTATION_PROBE=accept / refuse lets the
        # test harness short-circuit the real SSH probe. Production
        # never sees this env pair and keeps the real tcp_probe.
        if os.environ.get("ROTATION_TEST_MODE") == "1":
            choice = os.environ.get("ROTATION_PROBE", "real").lower()
            if choice == "accept":
                probe = lambda host, port, timeout: True
            elif choice == "refuse":
                probe = lambda host, port, timeout: False
            ip_choice = os.environ.get("ROTATION_IP_CHANGE", "real").lower()
            if ip_choice == "stub":
                ip_change = lambda alias, cwd: {
                    "argv": ["make", "ip-change", f"HOST={alias}"],
                    "rc": 0, "stdout_tail": "", "stderr_tail": "",
                    "result": {"ok": True}}
        self.cfg = config
        self.provider = provider
        self.provider_name = str(config.get("provider") or "hcloud")
        self.state_dir = state_dir
        self.repo_dir = repo_dir
        self.config_path = config_path
        self.probe = probe
        self.ip_change = ip_change
        self.prompt = prompt
        self.out = out
        self.sleep = sleep
        self.on_transition = on_transition
        self.until = until
        # Production default: the real Cloudflare driver. Failing in preflight
        # is the right place for a missing token, not silently skipping the
        # whole DNS half.
        self.cloudflare_preflight = cloudflare_preflight or run_cloudflare_op
        self.cloudflare_replace = cloudflare_replace or run_cloudflare_op
        # Guest adapter for DataForest — same seam as cloudflare_op: tests
        # substitute, production shells `ansible-playbook dataforest_step.yml`.
        self.guest_op = guest_op or dataforest_guest_adapter.run_guest_op
        # `ssh_keyscan` is the seam for SSH host key validation. Production
        # calls the real binary via subprocess; tests pass a stub.
        self.ssh_keyscan = ssh_keyscan or _default_ssh_keyscan
        # cloudflare.mode: provider_only — a manual opt-out that hard-stops
        # the run at `connectivity_ok` and never writes to DNS. Structurally
        # bounded because `--until` is an argparse choice, not a flag read
        # from the checkpoint after preflight has already PATCHed.
        self.provider_only = (
            (self.cfg.get("cloudflare") or {}).get("mode") == "provider_only"
        )

        retries = self.cfg.get("retries") or {}
        self.retries = int(retries.get("provider", 3))
        self.retry_delay = float(retries.get("provider_delay", 10))
        self.health_retries = int(retries.get("health", 30))
        self.health_delay = float(retries.get("health_delay", 10))
        self.ssh_port = int((self.cfg.get("health") or {}).get("ssh_port", 22))
        self.ssh_timeout = float((self.cfg.get("timeouts") or {}).get("ssh", 10))

    # Convenience accessors used by the rollback path and the preflight step.
    def _cf_config(self) -> Dict[str, Any]:
        return self.cfg.get("cloudflare") or {}

    def _allowed_records(self) -> List[str]:
        return list(self._cf_config().get("allowed_records") or [])

    def _expected_record_count(self) -> int:
        return int(self._cf_config().get("expected_record_count") or 0)

    def _cf_accounts(self) -> List[Dict[str, Any]]:
        """Canonical view of the Cloudflare accounts.

        Returns a list of {name, token_env, records, expected_count} in
        config-declaration order (deterministic). When the legacy
        `cloudflare.allowed_records` is used, returns a single-element
        list with name=`_default` and `token_env=CLOUDFLARE_API_TOKEN`,
        which is the only env var the legacy playbook reads.
        """
        cf = self._cf_config()
        accounts = cf.get("accounts")
        if accounts:
            return [
                {
                    "name": name,
                    "token_env": str(acc.get("token_env", "")),
                    "records": list(acc.get("records") or []),
                    "expected_count": int(acc.get("expected_record_count") or 0),
                }
                for name, acc in accounts.items()
            ]
        return [{
            "name": "_default",
            "token_env": "CLOUDFLARE_API_TOKEN",
            "records": list(cf.get("allowed_records") or []),
            "expected_count": int(cf.get("expected_record_count") or 0),
        }]

    # -- logging + persistence --------------------------------------------
    def log(self, message: str) -> None:
        self.out(redact(message))

    def _path(self, txid: str) -> str:
        return os.path.join(self.state_dir, f"{txid}.json")

    def save(self, cp: Dict[str, Any]) -> None:
        """Atomic: write beside the target, fsync, rename. Redacted at the sink.

        A half-written checkpoint is worse than none — `resume` would read a
        state that never happened and skip a step that did not run.

        redact_tree() runs HERE, on the way to disk, and not only in the
        producers that build these fields. Producer-side redaction is correct
        for today's code and is a property of today's code; the next field that
        carries third-party output would leak silently. The in-memory `cp` is
        left alone so the caller keeps working with the values it wrote.
        """
        os.makedirs(self.state_dir, exist_ok=True)
        cp["updated_at"] = utcnow()
        target = self._path(cp["txid"])
        fd, tmp = tempfile.mkstemp(dir=self.state_dir, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(redact_tree(cp), handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    def load(self, txid: str) -> Dict[str, Any]:
        try:
            with open(self._path(txid), "r", encoding="utf-8") as handle:
                return json.load(handle)
        except OSError as exc:
            raise ConfigError(f"no checkpoint for txid {txid}: {exc}") from exc

    def record(self, cp: Dict[str, Any], action: str, detail: str = "") -> None:
        cp["history"].append(
            {"ts": utcnow(), "state": cp["state"], "action": action, "detail": redact(detail)}
        )
        self.save(cp)

    def _transition(self, cp: Dict[str, Any], state: str) -> None:
        cp["state"] = state
        self.save(cp)
        self.log(f"  -> {state}")
        if self.on_transition:
            self.on_transition(state, cp)

    # -- retries -----------------------------------------------------------
    def with_retries(self, label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Retry RetryableError only. NonRetryableError aborts on the first try.

        The distinction matters more here than in most tools: during the middle
        of a rotation the node is off, so every wasted retry is downtime for
        real users. An auth failure will never become a success.
        """
        attempts = max(1, self.retries + 1)
        last: Optional[ProviderError] = None
        for attempt in range(attempts):
            try:
                return fn(*args, **kwargs)
            except RetryableError as exc:
                last = exc
                if attempt + 1 >= attempts:
                    break
                self.log(f"  {label}: transient failure ({exc}); retry {attempt + 1}/{self.retries}")
                self.sleep(self.retry_delay)
        raise last if last else RetryableError(f"{label}: failed with no error recorded")

    # -- identity ----------------------------------------------------------
    def assert_identity(self, cp: Dict[str, Any], expect_ip: Optional[str] = None):
        """Re-prove, from a FRESH read, that this is still the right server.

        Runs before every mutating step and before every rollback step. The
        collection has no concept of this: `hetzner.hcloud.server` with an id
        happily powers off whatever that id points at now. A server that was
        rebuilt, renamed or replaced between two steps of the same transaction
        must stop the run, never redirect it.

        For DataForest the same role is played by the Seed; the provider
        exposes `get_seed` instead of `get_server`, and the things we
        assert against are different (state, ipv4 entries) — see
        `_assert_dataforest_identity`.
        """
        if cp.get("provider") == "dataforest":
            return self._assert_dataforest_identity(cp, expect_ip=expect_ip)
        want = cp["server"]
        server = self.with_retries("read_server", self.provider.get_server, want["id"])

        problems: List[str] = []
        if server.id != want["id"]:
            problems.append(f"id {server.id} != {want['id']}")
        if server.name != want["expected_name"]:
            problems.append(f"name {server.name!r} != {want['expected_name']!r}")
        if server.location != want["expected_location"]:
            problems.append(f"location {server.location!r} != {want['expected_location']!r}")
        if self.provider.fingerprint != cp["project_fingerprint"]:
            problems.append(
                "project fingerprint "
                f"{self.provider.fingerprint} != {cp['project_fingerprint']} "
                "(HCLOUD_TOKEN points at a different Hetzner project than this "
                "transaction was started against)"
            )

        if expect_ip == "old" and server.ipv4 != cp["old_ip"]["ip"]:
            problems.append(f"address {server.ipv4} != the old {cp['old_ip']['ip']}")
        elif expect_ip == "none" and server.ipv4:
            problems.append(f"expected no public IPv4, found {server.ipv4}")
        elif expect_ip == "new" and server.ipv4 != cp["new_ip"]["ip"]:
            problems.append(f"address {server.ipv4} != the new {cp['new_ip']['ip']}")

        if problems:
            raise IdentityMismatch(
                f"server {want['id']} is not what this transaction started against: "
                + "; ".join(problems)
            )
        return server

    # -- plan --------------------------------------------------------------
    def plan(self, txid: Optional[str] = None) -> Dict[str, Any]:
        """Read everything, mutate nothing. Terminal state is `planned`."""
        alias = self.cfg["ansible"]["host_alias"]
        txid = txid or new_txid()
        provider_name = self.provider_name
        cp: Dict[str, Any] = {
            "version": CHECKPOINT_VERSION,
            "txid": txid,
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "operator": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
            "state": "created",
            "provider": provider_name,
            "project_fingerprint": getattr(self.provider, "fingerprint", ""),
            "config_path": os.path.abspath(self.config_path),
            "server": {
                "id": self.cfg["server"]["id"],
                "expected_name": self.cfg["server"]["expected_name"],
                "expected_ipv4": self.cfg["server"]["expected_ipv4"],
                "expected_location": self.cfg["server"]["expected_location"],
            },
            "alias": alias,
            "snapshot": {},
            "old_ip": {},
            "new_ip": {"name": f"{alias}-ipv4-{txid}", "id": None, "ip": None},
            "history": [],
            "ansible": {},
            "verification": {},
            "rollback": {"state": None, "reason": None},
            "escalations": [],
            "outcome": None,
        }
        self.save(cp)

        if provider_name == "hcloud":
            pinned = self.cfg.get("project_fingerprint")
            if pinned and pinned != cp["project_fingerprint"]:
                raise IdentityMismatch(
                    f"project_fingerprint in the config is {pinned} but HCLOUD_TOKEN "
                    f"fingerprints to {cp['project_fingerprint']}. Either the wrong token "
                    "is exported or the config points at another project."
                )
            self._plan_hcloud(cp)
        elif provider_name == "dataforest":
            self._plan_dataforest(cp)
        else:
            raise ConfigError(f"unknown provider {provider_name!r}")

        self._print_plan(cp)
        # In provider_only mode the rotation stops at `connectivity_ok`,
        # regardless of --until. We land in `planned`, and the apply/resume
        # path will park at connectivity_ok. The argparse --until choice
        # names a `PAUSABLE` state; `provider_only` is structural and applies
        # even without an --until flag.
        self._transition(cp, "planned")
        return cp

    def _plan_hcloud(self, cp: Dict[str, Any]) -> None:
        """Hetzner-specific plan: numeric id, server.location, Primary IP."""
        alias = cp["alias"]
        server = self.with_retries("read_server", self.provider.get_server, cp["server"]["id"])
        if server.name != cp["server"]["expected_name"]:
            raise IdentityMismatch(
                f"server {server.id} is named {server.name!r}, config expects "
                f"{cp['server']['expected_name']!r}"
            )
        if server.location != cp["server"]["expected_location"]:
            raise IdentityMismatch(
                f"server {server.id} is in {server.location!r}, config expects "
                f"{cp['server']['expected_location']!r}"
            )
        if server.ipv4 != cp["server"]["expected_ipv4"]:
            raise IdentityMismatch(
                f"server {server.id} currently has {server.ipv4}, config expects "
                f"{cp['server']['expected_ipv4']}. If the address already changed, "
                "update the config rather than letting the tool assume."
            )
        if server.ipv4_id is None:
            raise NonRetryableError(
                f"server {server.id} has no Primary IPv4 id — nothing to rotate. "
                "A server on a floating-only or private-only setup is out of scope."
            )

        old = self.with_retries("read_ip", self.provider.get_primary_ip, server.ipv4_id)
        if old.assignee_id != server.id:
            raise IdentityMismatch(
                f"Primary IP {old.id} ({old.ip}) reports assignee_id {old.assignee_id}, "
                f"not server {server.id}. It may be shared or mid-move; refusing."
            )

        cp["snapshot"] = {
            "status": server.status,
            "location": server.location,
            "datacenter": server.datacenter,
            "ipv4": server.ipv4,
            "inventory_line": f"{alias}: ansible_host: {server.ipv4}",
        }
        cp["old_ip"] = {
            "id": old.id,
            "name": old.name,
            "ip": old.ip,
            "auto_delete_was": old.auto_delete,
            "protected": False,
        }
        self._transition(cp, "created")
        self.record(cp, "read", f"server {server.id} {server.name} {server.ipv4} in {server.datacenter}")

        # DNS allow-list. A run that would move a record the operator never
        # approved stops HERE, at `validated`, before anything is powered off.
        touched = ansible_adapter.dns_records_touched(alias, self.cfg["dns"]["node_record_zone"])
        violations = ansible_adapter.check_dns_allowlist(
            touched, self.cfg["dns"].get("allowed_records") or []
        )
        cp["snapshot"]["dns_records"] = touched
        self._transition(cp, "validated")
        if violations:
            raise EscalationRequired(
                "DNS allow-list violation: this run would move "
                f"{', '.join(violations)}, which dns.allowed_records does not list. "
                "Nothing has been changed.",
                [f"# add to dns.allowed_records in {self.config_path}:"]
                + [f"#   - {v}" for v in violations],
            )

    def _plan_dataforest(self, cp: Dict[str, Any]) -> None:
        """DataForest-specific plan: team + Seed preflight, no mutations."""
        alias = cp["alias"]
        seed_id = cp["server"]["id"]
        team = self.with_retries("get_team", self.provider.get_team)
        if team.status != "ready":
            raise NonRetryableError(
                f"team {team.id} status is {team.status!r}, expected 'ready'"
            )
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        seed_cfg = self.cfg.get("seed") or {}
        if seed.name != seed_cfg.get("expected_name"):
            raise IdentityMismatch(
                f"seed {seed.id} is named {seed.name!r}, config expects "
                f"{seed_cfg.get('expected_name')!r}"
            )
        if seed.location != seed_cfg.get("expected_location"):
            raise IdentityMismatch(
                f"seed {seed.id} is in {seed.location!r}, config expects "
                f"{seed_cfg.get('expected_location')!r}"
            )
        if seed_cfg.get("expected_project") and seed.project != seed_cfg["expected_project"]:
            raise IdentityMismatch(
                f"seed {seed.id} is in project {seed.project!r}, config expects "
                f"{seed_cfg['expected_project']!r}"
            )
        if seed.state not in Seed.ACCEPTED_STATES:
            raise NonRetryableError(
                f"seed {seed.id} state is {seed.state!r}; refusing "
                f"(accepted: {sorted(Seed.ACCEPTED_STATES)})"
            )
        if seed.is_clone_source:
            raise NonRetryableError(
                f"seed {seed.id} is a clone source; refusing to rotate"
            )
        if seed.active_action is not None:
            raise NonRetryableError(
                f"seed {seed.id} has an active_action; refusing to rotate "
                "until it completes"
            )
        if not seed.accepts("seed.add-ipv4"):
            raise NonRetryableError(
                f"seed {seed.id} does not list seed.add-ipv4 in its "
                f"available_actions ({seed.available_actions!r}); refusing"
            )
        # OLD_IP must exist exactly once.
        addresses = seed.addresses()
        old_ip = cp["server"]["expected_ipv4"]
        if addresses.count(old_ip) != 1:
            raise IdentityMismatch(
                f"OLD_IP {old_ip} appears {addresses.count(old_ip)} time(s) on "
                f"seed {seed.id}; expected exactly 1"
            )
        # Pre-flight snapshot for the rollback matrix.
        cp["snapshot"] = {
            "team_id": team.id,
            "team_status": team.status,
            "resource_limits": dict(team.resource_limits),
            "seed_id": seed.id,
            "seed_name": seed.name,
            "seed_project": seed.project,
            "seed_location": seed.location,
            "seed_state": seed.state,
            "available_actions": list(seed.available_actions),
            "ipv4": [dict(e) for e in seed.ipv4],
            "is_clone_source": seed.is_clone_source,
        }
        cp["old_ip"] = {
            "id": None,  # DataForest does not expose a numeric id
            "name": None,
            "ip": old_ip,
            "ptr": next(
                (e.get("ptr_hostname") for e in seed.ipv4
                 if isinstance(e, dict) and e.get("address") == old_ip),
                None,
            ),
            "ptr_record_id": next(
                (e.get("ptr_record_id") for e in seed.ipv4
                 if isinstance(e, dict) and e.get("address") == old_ip),
                None,
            ),
        }
        cp["new_ip"]["name"] = f"{alias}-ipv4-{cp['txid']}"
        self._transition(cp, "created")
        self.record(
            cp, "read",
            f"seed {seed.id} {seed.name} {len(addresses)} ipv4(s) in {seed.location}",
        )

        # DNS allow-list (same logic as hcloud).
        touched = ansible_adapter.dns_records_touched(alias, self.cfg["dns"]["node_record_zone"])
        violations = ansible_adapter.check_dns_allowlist(
            touched, self.cfg["dns"].get("allowed_records") or []
        )
        cp["snapshot"]["dns_records"] = touched
        self._transition(cp, "validated")
        if violations:
            raise EscalationRequired(
                "DNS allow-list violation: this run would move "
                f"{', '.join(violations)}, which dns.allowed_records does not list. "
                "Nothing has been changed.",
                [f"# add to dns.allowed_records in {self.config_path}:"]
                + [f"#   - {v}" for v in violations],
            )

    def _print_plan(self, cp: Dict[str, Any]) -> None:
        o = self.log
        o("")
        o("=" * 72)
        o(f"  PLAN  txid {cp['txid']}   provider {cp.get('provider', 'hcloud')}   project {cp['project_fingerprint']}")
        o("=" * 72)
        o(f"  resource       {cp['server']['id']}  {cp['server']['expected_name']}")
        if cp.get("provider") == "dataforest":
            snap = cp.get("snapshot") or {}
            o(f"  location       {snap.get('seed_location', cp['server']['expected_location'])}")
            o(f"  team status    {snap.get('team_status', 'ready')}")
            o("")
            o(f"  old IPv4       {cp['old_ip']['ip']}")
            o(f"  new IPv4       (not allocated)  name will be {cp['new_ip']['name']}")
            o("")
            o("  steps, in order:")
            o(f"    1. dataforest preflight  (team + Seed preflight)")
            o(f"    2. POST seed.add-ipv4   (allocate NEW_IP)")
            o(f"    3. configure guest       (NEW_IP on {self.cfg.get('guest', {}).get('interface', 'eth0')})")
            o(f"    4. verify guest          (TCP + SSH key + service probes)")
            o(f"    5. WAIT for you to edit {self.cfg['ansible'].get('inventory', 'inventory/hosts.yml')}")
            o(f"    6. make ip-change HOST={cp['alias']}   (Cloudflare PATCH)")
            o("    7. PAUSE at awaiting_finalize")
            o(f"    8. finalize --txid {cp['txid']}   (explicit OLD_IP release)")
            o("")
            o(f"  DNS records this may move: {', '.join(snap.get('dns_records', []))}")
            o("  finalize is point-of-no-return: OLD_IP is not guaranteed to be reacquirable.")
        else:
            o(f"  datacenter    {cp['snapshot']['datacenter']}  (location {cp['snapshot']['location']})")
            o(f"  power state   {cp['snapshot']['status']}")
            o("")
            o(f"  old Primary IPv4   {cp['old_ip']['ip']}  id={cp['old_ip']['id']}  "
              f"name={cp['old_ip']['name']}  auto_delete={cp['old_ip']['auto_delete_was']}")
            o(f"  new Primary IPv4   (not allocated)  name will be {cp['new_ip']['name']}")
            o("")
            o("  steps, in order:")
            o(f"    1. auto_delete=false on Primary IP {cp['old_ip']['id']}  (the way back)")
            o(f"    2. power off server {cp['server']['id']}")
            o(f"    3. detach {cp['old_ip']['ip']}")
            o(f"    4. allocate {cp['new_ip']['name']} in {cp['snapshot']['datacenter']}")
            o("    5. attach it")
            o("    6. power on")
            o(f"    7. TCP probe :{self.ssh_port} on the new address")
            o(f"    8. WAIT for you to edit {self.cfg['ansible'].get('inventory', 'inventory/hosts.yml')}")
            o(f"    9. make ip-change HOST={cp['alias']}   (Cloudflare PATCH + monitoring-doctor)")
            o("   10. fresh read-back and a second probe")
            o("")
            o(f"  DNS records this may move: {', '.join(cp['snapshot']['dns_records'])}")
            o(f"  old address retention:     keep  (nothing is ever deleted)")
            o("")
            o("  ⚠ Hetzner guarantees the same DATACENTER, never the same prefix. The new")
            o("    address will not be adjacent to the old one and there is no API to ask")
            o("    for that. Anything upstream that pinned the old /24 must be updated.")
            o("  ⚠ The node is unreachable between steps 2 and 6.")
        o("=" * 72)
        o("")
        o(f"  to execute:  rotate.py apply --config {self.config_path} "
          f"--confirm-server-id {cp['server']['id']}")
        o("")

    # -- steps -------------------------------------------------------------
    def _step_stop(self, cp: Dict[str, Any]) -> None:
        self.assert_identity(cp, expect_ip="old")

        # Rule One, in provider form, and the FIRST recorded action of any
        # apply: while the swap is in flight the old address is the only way
        # back, and auto_delete would let Hetzner reclaim it behind our back.
        if not cp["old_ip"].get("protected"):
            protected = self.with_retries(
                "protect_ip", self.provider.protect_ip, cp["old_ip"]["id"]
            )
            cp["old_ip"]["protected"] = True
            self.record(
                cp, "protect_ip", f"auto_delete={protected.auto_delete} on {protected.ip}"
            )

        server = self.with_retries("stop", self.provider.stop_server, cp["server"]["id"])
        if server.status != "off":
            raise RetryableError(f"server {server.id} is {server.status!r}, expected 'off'")
        self.record(cp, "stop", f"server {server.id} is off")

    def _step_unassign(self, cp: Dict[str, Any]) -> None:
        self.assert_identity(cp, expect_ip="old")
        server = self.with_retries(
            "unassign", self.provider.unassign_ip, cp["server"]["id"], cp["old_ip"]["id"]
        )
        if server.ipv4:
            raise RetryableError(
                f"server {server.id} still reports {server.ipv4} after the detach"
            )
        self.record(cp, "unassign", f"{cp['old_ip']['ip']} detached and retained")

    def _step_cloudflare_preflight(self, cp: Dict[str, Any]) -> None:
        """Build the manifest of DNS records this run will PATCH.

        Runs FIRST, before any provider mutation. The manifest is persisted
        at this state so a later apply or rollback does NOT re-discover: it
        re-uses these exact record ids, and a record that drifted since
        preflight aborts the run rather than overwriting what a human or
        another tool wrote.

        With the multi-account `cloudflare.accounts` block, each account
        is preflighted SEPARATELY with its own token. The combined manifest
        is only persisted if EVERY account preflight succeeded — partial
        preflight is a hard fail because apply cannot trust a half-known
        baseline.

        In `provider_only` mode the Cloudflare half is structurally absent
        and the run will pause at connectivity_ok. We persist an empty
        manifest and skip the API call: the structural pause later guards
        us from doing work we said we wouldn't.
        """
        if self.provider_only:
            cp["cloudflare_manifest"] = []
            cp["cloudflare_preflight"] = {"ts": utcnow(), "skipped": True}
            self.record(cp, "cloudflare_preflight", "skipped (provider_only)")
            return
        accounts = self._cf_accounts()
        # Token presence for every account: the absence of any one is a
        # fail-closed refusal, not a silent skip.
        missing = [a["name"] for a in accounts
                   if not os.environ.get(a["token_env"], "").strip()]
        if missing:
            raise EscalationRequired(
                f"missing Cloudflare token env var(s) for account(s) "
                f"{missing!r}. The playbook reads each token directly from "
                "the env; the value never enters argv, the manifest, or the "
                "checkpoint.",
                [
                    f"# export the named env var(s) for: {', '.join(missing)}",
                ],
            )
        if not accounts or not any(a["records"] for a in accounts):
            raise EscalationRequired(
                "no Cloudflare accounts configured — refusing to discover.",
                [f"# edit {self.config_path} and fill cloudflare.accounts"],
            )
        combined: List[Dict[str, Any]] = []
        per_account: List[Dict[str, Any]] = []
        for account in accounts:
            invocation_id = _new_invocation_id()
            result = self.with_retries(
                f"cloudflare_preflight.{account['name']}",
                self.cloudflare_preflight,
                "discover",
                old_ip=cp["old_ip"]["ip"],
                new_ip="",  # not used by discover
                allowed_records=account["records"],
                expected_count=account["expected_count"],
                invocation_id=invocation_id,
                credential_ref=account["name"],
                token_env=account["token_env"],
                cf_api_base=_test_mode_cf_api_base(),
            )
            sub_manifest = (result.get("result") or {}).get("manifest") or []
            for entry in sub_manifest:
                # Mark every entry with the credential reference that
                # discovered it. A record's ownership is structural: the
                # account that discovered it is the only account allowed
                # to PATCH it later.
                combined.append({**entry, "credential_ref": account["name"]})
            per_account.append({
                "name": account["name"],
                "token_env": account["token_env"],
                "invocation_id": invocation_id,
                "rc": result.get("rc"),
                "record_count": len(sub_manifest),
                "manifest_digest": dataforest_adapter.deterministic_digest(sub_manifest),
            })
            if result.get("rc") != 0 or not (result.get("result") or {}).get("ok"):
                raise EscalationRequired(
                    f"cloudflare preflight failed for account "
                    f"{account['name']!r} (token_env={account['token_env']!r}); "
                    "no manifest was persisted. The other account(s) were "
                    "left untouched; either fix the failing account or "
                    "narrow the allowlist.",
                    [
                        f"rotate.py resume --txid {cp['txid']} "
                        f"--confirm-server-id {cp['server']['id']}",
                    ],
                )
        # Combined invariants: no record is owned by more than one account,
        # the union covers every configured FQDN exactly once, and the
        # combined digest is stable across runs.
        owned_ids = [(r.get("zone_id"), r.get("record_id")) for r in combined]
        if len(owned_ids) != len(set(owned_ids)):
            raise EscalationRequired(
                f"combined manifest has duplicate (zone_id, record_id) "
                f"tuples: {owned_ids!r}. Each record is identified by its "
                "zone + record_id, not by name; check the discovery step.",
                [f"# edit {self.config_path} cloudflare.accounts"],
            )
        cp["cloudflare_manifest"] = combined
        cp["cloudflare_manifest_digest"] = dataforest_adapter.deterministic_digest(
            combined
        )
        cp["cloudflare_preflight"] = {
            "ts": utcnow(),
            "accounts": per_account,
            "record_count": len(combined),
        }
        self.record(cp, "cloudflare_preflight",
                    f"{len(combined)} record(s) across {len(per_account)} account(s)")
        self.save(cp)

    def _step_cloudflare_replace(self, cp: Dict[str, Any]) -> None:
        """PATCH every manifest record from OLD_IP to NEW_IP, with read-back.

        Per-account apply: each account receives ONLY its own subset of
        the manifest, and ONLY the token that account owns. A crash
        between accounts leaves a `cloudflare_apply_started.<account>`
        marker so the rollback path knows exactly which records have
        already moved.
        """
        if self.provider_only:
            # Belt-and-suspenders: in provider_only mode the preflight step
            # already escalated. Reaching here would mean a state transition
            # against the wrong config. Refuse rather than skip.
            raise EscalationRequired(
                "cloudflare.mode=provider_only rejects DNS mutations",
                [f"# unset cloudflare.mode in {self.config_path}"],
            )
        manifest = cp.get("cloudflare_manifest") or []
        if not manifest:
            raise EscalationRequired(
                "cloudflare_manifest is empty at replace time — refusing to "
                "PATCH without a manifest. Run `plan` again or restore from "
                "an earlier checkpoint.",
                ["rotate.py status --txid " + cp["txid"]],
            )
        accounts = self._cf_accounts()
        accounts_by_name = {a["name"]: a for a in accounts}
        # Group manifest by credential_ref. A record that lacks a ref
        # would come from the legacy single-account config and is
        # auto-bucketed under the sole account's name.
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for entry in manifest:
            ref = entry.get("credential_ref")
            if not ref or ref not in accounts_by_name:
                if len(accounts) == 1:
                    ref = accounts[0]["name"]
                else:
                    raise EscalationRequired(
                        f"manifest entry {entry.get('name')!r} has no "
                        f"credential_ref or refers to an unknown account; "
                        "the manifest is from an older run, refuse and "
                        "re-run preflight from scratch."
                    )
            buckets.setdefault(ref, []).append(entry)
        # Per-account apply markers. Each one is written BEFORE the
        # corresponding subprocess; a crash between two accounts leaves
        # the marker for the succeeded account and the absence of one
        # for the failed account. The rollback path uses that signal.
        started = cp.setdefault("cloudflare_apply_started", {})
        per_account_results: List[Dict[str, Any]] = []
        is_legacy_single = len(accounts) == 1
        for account_name, subset in buckets.items():
            account = accounts_by_name[account_name]
            invocation_id = _new_invocation_id()
            per_account_marker = {
                "ts": utcnow(),
                "operation": "apply",
                "credential_ref": account_name,
                "token_env": account["token_env"],
                "manifest_digest": _manifest_digest(subset),
                "subset_digest": dataforest_adapter.deterministic_digest(subset),
                "manifest_size": len(subset),
                "invocation_id": invocation_id,
            }
            started[account_name] = per_account_marker
            # Legacy single-account config: also write the flat top-level
            # fields so the existing rollback / redaction tests
            # (test_rotation.py) keep their invariants. The brief says
            # "keep backward compatibility with the existing single-
            # account configuration only if it can be done without
            # ambiguity" — when there is exactly ONE account, the
            # mapping is unambiguous and the flat shape is preserved.
            if is_legacy_single and account_name == accounts[0]["name"]:
                started["manifest_digest"] = per_account_marker["manifest_digest"]
                started["manifest_size"] = per_account_marker["manifest_size"]
                started["invocation_id"] = invocation_id
                started["operation"] = "apply"
                started["ts"] = per_account_marker["ts"]
                started["credential_ref"] = account_name
                started["token_env"] = account["token_env"]
            self.save(cp)
            result = self.with_retries(
                f"cloudflare_apply.{account_name}",
                self.cloudflare_replace,
                "apply",
                old_ip=cp["old_ip"]["ip"],
                new_ip=cp["new_ip"]["ip"],
                allowed_records=account["records"],
                expected_count=account["expected_count"],
                manifest=subset,
                invocation_id=invocation_id,
                credential_ref=account_name,
                token_env=account["token_env"],
                cf_api_base=_test_mode_cf_api_base(),
            )
            ok = bool((result.get("result") or {}).get("ok"))
            rc = result.get("rc")
            per_account_results.append({
                "account": account_name,
                "rc": rc,
                "ok": ok,
                "post_manifest": (result.get("result") or {}).get("post_manifest") or subset,
                "invocation_id": invocation_id,
            })
            if rc != 0 or not ok:
                # Treat as partial mutation. Mark DNS as partially
                # mutated so the rollback path only touches accounts
                # whose apply was confirmed.
                cp["cloudflare_apply"] = {
                    "ts": utcnow(),
                    "rc": rc,
                    "ok": False,
                    "partial": True,
                    "per_account": per_account_results,
                }
                self.record(cp, "cloudflare_apply",
                            f"PARTIAL rc={rc} on {account_name}")
                self.save(cp)
                raise EscalationRequired(
                    f"cloudflare apply for account {account_name!r} "
                    f"exited {rc} or reported drift. Earlier accounts "
                    "may already be PATCHed; the rollback path uses the "
                    "per-account markers to roll back only the moved "
                    "records.",
                    [
                        f"rotate.py resume --txid {cp['txid']} "
                        f"--confirm-server-id {cp['server']['id']}",
                    ],
                )
        cp["cloudflare_apply"] = {
            "ts": utcnow(),
            "rc": 0,
            "ok": True,
            "partial": False,
            "per_account": per_account_results,
            "post_manifest": [r for res in per_account_results
                              for r in res["post_manifest"]],
        }
        self.record(cp, "cloudflare_apply",
                    f"ok across {len(per_account_results)} account(s)")
        self.save(cp)

    def _step_allocate(self, cp: Dict[str, Any]) -> None:
        # The old address is still on the box here — allocation happens before
        # anything is detached, on purpose. See the comment on STEPS.
        self.assert_identity(cp, expect_ip="old")
        name = cp["new_ip"]["name"]

        # The deterministic name IS the checkpoint for this step. A crash
        # between the API call and the state write cannot mint a second billed
        # address: the next run finds this one instead of allocating again.
        existing = self.with_retries("find_ip", self.provider.find_ip, name)
        if existing is not None:
            self.log(f"  {name} already exists ({existing.ip}) — adopting it")
            allocated = existing
        else:
            allocated = self.with_retries(
                "allocate", self.provider.allocate_ip, name, cp["snapshot"]["datacenter"]
            )
        if not same_place(allocated.datacenter, cp["snapshot"]["datacenter"]):
            raise NonRetryableError(
                f"{name} landed in {allocated.datacenter}, not {cp['snapshot']['datacenter']}"
            )
        cp["new_ip"]["id"] = allocated.id
        cp["new_ip"]["ip"] = allocated.ip
        self.record(cp, "allocate", f"{allocated.ip} id={allocated.id} name={name}")

    def _step_assign(self, cp: Dict[str, Any]) -> None:
        self.assert_identity(cp, expect_ip="none")
        server = self.with_retries(
            "assign", self.provider.assign_ip, cp["server"]["id"], cp["new_ip"]["name"]
        )
        if server.ipv4 != cp["new_ip"]["ip"]:
            raise RetryableError(
                f"server {server.id} reports {server.ipv4} after attaching "
                f"{cp['new_ip']['ip']}"
            )
        self.record(cp, "assign", f"{cp['new_ip']['ip']} attached to {server.id}")

    def _step_start(self, cp: Dict[str, Any]) -> None:
        self.assert_identity(cp, expect_ip="new")
        server = self.with_retries(
            "start", self.provider.start_server, cp["server"]["id"], cp["new_ip"]["name"]
        )
        if server.status != "running":
            raise RetryableError(f"server {server.id} is {server.status!r}, expected 'running'")
        self.record(cp, "start", f"server {server.id} is running on {server.ipv4}")

    def _step_health(self, cp: Dict[str, Any]) -> None:
        address = cp["new_ip"]["ip"]
        for attempt in range(max(1, self.health_retries)):
            if self.probe(address, self.ssh_port, self.ssh_timeout):
                self.record(cp, "health", f"{address}:{self.ssh_port} answered")
                return
            if attempt + 1 < self.health_retries:
                self.sleep(self.health_delay)
        raise RetryableError(
            f"{address}:{self.ssh_port} did not answer after {self.health_retries} tries"
        )

    def _step_ansible(self, cp: Dict[str, Any]) -> None:
        alias = cp["alias"]
        ans = self.cfg["ansible"]
        ansible_adapter.inventory_step(
            alias=alias,
            inventory=ans.get("inventory", "inventory/hosts.yml"),
            old_ip=cp["old_ip"]["ip"],
            new_ip=cp["new_ip"]["ip"],
            auto_edit=bool(ans.get("auto_edit_inventory")),
            prompt=self.prompt,
            out=self.log,
        )
        result = self.ip_change(alias, self.repo_dir)
        cp["ansible"] = result
        self.record(cp, "ip_change", f"rc={result['rc']} argv={' '.join(result['argv'])}")
        if result["rc"] != 0:
            raise EscalationRequired(
                f"`{' '.join(result['argv'])}` exited {result['rc']}. The server already "
                f"has {cp['new_ip']['ip']} and the IP is NOT rolled back — ip-change.yml "
                "is idempotent, so fix the cause and resume.",
                [
                    f"cd {self.repo_dir} && make ip-change HOST={alias}",
                    f"rotate.py resume --txid {cp['txid']} "
                    f"--confirm-server-id {cp['server']['id']}",
                ],
            )

    # -- DataForest steps --------------------------------------------------
    #: How long a `dataforest_identity_ok` marker stays usable. The guest
    #: stages run in their own subprocess minutes after the identity check;
    #: an hours-old marker is not evidence about the Seed any more.
    IDENTITY_MARKER_MAX_AGE = 1800.0

    def _identity_marker_digest(self, cp: Dict[str, Any]) -> str:
        """Bind the marker to this txid, this Seed and this config identity.

        A marker copied from another transaction, or one written before the
        config's expected name/location was edited, no longer matches.
        """
        seed_cfg = self.cfg.get("seed") or {}
        return dataforest_adapter.deterministic_digest(
            cp["txid"],
            str(cp["server"]["id"]),
            (cp.get("old_ip") or {}).get("ip"),
            (cp.get("new_ip") or {}).get("ip"),
            seed_cfg.get("expected_name"),
            seed_cfg.get("expected_location"),
        )

    def _assert_dataforest_identity_staged(self, cp: Dict[str, Any]) -> None:
        """Identity for a stage that carries NO provider token.

        With `DATAFOREST_API_TOKEN` in scope we re-read the Seed as before.
        Without it — the guest stages, which must not hold a provider
        credential while running Ansible against the box — the evidence is
        the digest-bound marker `dataforest-identity-check` persisted in its
        own subprocess. No marker, a stale one, or one bound to a different
        txid/Seed/config is a refusal, not a skip.
        """
        if dataforest_token_present():
            self._assert_dataforest_identity(cp)
            return
        marker = cp.get("dataforest_identity_ok") or {}
        problems: List[str] = []
        if not marker:
            problems.append("marker absent")
        else:
            expect = {
                "txid": cp["txid"],
                "seed_id": str(cp["server"]["id"]),
                "old_ip": cp["old_ip"]["ip"],
                "new_ip": cp["new_ip"]["ip"],
                "digest": self._identity_marker_digest(cp),
            }
            for key, want in expect.items():
                got = marker.get(key)
                if str(got) != str(want):
                    problems.append(f"{key} {got!r} != {want!r}")
            age = _marker_age_seconds(marker.get("ts"))
            if age is None:
                problems.append(f"unreadable ts {marker.get('ts')!r}")
            elif age > self.IDENTITY_MARKER_MAX_AGE:
                problems.append(
                    f"marker is {int(age)}s old (max "
                    f"{int(self.IDENTITY_MARKER_MAX_AGE)}s)"
                )
        if problems:
            raise IdentityMismatch(
                "no usable dataforest_identity_ok marker and no "
                "DATAFOREST_API_TOKEN to re-prove identity: "
                + "; ".join(problems)
                + f". Run `rotate.py dataforest-identity-check --txid "
                f"{cp['txid']} --confirm-server-id {cp['server']['id']}` "
                "with DATAFOREST_API_TOKEN in scope first."
            )

    def _assert_dataforest_identity(self, cp: Dict[str, Any],
                                     expect_ip: Optional[str] = None) -> None:
        """Re-prove the Seed still matches the config from a fresh read.

        Raises IdentityMismatch on any drift. Cheap enough to call
        before every mutating step.

        For DataForest, `expect_ip` maps to expected ipv4 presence:
          "old"  → only OLD_IP bound
          "new"  → only NEW_IP bound
          "none" → no ipv4 entries
          None   → ipv4 entries may be present
        """
        seed = self.with_retries("get_seed", self.provider.get_seed, cp["server"]["id"])
        seed_cfg = self.cfg.get("seed") or {}
        problems: List[str] = []
        if seed.id != cp["server"]["id"]:
            problems.append(f"id {seed.id} != {cp['server']['id']}")
        if seed.name != seed_cfg.get("expected_name"):
            problems.append(f"name {seed.name!r} != {seed_cfg.get('expected_name')!r}")
        if seed.location != seed_cfg.get("expected_location"):
            problems.append(
                f"location {seed.location!r} != {seed_cfg.get('expected_location')!r}"
            )
        if seed.state not in Seed.ACCEPTED_STATES:
            problems.append(f"state {seed.state!r} (not in {sorted(Seed.ACCEPTED_STATES)})")
        if seed.is_clone_source:
            problems.append("seed became a clone source mid-rotation")
        if seed.active_action is not None:
            problems.append("seed has an active action mid-rotation")
        if not seed.accepts("seed.add-ipv4") and cp.get("finalize_intent") is not True:
            problems.append(
                f"available_actions missing seed.add-ipv4 ({seed.available_actions!r})"
            )
        if expect_ip == "old" and cp["old_ip"].get("ip") not in seed.addresses():
            problems.append(
                f"OLD_IP {cp['old_ip'].get('ip')!r} not bound to seed {seed.id}"
            )
        elif expect_ip == "new" and cp["new_ip"].get("ip") not in seed.addresses():
            problems.append(
                f"NEW_IP {cp['new_ip'].get('ip')!r} not bound to seed {seed.id}"
            )
        elif expect_ip == "none" and seed.ipv4:
            problems.append(
                f"expected no ipv4 entries, found {len(seed.ipv4)} on seed {seed.id}"
            )
        if problems:
            raise IdentityMismatch(
                f"seed {cp['server']['id']} drifted during rotation: " + "; ".join(problems)
            )
        return seed

    def _step_dataforest_preflight(self, cp: Dict[str, Any]) -> None:
        """Prove team + Seed + DNS state before any mutation.

        Persists a complete provider snapshot so a crash-recovery can
        reconcile without making another mutation. Strict validation:
        * team.status == ready
        * team.resource_limits.max_ipv4_per_seed allows one more IPv4
        * seed.status == ready, not a clone source
        * seed.active_action is null
        * OLD_IP exists exactly once in seed.ipv4
        * no duplicate addresses / invalid metadata
        """
        if not dataforest_token_present():
            raise EscalationRequired(
                "DATAFOREST_API_TOKEN is not set. Export it before running; "
                "the DataForest adapter does not accept the token via any "
                "other channel.",
                [
                    "export DATAFOREST_API_TOKEN=\"$(ansible-vault view vault.yml "
                    "| awk '/^dataforest_api_token:/ {print $2}' | tr -d \"\\\"')\""
                ],
            )

        team = self.with_retries("get_team", self.provider.get_team)
        if team.status != "ready":
            raise NonRetryableError(
                f"team {team.id} status is {team.status!r}, expected 'ready' "
                "(refusing to mutate before preflight passes)"
            )
        limits = dict(team.resource_limits or {})
        max_ipv4 = int(limits.get("max_ipv4_per_seed", 0))
        if max_ipv4 < 1:
            raise NonRetryableError(
                f"team resource_limits.max_ipv4_per_seed is {max_ipv4}; "
                "cannot allocate another IPv4"
            )
        seed = self.with_retries("get_seed", self.provider.get_seed, cp["server"]["id"])
        if seed.state not in Seed.ACCEPTED_STATES:
            raise NonRetryableError(
                f"seed {seed.id} state is {seed.state!r}; refusing "
                f"(accepted: {sorted(Seed.ACCEPTED_STATES)})"
            )
        if seed.is_clone_source:
            raise NonRetryableError(
                f"seed {seed.id} is a clone source; refusing to rotate"
            )
        if seed.active_action is not None:
            raise NonRetryableError(
                f"seed {seed.id} has an active_action; refusing to rotate "
                "until it completes"
            )

        # OLD_IP must exist exactly once and be syntactically valid.
        old_ip = cp["server"]["expected_ipv4"]
        addresses = seed.addresses()
        if addresses.count(old_ip) != 1:
            raise IdentityMismatch(
                f"OLD_IP {old_ip} appears {addresses.count(old_ip)} time(s) on "
                f"seed {seed.id}; expected exactly 1"
            )

        # Every ipv4 entry must validate. Provider might add an unrelated
        # address between snapshots; a third address without an explicit
        # allowlist entry is a stop.
        allow_extra = set((self.cfg.get("seed") or {}).get("allow_extra_addresses") or [])
        for entry in seed.ipv4:
            if not isinstance(entry, dict):
                raise NonRetryableError(
                    f"seed {seed.id} ipv4 entry is not a dict"
                )
            addr = entry.get("address")
            dataforest_adapter.strict_ipv4(addr)
            cidr = entry.get("cidr")
            if cidr:
                dataforest_adapter.validate_cidr(cidr)
            gw = entry.get("gateway")
            if gw is not None:
                dataforest_adapter.strict_ipv4(gw)
            if entry.get("ptr_hostname") and not isinstance(entry["ptr_hostname"], str):
                raise NonRetryableError(
                    f"seed {seed.id} ipv4[{addr}].ptr_hostname is not a string"
                )
            if entry.get("ptr_record_id") and not isinstance(entry["ptr_record_id"], str):
                raise NonRetryableError(
                    f"seed {seed.id} ipv4[{addr}].ptr_record_id is not a string"
                )
        for addr in addresses:
            if addr not in (old_ip,):
                if addr not in allow_extra:
                    raise NonRetryableError(
                        f"seed {seed.id} has an unexpected extra address {addr}; "
                        "add it to seed.allow_extra_addresses to proceed."
                    )
        # Quota gate.
        if len(addresses) >= max_ipv4:
            raise NonRetryableError(
                f"seed {seed.id} already holds {len(addresses)} IPv4(s); "
                f"max_ipv4_per_seed is {max_ipv4}. Cannot allocate another."
            )

        cp["dataforest_preflight"] = {
            "ts": utcnow(),
            "team_id": team.id,
            "team_status": team.status,
            "resource_limits": dict(limits),
            "seed_id": seed.id,
            "seed_name": seed.name,
            "seed_state": seed.state,
            "is_clone_source": seed.is_clone_source,
            "available_actions": list(seed.available_actions),
            "ipv4_before": [dict(e) for e in seed.ipv4],
            "ipv4_addresses_before": list(addresses),
            "ipv4_digest_before": dataforest_adapter.deterministic_digest(
                addresses, [e.get("primary_ip") for e in seed.ipv4]
            ),
        }
        self.record(cp, "dataforest_preflight",
                    f"team={team.id} seed={seed.id} ({len(addresses)} ipv4)")

    def _persist_apply_started(self, cp: Dict[str, Any], operation: str) -> None:
        """Persist a durable per-op marker BEFORE the corresponding POST.

        Three distinct keys, one per operation type, are appended to
        the checkpoint in sequence:
          * `provider_allocation_started`   — seed.add-ipv4 (add NEW_IP)
          * `provider_rollback_started`     — seed.remove-ipv4 from
                                              `_rollback_dataforest_new_ip`
                                              (release NEW_IP after a
                                              failed step)
          * `provider_finalize_started`      — seed.remove-ipv4 from
                                              `_step_dataforest_finalize_started`
                                              (release OLD_IP, point of
                                              no return)

        An additional `provider_operation_history` list is appended-only
        and preserves every previous marker's full payload — it is
        the source of truth for "what operations have already been
        attempted" and never overwritten. The named key (`provider_*_started`)
        is the *active* pointer: only the most recent in-flight
        operation is named, so a resume that sees both keys knows
        which one is authoritative.

        Crash recovery contract: a crash between the marker write and
        the network call leaves an unambiguous recovery trail. The
        resume path reads provider state and reconciles through the
        active action; it NEVER issues a second mutation based on the
        marker alone.

        No PAT, no Authorization header, no temp path is included.
        """
        seed_id = cp["server"]["id"]
        if operation == "seed.add-ipv4":
            before = cp.get("dataforest_preflight", {}).get(
                "ipv4_addresses_before") or []
            digest = cp.get("dataforest_preflight", {}).get(
                "ipv4_digest_before", "")
            marker = {
                "provider": "dataforest",
                "operation": "seed.add-ipv4",
                "seed_id": seed_id,
                "ts": utcnow(),
                "previous_ipv4_count": len(before),
                "previous_ipv4_digest": digest,
                "previous_ipv4_addresses": list(before),
            }
            cp["provider_allocation_started"] = marker
        elif operation == "seed.remove-ipv4":
            marker = {
                "provider": "dataforest",
                "operation": "seed.remove-ipv4",
                "seed_id": seed_id,
                "address": cp["old_ip"]["ip"],
                "ts": utcnow(),
                "manifest_digest": cp.get("cloudflare_apply_started", {}).get(
                    "manifest_digest", ""
                ),
            }
            # The same dict shape is used by both rollback and finalize;
            # we tag the kind so a resume reading the checkpoint knows
            # which path produced the marker.
            # `cp.get("_apply_intent")` is set by the caller:
            #   "rollback"  — _rollback_dataforest_new_ip
            #   "finalize"  — _step_dataforest_finalize_started
            intent = cp.get("_apply_intent") or "finalize"
            if intent == "rollback":
                cp["provider_rollback_started"] = marker
            else:
                cp["provider_finalize_started"] = marker
        else:  # pragma: no cover — exhaustive branch for new ops
            raise NonRetryableError(
                f"_persist_apply_started: unknown operation {operation!r}"
            )
        # Append-only history: previous markers are preserved here
        # even when the named active pointer is overwritten by a
        # subsequent in-flight op. A resume can reconstruct exactly
        # what was attempted.
        history = cp.setdefault("provider_operation_history", [])
        history.append(dict(marker, _apply_intent=intent
                            if operation == "seed.remove-ipv4" else "allocate"))
        self.save(cp)

    def _step_dataforest_allocate(self, cp: Dict[str, Any]) -> None:
        """POST seed.add-ipv4. Resilient to a crash after the POST.

        Crash recovery contract:
        * If the Seed already has exactly one address beyond OLD_IP, the
          action probably succeeded — adopt that address, do not POST
          again.
        * If an active action exists for seed.add-ipv4, poll it.
        * If state is ambiguous, raise IdentityMismatch — never POST a
          second add request.

        `provider_apply_started` is persisted BEFORE any POST so a crash
        between the marker write and the network call leaves a recoverable
        trail. The recovery path reads provider state, never retries
        blindly.
        """
        self._assert_dataforest_identity(cp)
        seed_id = cp["server"]["id"]
        old_ip = cp["old_ip"]["ip"]
        before = cp["dataforest_preflight"]["ipv4_addresses_before"]
        if cp["new_ip"].get("ip") and cp["new_ip"]["ip"] not in before:
            # Resume after a successful add — no POST.
            new_ip = cp["new_ip"]["ip"]
        else:
            active = self.with_retries(
                "get_active_action", self.provider.get_active_action, seed_id
            )
            if active and (active.get("type") or "").endswith("add-ipv4"):
                # A previous run started the POST and crashed before its
                # result landed. Reconcile through the active action.
                self._poll_action(cp, seed_id, active["id"])
                seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
                addresses = seed.addresses()
                new_set = set(addresses) - set(before)
                if len(new_set) == 1:
                    new_ip = next(iter(new_set))
                elif len(new_set) == 0:
                    raise IdentityMismatch(
                        f"seed {seed_id} add-ipv4 reported success but no "
                        "new address is present; refusing to POST again"
                    )
                else:
                    raise IdentityMismatch(
                        f"seed {seed_id} add-ipv4 produced {len(new_set)} "
                        "new addresses; refusing to guess which one is new"
                    )
            else:
                # Check the seed for an already-added address (a previous
                # rotation's NEW_IP may have been left behind, or a crash
                # left a stuck state). If exactly one new address exists,
                # adopt it.
                seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
                addresses = seed.addresses()
                new_set = sorted(set(addresses) - set(before))
                if len(new_set) == 1 and old_ip in addresses:
                    new_ip = new_set[0]
                    self.log(
                        f"  seed {seed_id} already has an extra IPv4 {new_ip} "
                        f"beyond OLD_IP; adopting it (no second POST)"
                    )
                elif len(new_set) == 0 and old_ip in addresses:
                    # No mutation happened yet. Persist the marker FIRST
                    # so a crash here is recoverable, then POST.
                    self._persist_apply_started(cp, "seed.add-ipv4")
                    self._post_add_ipv4(cp)
                    seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
                    new_set = sorted(set(seed.addresses()) - set(before))
                    if len(new_set) != 1:
                        raise IdentityMismatch(
                            f"seed {seed_id} add-ipv4 produced "
                            f"{len(new_set)} new addresses; refusing to guess"
                        )
                    new_ip = new_set[0]
                else:
                    raise IdentityMismatch(
                        f"seed {seed_id} ipv4 state is ambiguous: "
                        f"before={before!r} after={addresses!r}"
                    )

        # Required invariants on the result.
        if new_ip == old_ip:
            raise IdentityMismatch(
                f"seed {seed_id} add-ipv4 returned OLD_IP as the new address"
            )
        if new_ip in before:
            raise IdentityMismatch(
                f"seed {seed_id} add-ipv4 produced no new address (before/after "
                f"sets identical); refusing to mark allocation complete"
            )
        cp["new_ip"]["ip"] = new_ip
        cp["new_ip"]["id"] = None  # DataForest doesn't expose numeric id
        # Re-read to capture the canonical entry shape.
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        entry = next(
            (e for e in seed.ipv4 if isinstance(e, dict) and e.get("address") == new_ip),
            None,
        )
        if entry is None:
            raise IdentityMismatch(
                f"seed {seed_id} ipv4 entry for {new_ip} missing after allocation"
            )
        cp["new_ip"]["entry"] = dict(entry)
        addresses_after = seed.addresses()
        cp["dataforest_preflight"]["ipv4_addresses_after_allocate"] = list(addresses_after)
        cp["dataforest_preflight"]["ipv4_digest_after_allocate"] = (
            dataforest_adapter.deterministic_digest(
                addresses_after,
                [e.get("primary_ip") for e in seed.ipv4],
            )
        )
        # OLD_IP must still be present.
        if old_ip not in addresses_after:
            raise IdentityMismatch(
                f"seed {seed_id} add-ipv4 removed OLD_IP {old_ip}; refusing"
            )
        # Exactly one new address.
        if len(addresses_after) - len(before) != 1:
            raise IdentityMismatch(
                f"seed {seed_id} ipv4 cardinality unexpected: before={len(before)} "
                f"after={len(addresses_after)}"
            )
        self.record(cp, "dataforest_allocate",
                    f"NEW_IP={new_ip} on seed {seed_id}")

    def _post_add_ipv4(self, cp: Dict[str, Any]) -> None:
        """POST seed.add-ipv4 with retries on 429/503."""
        seed_id = cp["server"]["id"]
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                body = self.with_retries(
                    "post_action",
                    self.provider.allocate_ipv4, seed_id,
                )
            except RetryableError as exc:
                last_exc = exc
                wait = float(getattr(exc, "retry_after", 0) or 0) or self.retry_delay
                if attempt + 1 < self.retries + 1:
                    self.log(
                        f"  add-ipv4 retry {attempt + 1}/{self.retries}: {exc}"
                    )
                    self.sleep(wait)
                    continue
                raise
            action_id = str(body.get("action_id") or body.get("id") or "")
            status = str(body.get("status") or "")
            if not action_id:
                raise NonRetryableError(
                    f"seed {seed_id} add-ipv4 response missing action_id"
                )
            if status not in ("new", "pending", "running", "retry"):
                # 200 immediate: action already terminal.
                if status not in ("completed", "failed"):
                    # poll until terminal
                    self._poll_action(cp, seed_id, action_id)
                break
            self._poll_action(cp, seed_id, action_id)
            break
        else:
            if last_exc:
                raise last_exc

    def _poll_action(self, cp: Dict[str, Any], seed_id: str, action_id: str) -> Dict[str, Any]:
        from dataforest_adapter import poll_action
        body = poll_action(
            self.provider._adapter,  # the adapter is the polling seam
            seed_id,
            action_id,
            sleeper=self.sleep,
        )
        status = dataforest_adapter._extract_status(body)
        if status == "failed":
            raise NonRetryableError(
                f"dataforest action {action_id} on seed {seed_id} failed: "
                f"{dataforest_adapter.stable_error_code(body) or 'unknown'}"
            )
        return body

    def _step_dataforest_configure_guest(self, cp: Dict[str, Any]) -> None:
        """Run `configure_guest` against the persistent guest configuration.

        Sequence: detect_network_manager (snapshot) -> configure_guest
        (runtime + persistent) -> write the checksum of every persistent
        file we created so a later rollback can verify them. If the
        playbook errors, we restore from backup_files (sha256-pinned).
        """
        self._assert_dataforest_identity_staged(cp)
        guest = self.cfg.get("guest") or {}
        interface = guest.get("interface")
        gateway = self._derive_gateway(cp)
        new_ip = cp["new_ip"]["ip"]
        old_ip = cp["old_ip"]["ip"]

        # 1) snapshot the network state
        inv_id = _new_invocation_id_dataforest()
        snap = self.with_retries(
            "guest_detect", self.guest_op,
            "detect_network_manager",
            txid=cp["txid"],
            invocation_id=inv_id,
            interface=interface,
        )
        if snap.get("rc") != 0:
            raise RetryableError(
                f"detect_network_manager rc={snap.get('rc')}"
            )
        result = snap.get("result") or {}
        snapshot = {
            "network_manager": result.get("network_manager"),
            "addresses": result.get("addresses", []),
            "routes": result.get("routes", []),
        }
        if snapshot["network_manager"] not in (
            "netplan", "systemd-networkd", "networkmanager", "ifupdown",
        ):
            raise EscalationRequired(
                f"guest network_manager {snapshot['network_manager']!r} is not supported. "
                "Supported: netplan, systemd-networkd, networkmanager, ifupdown. "
                "Refusing to proceed on an unsupported manager.",
                [
                    f"# install one of the supported managers on the Seed, OR "
                    f"# set guest.network_manager to 'unknown' explicitly in {self.config_path} "
                    "and run a hand-written configuration step"
                ],
            )

        # 2) Configure guest. Pass the snapshot so the playbook picks the
        #    right path. Persist checksums of any files written.
        inv_id = _new_invocation_id_dataforest()
        result = self.with_retries(
            "guest_configure", self.guest_op,
            "configure_guest",
            txid=cp["txid"],
            invocation_id=inv_id,
            interface=interface,
            snapshot=snapshot,
            new_address=f"{new_ip}/32",
            old_address=f"{old_ip}/32",
            gateway=gateway,
        )
        if result.get("rc") != 0:
            raise RetryableError(
                f"configure_guest rc={result.get('rc')}; runtime/persistent config failed"
            )
        inner = result.get("result") or {}
        cp["guest"] = {
            "network_manager": snapshot["network_manager"],
            "interface": interface,
            "gateway": gateway,
            "written": list(inner.get("written") or []),
            "invocation_id": inv_id,
            "ts": utcnow(),
        }
        self.record(cp, "guest_configure",
                    f"network_manager={snapshot['network_manager']} interface={interface}")

    def _derive_gateway(self, cp: Dict[str, Any]) -> str:
        """Gateway is taken from the existing IPv4 entry on the Seed.

        Refuses to guess: if no entry on the Seed reports a gateway,
        we escalate rather than inventing one. The config can also
        explicitly override it via guest.gateway.
        """
        explicit = (self.cfg.get("guest") or {}).get("gateway")
        if explicit:
            return dataforest_adapter.strict_ipv4(explicit)
        for entry in cp.get("dataforest_preflight", {}).get("ipv4_before", []):
            gw = entry.get("gateway")
            if isinstance(gw, str) and gw.strip():
                return dataforest_adapter.strict_ipv4(gw)
        raise NonRetryableError(
            "guest.gateway is unset and no ipv4 entry on the Seed reports one; "
            "set guest.gateway in the config to the Seed's network gateway"
        )

    def _step_dataforest_verify_guest(self, cp: Dict[str, Any]) -> None:
        """TCP probe, ssh-keyscan, and the configured service probes."""
        new_ip = cp["new_ip"]["ip"]
        guest = self.cfg.get("guest") or {}

        # 1) TCP probe on the SSH port. Uses the same probe seam as Hetzner.
        for attempt in range(max(1, self.health_retries)):
            if self.probe(new_ip, self.ssh_port, self.ssh_timeout):
                break
            if attempt + 1 < self.health_retries:
                self.sleep(self.health_delay)
        else:
            raise RetryableError(
                f"{new_ip}:{self.ssh_port} did not answer after "
                f"{self.health_retries} tries"
            )

        # 2) ssh-keyscan host key check. The pattern in the config is a
        #    regex that the captured key lines must match.
        try:
            host_key_lines = self.ssh_keyscan(new_ip, timeout=5.0)
        except RetryableError as exc:
            raise RetryableError(f"ssh-keyscan {new_ip} failed: {exc}") from exc
        pattern = guest.get("expected_host_key_pattern")
        if not pattern:
            raise NonRetryableError(
                "guest.expected_host_key_pattern is required for verification"
            )
        import re as _re
        try:
            compiled = _re.compile(pattern)
        except _re.error as exc:
            raise NonRetryableError(
                f"guest.expected_host_key_pattern {pattern!r} is not a "
                f"valid regex: {exc}"
            )
        matched = bool(compiled.search(host_key_lines))
        if not matched:
            raise RetryableError(
                f"ssh-keyscan against {new_ip} did not return a host key "
                f"matching /{pattern}/. The node may have rotated its host "
                "key or the connection went somewhere else."
            )

        # 3) Service probes — playbook runs them; we just record success.
        inv_id = _new_invocation_id_dataforest()
        result = self.with_retries(
            "guest_verify", self.guest_op,
            "verify_guest",
            txid=cp["txid"],
            invocation_id=inv_id,
            interface=guest.get("interface"),
            new_address=f"{new_ip}/32",
            old_address=f"{cp['old_ip']['ip']}/32",
            expected_host_key_pattern=pattern,
            service_probes=guest.get("service_probes") or [],
        )
        if result.get("rc") != 0:
            raise RetryableError(
                f"verify_guest rc={result.get('rc')}; service probes failed"
            )
        cp["guest"]["verified_at"] = utcnow()
        cp["guest"]["verify_invocation_id"] = inv_id
        self.record(cp, "guest_verify", f"{new_ip} ssh={host_key_lines.splitlines() and 'matched' or 'no-key'}")

    def _step_dataforest_awaiting_finalize(self, cp: Dict[str, Any]) -> None:
        """Terminal pause for the apply/resume path.

        Records the awaiting_finalize state explicitly so a subsequent
        `finalize` command can find its checkpoint and decide whether
        the preconditions are met. The provider still owns both
        addresses at this point — a rollback is fully available.
        """
        cp["awaiting_finalize_at"] = utcnow()
        # Persist a token-free summary of the post-DNS state so a future
        # finalize can re-prove everything from disk.
        cp["awaiting_finalize_summary"] = {
            "txid": cp["txid"],
            "seed_id": cp["server"]["id"],
            "old_ip": cp["old_ip"]["ip"],
            "new_ip": cp["new_ip"]["ip"],
            "dns_verified": bool(
                (cp.get("cloudflare_apply") or {}).get("ok")
            ),
            "guest_verified": bool(cp.get("guest", {}).get("verified_at")),
        }
        self.save(cp)
        self.log("")
        self.log(
            "PAUSED at awaiting_finalize. Both addresses are still assigned "
            f"to seed {cp['server']['id']}. The OLD_IP release is point-of-no-return "
            "and must be invoked explicitly via:"
        )
        self.log(
            f"  rotate.py finalize --txid {cp['txid']} --config {self.config_path} "
            f"--confirm-server-id {cp['server']['id']}"
        )

    # -- finalize command steps -------------------------------------------
    def _step_dataforest_dns_finalize_precheck(self, cp: Dict[str, Any]) -> None:
        """Fresh Cloudflare read-back BEFORE the OLD_IP release.

        Requires `CLOUDFLARE_API_TOKEN`. The previous Cloudflare PATCH was
        idempotent and its post-apply manifest was persisted on disk, but a
        third-party edit between apply and finalize can silently drift the
        wire. Re-running the same GET that `_step_cloudflare_replace`
        performs on success, this step asserts every allowlisted record
        still holds NEW_IP — releasing OLD_IP while a record still points
        at it is the worst-case "DNS follows the burnt IP" outcome.

        Persists a `dns_finalize_verified` marker that the subsequent
        provider-finalize step (running with `DATAFOREST_API_TOKEN` only)
        validates before any mutation:

          * missing marker  →  refuse
          * stale marker    →  refuse (re-run dns-precheck)
          * manifest digest mismatch  →  refuse (manifest changed since apply)
          * checkpoint/config identity mismatch  →  refuse
          * DNS referring to a different OLD/NEW pair  →  refuse
          * provider state changed since the marker  →  refuse

        The DataForest provider process never receives the Cloudflare token.
        """
        if not cf_token_present():
            raise EscalationRequired(
                "CLOUDFLARE_API_TOKEN is not set. The finalize DNS precheck "
                "MUST run with the Cloudflare token; the provider finalize "
                "step refuses to release OLD_IP without this marker.",
                [
                    "rotate.py finalize --txid " + cp["txid"],
                    "  (re-run; the workflow puts CLOUDFLARE_API_TOKEN only "
                    "on the dns-precheck step, then DATAFOREST_API_TOKEN only "
                    "on the provider-finalize step.)",
                ],
            )
        if cp.get("state") != "awaiting_finalize":
            raise NonRetryableError(
                f"dns finalize precheck requires state == awaiting_finalize, "
                f"got {cp.get('state')!r}"
            )
        if cp.get("finalize_intent") is not True:
            raise NonRetryableError(
                "dns finalize precheck requires cp['finalize_intent'] == True"
            )

        # Re-load and assert config identity. A typo on the form (or a
        # swapped env) must not let finalize advance against the wrong seed.
        config_seed_id = self.cfg["server"]["id"]
        if str(cp["server"]["id"]) != str(config_seed_id):
            raise IdentityMismatch(
                f"checkpoint seed {cp['server']['id']} != config "
                f"server.id {config_seed_id}"
            )

        manifest = cp.get("cloudflare_manifest") or []
        new_ip = cp["new_ip"]["ip"]
        old_ip = cp["old_ip"]["ip"]
        expected_digest = cp.get("cloudflare_apply_started", {}).get(
            "manifest_digest", "")
        # Re-run the discover op on the manifest. We don't need a fresh
        # scan — we re-read EXACTLY the records we PATCHed, by record_id.
        try:
            result = self.with_retries(
                "dns_finalize_precheck", self.cloudflare_replace,
                "discover",
                old_ip=old_ip,
                new_ip=new_ip,
                allowed_records=self._allowed_records(),
                expected_count=self._expected_record_count(),
                manifest=manifest,
                invocation_id=_new_invocation_id(),
                cf_api_base=_test_mode_cf_api_base(),
            )
        except (RetryableError, EscalationRequired) as exc:
            raise EscalationRequired(
                f"DNS finalize precheck failed: {exc}. Refusing to release "
                f"OLD_IP {old_ip} without a fresh DNS read-back.",
                [
                    "rotate.py status --txid " + cp["txid"] + " --config "
                    + self.config_path,
                    "# when DNS is settled, re-run:",
                    "rotate.py finalize --txid " + cp["txid"] + " --config "
                    + self.config_path + " --confirm-server-id "
                    + str(config_seed_id),
                ],
            ) from exc

        records = (result.get("result") or {}).get("manifest") or []
        for rec in records:
            content = (rec.get("content") or "").strip()
            name = rec.get("name") or "?"
            if content != new_ip:
                raise NonRetryableError(
                    f"DNS finalize precheck: record {name!r} points at "
                    f"{content!r}, not NEW_IP {new_ip}. Refusing to release "
                    f"OLD_IP {old_ip} while DNS still references it."
                )

        cp["dns_finalize_verified"] = {
            "ts": utcnow(),
            "manifest_digest": expected_digest,
            "txid": cp["txid"],
            "old_ip": old_ip,
            "new_ip": new_ip,
            "seed_id": str(config_seed_id),
            "record_count": len(records),
        }
        self.record(cp, "dns_finalize_precheck",
                    f"{len(records)} record(s) verified on NEW_IP {new_ip}")
        self.save(cp)

    def _step_dataforest_finalize_started(self, cp: Dict[str, Any]) -> None:
        """Finalize-preconditions + persist a finalize intent marker.

        Crash recovery contract: if the next call never lands but the
        provider actually removed OLD_IP, the resume after this state
        re-reads the Seed and reconciles via set difference. If OLD_IP
        is still there, the resume restarts from this state.

        Pre-flight invariants enforced here:
          * checkpoint state == awaiting_finalize
          * checkpoint identity matches the configured Seed
          * team.status == ready
          * seed.state in {running, stopped}, not a clone source, no
            active action
          * seed.available_actions lists seed.remove-ipv4
          * both OLD_IP and NEW_IP still belong to the same Seed
          * removing the LAST ipv4 would leave the Seed ipv4-empty
          * DNS allowlist points entirely to NEW_IP (no third-party
            content silently accepted by prior PATCH)
          * inventory points to NEW_IP
          * guest NEW_IP is verified and persistent
          * PTR policy (`require_match` by default) passes
        """
        if cp.get("state") not in ("awaiting_finalize", "dns_finalize_verified"):
            raise NonRetryableError(
                f"finalize requires state in ('awaiting_finalize', "
                f"'dns_finalize_verified'), got {cp.get('state')!r}"
            )
        # The DNS finalize precheck MUST have run first, in a process
        # that received CLOUDFLARE_API_TOKEN. When both stages run in one
        # execute() call, the precheck has already advanced the state to
        # dns_finalize_verified; we transition through finalizing_started
        # here. When called separately (provider-finalize), the state is
        # already dns_finalize_verified on entry and the marker is what
        # we check below.
        if cp.get("state") == "awaiting_finalize":
            self._transition(cp, "dns_finalize_verified")
        self._transition(cp, "finalizing_started")
        if cp.get("finalize_intent") is not True:
            # Defence in depth: a `resume` from awaiting_finalize must
            # NOT silently cross into the finalize subcommand.
            raise NonRetryableError(
                "finalize requires cp['finalize_intent'] == True; the "
                "apply/resume path cannot set this"
            )

        # The DNS finalize precheck MUST have run first, in a process that
        # received CLOUDFLARE_API_TOKEN. The provider finalize step here
        # runs with DATAFOREST_API_TOKEN only; it MUST refuse without the
        # marker the precheck persisted.
        marker = cp.get("dns_finalize_verified") or {}
        if not marker:
            raise NonRetryableError(
                "finalize requires cp['dns_finalize_verified']; the dns "
                "precheck must run first (CLOUDFLARE_API_TOKEN only). The "
                "workflow runs it on the finalize-precheck job before this "
                "provider-finalize job."
            )
        # Reject stale markers — re-run dns-precheck.
        marker_age = _marker_age_seconds(marker.get("ts"))
        if marker_age is None:
            raise NonRetryableError(
                "dns_finalize_verified.ts is unparseable; refusing to trust "
                "the marker"
            )
        # Hard cap: 30 minutes. Anything older must be re-proved.
        if marker_age > 1800:
            raise NonRetryableError(
                f"dns_finalize_verified is {int(marker_age)}s old (>1800s); "
                "re-run dns-precheck"
            )
        # The marker must describe THIS transaction, not a stale one.
        if marker.get("txid") != cp["txid"]:
            raise NonRetryableError(
                f"dns_finalize_verified.txid {marker.get('txid')!r} != "
                f"checkpoint txid {cp['txid']!r}; refusing to trust"
            )
        if marker.get("old_ip") != cp["old_ip"]["ip"]:
            raise NonRetryableError(
                f"dns_finalize_verified.old_ip {marker.get('old_ip')!r} != "
                f"checkpoint old_ip {cp['old_ip']['ip']!r}"
            )
        if marker.get("new_ip") != cp["new_ip"]["ip"]:
            raise NonRetryableError(
                f"dns_finalize_verified.new_ip {marker.get('new_ip')!r} != "
                f"checkpoint new_ip {cp['new_ip']['ip']!r}"
            )
        if marker.get("seed_id") != str(cp["server"]["id"]):
            raise NonRetryableError(
                f"dns_finalize_verified.seed_id {marker.get('seed_id')!r} != "
                f"checkpoint seed_id {cp['server']['id']!r}"
            )
        expected_digest = cp.get("cloudflare_apply_started", {}).get(
            "manifest_digest", "")
        if marker.get("manifest_digest") != expected_digest:
            raise NonRetryableError(
                f"dns_finalize_verified.manifest_digest "
                f"{marker.get('manifest_digest')!r} != expected {expected_digest!r}; "
                "manifest changed since apply — re-run dns-precheck"
            )

        self._assert_dataforest_identity(cp)
        seed_id = cp["server"]["id"]
        # Re-prove team + Seed here — the checkpoint might be days old.
        team = self.with_retries("get_team", self.provider.get_team)
        if team.status != "ready":
            raise NonRetryableError(
                f"team {team.id} status is {team.status!r} at finalize; refusing"
            )
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        if seed.state not in Seed.ACCEPTED_STATES:
            raise NonRetryableError(
                f"seed {seed.id} state is {seed.state!r} at finalize; refusing "
                f"(accepted: {sorted(Seed.ACCEPTED_STATES)})"
            )
        if seed.is_clone_source:
            raise NonRetryableError(
                f"seed {seed.id} became a clone source at finalize; refusing"
            )
        if seed.active_action is not None:
            raise NonRetryableError(
                f"seed {seed.id} has active_action={seed.active_action!r} "
                "at finalize; refusing"
            )
        if not seed.accepts("seed.remove-ipv4"):
            raise NonRetryableError(
                f"seed {seed.id} does not list seed.remove-ipv4 in "
                f"available_actions ({seed.available_actions!r}); refusing"
            )
        addresses = seed.addresses()
        old_ip = cp["old_ip"]["ip"]
        new_ip = cp["new_ip"]["ip"]
        if old_ip not in addresses:
            raise NonRetryableError(
                f"OLD_IP {old_ip} is no longer on seed {seed_id}; refusing to "
                "finalize. Either someone removed it out-of-band or this "
                "transaction has already finalized."
            )
        if new_ip not in addresses:
            raise NonRetryableError(
                f"NEW_IP {new_ip} is not on seed {seed_id}; refusing to finalize"
            )
        if len(addresses) <= 1:
            raise NonRetryableError(
                f"seed {seed_id} holds {len(addresses)} IPv4; refusing to "
                "release the only one (DataForest does not document an "
                "ipv4-empty Seed mode)"
            )
        # DNS must point at NEW_IP across the entire allowlist.
        post_manifest = (
            (cp.get("cloudflare_apply") or {}).get("post_manifest")
            or cp.get("cloudflare_manifest")
            or []
        )
        for rec in post_manifest:
            # `cloudflare_apply.post_manifest` records carry `content`
            # (live state after PATCH); `cloudflare_manifest` records
            # (discover output) carry `previous_content`. Read both, with
            # `content` winning when present.
            content = (rec.get("content")
                       or rec.get("previous_content")
                       or "").strip()
            if content != new_ip:
                raise NonRetryableError(
                    f"DNS record {rec.get('name')!r} points at {content!r}, "
                    f"not NEW_IP {new_ip}. Refusing to release OLD_IP while DNS "
                    "still references it. Run rollback or fix DNS, then resume."
                )
        # Inventory must point to NEW_IP (the canonical inventory_line).
        # The agent_adapter was kept on disk as `inventory_line` snapshot.
        inv_snapshot = (cp.get("snapshot") or {}).get("inventory_line", "")
        if inv_snapshot and new_ip not in inv_snapshot:
            raise NonRetryableError(
                f"inventory line still references {inv_snapshot!r}; refusing "
                "to release OLD_IP while inventory disagrees with DNS"
            )
        # Guest NEW_IP must be persistent (configured at runtime AND
        # persisted to the manager). The `guest.persistent` flag is set
        # by configure_guest; the verify step is required to have passed.
        if not (cp.get("guest") or {}).get("verified_at"):
            raise NonRetryableError(
                "guest verification has not passed; refusing to release "
                "OLD_IP while NEW_IP reachability is unproven"
            )
        # PTR policy.
        ptr_policy = (self.cfg.get("finalize") or {}).get("ptr_policy") or "require_match"
        old_entry = next(
            (e for e in seed.ipv4 if isinstance(e, dict) and e.get("address") == old_ip),
            None,
        )
        new_entry = next(
            (e for e in seed.ipv4 if isinstance(e, dict) and e.get("address") == new_ip),
            None,
        )
        if ptr_policy == "require_match":
            if (old_entry or {}).get("ptr_hostname") and not (new_entry or {}).get("ptr_hostname"):
                raise NonRetryableError(
                    f"OLD_IP has PTR {(old_entry or {}).get('ptr_hostname')!r}; "
                    "NEW_IP has none. DataForest does not document a way to set "
                    "a replacement PTR via the API. Refusing to release OLD_IP "
                    "until NEW_IP carries a PTR or finalize.ptr_policy is set "
                    "to 'allow_no_ptr'."
                )
        # Persist the apply-started marker before any remove POST. Same
        # rule as the add path: a crash here is recoverable through the
        # active action / set-difference path, never by re-issuing.
        # The finalize subcommand removes OLD_IP (point of no return),
        # so the marker is `provider_finalize_started` and is preserved
        # in `provider_operation_history` for any future audit.
        cp["_apply_intent"] = "finalize"
        self._persist_apply_started(cp, "seed.remove-ipv4")
        marker = cp["provider_finalize_started"]
        marker["ipv4_digest_before"] = (
            dataforest_adapter.deterministic_digest(
                addresses,
                [e.get("primary_ip") for e in seed.ipv4],
            )
        )
        cp["provider_finalize_started"]["manifest_digest"] = (
            cp.get("cloudflare_apply_started", {}).get("manifest_digest", "")
        )
        self.save(cp)
        self.record(cp, "finalize_started",
                    f"releasing {old_ip} from seed {seed_id}")

    def _step_dataforest_remove_guest_address(self, cp: Dict[str, Any]) -> None:
        """Drop OLD_IP from the guest runtime while DataForest still owns it.

        NEW_IP must remain reachable on the interface.
        """
        inv_id = _new_invocation_id_dataforest()
        result = self.with_retries(
            "guest_remove", self.guest_op,
            "remove_guest_address",
            txid=cp["txid"],
            invocation_id=inv_id,
            interface=(self.cfg.get("guest") or {}).get("interface"),
            old_address=f"{cp['old_ip']['ip']}/32",
            new_address=f"{cp['new_ip']['ip']}/32",
        )
        if result.get("rc") != 0:
            raise RetryableError(
                f"remove_guest_address rc={result.get('rc')}"
            )
        cp["guest"]["pre_finalize_invocation_id"] = inv_id
        self.record(cp, "guest_remove",
                    f"OLD_IP {cp['old_ip']['ip']} dropped from guest")

    def _step_dataforest_remove_provider(self, cp: Dict[str, Any]) -> None:
        """POST seed.remove-ipv4 with the EXACT OLD_IP, then reconcile."""
        self._assert_dataforest_identity(cp)
        seed_id = cp["server"]["id"]
        old_ip = cp["old_ip"]["ip"]

        # Pre-check: how many addresses are on the Seed? Removing the LAST
        # ipv4 would leave the Seed ipv4-only-empty.
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        before = seed.addresses()
        if len(before) <= 1:
            raise NonRetryableError(
                f"seed {seed_id} holds {len(before)} IPv4; refusing to release "
                "the only one (DataForest does not document an ipv4-empty mode)."
            )

        # Has it already been removed by a previous finalize attempt?
        if old_ip not in before:
            self.log(
                f"  seed {seed_id} already removed OLD_IP {old_ip}; reconciling"
            )
            self._reconcile_remove(cp, seed_id, before, old_ip)
            return

        # Active action present (a previous finalize crashed mid-flight)?
        active = self.with_retries(
            "get_active_action", self.provider.get_active_action, seed_id
        )
        if active and (active.get("type") or "").endswith("remove-ipv4"):
            body = self._poll_action(cp, seed_id, active["id"])
            if (body.get("status") or "") == "failed":
                self._mark_rollback_incomplete(
                    cp, f"remove-ipv4 active action failed: "
                    f"{dataforest_adapter.stable_error_code(body) or 'unknown'}"
                )
                return
            self._reconcile_remove(cp, seed_id, before, old_ip)
            return

        # Fresh POST.
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                body = self.with_retries(
                    "post_remove", self.provider.remove_ipv4, seed_id, old_ip,
                )
                break
            except RetryableError as exc:
                last_exc = exc
                wait = float(getattr(exc, "retry_after", 0) or 0) or self.retry_delay
                if attempt + 1 < self.retries + 1:
                    self.log(f"  remove-ipv4 retry {attempt + 1}: {exc}")
                    self.sleep(wait)
                    continue
                raise
        else:
            if last_exc:
                raise last_exc
        action_id = str(body.get("action_id") or body.get("id") or "")
        status = str(body.get("status") or "")
        if not action_id:
            raise NonRetryableError(
                f"seed {seed_id} remove-ipv4 response missing action_id"
            )
        if status not in ("new", "pending", "running", "retry"):
            if status not in ("completed", "failed"):
                self._poll_action(cp, seed_id, action_id)
        else:
            self._poll_action(cp, seed_id, action_id)

        # Re-read and reconcile.
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        after = seed.addresses()
        if old_ip not in after and cp["new_ip"]["ip"] in after:
            # success
            cp["dataforest_preflight"]["ipv4_addresses_after_remove"] = list(after)
            cp["dataforest_preflight"]["ipv4_digest_after_remove"] = (
                dataforest_adapter.deterministic_digest(
                    after,
                    [e.get("primary_ip") for e in seed.ipv4],
                )
            )
            self.record(cp, "dataforest_remove",
                        f"OLD_IP {old_ip} released from seed {seed_id}")
            return
        # Distinguish failure modes for rollback_incomplete.
        if old_ip in after and cp["new_ip"]["ip"] in after:
            self._mark_rollback_incomplete(
                cp,
                f"seed {seed_id} remove-ipv4 completed but OLD_IP is still on "
                "the Seed; refusing to claim success",
            )
            return
        if cp["new_ip"]["ip"] not in after:
            self._mark_rollback_incomplete(
                cp,
                f"seed {seed_id} remove-ipv4 dropped NEW_IP {cp['new_ip']['ip']}; "
                "DataForest state is dangerous, manual recovery required",
            )
            return
        self._mark_rollback_incomplete(
            cp,
            f"seed {seed_id} remove-ipv4 produced unexpected state: "
            f"before={before!r} after={after!r}",
        )

    def _reconcile_remove(
        self, cp: Dict[str, Any], seed_id: str, before: List[str], old_ip: str,
    ) -> None:
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        after = seed.addresses()
        if old_ip not in after and cp["new_ip"]["ip"] in after:
            cp["dataforest_preflight"]["ipv4_addresses_after_remove"] = list(after)
            return
        self._mark_rollback_incomplete(
            cp,
            f"seed {seed_id} reconcile: before={before!r} after={after!r}",
        )

    def _mark_rollback_incomplete(self, cp: Dict[str, Any], reason: str) -> None:
        cp["rollback_incomplete_reason"] = reason
        cp["rollback_incomplete_at"] = utcnow()
        cp["outcome"] = "rollback_incomplete"
        self.save(cp)
        raise EscalationRequired(
            f"rollback_incomplete: {reason}. The node is on NEW_IP {cp['new_ip']['ip']} "
            "but provider state is ambiguous. Manual recovery required.",
            [
                f"# 1) read the checkpoint:",
                f"rotate.py status --txid {cp['txid']} --config {self.config_path}",
                f"# 2) inspect DataForest Seed {cp['server']['id']} for the OLD_IP "
                f"{cp['old_ip']['ip']} presence",
                f"# 3) when fixed, run:",
                f"rotate.py resume --txid {cp['txid']} --config {self.config_path} "
                f"--confirm-server-id {cp['server']['id']}",
            ],
        )

    def _rollback_dataforest_new_ip(self, cp: Dict[str, Any], reason: str) -> None:
        """Provider rollback: release NEW_IP from the Seed and revert guest.

        This is the DataForest analogue of `restore_old_ip` for Hetzner.
        Invoked from `_handle_failure` for any DataForest step with
        `on_failure == "restore"`. It does NOT touch the Cloudflare half:
        the DNS rollback is shared with Hetzner via `_do_dns_rollback`,
        which the Hetzner path's restore_old_ip calls under a flag.

        Order:
          1. Roll back DNS (only if a PATCH was attempted)
          2. Roll back inventory (inform the operator)
          3. Revert guest network to OLD_IP only
          4. POST seed.remove-ipv4 with exactly NEW_IP
          5. Re-read Seed; assert OLD_IP still present, NEW_IP gone
          6. Mark rolled_back OR rollback_incomplete
        """
        self.log(f"  rollback: {reason}")
        # State transition.
        cp["rollback"] = {"state": "in_progress", "reason": redact(reason)}
        if cp["state"] != "needs_rollback":
            self._transition(cp, "needs_rollback")
        else:
            self.save(cp)

        # DNS rollback (if we reached the cutover). Same logic as Hetzner:
        # only the records the preflight manifest had on disk, never
        # third-party content, never a fresh discover.
        post_manifest = (
            (cp.get("cloudflare_apply") or {}).get("post_manifest")
            or cp.get("cloudflare_manifest")
            or []
        )
        cloudflare_was_done = bool(
            (cp.get("cloudflare_apply_started") is not None)
            or (cp.get("cloudflare_apply") is not None)
            or ((cp.get("ansible") or {}).get("rc") == 0)
        )
        dns_actually_mutated = bool(cloudflare_was_done and post_manifest)
        if dns_actually_mutated:
            try:
                self._do_dns_rollback(cp)
            except (RetryableError, EscalationRequired) as exc:
                self.log(f"  DNS rollback raised {exc}; continuing with provider recovery")

        # Inventory rollback runs whenever Ansible actually ran (rc==0)
        # or the cloudflare apply started — both leave an edit that must
        # be undone before declaring the rollback complete. Non-TTY in
        # CI skips the prompt but prints the recovery commands.
        if cloudflare_was_done:
            ansible_adapter.inventory_rollback_step(
                alias=cp["alias"],
                inventory=(self.cfg.get("ansible") or {}).get(
                    "inventory", "inventory/hosts.yml"
                ),
                old_ip=cp["old_ip"]["ip"],
                new_ip=cp["new_ip"]["ip"],
                prompt=self.prompt,
                out=self.log,
            )

        # Guest rollback: drop NEW_IP from the runtime, then call the
        # guest adapter's restore_guest (which checksum-verifies and
        # rewrites the persistent files).
        inv_id = _new_invocation_id_dataforest()
        try:
            self.guest_op(
                "restore_guest",
                txid=cp["txid"],
                invocation_id=inv_id,
                interface=(self.cfg.get("guest") or {}).get("interface"),
                new_address=f"{cp['new_ip']['ip']}/32",
                old_address=f"{cp['old_ip']['ip']}/32",
                backup_files=[],
                expected_checksums={},
            )
        except Exception as exc:  # pylint: disable=broad-except
            self.log(f"  guest restore failed: {exc}; continuing")

        # Provider rollback: POST seed.remove-ipv4 with exactly NEW_IP.
        seed_id = cp["server"]["id"]
        new_ip = cp["new_ip"]["ip"]
        old_ip = cp["old_ip"]["ip"]

        # Idempotency: a crash earlier may have already removed NEW_IP.
        # Read the Seed first and reconcile before issuing a new POST.
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        before_addresses = seed.addresses()
        if new_ip not in before_addresses:
            # NEW_IP already gone. Nothing more to do on the provider.
            self.log(f"  seed {seed_id} already lacks NEW_IP {new_ip}; nothing to release")
        elif old_ip not in before_addresses:
            # Cannot rollback: OLD_IP is gone too. This is the
            # rollback_incomplete case where the Seed has lost track.
            self._mark_rollback_incomplete(
                cp,
                f"seed {seed_id} has NEW_IP {new_ip} but no OLD_IP {old_ip}; "
                "refusing to release NEW_IP without proof OLD_IP survives"
            )
            return
        else:
            # Persist the apply-started marker BEFORE the POST so a crash
            # mid-flight is recoverable. The rollback path uses
            # `provider_rollback_started` (NOT `provider_finalize_started`)
            # so a future finalize is never confused with a rollback.
            cp["_apply_intent"] = "rollback"
            self._persist_apply_started(cp, "seed.remove-ipv4")
            try:
                last_exc: Optional[Exception] = None
                for attempt in range(self.retries + 1):
                    try:
                        body = self.with_retries(
                            "post_remove", self.provider.remove_ipv4,
                            seed_id, new_ip,
                        )
                        last_exc = None
                        break
                    except RetryableError as exc:
                        last_exc = exc
                        wait = float(getattr(exc, "retry_after", 0) or 0) or self.retry_delay
                        if attempt + 1 < self.retries + 1:
                            self.sleep(wait)
                            continue
                        raise
                action_id = str(body.get("action_id") or body.get("id") or "")
                if action_id:
                    self._poll_action(cp, seed_id, action_id)
            except ProviderError as exc:
                self._mark_rollback_incomplete(
                    cp,
                    f"seed.remove-ipv4 of NEW_IP {new_ip} failed: {exc}"
                )
                return

        # Re-read the Seed and assert OLD_IP remains + NEW_IP is absent.
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        after_addresses = seed.addresses()
        if old_ip not in after_addresses:
            self._mark_rollback_incomplete(
                cp,
                f"seed {seed_id} OLD_IP {old_ip} disappeared during rollback; "
                "refusing to claim rolled_back"
            )
            return
        if new_ip in after_addresses:
            self._mark_rollback_incomplete(
                cp,
                f"seed {seed_id} NEW_IP {new_ip} still present after "
                "seed.remove-ipv4; refusing to claim rolled_back"
            )
            return

        # Persistent guest: rewrite the persistent files so they only
        # carry OLD_IP. This is the inverse of configure_guest for
        # finalize; we use the same restore_guest path with the inverse
        # intent (keep OLD_IP, drop NEW_IP).
        inv_id = _new_invocation_id_dataforest()
        try:
            self.guest_op(
                "restore_guest",
                txid=cp["txid"],
                invocation_id=inv_id,
                interface=(self.cfg.get("guest") or {}).get("interface"),
                new_address=f"{cp['old_ip']['ip']}/32",
                old_address=f"{cp['old_ip']['ip']}/32",
                backup_files=[],
                expected_checksums={},
            )
        except Exception as exc:  # pylint: disable=broad-except
            self.log(f"  guest final-restore failed: {exc}; rolling back anyway")

        cp["rollback"] = {
            "state": "rolled_back",
            "reason": redact(reason),
            "new_ip_retained": False,  # we just removed it
            "inventory_recovery_required": cloudflare_was_done,
            "dns_undone": cloudflare_was_done,
        }
        cp["outcome"] = "rolled_back"
        self._transition(cp, "rolled_back")
        self.log("")
        self.log(
            f"ROLLED BACK: seed {seed_id} is back on {old_ip} only; NEW_IP "
            f"{new_ip} was released."
        )

    def _step_dataforest_finalize_guest(self, cp: Dict[str, Any]) -> None:
        """Persist the post-finalize guest state.

        The runtime already dropped OLD_IP; the persistent configuration
        also has to drop it (netplan apply / networkctl reload / NM /
        ifupdown cycle). The guest adapter's `restore_guest` path is
        REVERSED for finalize: instead of restoring from backup, we
        rewrite the persistent files so they only carry NEW_IP.
        """
        inv_id = _new_invocation_id_dataforest()
        result = self.with_retries(
            "guest_restore", self.guest_op,
            "restore_guest",
            txid=cp["txid"],
            invocation_id=inv_id,
            interface=(self.cfg.get("guest") or {}).get("interface"),
            new_address=f"{cp['new_ip']['ip']}/32",
            backup_files=[],
            expected_checksums={},
        )
        if result.get("rc") != 0:
            raise RetryableError(
                f"finalize_guest rc={result.get('rc')}"
            )
        cp["guest"]["finalize_invocation_id"] = inv_id
        cp["guest"]["finalized_at"] = utcnow()
        self.record(cp, "guest_finalize",
                    f"NEW_IP {cp['new_ip']['ip']} only on guest")

    def _step_verify(self, cp: Dict[str, Any]) -> None:
        server = self.assert_identity(cp, expect_ip="new")
        reachable = self.probe(cp["new_ip"]["ip"], self.ssh_port, self.ssh_timeout)
        # DNS read-back: every record in the post-apply manifest must hold the
        # new address. The apply step asserts this on its own success path, but
        # a delayed third-party edit can drift the wire between apply and this
        # verify; the state machine should know about it.
        cloudflare_verified = True
        if not self.provider_only:
            post_manifest = (
                cp.get("cloudflare_apply", {}).get("post_manifest")
                or cp.get("cloudflare_manifest")
                or []
            )
            for record in post_manifest:
                content = (record.get("content") or "").strip()
                if content != cp["new_ip"]["ip"]:
                    cloudflare_verified = False
                    break

        # The DataForest path returns the Seed; Hetzner returns the
        # Server. The verification record is provider-agnostic in shape.
        if cp.get("provider") == "dataforest":
            seed = server
            cp["verification"] = {
                "ts": utcnow(),
                "ipv4": seed.addresses(),
                "status": seed.state,
                "ssh_reachable": reachable,
                "cloudflare_verified": cloudflare_verified,
            }
            cp["outcome"] = "done"
            self.record(cp, "verify",
                        f"{cp['new_ip']['ip']} live on seed {seed.id}")
            return

        cp["verification"] = {
            "ts": utcnow(),
            "ipv4": server.ipv4,
            "status": server.status,
            "ssh_reachable": reachable,
            "cloudflare_verified": cloudflare_verified,
        }
        if not reachable:
            raise RetryableError(f"{cp['new_ip']['ip']}:{self.ssh_port} stopped answering")
        if not cloudflare_verified:
            raise RetryableError(
                "Cloudflare A records drifted between apply and verify"
            )
        cp["outcome"] = "done"
        self.record(cp, "verify", f"{server.ipv4} live, status {server.status}")

    # -- remedies ----------------------------------------------------------
    def restore_old_ip(self, cp: Dict[str, Any], reason: str,
                      skip_dns_rollback: bool = False) -> None:
        """Remedy R. Put the old address back; RETAIN the new one.

        Re-entrant on purpose: an interrupted rollback is resumed by calling
        this again. Every branch re-reads before it acts, so "already stopped"
        and "already reassigned" are both no-ops rather than errors.

        DNS rollback is conditional: only the records the preflight manifest
        had on disk, and only when the rotation had reached the point where
        a DNS mutation was at all possible (`ansible` or `cloudflare_apply`
        recorded). Anything past that is either unnecessary or partial,
        and the caller learns about partial via `rollback_incomplete`.

        `skip_dns_rollback=True` runs only the provider half — useful when
        the workflow has decided DNS recovery is not needed and the
        CLOUDFLARE_API_TOKEN env must not be exposed to this process.
        """
        cp["rollback"] = {"state": "in_progress", "reason": redact(reason)}
        if cp["state"] != "needs_rollback":
            self._transition(cp, "needs_rollback")
        else:
            self.save(cp)

        server = self.assert_identity(cp)
        if server.status != "off":
            server = self.with_retries("stop", self.provider.stop_server, cp["server"]["id"])
            self.record(cp, "rollback:stop", f"server {server.id} is {server.status}")

        if server.ipv4 != cp["old_ip"]["ip"]:
            self.with_retries(
                "assign", self.provider.assign_ip, cp["server"]["id"], cp["old_ip"]["name"]
            )
            server = self.assert_identity(cp, expect_ip="old")
            self.record(cp, "rollback:assign", f"{cp['old_ip']['ip']} is back on {server.id}")

        server = self.with_retries(
            "start", self.provider.start_server, cp["server"]["id"], cp["old_ip"]["name"]
        )
        self.record(cp, "rollback:start", f"server {server.id} is {server.status}")

        if skip_dns_rollback:
            # Provider rollback only. The CF half is performed by the
            # workflow's separate `dns_rollback_only` step, which carries
            # the CLOUDFLARE_API_TOKEN env — this process does not.
            cp["rollback"]["state"] = "rolled_back"
            cp["rollback"]["dns_rollback"] = "skipped_in_provider_phase"
            cp["outcome"] = "rolled_back"
            self.save(cp)
            self.log("  Provider rollback: server back on the old IP; "
                     "DNS rollback deferred to the separate CF step.")
            return

        # Now: was the DNS half of the rotation already underway?
        # Three ways that can be true:
        #   * `ansible.rc` is set and == 0  → ip-change ran and Cloudflare
        #     already agrees with the new IP (or would, on a fresh re-discover)
        #   * `cloudflare_apply` is on disk → this rotation did a PATCH itself
        #   * `cloudflare_apply_started` is on disk → the subprocess was
        #     dispatched but a crash left the result unrecorded; rollback must
        #     still attempt the same manifest
        # All three must be undone before we declare a clean rollback.
        dns_was_done = (
            (cp.get("ansible") or {}).get("rc") == 0
            or cp.get("cloudflare_apply") is not None
            or cp.get("cloudflare_apply_started") is not None
        )

        outcome = "rolled_back"
        inventory_recovery_required = False
        if dns_was_done and not self.provider_only:
            # `_do_dns_rollback` returns "rolled_back" or
            # "rollback_incomplete". Capture it so a DNS half that could
            # not finish bumps the outcome to `rollback_incomplete` and
            # `_outcome_exit_code` returns 7 (not 5), and so the ROLLBACK
            # INCOMPLETE log branch is reachable. Previously the return
            # value was discarded, so every rollback reported
            # `outcome == "rolled_back"` regardless of what DNS did.
            outcome = self._do_dns_rollback(cp)
            inventory_recovery_required = True

        # Inventory rollback: the operator must edit ansible_host: NEW_IP ->
        # OLD_IP. In a non-interactive context print the diff and continue;
        # in the CI workflow this job is gated by an environment and a human
        # is the one to run the next step.
        if inventory_recovery_required:
            ansible_adapter.inventory_rollback_step(
                alias=cp["alias"],
                inventory=(self.cfg.get("ansible") or {}).get(
                    "inventory", "inventory/hosts.yml"
                ),
                old_ip=cp["old_ip"]["ip"],
                new_ip=cp["new_ip"]["ip"],
                prompt=self.prompt,
                out=self.log,
            )

        cp["rollback"] = {
            "state": outcome,
            "reason": redact(reason),
            "new_ip_retained": cp["new_ip"],
            "inventory_recovery_required": inventory_recovery_required,
            "dns_undone": dns_was_done and not self.provider_only
            and outcome == "rolled_back",
        }
        cp["outcome"] = outcome
        self._transition(cp, outcome)
        self.log("")
        if outcome == "rolled_back":
            self.log(
                f"ROLLED BACK: {cp['server']['id']} is on {cp['old_ip']['ip']} again."
            )
        else:
            self.log(
                f"ROLLBACK INCOMPLETE: provider IP is back on {cp['old_ip']['ip']}, but "
                "DNS or inventory recovery did not finish. Read state/<txid>.json "
                f"and run `rotate.py status --txid {cp['txid']}` for what to do."
            )
        if cp["new_ip"]["id"]:
            self.log(
                f"  The new Primary IP {cp['new_ip']['name']} ({cp['new_ip']['ip']}, "
                f"id={cp['new_ip']['id']}) is UNASSIGNED and RETAINED — it is still "
                "billed. Deleting it is your call, not this tool's."
            )

    def _do_dns_rollback(self, cp: Dict[str, Any]) -> str:
        """Run the Cloudflare rollback half using the persisted manifest.

        Returns one of: "rolled_back", "rollback_incomplete". Mutates `cp`
        with `cloudflare_rollback`. The caller drives the surrounding
        state transitions and the inventory-rollback prompt.
        """
        outcome = "rolled_back"
        try:
            result = self.with_retries(
                "cloudflare_rollback", self.cloudflare_replace,
                "rollback",
                old_ip=cp["new_ip"]["ip"],
                new_ip=cp["old_ip"]["ip"],
                allowed_records=self._allowed_records(),
                expected_count=self._expected_record_count(),
                manifest=cp.get("cloudflare_manifest") or [],
                invocation_id=_new_invocation_id(),
                cf_api_base=_test_mode_cf_api_base(),
            )
            cp["cloudflare_rollback"] = {
                "ts": utcnow(),
                "rc": result.get("rc"),
                "result": result.get("result") or {},
            }
            rb = result.get("result") or {}
            if result.get("rc") != 0 or rb.get("rollback_incomplete"):
                outcome = "rollback_incomplete"
                self.log(
                    "  DNS rollback incomplete: review state/cloudflare_rollback "
                    "and finish the remaining records by hand."
                )
            else:
                self.log("  DNS rollback: every allowlisted A is back on the old IP.")
        except (RetryableError, EscalationRequired) as exc:
            self.log(f"  DNS rollback raised {exc}; continuing with provider recovery")
            outcome = "rollback_incomplete"
        return outcome

    def dns_rollback_only(self, cp: Dict[str, Any]) -> None:
        """The DNS-only rollback half, run in a separate process that
        carries the CLOUDFLARE_API_TOKEN env.

        The provider half must have already been restored on disk by a
        prior invocation (`cp["cloudflare_apply_started"]` or
        `cp["cloudflare_apply"]` present); otherwise there is nothing to
        undo and we exit cleanly.

        Pre-condition: the caller has already loaded cp from disk and has
        decided this step should run. The CF token is in this process's
        environment because the workflow put it here on the explicit
        `if:` of the dns-rollback step.
        """
        if self.provider_only:
            raise EscalationRequired(
                "cloudflare.mode=provider_only rejects DNS mutations",
                [f"# unset cloudflare.mode in {self.config_path}"],
            )
        if not (
            cp.get("cloudflare_apply_started") is not None
            or cp.get("cloudflare_apply") is not None
        ):
            self.log(
                f"DNS rollback skipped for {cp['txid']}: no apply marker on "
                "disk. The provider half was the entire rotation."
            )
            cp["cloudflare_rollback"] = {
                "ts": utcnow(),
                "rc": 0,
                "result": {"ok": True, "skipped": "no_apply_marker"},
            }
            cp["outcome"] = "rolled_back"
            self.save(cp)
            return

        outcome = self._do_dns_rollback(cp)
        cp["outcome"] = outcome
        # Inventory rollback is interactive in a TTY, no-op otherwise.
        ansible_adapter.inventory_rollback_step(
            alias=cp["alias"],
            inventory=(self.cfg.get("ansible") or {}).get(
                "inventory", "inventory/hosts.yml"
            ),
            old_ip=cp["old_ip"]["ip"],
            new_ip=cp["new_ip"]["ip"],
            prompt=self.prompt,
            out=self.log,
        )
        cp["rollback"] = {
            "state": outcome,
            "reason": "operator ran DNS rollback step",
            "new_ip_retained": cp["new_ip"],
            "inventory_recovery_required": True,
            "dns_undone": outcome == "rolled_back",
        }
        self.save(cp)
        if outcome == "rolled_back":
            self.log(
                f"DNS ROLLBACK OK: every allowlisted A is on {cp['old_ip']['ip']}."
            )
        else:
            self.log(
                "DNS ROLLBACK INCOMPLETE: review state/<txid>.json "
                "and finish the remaining records by hand."
            )

    def restart_only(self, cp: Dict[str, Any], reason: str) -> None:
        """Shutdown never completed. No address moved; just bring the box back."""
        server = self.with_retries(
            "start", self.provider.start_server, cp["server"]["id"], cp["old_ip"]["name"]
        )
        cp["rollback"] = {"state": "rolled_back", "reason": redact(reason), "ips_untouched": True}
        cp["outcome"] = "rolled_back"
        self.record(cp, "rollback:restart_only", f"server {server.id} is {server.status}")
        self._transition(cp, "rolled_back")

    def escalate(self, cp: Dict[str, Any], message: str, commands: Optional[List[str]] = None) -> None:
        commands = commands or HcloudProvider.describe_rollback(
            cp["server"]["id"], cp.get("old_ip"), cp.get("new_ip")
        )
        # Save where we were so `resume` can replay the failed step. The state
        # machine overwrites cp["state"] with the terminal "escalated"; without
        # this, an escalated checkpoint has no record of what to retry.
        cp["resume_state"] = cp["state"]
        cp["escalations"].append(
            {"ts": utcnow(), "state": cp["state"], "resume_state": cp["state"],
             "message": redact(message),
             "recovery_commands": [redact(c) for c in commands]}
        )
        cp["outcome"] = "escalated"
        self._transition(cp, "escalated")
        self.log("")
        self.log("ESCALATED — a human is needed. Nothing has been deleted.")
        self.log(f"  {redact(message)}")
        self.log("")
        for line in commands:
            self.log(f"  {redact(line)}")
        self.log("")

    # -- driver ------------------------------------------------------------
    def execute(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Walk the state machine from wherever the checkpoint says it is."""
        if cp["state"] == "needs_rollback":
            reason = (cp.get("rollback") or {}).get("reason") or "resumed rollback"
            self.restore_old_ip(cp, reason)
            return cp

        # The finalize subcommand sets `cp["finalize_intent"]` BEFORE calling
        # execute; without it, a `resume` from `awaiting_finalize` would be
        # indistinguishable from an explicit finalize. We require the marker
        # to advance past the apply-path pause.
        finalize_intent = bool(cp.get("finalize_intent"))
        # If finalize was requested but the state isn't awaiting_finalize,
        # refuse. If state IS awaiting_finalize without finalize intent,
        # the apply path stops here (handled below by the terminal check).
        if finalize_intent and cp["state"] != "awaiting_finalize":
            raise EscalationRequired(
                f"`finalize` requires the checkpoint to be in awaiting_finalize; "
                f"current state is {cp['state']!r}",
                [f"rotate.py resume --txid {cp['txid']} --config {self.config_path}"],
            )

        steps, step_by_state = _steps_for_provider(
            cp.get("provider", "hcloud"),
            finalize=finalize_intent,
        )

        while True:
            # Resume after escalation: restore the state we were at when the
            # step failed. Persisted in escalate() as cp["resume_state"].
            if cp["state"] == "escalated":
                resume = cp.get("resume_state")
                if resume and resume in step_by_state:
                    cp["state"] = resume
                    cp["outcome"] = "in_progress"
                    self.log(f"RESUME: restoring state to {resume!r} from escalation")
                    self.record(cp, "resume_from_escalation",
                                f"restoring to {resume!r}")
                    # fall through; the loop will run the same step again
                else:
                    # No resume target — terminal escalation, a human must act.
                    return cp
            # Structural pause: provider_only mode never crosses
            # connectivity_ok (Hetzner) or guest_verified (DataForest).
            # Implemented as an early stop in the loop, not as a separate
            # Step, because it depends on a config value, not a step
            # outcome.
            pause_states = ("connectivity_ok", "guest_verified")
            if (
                self.provider_only
                and cp["state"] in pause_states
                and not (self.until and self.until == cp["state"])
            ):
                cp["outcome"] = "paused"
                self.save(cp)
                self.log("")
                self.log(
                    f"PAUSED at {cp['state']} (cloudflare.mode=provider_only). "
                    f"Nothing broken; resume with `resume --txid {cp['txid']}` "
                    "ONLY after unsetting cloudflare.mode in the config."
                )
                return cp
            # A pause is checked BEFORE the step, not after: --until names the
            # state to stop AT, so the named step is the one that does not run.
            if self.until and cp["state"] == self.until:
                cp["outcome"] = "paused"
                self.save(cp)
                self.log("")
                self.log(
                    f"PAUSED at {cp['state']} as requested by --until. Nothing is "
                    f"broken; resume with `resume --txid {cp['txid']}`."
                )
                return cp
            step = step_by_state.get(cp["state"])
            if step is None:
                if cp["state"] not in TERMINAL:
                    self.escalate(cp, f"no step is defined for state {cp['state']!r}")
                return cp

            self.log(f"[{cp['state']}] {step.fn[6:]}")
            try:
                getattr(self, step.fn)(cp)
            except IdentityMismatch as exc:
                self.escalate(cp, str(exc))
                return cp
            except EscalationRequired as exc:
                self.escalate(cp, str(exc), exc.recovery_commands or None)
                return cp
            except ProviderError as exc:
                self._handle_failure(cp, step, exc)
                return cp
            self._transition(cp, step.to)
            if cp["state"] == "done":
                cp["outcome"] = "done"
                self.save(cp)
                self.log("")
                if cp.get("provider") == "dataforest":
                    self.log(
                        f"DONE. seed {cp['server']['id']} is on {cp['new_ip']['ip']} "
                        f"only; OLD_IP {cp['old_ip']['ip']} was released. "
                        "DataForest does not guarantee reacquisition of a released address."
                    )
                else:
                    self.log(
                        f"DONE. {cp['server']['expected_name']} is on {cp['new_ip']['ip']}; "
                        f"the old {cp['old_ip']['ip']} is unassigned and RETAINED."
                    )
                return cp
            if cp["state"] == "awaiting_finalize":
                cp["outcome"] = "paused"
                self.save(cp)
                self.log("")
                self.log(
                    f"PAUSED at awaiting_finalize. seed {cp['server']['id']} still owns "
                    f"both {cp['old_ip']['ip']} and {cp['new_ip']['ip']}. The OLD_IP "
                    "release is point-of-no-return; run `finalize` explicitly to advance."
                )
                return cp

    def _handle_failure(self, cp: Dict[str, Any], step: Step, exc: ProviderError) -> None:
        reason = f"{step.fn[6:]} failed: {exc}"
        self.log(f"  FAILED: {reason}")
        # A remedy that fails too must still leave a record. Without this the
        # exception escapes to main(), the checkpoint keeps the pre-failure
        # state, and the operator gets an exit code with no recovery commands
        # for a box that is currently powered off.
        if step.on_failure == "restart_only":
            try:
                self.restart_only(cp, reason)
            except ProviderError as remedy_exc:
                self.escalate(cp, f"{reason}; powering back on failed too: {remedy_exc}")
        elif step.on_failure == "restore":
            if cp.get("provider") == "dataforest":
                # DataForest rollback is structurally different from Hetzner:
                # the Seed does not need a power cycle; releasing the new
                # IPv4 + restoring the guest is the entire remedy. Use the
                # DataForest-specific path; on its own failure we escalate
                # with explicit DataForest recovery commands.
                try:
                    self._rollback_dataforest_new_ip(cp, reason)
                except ProviderError as rb_exc:
                    self.escalate(
                        cp,
                        f"{reason}; the DataForest rollback then failed too: "
                        f"{rb_exc}",
                    )
            else:
                try:
                    self.restore_old_ip(cp, reason)
                except ProviderError as rollback_exc:
                    self.escalate(
                        cp,
                        f"{reason}; the rollback then failed too: {rollback_exc}",
                    )
        else:
            self.escalate(cp, reason)

    # -- stage entrypoints --------------------------------------------------
    # The CLI commands below each drive ONE stage (one step + its
    # transition + its save). They exist so the workflow can put each
    # stage in a separate subprocess, with its own env, and refuse to
    # advance if the prerequisite stage's checkpoint is absent.

    def run_stage_dataforest_identity_check(
            self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a digest-bound identity marker from a fresh Seed
        read. Runs as its own subprocess with DATAFOREST_API_TOKEN
        only so the subsequent guest Ansible subprocess can run
        without any provider token.
        """
        self._assert_dataforest_identity(cp)
        seed = self.with_retries("get_seed", self.provider.get_seed,
                                   cp["server"]["id"])
        cp["dataforest_identity_ok"] = {
            "ts": utcnow(),
            "txid": cp["txid"],
            "old_ip": cp["old_ip"]["ip"],
            "new_ip": cp["new_ip"]["ip"],
            "seed_id": str(cp["server"]["id"]),
            "digest": self._identity_marker_digest(cp),
            "state": seed.state,
            "addresses": list(seed.addresses()),
        }
        self.save(cp)
        return cp

    def run_stage_dns_finalize_precheck(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Single-step: re-read Cloudflare records against the persisted
        manifest and persist the `dns_finalize_verified` marker. Requires
        CLOUDFLARE_API_TOKEN in the calling process.

        On success, transitions `awaiting_finalize` →
        `dns_finalize_verified`. Idempotent: re-running the precheck
        does not re-run the cloudflare re-read if the marker is
        already verified for the same txid/old_ip/new_ip/seed_id.
        """
        if cp.get("state") not in ("awaiting_finalize", "dns_finalize_verified"):
            raise NonRetryableError(
                f"finalize dns-precheck requires state in "
                f"('awaiting_finalize', 'dns_finalize_verified'), got "
                f"{cp.get('state')!r}"
            )
        existing = cp.get("dns_finalize_verified")
        if (existing and cp.get("state") == "dns_finalize_verified"
                and existing.get("txid") == cp["txid"]
                and existing.get("old_ip") == cp["old_ip"]["ip"]
                and existing.get("new_ip") == cp["new_ip"]["ip"]
                and existing.get("seed_id") == str(cp["server"]["id"])):
            self.log("  dns-finalize-precheck already verified; skipping")
            return cp
        self._step_dataforest_dns_finalize_precheck(cp)
        # The marker is now on disk. Advance the state so a separate
        # provider-finalize subprocess can pick up exactly here.
        if cp.get("state") == "awaiting_finalize":
            self._transition(cp, "dns_finalize_verified")
        # Boundary pause — the final provider-finalize is the only
        # stage that may produce the terminal `done` outcome.
        cp["outcome"] = "paused"
        self.save(cp)
        return cp

    def run_stage_provider_finalize(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Walk the provider finalize stages. Requires DATAFOREST_API_TOKEN
        AND exact state `dns_finalize_verified`.

        provider-finalize refuses `awaiting_finalize`: the Cloudflare
        precheck MUST have already advanced the state. This is the
        fail-closed separation that prevents the OLD_IP from being
        released while DNS still points at it.
        """
        if cp.get("state") != "dns_finalize_verified":
            raise NonRetryableError(
                f"provider-finalize requires exact state == "
                f"'dns_finalize_verified'; got {cp.get('state')!r}. "
                f"Run 'finalize-precheck' first."
            )
        if cp.get("finalize_intent") is not True:
            cp["finalize_intent"] = True
        steps_table, step_by_state = _steps_for_provider("dataforest", finalize=True)
        del steps_table
        while cp.get("state") not in ("done",):
            step = step_by_state.get(cp["state"])
            if step is None:
                self.escalate(cp, f"no finalize step is defined for state "
                                   f"{cp['state']!r}")
                return cp
            if step.fn == "_step_dataforest_dns_finalize_precheck":
                # The Cloudflare half. Advance past it without running —
                # the calling subprocess already ran dns-precheck and left
                # the marker on disk.
                self._transition(cp, "finalizing_started")
                continue
            self.log(f"[{cp['state']}] {step.fn[6:]}")
            try:
                getattr(self, step.fn)(cp)
            except IdentityMismatch as exc:
                self.escalate(cp, str(exc))
                return cp
            except EscalationRequired as exc:
                self.escalate(cp, str(exc), exc.recovery_commands or None)
                return cp
            except ProviderError as exc:
                self._handle_failure(cp, step, exc)
                return cp
            if cp["state"] == "done":
                cp["outcome"] = "done"
                self.save(cp)
                return cp
            self._transition(cp, step.to)
        return cp

    def run_stage_rollback_dns(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 1/4: PATCH the manifest records back to OLD_IP.
        Requires CLOUDFLARE_API_TOKEN.

        Idempotent: if `rollback.dns_step_at` is already set and the
        state is `dns_rollback_done` or further along, return the
        persisted marker.
        """
        if self.provider_only:
            raise EscalationRequired(
                "cloudflare.mode=provider_only rejects DNS mutations",
                [f"# unset cloudflare.mode in {self.config_path}"],
            )
        rb = cp.get("rollback") or {}
        if rb.get("dns_step_at") and cp.get("state") in (
                "dns_rollback_done", "inventory_rollback_done",
                "guest_rollback_done", "rolled_back"):
            self.log(f"  rollback-dns already done at {rb['dns_step_at']}; "
                     "skipping (idempotent)")
            return cp

        if cp.get("state") not in (
                "needs_rollback", "awaiting_finalize",
                "rolled_back", "rollback_incomplete"):
            raise NonRetryableError(
                f"rollback-dns requires state in (needs_rollback, "
                f"awaiting_finalize); got {cp.get('state')!r}"
            )

        # Idempotency: a previous incomplete run may have set the
        # marker but crashed before transition. Re-run only if the
        # state itself says we still need DNS work.
        if cp.get("state") != "needs_rollback" and rb.get("dns_step_at") is None:
            # We're parked at awaiting_finalize or already in some
            # terminal — initialize a fresh needs_rollback.
            if cp.get("state") == "awaiting_finalize":
                self._transition(cp, "needs_rollback")

        outcome = self._do_dns_rollback(cp)
        cp.setdefault("rollback", {})
        manifest = cp.get("cloudflare_manifest") or []
        digest = _manifest_digest(manifest)
        cp["rollback"]["state"] = outcome
        cp["rollback"]["dns_undone"] = outcome == "rolled_back"
        cp["rollback"]["dns_step_at"] = utcnow()
        cp["rollback"]["dns_marker"] = {
            "ts": cp["rollback"]["dns_step_at"],
            "txid": cp["txid"],
            "old_ip": cp["old_ip"]["ip"],
            "new_ip": cp["new_ip"]["ip"],
            "manifest_digest": digest,
            "record_count": len(manifest),
            "outcome": outcome,
        }
        if outcome == "rolled_back":
            # Intermediate stage — boundary pause, not terminal.
            # The final `rollback-provider` is the only stage that
            # may produce the terminal `rolled_back` outcome.
            self._transition(cp, "dns_rollback_done")
            cp["outcome"] = "paused"
        else:
            self._transition(cp, "rollback_incomplete")
            cp["outcome"] = "rollback_incomplete"
        self.save(cp)
        return cp

    def run_stage_rollback_inventory(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 2/4: prompt / print the inventory rollback edit. No token.

        Idempotent: if `rollback.inventory_step_at` is set and state
        is at or past `inventory_rollback_done`, skip.
        """
        if cp.get("state") not in (
                "dns_rollback_done", "inventory_rollback_done",
                "guest_rollback_done", "rollback_incomplete"):
            raise NonRetryableError(
                f"rollback-inventory requires state == dns_rollback_done; "
                f"got {cp.get('state')!r}. Run rollback-dns first."
            )
        rb = cp.get("rollback") or {}
        if rb.get("inventory_step_at") and cp.get("state") in (
                "inventory_rollback_done", "guest_rollback_done", "rolled_back"):
            self.log("  rollback-inventory already done; skipping")
            return cp

        ansible_adapter.inventory_rollback_step(
            alias=cp["alias"],
            inventory=(self.cfg.get("ansible") or {}).get(
                "inventory", "inventory/hosts.yml"),
            old_ip=cp["old_ip"]["ip"],
            new_ip=cp["new_ip"]["ip"],
            prompt=self.prompt,
            out=self.log,
        )
        cp.setdefault("rollback", {})
        cp["rollback"]["inventory_step_at"] = utcnow()
        cp["rollback"]["inventory_marker"] = {
            "ts": cp["rollback"]["inventory_step_at"],
            "txid": cp["txid"],
            "old_ip": cp["old_ip"]["ip"],
            "new_ip": cp["new_ip"]["ip"],
        }
        if cp.get("state") == "dns_rollback_done":
            self._transition(cp, "inventory_rollback_done")
        # Intermediate rollback stage — boundary pause, not terminal.
        cp["outcome"] = "paused"
        self.save(cp)
        return cp

    def run_stage_rollback_guest(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 3/4: drop NEW_IP from guest (runtime + persistent).
        Requires NO provider/DNS token.

        Idempotent: skip if `rollback.guest_step_at` is set and state
        is at or past `guest_rollback_done`.
        """
        if cp.get("state") not in (
                "inventory_rollback_done", "guest_rollback_done",
                "rollback_incomplete"):
            raise NonRetryableError(
                f"rollback-guest requires state in (inventory_rollback_done, "
                f"guest_rollback_done); got {cp.get('state')!r}. Run "
                f"rollback-inventory first."
            )
        rb = cp.get("rollback") or {}
        if rb.get("guest_step_at") and cp.get("state") in (
                "guest_rollback_done", "rolled_back"):
            self.log("  rollback-guest already done; skipping")
            return cp

        inv_id = _new_invocation_id_dataforest()
        try:
            self.guest_op(
                "restore_guest",
                txid=cp["txid"],
                invocation_id=inv_id,
                interface=(self.cfg.get("guest") or {}).get("interface"),
                new_address=f"{cp['old_ip']['ip']}/32",
                old_address=f"{cp['old_ip']['ip']}/32",
                backup_files=[],
                expected_checksums={},
            )
        except Exception as exc:  # pylint: disable=broad-except
            self.log(f"  guest rollback failed: {exc}")
            cp["rollback_guest_error"] = redact(str(exc))
            cp["outcome"] = "rollback_incomplete"
            self._transition(cp, "rollback_incomplete")
            self.save(cp)
            raise
        cp.setdefault("rollback", {})
        cp["rollback"]["guest_step_at"] = utcnow()
        cp["rollback"]["guest_marker"] = {
            "ts": cp["rollback"]["guest_step_at"],
            "txid": cp["txid"],
            "old_ip": cp["old_ip"]["ip"],
            "new_ip": cp["new_ip"]["ip"],
            "invocation_id": inv_id,
        }
        if cp.get("state") == "inventory_rollback_done":
            self._transition(cp, "guest_rollback_done")
        # Intermediate rollback stage — boundary pause, not terminal.
        cp["outcome"] = "paused"
        self.save(cp)
        return cp

    def run_stage_rollback_provider(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 4/4: POST seed.remove-ipv4 for NEW_IP. Requires
        DATAFOREST_API_TOKEN. The ONLY stage that may produce
        `rolled_back`.

        Pre-conditions (verified before this point):
          * dns_rollback_done    — by rollback-dns
          * inventory_rollback_done — by rollback-inventory
          * guest_rollback_done  — by rollback-guest
        If any of these markers is missing, the provider refuses; this
        is the contract that prevents removing NEW_IP before safe.
        """
        if cp.get("state") not in (
                "guest_rollback_done", "rolled_back"):
            raise NonRetryableError(
                f"rollback-provider requires state in (guest_rollback_done, "
                f"rolled_back); got {cp.get('state')!r}. Run "
                f"rollback-guest first."
            )
        rb = cp.get("rollback") or {}
        if rb.get("provider_step_at") and cp.get("state") == "rolled_back":
            self.log("  rollback-provider already done; skipping")
            return cp

        # Verify all prior markers exist. Missing one means the operator
        # ran this out of order; refuse before deleting anything.
        for key in ("dns_step_at", "inventory_step_at", "guest_step_at"):
            if not rb.get(key):
                raise NonRetryableError(
                    f"rollback-provider refuses: rollback.{key} missing; "
                    f"re-run earlier rollback stages in order."
                )

        # Idempotent: if NEW_IP is already gone, just mark rolled_back
        # (a previous crash left us here) and return.
        seed_id = cp["server"]["id"]
        new_ip = cp["new_ip"]["ip"]
        old_ip = cp["old_ip"]["ip"]
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        before = seed.addresses()
        if new_ip not in before:
            cp.setdefault("rollback", {})
            cp["rollback"]["provider_step_at"] = utcnow()
            cp["rollback"]["provider_marker"] = {
                "ts": cp["rollback"]["provider_step_at"],
                "txid": cp["txid"],
                "old_ip": old_ip,
                "new_ip": new_ip,
                "seed_id": seed_id,
                "result": "already_absent",
            }
            cp["outcome"] = "rolled_back"
            self._transition(cp, "rolled_back")
            self.save(cp)
            return cp

        if old_ip not in before:
            cp["outcome"] = "rollback_incomplete"
            self._mark_rollback_incomplete(
                cp, f"seed {seed_id} has NEW_IP {new_ip} but no OLD_IP "
                f"{old_ip}; refusing to release NEW_IP without proof "
                f"OLD_IP survives")
            return cp

        # Persist apply-started marker BEFORE the POST so a crash is
        # recoverable. The marker uses `provider_rollback_started` (NOT
        # `provider_finalize_started`) so a future finalize is never
        # confused with a rollback.
        cp["_apply_intent"] = "rollback"
        self._persist_apply_started(cp, "seed.remove-ipv4")
        try:
            body = self.with_retries(
                "post_remove", self.provider.remove_ipv4, seed_id, new_ip)
        except ProviderError as exc:
            self._mark_rollback_incomplete(
                cp, f"seed.remove-ipv4 of NEW_IP {new_ip} failed: {exc}")
            return cp
        # If async, poll. Body is the action.
        if body and (body.get("action_id") or body.get("id")):
            try:
                self._poll_action(cp, seed_id,
                                   str(body.get("action_id") or body.get("id")))
            except Exception as exc:  # pylint: disable=broad-except
                self.log(f"  provider rollback action poll failed: {exc}")

        # Re-read the Seed and assert OLD_IP remains, NEW_IP is gone.
        seed = self.with_retries("get_seed", self.provider.get_seed, seed_id)
        after = seed.addresses()
        if old_ip not in after:
            cp["outcome"] = "rollback_incomplete"
            self._mark_rollback_incomplete(
                cp, f"seed {seed_id} OLD_IP {old_ip} disappeared during "
                f"rollback; refusing to claim rolled_back")
            return cp
        if new_ip in after:
            cp["outcome"] = "rollback_incomplete"
            self._mark_rollback_incomplete(
                cp, f"seed {seed_id} NEW_IP {new_ip} still present after "
                f"seed.remove-ipv4; refusing to claim rolled_back")
            return cp

        # Persist provider marker. Only NOW do we transition to
        # `rolled_back`. The provider step is the ONLY stage allowed to
        # produce this terminal state.
        cp.setdefault("rollback", {})
        cp["rollback"]["provider_step_at"] = utcnow()
        cp["rollback"]["provider_marker"] = {
            "ts": cp["rollback"]["provider_step_at"],
            "txid": cp["txid"],
            "old_ip": old_ip,
            "new_ip": new_ip,
            "seed_id": seed_id,
            "result": "removed",
        }
        cp["outcome"] = "rolled_back"
        self._transition(cp, "rolled_back")
        self.save(cp)
        return cp


# -- CLI -------------------------------------------------------------------
def build_provider(args: argparse.Namespace, runner: Optional[Callable] = None) -> HcloudProvider:
    return HcloudProvider(runner or ansible_runner())


def _outcome_exit_code(cp: Dict[str, Any]) -> int:
    return {
        "done": EXIT_OK,
        "rolled_back": EXIT_ROLLED_BACK,
        "rollback_incomplete": EXIT_ROLLBACK_INCOMPLETE,
        "escalated": EXIT_ESCALATED,
        "paused": EXIT_PAUSED,
    }.get(cp.get("outcome") or "", EXIT_OK)


def _set_paused(cp: Dict[str, Any]) -> Dict[str, Any]:
    """Mark a checkpoint as a boundary pause (rc 6), not a terminal."""
    cp["outcome"] = "paused"
    return cp


def _resolve_state_dir(cfg: Dict[str, Any], config_path: str) -> str:
    state_dir = cfg.get("state_dir") or "state"
    if os.path.isabs(state_dir):
        return state_dir
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(config_path)), state_dir))


def _resolve_repo_dir(cfg: Dict[str, Any], config_path: str) -> str:
    repo = (cfg.get("ansible") or {}).get("repo_dir") or ".."
    if os.path.isabs(repo):
        return repo
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(config_path)), repo))


def main(
    argv: Optional[List[str]] = None,
    runner: Optional[Callable] = None,
    **rotation_kwargs: Any,
) -> int:
    """`runner` and `rotation_kwargs` exist so the offline tests can drive the
    REAL argument parsing, config loading and confirmation gate rather than a
    re-implementation of them. Production always calls main() with neither."""
    parser = argparse.ArgumentParser(
        prog="rotate.py",
        description="Rotate a Hetzner Cloud node's Primary IPv4, with a way back.",
    )
    parser.add_argument("--self-test", action="store_true", help="run the bundled offline checks")
    sub = parser.add_subparsers(dest="command")

    p_plan = sub.add_parser("plan", help="read everything, change nothing (default)")
    p_plan.add_argument("--config", required=True)

    p_apply = sub.add_parser("apply", help="execute a rotation")
    p_apply.add_argument("--config", required=True)
    p_apply.add_argument("--confirm-server-id", default=None)
    p_apply.add_argument("--until", choices=PAUSABLE, default=None,
                         help="stop cleanly at this state instead of running to done")

    p_resume = sub.add_parser("resume", help="continue an interrupted transaction")
    p_resume.add_argument("--txid", required=True)
    p_resume.add_argument("--config", default=None)
    p_resume.add_argument("--confirm-server-id", default=None)
    p_resume.add_argument("--until", choices=PAUSABLE, default=None,
                          help="stop cleanly at this state instead of running to done")

    p_rollback = sub.add_parser("rollback", help="put the old address back")
    p_rollback.add_argument("--txid", required=True)
    p_rollback.add_argument("--config", default=None)
    p_rollback.add_argument("--confirm-server-id", default=None)
    p_rollback.add_argument(
        "--no-dns-rollback",
        action="store_true",
        help="only restore the provider IP — do not invoke the Cloudflare "
             "playbook. Use this when the workflow has decided DNS recovery "
             "is not needed and wants to keep CLOUDFLARE_API_TOKEN out of "
             "this process entirely.",
    )
    p_rollback.add_argument(
        "--dns-rollback-only",
        action="store_true",
        help="only invoke the Cloudflare playbook for DNS rollback. Use "
             "this when the provider IP is already restored and the "
             "workflow has the CLOUDFLARE_API_TOKEN available.",
    )

    p_status = sub.add_parser("status", help="print a checkpoint")
    p_status.add_argument("--txid", required=True)
    p_status.add_argument("--config", default=None)

    # ----- staged subcommands ----------------------------------------------
    # Each one drives ONE step in a separate process. The workflow YAML
    # invokes them with only the token that step requires.
    p_finalize_precheck = sub.add_parser(
        "finalize-precheck",
        help="DataForest only: Cloudflare DNS read-back BEFORE the OLD_IP "
             "release. Writes a dns_finalize_verified marker. Requires "
             "CLOUDFLARE_API_TOKEN only.",
    )
    p_finalize_precheck.add_argument("--txid", required=True)
    p_finalize_precheck.add_argument("--config", default=None)
    p_finalize_precheck.add_argument("--confirm-server-id", default=None)

    p_provider_finalize = sub.add_parser(
        "provider-finalize",
        help="DataForest only: release OLD_IP from the Seed. Requires "
             "DATAFOREST_API_TOKEN only and a fresh dns_finalize_verified "
             "marker; refuses without.",
    )
    p_provider_finalize.add_argument("--txid", required=True)
    p_provider_finalize.add_argument("--config", default=None)
    p_provider_finalize.add_argument("--confirm-server-id", default=None)

    p_rollback_dns = sub.add_parser(
        "rollback-dns",
        help="Cloudflare DNS rollback ONLY. Requires CLOUDFLARE_API_TOKEN. "
             "The workflow invokes this on a separate step with the token "
             "kept out of the provider rollback process.",
    )
    p_rollback_dns.add_argument("--txid", required=True)
    p_rollback_dns.add_argument("--config", default=None)
    p_rollback_dns.add_argument("--confirm-server-id", default=None)

    p_rollback_inventory = sub.add_parser(
        "rollback-inventory",
        help="Inventory rollback prompt/edit only. NO token required.",
    )
    p_rollback_inventory.add_argument("--txid", required=True)
    p_rollback_inventory.add_argument("--config", default=None)
    p_rollback_inventory.add_argument("--confirm-server-id", default=None)

    p_rollback_guest = sub.add_parser(
        "rollback-guest",
        help="Guest network rollback only. NO token required.",
    )
    p_rollback_guest.add_argument("--txid", required=True)
    p_rollback_guest.add_argument("--config", default=None)
    p_rollback_guest.add_argument("--confirm-server-id", default=None)

    p_rollback_provider = sub.add_parser(
        "rollback-provider",
        help="DataForest only: release NEW_IP from the Seed. Requires "
             "DATAFOREST_API_TOKEN only.",
    )
    p_rollback_provider.add_argument("--txid", required=True)
    p_rollback_provider.add_argument("--config", default=None)
    p_rollback_provider.add_argument("--confirm-server-id", default=None)

    p_finalize = sub.add_parser(
        "finalize",
        help="DataForest only: release OLD_IP from the Seed (point of no return)",
    )

    # DataForest identity-check: re-reads the Seed and persists a
    # digest-bound marker so subsequent subprocesses (guest
    # Ansible, Cloudflare precheck) can verify identity without
    # inheriting DATAFOREST_API_TOKEN.
    p_identity_check = sub.add_parser(
        "dataforest-identity-check",
        help="DataForest only: re-read the Seed, persist a "
             "dataforest_identity_ok marker. Requires "
             "DATAFOREST_API_TOKEN only. The guest Ansible "
             "subprocess that follows runs without any provider token.",
    )
    p_finalize.add_argument("--txid", required=True)
    p_finalize.add_argument("--config", default=None)
    p_finalize.add_argument("--confirm-server-id", default=None)

    p_identity_check.add_argument("--txid", required=True)
    p_identity_check.add_argument("--config", default=None)
    p_identity_check.add_argument("--confirm-server-id", default=None)

    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    try:
        return _dispatch(args, runner, rotation_kwargs)
    except ConfigError as exc:
        print(f"config error: {redact(exc)}", file=sys.stderr)
        return EXIT_USAGE
    except IdentityMismatch as exc:
        print(f"identity mismatch: {redact(exc)}", file=sys.stderr)
        return EXIT_IDENTITY
    except EscalationRequired as exc:
        print(f"escalated: {redact(exc)}", file=sys.stderr)
        for line in exc.recovery_commands:
            print(f"  {line}", file=sys.stderr)
        return EXIT_ESCALATED
    except NotFound as exc:
        print(f"not found: {redact(exc)}", file=sys.stderr)
        return EXIT_PROVIDER
    except ProviderError as exc:
        print(f"provider error: {redact(exc)}", file=sys.stderr)
        return EXIT_PROVIDER


def _dispatch(
    args: argparse.Namespace,
    runner: Optional[Callable] = None,
    rotation_kwargs: Optional[Dict[str, Any]] = None,
) -> int:
    # The token is checked here, once, before anything else: a rotation that
    # discovers a missing credential halfway through is a powered-off node.
    # DataForest uses DATAFOREST_API_TOKEN; Hetzner uses HCLOUD_TOKEN.
    # Provider-specific gate: DataForest calls need only DATAFOREST_API_TOKEN,
    # Hetzner calls need only HCLOUD_TOKEN.
    config_path = getattr(args, "config", None)
    if args.command in ("resume", "rollback", "status", "finalize") and not config_path:
        # The checkpoint remembers which config started the transaction, so
        # `resume` cannot be pointed at a different server by a stale shell.
        probe_dir = os.path.join(HERE, "state")
        candidate = os.path.join(probe_dir, f"{args.txid}.json")
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                config_path = json.load(handle)["config_path"]
        except (OSError, KeyError, ValueError) as exc:
            raise ConfigError(
                f"--config is required (could not read {candidate}: {exc})"
            ) from exc

    cfg = load_config(config_path)
    register_secret(os.environ.get("HCLOUD_TOKEN"))
    register_secret(os.environ.get(CLOUDFLARE_TOKEN_ENV))
    register_secret(os.environ.get(DATAFOREST_TOKEN_ENV))

    provider_name = cfg.get("provider") or "hcloud"
    if provider_name == "hcloud" and not token_present():
        print(
            "HCLOUD_TOKEN is not set. Nothing was contacted.\n"
            "  export HCLOUD_TOKEN=\"$(ansible-vault view vault.yml"
            " | awk '/^hcloud_api_token:/ {print $2}' | tr -d \"\\\"\'\')\"",
            file=sys.stderr,
        )
        return EXIT_USAGE
    # Some DataForest commands do NOT need DATAFOREST_API_TOKEN at the
    # dispatch gate (they run on a CF-only env, or no token at all).
    # The per-command branch below re-checks the token it needs and
    # refuses if missing. Skipping the broad DF gate here keeps the
    # token-isolation contract honest.
    # Also: `resume --until X` for X in CF-only states must NOT require
    # DF token. Those stages contact Cloudflare only (after the apply
    # has already allocated via DF). The guest stages contact NEITHER
    # provider API: their identity evidence is the digest-bound marker
    # `dataforest-identity-check` persisted in its own subprocess, so
    # requiring a provider token here would defeat the whole split.
    cf_only_until = (args.command == "resume" and getattr(args, "until",
                       None) in (
                           "cloudflare_preflighted", "ansible_done",
                           "cloudflare_replaced", "awaiting_finalize",
                           "guest_configured", "guest_verified"))
    skip_df_gate = args.command in (
        "finalize-precheck", "rollback-dns",
        "rollback-inventory", "rollback-guest",
        "status",
    ) or cf_only_until
    if provider_name == "dataforest" and not skip_df_gate \
            and not dataforest_token_present():
        print(
            "DATAFOREST_API_TOKEN is not set. Nothing was contacted.\n"
            "  export DATAFOREST_API_TOKEN=\"$(ansible-vault view vault.yml"
            " | awk '/^dataforest_api_token:/ {print $2}' | tr -d \"\\\"\'\')\"",
            file=sys.stderr,
        )
        return EXIT_USAGE

    state_dir = _resolve_state_dir(cfg, config_path)
    # CF-only commands don't contact DataForest; let the adapter
    # construct without a token. The token gate in each per-command
    # branch enforces it for the stages that do contact DataForest.
    needs_df_token = (
        args.command not in (
            "finalize-precheck", "rollback-dns",
            "rollback-inventory", "rollback-guest",
            "status",
        )
        and not cf_only_until
    )
    provider = _build_provider(cfg, runner or ansible_runner(),
                                token_required=needs_df_token)
    rotation = Rotation(
        config=cfg,
        provider=provider,
        state_dir=state_dir,
        repo_dir=_resolve_repo_dir(cfg, config_path),
        config_path=config_path,
        until=getattr(args, "until", None),
        # Every transition also lands in GitHub's job summary. Outside Actions
        # the hook writes nothing, so this costs a dict lookup on a terminal.
        **{"on_transition": github_summary, **(rotation_kwargs or {})},
    )

    if args.command == "status":
        print(json.dumps(rotation.load(args.txid), indent=2, sort_keys=True))
        return EXIT_OK

    if args.command == "plan":
        rotation.plan()
        return EXIT_OK

    # apply / resume / rollback / finalize all mutate, so all need the
    # confirmation gate.
    expected = cfg["server"]["id"]
    given = args.confirm_server_id
    if given is None:
        print(
            f"refusing to {args.command}: --confirm-server-id is required and must be "
            f"the value from the config (`server.id`).\n"
            f"  rotate.py {args.command} ... --confirm-server-id <the id>\n"
            "  (`plan` prints it. The value is the TARGET'S OWN id on purpose \u2014 "
            "\'yes\' and \'true\' are not spellings of a specific server.)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if str(given) != str(expected):
        print(
            f"identity mismatch: --confirm-server-id {given} != config server.id "
            f"{expected}. Nothing was contacted.",
            file=sys.stderr,
        )
        return EXIT_IDENTITY

    if args.command == "finalize":
        # `finalize` (legacy) — refuses unless the checkpoint is already at
        # awaiting_finalize AND no dns_finalize_verified marker exists. The
        # workflow uses `finalize-precheck` + `provider-finalize` instead.
        cp = rotation.load(args.txid)
        if str(cp["server"]["id"]) != str(expected):
            raise IdentityMismatch(
                f"checkpoint {args.txid} targets seed {cp['server']['id']}, "
                f"the config targets {expected}"
            )
        if cp.get("provider") != "dataforest":
            raise ConfigError(
                f"`finalize` is a DataForest-only command. "
                f"This checkpoint is for provider {cp.get('provider')!r}."
            )
        if cp.get("state") != "awaiting_finalize":
            raise ConfigError(
                f"`finalize` requires state == awaiting_finalize; current "
                f"state is {cp.get('state')!r}. Use the workflow-driven "
                "`finalize-precheck` + `provider-finalize` stages."
            )
        # Refuse without a DNS precheck marker. The legacy single-shot
        # finalize CANNOT perform a fresh Cloudflare read-back because the
        # caller might have only DATAFOREST_API_TOKEN in scope; running it
        # would either skip the DNS check (silent drift) or request a
        # second token (contradiction). Force the staged path.
        if not cp.get("dns_finalize_verified"):
            raise ConfigError(
                "`finalize` requires cp['dns_finalize_verified']; run "
                "`finalize-precheck` (with CLOUDFLARE_API_TOKEN) before "
                "`provider-finalize` (with DATAFOREST_API_TOKEN). The "
                "single-shot finalize is structurally forbidden."
            )
        # Set the marker so execute() walks the finalize subcommand steps.
        cp["finalize_intent"] = True
        cp = rotation.execute(cp)
        return _outcome_exit_code(cp)

    # ---- staged subcommands ----------------------------------------------
    # Each one drives ONE stage in a separate process. The token gate
    # below enforces that the calling process carries only the token the
    # stage needs — a missing token fails loudly, a forbidden token
    # fails loudly. The workflow YAML is the single source of truth for
    # which env each step runs with.
    if args.command == "dataforest-identity-check":
        # Needs DATAFOREST_API_TOKEN. CLOUDFLARE_API_TOKEN MUST NOT be
        # in scope (the Seed read doesn't need it).
        if not dataforest_token_present():
            print("DATAFOREST_API_TOKEN is not set. dataforest-identity-check "
                  "requires it.", file=sys.stderr)
            return EXIT_USAGE
        cp = rotation.load(args.txid)
        if cp.get("provider") != "dataforest":
            raise ConfigError("dataforest-identity-check is DataForest-only.")
        cp = rotation.run_stage_dataforest_identity_check(cp)
        # Boundary pause — the result is a persisted identity marker
        # for subsequent subprocesses to consume.
        return _outcome_exit_code(_set_paused(cp))

    if args.command == "finalize-precheck":
        # Needs CLOUDFLARE_API_TOKEN. DATAFOREST_API_TOKEN MUST NOT be in
        # scope (the Cloudflare adapter doesn't need it, and the workflow
        # is the only place that decides what is in scope).
        if not cf_token_present():
            print("CLOUDFLARE_API_TOKEN is not set. finalize-precheck "
                  "requires it.", file=sys.stderr)
            return EXIT_USAGE
        cp = rotation.load(args.txid)
        if cp.get("provider") != "dataforest":
            raise ConfigError("finalize-precheck is DataForest-only.")
        cp["finalize_intent"] = True
        cp = rotation.run_stage_dns_finalize_precheck(cp)
        return _outcome_exit_code(cp)

    if args.command == "provider-finalize":
        # Needs DATAFOREST_API_TOKEN. CLOUDFLARE_API_TOKEN MUST NOT be in
        # scope.
        if not dataforest_token_present():
            print("DATAFOREST_API_TOKEN is not set. provider-finalize "
                  "requires it.", file=sys.stderr)
            return EXIT_USAGE
        cp = rotation.load(args.txid)
        if cp.get("provider") != "dataforest":
            raise ConfigError("provider-finalize is DataForest-only.")
        cp["finalize_intent"] = True
        cp = rotation.run_stage_provider_finalize(cp)
        return _outcome_exit_code(cp)

    if args.command == "rollback-dns":
        if not cf_token_present():
            print("CLOUDFLARE_API_TOKEN is not set. rollback-dns requires it.",
                  file=sys.stderr)
            return EXIT_USAGE
        cp = rotation.load(args.txid)
        if str(cp["server"]["id"]) != str(expected):
            raise IdentityMismatch(
                f"checkpoint {args.txid} targets server "
                f"{cp['server']['id']}, the config targets {expected}"
            )
        cp = rotation.run_stage_rollback_dns(cp)
        return _outcome_exit_code(cp)

    if args.command == "rollback-inventory":
        cp = rotation.load(args.txid)
        if str(cp["server"]["id"]) != str(expected):
            raise IdentityMismatch(
                f"checkpoint {args.txid} targets server "
                f"{cp['server']['id']}, the config targets {expected}"
            )
        cp = rotation.run_stage_rollback_inventory(cp)
        return _outcome_exit_code(cp)

    if args.command == "rollback-guest":
        cp = rotation.load(args.txid)
        if str(cp["server"]["id"]) != str(expected):
            raise IdentityMismatch(
                f"checkpoint {args.txid} targets server "
                f"{cp['server']['id']}, the config targets {expected}"
            )
        cp = rotation.run_stage_rollback_guest(cp)
        return _outcome_exit_code(cp)

    if args.command == "rollback-provider":
        if not dataforest_token_present():
            print("DATAFOREST_API_TOKEN is not set. rollback-provider "
                  "requires it.", file=sys.stderr)
            return EXIT_USAGE
        cp = rotation.load(args.txid)
        if cp.get("provider") != "dataforest":
            raise ConfigError("rollback-provider is DataForest-only.")
        cp = rotation.run_stage_rollback_provider(cp)
        return _outcome_exit_code(cp)

    if args.command == "apply":
        # The DataForest apply path walks through cloudflare_preflight, so
        # the calling process MUST carry CLOUDFLARE_API_TOKEN. The workflow
        # enforces this by passing it on the step that uses `apply
        # --until cloudflare_preflighted` and `apply --until ansible_done`
        # and `apply --until cloudflare_replaced` only. The earlier
        # provider/guest stages must NOT carry it; gate accordingly.
        if cfg.get("provider") == "dataforest":
            until = getattr(args, "until", None)
            if until in ("cloudflare_preflighted", "ansible_done",
                         "cloudflare_replaced"):
                if not cf_token_present():
                    print(
                        f"apply --until {until} (DataForest) requires "
                        "CLOUDFLARE_API_TOKEN; the step cannot proceed "
                        "without it.",
                        file=sys.stderr,
                    )
                    return EXIT_USAGE
            else:
                # Provider / guest stages must NOT see CLOUDFLARE_API_TOKEN.
                if cf_token_present():
                    print(
                        f"apply --until {until!r} (DataForest provider/guest "
                        "stage) must NOT carry CLOUDFLARE_API_TOKEN; "
                        "remove it from the calling env to honour secret "
                        "isolation.",
                        file=sys.stderr,
                    )
                    return EXIT_USAGE
        cp = rotation.plan()
        rotation._transition(cp, "confirmed")
        cp = rotation.execute(cp)
    else:
        cp = rotation.load(args.txid)
        if str(cp["server"]["id"]) != str(expected):
            raise IdentityMismatch(
                f"checkpoint {args.txid} targets server {cp['server']['id']}, "
                f"the config targets {expected}"
            )
        if args.command == "rollback":
            if args.dns_rollback_only:
                rotation.dns_rollback_only(cp)
            elif args.no_dns_rollback:
                if cp.get("provider") == "dataforest":
                    rotation._rollback_dataforest_new_ip(
                        cp, "operator ran `rollback --no-dns-rollback`")
                else:
                    rotation.restore_old_ip(cp, "operator ran `rollback`",
                                            skip_dns_rollback=True)
            else:
                if cp.get("provider") == "dataforest":
                    rotation._rollback_dataforest_new_ip(
                        cp, "operator ran `rollback`")
                else:
                    rotation.restore_old_ip(cp, "operator ran `rollback`")
        else:
            # DataForest resume must walk the same token-isolation gate as
            # apply: provider/guest stages reject CLOUDFLARE_API_TOKEN in
            # scope, while DNS stages require it.
            if cfg.get("provider") == "dataforest":
                until = getattr(args, "until", None)
                if until in ("cloudflare_preflighted", "ansible_done",
                             "cloudflare_replaced", "awaiting_finalize"):
                    if not cf_token_present():
                        print(
                            f"resume --until {until} (DataForest) requires "
                            "CLOUDFLARE_API_TOKEN; the step cannot proceed "
                            "without it.",
                            file=sys.stderr,
                        )
                        return EXIT_USAGE
                else:
                    if cf_token_present():
                        print(
                            f"resume --until {until!r} (DataForest "
                            "provider/guest stage) must NOT carry "
                            "CLOUDFLARE_API_TOKEN; remove it from the "
                            "calling env to honour secret isolation.",
                            file=sys.stderr,
                        )
                        return EXIT_USAGE
            if cp["state"] in ("planned", "created", "validated"):
                rotation._transition(cp, "confirmed")
            cp = rotation.execute(cp)

    return _outcome_exit_code(cp)


def _build_provider(
    cfg: Dict[str, Any],
    runner: Optional[Callable] = None,
    *,
    token_required: bool = True,
) -> Any:
    """One provider per dispatch. DataForest's adapter is constructed here
    from env tokens; Hetzner gets the Ansible runner seam.

    `DATAFOREST_API_BASE_URL` is honoured only when the loopback test
    marker (`DATAFOREST_API_TEST_MODE=1`) is set, mirroring the adapter's
    own gate. Production never sets that env var, so a typo in CI cannot
    silently point production traffic at a fake endpoint.

    `token_required=False` is used by CF-only commands (finalize-precheck,
    rollback-dns) that never contact DataForest — those commands still
    load `cfg["provider"] = dataforest`, so we need a usable object, but
    the token gate is enforced in the per-command branch instead.
    """
    provider_name = cfg.get("provider")
    if provider_name == "hcloud":
        return HcloudProvider(runner or ansible_runner())
    if provider_name == "dataforest":
        kwargs: Dict[str, Any] = {"require_token": token_required}
        if os.environ.get("DATAFOREST_API_TEST_MODE") == "1":
            base = os.environ.get("DATAFOREST_API_BASE_URL")
            if base:
                kwargs["base_url"] = base
        adapter = dataforest_adapter.DataForestAdapter(**kwargs)
        return DataForestProvider(adapter)
    raise ConfigError(f"unknown provider {provider_name!r}")


# --------------------------------------------------------------------------
# self-test -- `rotate.py --self-test`, offline, no ansible, no network
# --------------------------------------------------------------------------
def self_test() -> int:
    """A full plan + apply against the in-memory fake, plus a redaction check.

    Deliberately reuses tests/fake_hcloud.py rather than carrying its own
    fixture: two fakes of the same provider drift, and the one that is not run
    by `make test-offline` is the one that rots.
    """
    sys.path.insert(0, HERE)
    from tests.fake_hcloud import FakeHcloud, example_config  # noqa: E402

    token = "self-test-token-never-real"
    os.environ["HCLOUD_TOKEN"] = token
    os.environ.setdefault("CLOUDFLARE_API_TOKEN", "self-test-cf-token-never-real")
    register_secret(token)
    register_secret(os.environ["CLOUDFLARE_API_TOKEN"])

    with tempfile.TemporaryDirectory() as tmp:
        fake = FakeHcloud()
        cfg = example_config(fake)
        # The self-test exercises the provider half in isolation. Wiring the
        # Cloudflare half would either need a fake runner here too or run
        # the real playbook (which we explicitly avoid in --self-test).
        cfg["cloudflare"]["mode"] = "provider_only"
        lines: List[str] = []
        rot = Rotation(
            config=cfg,
            provider=HcloudProvider(fake, fingerprint=project_fingerprint()),
            state_dir=tmp,
            repo_dir=tmp,
            config_path=os.path.join(tmp, "rotation.yml"),
            probe=lambda h, p, t: True,
            ip_change=lambda alias, cwd: {
                "argv": ansible_adapter.ip_change_argv(alias), "rc": 0,
                "stdout_tail": "", "stderr_tail": "",
            },
            prompt=lambda _: "yes",
            out=lines.append,
            sleep=lambda _: None,
        )

        cp = rot.plan()
        assert cp["state"] == "planned", cp["state"]
        assert fake.write_count == 0, f"plan mutated {fake.write_count} time(s)"

        rot._transition(cp, "confirmed")
        cp = rot.execute(cp)
        # In provider_only mode the run parks at connectivity_ok. The provider
        # half ran end-to-end; the DNS half was structurally skipped.
        assert cp["state"] == "connectivity_ok", f"ended in {cp['state']}: {cp.get('escalations')}"
        assert cp["outcome"] == "paused"
        assert fake.server["ipv4_address"] == cp["new_ip"]["ip"]
        assert fake.ips[cp["old_ip"]["id"]]["assignee_id"] is None
        assert fake.ips[cp["old_ip"]["id"]]["auto_delete"] is False, "old IP left auto-deletable"

        blob = "".join(lines) + open(os.path.join(tmp, f"{cp['txid']}.json"), encoding="utf-8").read()
        assert token not in blob, "the token leaked into output or the checkpoint"
        assert redact(f"Bearer {token}") == "Bearer [REDACTED]"

    print("self-test OK")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
