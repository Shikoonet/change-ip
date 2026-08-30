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
from providers import (  # noqa: E402
    CLOUDFLARE_TOKEN_ENV,
    EscalationRequired,
    HcloudProvider,
    IdentityMismatch,
    NonRetryableError,
    NotFound,
    ProviderError,
    RetryableError,
    cf_token_present,
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

STEP_BY_STATE = {s.frm: s for s in STEPS}

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


TERMINAL = ("done", "planned", "rolled_back", "rollback_incomplete", "escalated")

#: States `--until` may name. ONLY the three where the box is up and
#: reachable and DNS is settled: everything else is mid-swap or pre-DNS, where
#: "stop here" means "a node with an inconsistent DNS picture".
PAUSABLE = ("connectivity_ok", "ansible_done", "cloudflare_replaced")


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
    if data.get("provider") != "hcloud":
        raise ConfigError(f"{path}: provider must be 'hcloud' (only one is implemented)")

    server = data.get("server") or {}
    for key in ("id", "expected_name", "expected_ipv4", "expected_location"):
        if not server.get(key):
            raise ConfigError(
                f"{path}: server.{key} is required. The numeric id is immutable and "
                "is read from the Hetzner console once; the expected_* values are "
                "what every identity assert compares against."
            )
    try:
        server["id"] = int(server["id"])
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: server.id must be the numeric id, not a name") from exc

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
    if not mode:  # full run — require allowlist
        if not cf.get("allowed_records"):
            raise ConfigError(
                f"{path}: cloudflare.allowed_records is required when "
                "cloudflare.mode is not 'provider_only'. An empty allow-list "
                "is a stop, not a pass."
            )
        if not cf.get("expected_record_count"):
            raise ConfigError(
                f"{path}: cloudflare.expected_record_count is required when "
                "cloudflare.mode is not 'provider_only'."
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
        provider: HcloudProvider,
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
    ):
        self.cfg = config
        self.provider = provider
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
        """
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
        cp: Dict[str, Any] = {
            "version": CHECKPOINT_VERSION,
            "txid": txid,
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "operator": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
            "state": "created",
            "provider": "hcloud",
            "project_fingerprint": self.provider.fingerprint,
            "config_path": os.path.abspath(self.config_path),
            "server": {
                "id": int(self.cfg["server"]["id"]),
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

        pinned = self.cfg.get("project_fingerprint")
        if pinned and pinned != cp["project_fingerprint"]:
            raise IdentityMismatch(
                f"project_fingerprint in the config is {pinned} but HCLOUD_TOKEN "
                f"fingerprints to {cp['project_fingerprint']}. Either the wrong token "
                "is exported or the config points at another project."
            )

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

        self._print_plan(cp)
        # In provider_only mode the rotation stops at `connectivity_ok`,
        # regardless of --until. We land in `planned`, and the apply/resume
        # path will park at connectivity_ok. The argparse --until choice
        # names a `PAUSABLE` state; `provider_only` is structural and applies
        # even without an --until flag.
        self._transition(cp, "planned")
        return cp

    def _print_plan(self, cp: Dict[str, Any]) -> None:
        o = self.log
        o("")
        o("=" * 72)
        o(f"  PLAN  txid {cp['txid']}   project {cp['project_fingerprint']}")
        o("=" * 72)
        o(f"  server        {cp['server']['id']}  {cp['server']['expected_name']}")
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
        if not cf_token_present():
            raise EscalationRequired(
                "CLOUDFLARE_API_TOKEN is not set. The ansible uri tasks read "
                "it from the environment themselves; export it before running.",
                [
                    "export CLOUDFLARE_API_TOKEN=\"$(ansible-vault view vault.yml "
                    "| awk '/^cloudflare_api_token:/ {print $2}' | tr -d \"\\\"')\""
                ],
            )
        allowed = self._allowed_records()
        expected = self._expected_record_count()
        if not allowed:
            raise EscalationRequired(
                "cloudflare.allowed_records is empty — refusing to discover.",
                [f"# edit {self.config_path} and fill cloudflare.allowed_records"],
            )
        result = self.with_retries(
            "cloudflare_preflight", self.cloudflare_preflight,
            "discover",
            old_ip=cp["old_ip"]["ip"],
            new_ip="",  # not used by discover, but the adapter requires it
            allowed_records=allowed,
            expected_count=expected,
            invocation_id=_new_invocation_id(),
        )
        manifest = (result.get("result") or {}).get("manifest") or []
        cp["cloudflare_manifest"] = manifest
        cp["cloudflare_preflight"] = {
            "ts": utcnow(),
            "rc": result.get("rc"),
            "record_count": len(manifest),
        }
        self.record(cp, "cloudflare_preflight", f"{len(manifest)} record(s)")

    def _step_cloudflare_replace(self, cp: Dict[str, Any]) -> None:
        """PATCH every manifest record from OLD_IP to NEW_IP, with read-back."""
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
        # Persist a marker BEFORE invoking the subprocess so a crash mid-PATCH
        # leaves an unambiguous signal in the checkpoint: rollback treats DNS
        # mutation as having begun and uses this manifest to reverse it.
        invocation_id = _new_invocation_id()
        cp["cloudflare_apply_started"] = {
            "ts": utcnow(),
            "operation": "apply",
            "manifest_digest": _manifest_digest(manifest),
            "manifest_size": len(manifest),
            "invocation_id": invocation_id,
        }
        self.save(cp)
        result = self.with_retries(
            "cloudflare_apply", self.cloudflare_replace,
            "apply",
            old_ip=cp["old_ip"]["ip"],
            new_ip=cp["new_ip"]["ip"],
            allowed_records=self._allowed_records(),
            expected_count=self._expected_record_count(),
            manifest=manifest,
            invocation_id=invocation_id,
        )
        cp["cloudflare_apply"] = {
            "ts": utcnow(),
            "rc": result.get("rc"),
            "ok": bool((result.get("result") or {}).get("ok")),
            "post_manifest": (result.get("result") or {}).get("post_manifest") or manifest,
        }
        self.record(cp, "cloudflare_apply", f"rc={result.get('rc')}")
        if result.get("rc") != 0 or not cp["cloudflare_apply"]["ok"]:
            raise EscalationRequired(
                f"`{' '.join(result.get('argv', []))}` exited {result.get('rc')} "
                "or the read-back reported drift. The provider IP swap already "
                "happened — fixing DNS does not roll the address back; fix the "
                "manifest and resume.",
                [
                    f"rotate.py resume --txid {cp['txid']} "
                    f"--confirm-server-id {cp['server']['id']}",
                ],
            )

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
            self._do_dns_rollback(cp)
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

        while True:
            # Resume after escalation: restore the state we were at when the
            # step failed. Persisted in escalate() as cp["resume_state"].
            if cp["state"] == "escalated":
                resume = cp.get("resume_state")
                if resume and resume in STEP_BY_STATE:
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
            # connectivity_ok. Implemented as an early stop in the loop, not
            # as a separate Step, because it depends on a config value, not
            # a step outcome.
            if (
                self.provider_only
                and cp["state"] == "connectivity_ok"
                and not (self.until and self.until == "connectivity_ok")
            ):
                cp["outcome"] = "paused"
                self.save(cp)
                self.log("")
                self.log(
                    "PAUSED at connectivity_ok (cloudflare.mode=provider_only). "
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
            step = STEP_BY_STATE.get(cp["state"])
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
                self.log(
                    f"DONE. {cp['server']['expected_name']} is on {cp['new_ip']['ip']}; "
                    f"the old {cp['old_ip']['ip']} is unassigned and RETAINED."
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
            try:
                self.restore_old_ip(cp, reason)
            except ProviderError as rollback_exc:
                self.escalate(
                    cp,
                    f"{reason}; the rollback then failed too: {rollback_exc}",
                )
        else:
            self.escalate(cp, reason)


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
    p_apply.add_argument("--confirm-server-id", type=int, default=None)
    p_apply.add_argument("--until", choices=PAUSABLE, default=None,
                         help="stop cleanly at this state instead of running to done")

    p_resume = sub.add_parser("resume", help="continue an interrupted transaction")
    p_resume.add_argument("--txid", required=True)
    p_resume.add_argument("--config", default=None)
    p_resume.add_argument("--confirm-server-id", type=int, default=None)
    p_resume.add_argument("--until", choices=PAUSABLE, default=None,
                          help="stop cleanly at this state instead of running to done")

    p_rollback = sub.add_parser("rollback", help="put the old address back")
    p_rollback.add_argument("--txid", required=True)
    p_rollback.add_argument("--config", default=None)
    p_rollback.add_argument("--confirm-server-id", type=int, default=None)
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
    if not token_present():
        print(
            "HCLOUD_TOKEN is not set. Nothing was contacted.\n"
            "  export HCLOUD_TOKEN=\"$(ansible-vault view vault.yml"
            " | awk '/^hcloud_api_token:/ {print $2}' | tr -d \"\\\"'\")\"",
            file=sys.stderr,
        )
        return EXIT_USAGE
    register_secret(os.environ.get("HCLOUD_TOKEN"))
    register_secret(os.environ.get(CLOUDFLARE_TOKEN_ENV))

    config_path = getattr(args, "config", None)
    if args.command in ("resume", "rollback", "status") and not config_path:
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
    state_dir = _resolve_state_dir(cfg, config_path)
    rotation = Rotation(
        config=cfg,
        provider=HcloudProvider(runner or ansible_runner()),
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

    # apply / resume / rollback all mutate, so all need the confirmation gate.
    expected = int(cfg["server"]["id"])
    given = args.confirm_server_id
    if given is None:
        print(
            f"refusing to {args.command}: --confirm-server-id is required and must be "
            f"the numeric server id from the config.\n"
            f"  rotate.py {args.command} ... --confirm-server-id <the id>\n"
            "  (`plan` prints it. The value is the TARGET'S OWN id on purpose — "
            "'yes' and 'true' are not spellings of a specific server.)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if given != expected:
        print(
            f"identity mismatch: --confirm-server-id {given} != config server.id "
            f"{expected}. Nothing was contacted.",
            file=sys.stderr,
        )
        return EXIT_IDENTITY

    if args.command == "apply":
        cp = rotation.plan()
        rotation._transition(cp, "confirmed")
        cp = rotation.execute(cp)
    else:
        cp = rotation.load(args.txid)
        if int(cp["server"]["id"]) != expected:
            raise IdentityMismatch(
                f"checkpoint {args.txid} targets server {cp['server']['id']}, "
                f"the config targets {expected}"
            )
        if args.command == "rollback":
            # The workflow splits rollback into two phases so that the
            # CLOUDFLARE_API_TOKEN env can be scoped to the phase that
            # actually needs it. `--no-dns-rollback` does only the
            # provider half; `--dns-rollback-only` does only the DNS
            # half. The default is unchanged: both.
            if args.dns_rollback_only:
                rotation.dns_rollback_only(cp)
            elif args.no_dns_rollback:
                rotation.restore_old_ip(cp, "operator ran `rollback`",
                                        skip_dns_rollback=True)
            else:
                rotation.restore_old_ip(cp, "operator ran `rollback`")
        else:
            if cp["state"] in ("planned", "created", "validated"):
                rotation._transition(cp, "confirmed")
            cp = rotation.execute(cp)

    return _outcome_exit_code(cp)


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
