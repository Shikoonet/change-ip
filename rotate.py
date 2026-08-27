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
from providers import (  # noqa: E402
    EscalationRequired,
    HcloudProvider,
    IdentityMismatch,
    NonRetryableError,
    NotFound,
    ProviderError,
    RetryableError,
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
    # Nothing has moved yet, so a shutdown that never completes costs only the
    # downtime: power the box back on and stop. No address was touched.
    Step("confirmed", "server_off", "_step_stop", "restart_only"),
    # From here to server_on the box is mid-swap and a failure means "put the
    # old address back", which is only possible because protect_ip ran first.
    Step("server_off", "old_ip_unassigned", "_step_unassign", "restore"),
    Step("old_ip_unassigned", "new_ip_allocated", "_step_allocate", "restore"),
    Step("new_ip_allocated", "new_ip_assigned", "_step_assign", "restore"),
    # Swapping the addresses back does not fix a box that will not boot, so
    # this one goes straight to a human with the commands in hand.
    Step("new_ip_assigned", "server_on", "_step_start", "escalate"),
    Step("server_on", "connectivity_ok", "_step_health", "restore"),
    # ip-change.yml is idempotent and the address on the box is already
    # correct here. Taking a working node offline to undo a Cloudflare record
    # would be a bigger outage than the one being fixed: escalate, resume.
    Step("connectivity_ok", "ansible_done", "_step_ansible", "escalate"),
    Step("ansible_done", "done", "_step_verify", "escalate"),
)

STEP_BY_STATE = {s.frm: s for s in STEPS}

TERMINAL = ("done", "planned", "rolled_back", "escalated")

#: States `--until` may name. Only the two the CD pipeline splits on: everything
#: else is mid-swap, where "stop here" means "a node with no address".
PAUSABLE = ("connectivity_ok", "ansible_done")


class ConfigError(Exception):
    """The config file is missing something, or says something impossible."""


# -- helpers ---------------------------------------------------------------
def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    if any(marker in low for marker in ("unauthorized", "401", "forbidden", "403", "invalid token")):
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

        retries = self.cfg.get("retries") or {}
        self.retries = int(retries.get("provider", 3))
        self.retry_delay = float(retries.get("provider_delay", 10))
        self.health_retries = int(retries.get("health", 30))
        self.health_delay = float(retries.get("health_delay", 10))
        self.ssh_port = int((self.cfg.get("health") or {}).get("ssh_port", 22))
        self.ssh_timeout = float((self.cfg.get("timeouts") or {}).get("ssh", 10))

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

    def _step_allocate(self, cp: Dict[str, Any]) -> None:
        self.assert_identity(cp, expect_ip="none")
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
        if allocated.datacenter != cp["snapshot"]["datacenter"]:
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
        cp["verification"] = {
            "ts": utcnow(),
            "ipv4": server.ipv4,
            "status": server.status,
            "ssh_reachable": reachable,
        }
        if not reachable:
            raise RetryableError(f"{cp['new_ip']['ip']}:{self.ssh_port} stopped answering")
        cp["outcome"] = "done"
        self.record(cp, "verify", f"{server.ipv4} live, status {server.status}")

    # -- remedies ----------------------------------------------------------
    def restore_old_ip(self, cp: Dict[str, Any], reason: str) -> None:
        """Remedy R. Put the old address back; RETAIN the new one.

        Re-entrant on purpose: an interrupted rollback is resumed by calling
        this again. Every branch re-reads before it acts, so "already stopped"
        and "already reassigned" are both no-ops rather than errors.
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

        cp["rollback"] = {
            "state": "rolled_back",
            "reason": redact(reason),
            "new_ip_retained": cp["new_ip"],
        }
        cp["outcome"] = "rolled_back"
        self._transition(cp, "rolled_back")
        self.log("")
        self.log(f"ROLLED BACK: {cp['server']['id']} is on {cp['old_ip']['ip']} again.")
        if cp["new_ip"]["id"]:
            self.log(
                f"  The new Primary IP {cp['new_ip']['name']} ({cp['new_ip']['ip']}, "
                f"id={cp['new_ip']['id']}) is UNASSIGNED and RETAINED — it is still "
                "billed. Deleting it is your call, not this tool's."
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
        cp["escalations"].append(
            {"ts": utcnow(), "state": cp["state"], "message": redact(message),
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
        **(rotation_kwargs or {}),
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
    register_secret(token)

    with tempfile.TemporaryDirectory() as tmp:
        fake = FakeHcloud()
        cfg = example_config(fake)
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
        assert cp["state"] == "done", f"ended in {cp['state']}: {cp.get('escalations')}"
        assert cp["outcome"] == "done"
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
