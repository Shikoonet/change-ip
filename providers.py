#!/usr/bin/env python3
"""Provider domain types, the error taxonomy, and the Hetzner Cloud adapter.

Pure stdlib. There is no HTTP client to Hetzner anywhere in this project's
Python: every provider read AND write goes out through one callable, the
`runner`, which in production shells `ansible-playbook hcloud_step.yml` and in
tests is an in-memory fake.

Said precisely, because the loose version ("the token never enters Python") is
not true and a reader who believes it will not look for the exceptions:

  * Python opens exactly one socket, in rotate.py's `tcp_probe()`, and it goes
    to the NODE's ssh port to check the new address is live. Nothing in this
    process ever connects to api.hetzner.cloud.
  * Python reads HCLOUD_TOKEN exactly once, in project_fingerprint() below, to
    compute sha256(token)[:12]. The token is never written anywhere -- not to
    argv, not to a var file, not to a checkpoint -- and the fingerprint is not
    the token.

WHY THE SEAM IS A CALLABLE AND NOT A SUBCLASS. One code path to Hetzner means
one place a credential can leak and one place to fake. Faking at the HTTP layer
would leave this file's normalisation untested; faking at the class layer would
leave it untested too, because a test double would replace it. A callable
`(op, params) -> dict` is the narrowest cut that still runs every line below in
every test.

THE COLLECTION'S SHAPE STOPS HERE. `hcloud_server_info` / `hcloud_primary_ip`
dicts are turned into the two frozen dataclasses at the bottom of this
docstring's file and never escape. Verified against hetzner.hcloud 6.2.1
installed at /usr/lib/python3/dist-packages/ansible_collections/hetzner/hcloud
on 2026-08-26 by reading plugins/modules/*.py, not from memory:

  * `primary_ip_info` calls the datacenter field `home_location`
    (primary_ip_info.py:155 -> `primary_ip.datacenter.name`) while `primary_ip`
    calls the SAME value `datacenter` (primary_ip.py:189). Two names, one
    value. `_ip()` below accepts either; a reader who only ever saw one module
    would write code that silently gets None from the other.

  * `server_info` returns `ipv4_address` (a string) and NO Primary IP id
    (server_info.py:_prepare_result). The id has to be correlated from
    `primary_ip_info` by `assignee_id`. That correlation lives in
    hcloud_step.yml, not here.

  * Aug 2026 quirk, still binding: `assignee_id` is the source of truth for
    "is this IP attached to anything". A null `assignee_id` is normalised to
    `assignee_type == "unassigned"` no matter what the API said; a set
    `assignee_id` with an assignee_type we do not know is a NON-retryable
    error, because guessing there means guessing which machine we are about to
    take an address away from.

  * `type != "ipv4"` is rejected on sight. IPv6 rotation is out of scope and a
    v6 Primary IP reaching the state machine would be silently mishandled.

REDACTION lives here rather than in rotate.py because this is the lowest layer
and both layers need it; rotate.py re-exports the name. The primary defence is
structural -- the token is never part of a value this process passes around,
because the hcloud modules read HCLOUD_TOKEN from the environment themselves.
`redact()` is the belt, and `redact_tree()` in Rotation.save() is where it is
buckled: at the sink, so a field added later that carries third-party output
cannot leak just because its producer forgot.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional

# runner(op, params) -> dict with either {"ok": True, "data": {...}} or
# {"ok": False, "error": str, "error_kind": "auth"|"not_found"|"validation"|"retryable"}
Runner = Callable[[str, Dict[str, Any]], Dict[str, Any]]

TOKEN_ENV = "HCLOUD_TOKEN"


# --------------------------------------------------------------------------
# redaction
# --------------------------------------------------------------------------
_SECRETS: List[str] = []
_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)


def register_secret(value: Optional[str]) -> None:
    """Remember a literal string that must never be printed.

    Called once with the token value if it is present in the environment. The
    value is held only to be searched for -- it is never written to a
    checkpoint, an audit record, or argv.
    """
    if value and value not in _SECRETS:
        _SECRETS.append(value)


def redact(text: Any) -> str:
    """Replace any registered secret and any `Bearer <x>` with [REDACTED]."""
    out = str(text)
    for secret in _SECRETS:
        out = out.replace(secret, "[REDACTED]")
    return _BEARER.sub("Bearer [REDACTED]", out)


def redact_tree(value: Any) -> Any:
    """redact() every string in a nested structure, without mutating the input.

    This is the SINK-side guard. Every producer already redacts, so with the
    current code path nothing reaches here dirty — but that is a property of
    today's code, not of the schema. Measured 2026-08-26: swapping the
    ip_change adapter for a stub that skips redact() put a raw token straight
    into the checkpoint's `ansible.stdout_tail` and `ansible.stderr_tail`. Any
    field added tomorrow that carries third-party output has the same hole.
    Scrubbing where the bytes hit the disk closes the class rather than one
    instance of it.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_tree(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_tree(item) for item in value]
    return value


def token_present() -> bool:
    return bool(os.environ.get(TOKEN_ENV, "").strip())


def project_fingerprint() -> str:
    """First 12 hex chars of sha256(HCLOUD_TOKEN).

    Identifies WHICH Hetzner project a run is pointed at without revealing
    anything about the token: sha256 is not invertible and 12 hex chars is not
    enough material to brute-force against. The operator pins the value that
    `plan` prints, and every later run asserts against it -- that is what stops
    a rotation aimed at the production project from being resumed with a
    staging token still exported in the shell.
    """
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        raise NonRetryableError(
            f"{TOKEN_ENV} is not set. Export it first:\n"
            "  export HCLOUD_TOKEN=\"$(ansible-vault view vault.yml "
            "| awk '/^hcloud_api_token:/ {print $2}' | tr -d \\\"'\\\")\""
        )
    register_secret(token)
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------
# error taxonomy
# --------------------------------------------------------------------------
class ProviderError(Exception):
    """Anything the provider layer refused to do."""


class RetryableError(ProviderError):
    """Transient: a timeout, a 429, a runner that died mid-flight.

    On-disk state is unchanged, so the remedy is to try the same step again.
    """


class NonRetryableError(ProviderError):
    """Auth, validation, a shape we refuse to interpret. Retrying cannot help."""


class NotFound(NonRetryableError):
    """The named server or Primary IP does not exist in this project."""


class IdentityMismatch(ProviderError):
    """The thing we are about to mutate is not the thing we were told to mutate.

    Never recoverable by falling back to some other resource -- that is exactly
    the failure mode this class exists to make impossible.
    """


class EscalationRequired(ProviderError):
    """Stop and hand the box to a human, with the commands they will need."""

    def __init__(self, message: str, recovery_commands: Optional[List[str]] = None):
        super().__init__(redact(message))
        self.recovery_commands = [redact(c) for c in (recovery_commands or [])]


# --------------------------------------------------------------------------
# domain types -- no hetzner.hcloud dict escapes the adapter
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Server:
    id: int
    name: str
    status: str
    location: str
    datacenter: str
    ipv4_id: Optional[int]
    ipv4: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PrimaryIP:
    id: int
    name: str
    ip: str
    ip_type: str
    datacenter: str
    assignee_id: Optional[int]
    assignee_type: str
    auto_delete: bool

    @property
    def assigned(self) -> bool:
        return self.assignee_id is not None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# adapter
# --------------------------------------------------------------------------
class HcloudProvider:
    """Every Hetzner mutation in this project goes through one of these methods."""

    #: Ops hcloud_step.yml understands. Kept here so a typo is a Python error
    #: rather than a playbook that skips every task and exits green.
    OPS = (
        "read_server",
        "read_ip",
        "find_ip",
        "protect_ip",
        "stop",
        "unassign",
        "allocate",
        "assign",
        "start",
    )

    def __init__(self, runner: Runner, fingerprint: Optional[str] = None):
        self._run = runner
        self._fingerprint = fingerprint

    # -- plumbing ----------------------------------------------------------
    @property
    def fingerprint(self) -> str:
        if self._fingerprint is None:
            self._fingerprint = project_fingerprint()
        return self._fingerprint

    def _call(self, op: str, **params: Any) -> Dict[str, Any]:
        if op not in self.OPS:
            raise NonRetryableError(f"unknown provider op {op!r}")
        result = self._run(op, params)
        if not isinstance(result, dict):
            raise RetryableError(f"{op}: runner returned {type(result).__name__}, not a dict")
        if result.get("ok"):
            return result.get("data") or {}

        message = redact(result.get("error") or f"{op}: provider call failed with no message")
        kind = result.get("error_kind") or "retryable"
        if kind == "not_found":
            raise NotFound(message)
        if kind in ("auth", "validation"):
            raise NonRetryableError(message)
        raise RetryableError(message)

    # -- normalisation -----------------------------------------------------
    @staticmethod
    def _server(data: Dict[str, Any]) -> Server:
        try:
            return Server(
                id=int(data["id"]),
                name=str(data["name"]),
                status=str(data["status"]),
                location=str(data["location"]),
                datacenter=str(data["datacenter"]),
                ipv4_id=int(data["ipv4_id"]) if data.get("ipv4_id") is not None else None,
                ipv4=data.get("ipv4_address") or data.get("ipv4") or None,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise NonRetryableError(f"unreadable server payload: {redact(exc)}") from exc

    @staticmethod
    def _ip(data: Dict[str, Any]) -> PrimaryIP:
        ip_type = str(data.get("type") or data.get("ip_type") or "")
        if ip_type != "ipv4":
            raise NonRetryableError(
                f"Primary IP {data.get('name')!r} has type {ip_type!r}; only ipv4 is in scope"
            )

        # primary_ip_info says home_location, primary_ip says datacenter, and
        # both mean datacenter.name. Accepting one name only would read None
        # from half the module surface with no error anywhere.
        datacenter = data.get("datacenter") or data.get("home_location")
        if not datacenter:
            raise NonRetryableError(f"Primary IP {data.get('name')!r} has no datacenter")

        assignee_id = data.get("assignee_id")
        if assignee_id is None:
            assignee_type = "unassigned"
        else:
            assignee_type = str(data.get("assignee_type") or "")
            if assignee_type != "server":
                raise NonRetryableError(
                    f"Primary IP {data.get('name')!r} is attached to assignee_id "
                    f"{assignee_id} of unknown type {assignee_type!r}; refusing to guess "
                    "what it would be taken away from"
                )
            assignee_id = int(assignee_id)

        try:
            return PrimaryIP(
                id=int(data["id"]),
                name=str(data["name"]),
                ip=str(data["ip"]),
                ip_type=ip_type,
                datacenter=str(datacenter),
                assignee_id=assignee_id,
                assignee_type=assignee_type,
                auto_delete=bool(data.get("auto_delete", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise NonRetryableError(f"unreadable Primary IP payload: {redact(exc)}") from exc

    # -- reads -------------------------------------------------------------
    def get_server(self, server_id: int) -> Server:
        return self._server(self._call("read_server", server_id=int(server_id)))

    def get_primary_ip(self, ip_id: Optional[int] = None, name: Optional[str] = None) -> PrimaryIP:
        if (ip_id is None) == (name is None):
            raise NonRetryableError("get_primary_ip needs exactly one of ip_id / name")
        params: Dict[str, Any] = {}
        if ip_id is not None:
            params["ip_id"] = int(ip_id)
        else:
            params["ip_name"] = str(name)
        return self._ip(self._call("read_ip", **params))

    def find_ip(self, name: str) -> Optional[PrimaryIP]:
        """Zero or one Primary IP by name. Two is a hard stop, not a pick.

        Hetzner keeps Primary IP names unique per project, so more than one
        match means our assumption about the API is wrong -- and the next step
        would move a live address. Refuse instead.
        """
        data = self._call("find_ip", ip_name=str(name))
        matches = data.get("matches") or []
        if len(matches) > 1:
            raise NonRetryableError(
                f"{len(matches)} Primary IPs are named {name!r}; refusing to choose"
            )
        return self._ip(matches[0]) if matches else None

    # -- mutations ---------------------------------------------------------
    def protect_ip(self, ip_id: int) -> PrimaryIP:
        """auto_delete=false on the OLD address, before anything else moves.

        Rule One in provider form: while the rotation is in flight, the old
        address is the only way back. auto_delete would let Hetzner reclaim it
        behind our back and turn a rollback into an escalation.
        """
        return self._ip(self._call("protect_ip", ip_id=int(ip_id)))

    def stop_server(self, server_id: int) -> Server:
        return self._server(self._call("stop", server_id=int(server_id)))

    def unassign_ip(self, server_id: int, ip_id: int) -> Server:
        return self._server(self._call("unassign", server_id=int(server_id), ip_id=int(ip_id)))

    def allocate_ip(self, name: str, datacenter: str) -> PrimaryIP:
        return self._ip(
            self._call("allocate", ip_name=str(name), datacenter=str(datacenter))
        )

    def assign_ip(self, server_id: int, ip_name: str) -> Server:
        return self._server(self._call("assign", server_id=int(server_id), ip_name=str(ip_name)))

    def start_server(self, server_id: int, ip_name: str) -> Server:
        return self._server(self._call("start", server_id=int(server_id), ip_name=str(ip_name)))

    # -- escalation help ---------------------------------------------------
    @staticmethod
    def describe_rollback(
        server_id: int,
        old_ip: Optional[Dict[str, Any]],
        new_ip: Optional[Dict[str, Any]],
    ) -> List[str]:
        """The exact commands a human needs, with the real IDs already in them.

        An escalation that says "restore the old IP" costs the operator the
        same twenty minutes of console archaeology every time. These are
        copy-pasteable and name the resources by immutable id.
        """
        old_id = (old_ip or {}).get("id")
        old_addr = (old_ip or {}).get("ip")
        new_name = (new_ip or {}).get("name")
        lines = [
            f"# server {server_id}: put the old address {old_addr} (Primary IP {old_id}) back",
            f"hcloud server poweroff {server_id}",
        ]
        if new_name:
            lines.append(
                f"# detach the new IP first -- a server holds one Primary IPv4: {new_name}"
            )
        lines += [
            f"hcloud primary-ip assign {old_id} --server {server_id}",
            f"hcloud server poweron {server_id}",
            f"hcloud server describe {server_id}   # confirm ipv4 == {old_addr}",
            "# NOTHING is deleted here. The new Primary IP is retained on purpose;",
            "# removing it is a separate, explicitly approved decision.",
        ]
        return lines
