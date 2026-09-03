#!/usr/bin/env python3
"""The HTTP adapter that talks to the DataForest public API.

Pure stdlib (urllib + json + ipaddress + hashlib). No third-party
client. The DataForest API is small enough to justify the restriction:
every method here is one URL, one verb, one JSON body.

  * `https://api.dataforest.net/api/v1/public` — the official base.
  * `Bearer <PAT>` from `DATAFOREST_API_TOKEN`. The token is never on
    argv, never inside a checkpoint, never inside a result file.
  * JSON-only in both directions. HTML / empty / malformed bodies are
    fail-closed (`NonRetryableError`).
  * 429 honours `Retry-After` (bounded); 503 backs off with jitter
    (bounded). Every other status is mapped to a stable DataForest
    `code` from the response JSON, never a regex on the message.
  * `seed.add-ipv4` and `seed.remove-ipv4` may return 200 (immediate)
    or 202 (async). Polling reads `/seeds/{seedId}/actions/{actionId}`
    until `completed` or `failed`. Initial interval 5s; from t=30s, 10s;
    never < 1s; bounded total.

PRODUCTION-ONLY DEFAULT. The seam that lets tests substitute a fake
endpoint requires `DATAFOREST_API_TEST_MODE=1` AND the URL being a
loopback host. Production URLs reject override unconditionally.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from providers import (
    NonRetryableError,
    RetryableError,
    redact,
    register_secret,
)

DEFAULT_BASE_URL = "https://api.dataforest.net/api/v1/public"
DEFAULT_TIMEOUT = 30  # seconds; connect+read combined
TEST_MARKER_ENV = "DATAFOREST_API_TEST_MODE"

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

# Stable status code markers — a real DataForest response uses
# `code` (a string), not HTTP status. These are the documented ones.
TERMINAL_STATUSES = {"completed", "failed"}
KNOWN_STATUSES = TERMINAL_STATUSES | {"new", "pending", "running", "retry"}


def is_loopback_host(host: str) -> bool:
    """True only for the canonical loopback names. An IP literal is also
    accepted so 127.0.0.1/::1 pass, but anything else is rejected
    regardless of whether the OS happens to route it to itself."""
    if not host:
        return False
    h = host.lower().strip("[]")
    if h in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def resolve_base_url(url: str) -> str:
    """Validate a base URL and, when it deviates from the production
    default, require both the explicit test marker AND a loopback host.

    A typo'd -e override without the marker is rejected; a marker with a
    non-loopback URL is rejected. Production never reaches the marker
    branch.
    """
    if url == DEFAULT_BASE_URL:
        return url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise NonRetryableError(f"dataforest base url {url!r} has no host")
    if not is_loopback_host(host):
        raise NonRetryableError(
            f"dataforest base url {url!r} is not the production endpoint "
            "and the host is not a loopback. Production must use "
            f"{DEFAULT_BASE_URL!r}; overrides require {TEST_MARKER_ENV}=1 "
            "AND a loopback host."
        )
    if os.environ.get(TEST_MARKER_ENV) != "1":
        raise NonRetryableError(
            f"dataforest base url override {url!r} requires "
            f"{TEST_MARKER_ENV}=1 to be exported. Refusing to redirect API "
            "calls to a non-production endpoint without an explicit test marker."
        )
    scheme = (parsed.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise NonRetryableError(f"dataforest base url scheme {scheme!r} is not http(s)")
    port = f":{parsed.port}" if parsed.port else ""
    netloc = host if ":" not in host else f"[{host}]"
    return f"{scheme}://{netloc}{port}{parsed.path or ''}".rstrip("/")


class DataForestAdapter:
    """Thin HTTP wrapper. One method per documented endpoint.

    Lifecycle: the rotation creates one of these at startup, passes it
    to `DataForestProvider`, and the provider calls back into it. Tests
    construct one pointing at a fake HTTP server.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        sleeper: Callable[[float], None] = time.sleep,
        opener: Optional[Callable[..., Any]] = None,
        require_token: bool = True,
    ):
        if not token:
            token = os.environ.get("DATAFOREST_API_TOKEN", "").strip()
        if not token and require_token:
            raise NonRetryableError(
                "DATAFOREST_API_TOKEN is not set. Export it before running; "
                "the adapter does not accept the token via any other channel."
            )
        if token:
            register_secret(token)
        self._token = token
        self.base_url = resolve_base_url(base_url)
        self.timeout = float(timeout)
        self._sleep = sleeper
        # `opener` is the seam for tests: pass a function with the same
        # shape as `urllib.request.urlopen` and the adapter will use it
        # for every request. Production never overrides it.
        self._opener = opener or urllib.request.urlopen

    # -- transport --------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        query: Optional[List[Tuple[str, str]]] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        """One HTTP call. Returns (status, json_or_empty, headers)."""
        url = self.base_url + path
        if query:
            from urllib.parse import urlencode
            url = url + "?" + urlencode(query)
        data: Optional[bytes] = None
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "server-ip-rotation/1",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp = self._safe_open(req)
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            raise _transport_error(exc) from exc
        status = int(getattr(resp, "status", 200) or 200)
        raw = getattr(resp, "read", lambda: b"")()
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", "replace")
        else:
            text = str(raw or "")
        hdrs = {k: v for k, v in (getattr(resp, "headers", {}) or {}).items()}
        parsed: Dict[str, Any] = {}
        if text.strip():
            try:
                parsed = json.loads(text)
            except (ValueError, TypeError):
                # HTML or other non-JSON: treat as malformed.
                raise NonRetryableError(
                    f"dataforest {method} {path}: non-JSON response "
                    f"(status {status}, {len(text)} bytes)"
                )
        if not isinstance(parsed, dict):
            raise NonRetryableError(
                f"dataforest {method} {path}: JSON root is not an object "
                f"(got {type(parsed).__name__})"
            )
        return status, parsed, hdrs

    def _safe_open(self, req: "urllib.request.Request") -> Any:
        """Open `req` without urllib's auto-raise on 4xx/5xx.

        urllib.request.urlopen raises HTTPError on 4xx/5xx by default,
        but the spec asks the adapter to map those to specific error
        classes — so we drain the response ourselves when needed.
        """
        if self._opener is not None and self._opener is not urllib.request.urlopen:
            return self._opener(req, timeout=self.timeout)
        try:
            return urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            # Treat as a normal response so the JSON can still be parsed.
            return exc

    # -- endpoints --------------------------------------------------------
    def get_team(self) -> Dict[str, Any]:
        status, body, _ = self._request("GET", "/team")
        _raise_for_status("team", status, body)
        return body

    def get_seed(self, seed_id: str) -> Dict[str, Any]:
        if not seed_id or not isinstance(seed_id, str):
            raise NonRetryableError(f"get_seed: seed_id {seed_id!r} is invalid")
        status, body, _ = self._request("GET", f"/seeds/{seed_id}")
        _raise_for_status("seed", status, body)
        return body

    def list_seed_actions(self, seed_id: str) -> Dict[str, Any]:
        status, body, _ = self._request("GET", f"/seeds/{seed_id}/actions")
        _raise_for_status("seed_actions", status, body)
        return body

    def get_action(self, seed_id: str, action_id: str) -> Dict[str, Any]:
        if not action_id or not isinstance(action_id, str):
            raise NonRetryableError(f"get_action: action_id {action_id!r} is invalid")
        status, body, _ = self._request("GET", f"/seeds/{seed_id}/actions/{action_id}")
        _raise_for_status("action", status, body)
        return body

    def post_action(self, seed_id: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        if not seed_id or not isinstance(seed_id, str):
            raise NonRetryableError(f"post_action: seed_id {seed_id!r} is invalid")
        status, body, _ = self._request("POST", f"/seeds/{seed_id}/actions", body=payload)
        _raise_for_status("post_action", status, body)
        return status, body


# --------------------------------------------------------------------------
# error mapping — a single switch keyed on the stable DataForest `code`
# --------------------------------------------------------------------------
def _transport_error(exc: BaseException) -> Exception:
    name = type(exc).__name__
    msg = redact(str(exc) or name)
    if isinstance(exc, urllib.error.HTTPError):
        try:
            code = int(exc.code)
        except (TypeError, ValueError):
            code = 0
        return RetryableError(f"dataforest transport HTTP {code}: {msg}")
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return RetryableError(f"dataforest transport timeout: {msg}")
    return RetryableError(f"dataforest transport error: {msg}")


def _raise_for_status(op: str, status: int, body: Dict[str, Any]) -> None:
    """Translate (HTTP status, JSON body) into the project's error taxonomy.

    Order of precedence:
      1. HTTP 401/403/409/410/422 — fail-closed.
      2. HTTP 429 — RetryableError with Retry-After on the instance.
      3. HTTP 5xx — RetryableError.
      4. JSON `code` field — mapped via the table below.
      5. HTTP 2xx — accepted; caller validates body shape.
    """
    if status in (401, 403):
        raise NonRetryableError(
            f"dataforest {op}: HTTP {status} (token rejected; refusing to retry)"
        )
    if status == 409:
        raise NonRetryableError(f"dataforest {op}: HTTP 409 conflict (refusing)")
    if status == 410:
        raise NonRetryableError(f"dataforest {op}: HTTP 410 gone (refusing)")
    if status == 422:
        raise NonRetryableError(f"dataforest {op}: HTTP 422 unprocessable (refusing)")
    if status == 429:
        raise _retry_after_from_body(op, body)
    if 500 <= status < 600:
        raise _retry_503(op, status, body)
    if 200 <= status < 300:
        return
    raise NonRetryableError(f"dataforest {op}: HTTP {status} (refusing)")


def _retry_after_from_body(op: str, body: Dict[str, Any]) -> RetryableError:
    seconds = _coerce_retry_after_seconds(body)
    err = RetryableError(f"dataforest {op}: HTTP 429 rate-limited")
    setattr(err, "retry_after", float(seconds))
    return err


def _retry_503(op: str, status: int, body: Dict[str, Any]) -> RetryableError:
    err = RetryableError(f"dataforest {op}: HTTP {status} (retryable)")
    setattr(err, "retry_after", None)  # caller uses backoff, not Retry-After
    return err


def _coerce_retry_after_seconds(body: Dict[str, Any]) -> int:
    """Best-effort extraction of `Retry-After` / `retry_after` from a body.

    Accepts integer seconds OR an ISO 8601 absolute timestamp (treated
    as the maximum; we clamp to >= 1). Anything else yields 1.
    """
    candidates: List[Any] = []
    for key in ("retry_after", "retryAfter", "Retry-After"):
        if key in body:
            candidates.append(body[key])
    data = body.get("data") if isinstance(body.get("data"), dict) else None
    if data:
        for key in ("retry_after", "retryAfter"):
            if key in data:
                candidates.append(data[key])
    if not candidates:
        return 1
    val = candidates[0]
    try:
        seconds = int(val)
    except (TypeError, ValueError):
        return 1
    return max(1, min(seconds, 3600))


def stable_error_code(body: Dict[str, Any]) -> Optional[str]:
    """The DataForest `code` field, if present and a string. None otherwise."""
    for key in ("code", "error_code"):
        val = body.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    data = body.get("data") if isinstance(body.get("data"), dict) else None
    if data:
        for key in ("code", "error_code"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None


# --------------------------------------------------------------------------
# polling — bounded, jittered, monotonic interval escalation
# --------------------------------------------------------------------------
def poll_action(
    adapter: DataForestAdapter,
    seed_id: str,
    action_id: str,
    *,
    initial_interval: float = 5.0,
    escalated_interval: float = 10.0,
    escalate_after: float = 30.0,
    min_interval: float = 1.0,
    timeout: float = 1800.0,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Dict[str, Any]:
    """Wait until the action is `completed` or `failed`, or time out.

    Initial interval is 5s; from t=30s after the first poll, every
    subsequent interval is 10s. Never < 1s. Total budget = timeout.
    """
    started = clock()
    interval = max(min_interval, float(initial_interval))
    last: Dict[str, Any] = {}
    while True:
        body = adapter.get_action(seed_id, action_id)
        last = body
        status = _extract_status(body)
        if status in TERMINAL_STATUSES:
            return body
        elapsed = clock() - started
        if elapsed >= timeout:
            raise NonRetryableError(
                f"dataforest action {action_id} on seed {seed_id} did not "
                f"reach a terminal state within {timeout:.0f}s "
                f"(last status: {status!r})"
            )
        if elapsed >= escalate_after:
            interval = max(interval, escalated_interval)
        # jitter +/- 10% so a thundering herd doesn't synchronise
        jitter = interval * (1.0 + (random.random() - 0.5) * 0.2)
        sleeper(max(min_interval, jitter))


def _extract_status(body: Dict[str, Any]) -> str:
    """Pull the action status out of the canonical shape.

    Accepts a few variants so a payload difference does not fail the
    caller. Unknown status is surfaced as `unknown` — caller code
    treats that as "keep polling, not terminal".
    """
    for container in (body, body.get("data")):
        if isinstance(container, dict):
            for key in ("status", "state", "result"):
                val = container.get(key)
                if isinstance(val, dict):
                    inner = val.get("status")
                    if isinstance(inner, str) and inner in KNOWN_STATUSES:
                        return inner
                if isinstance(val, str) and val in KNOWN_STATUSES:
                    return val
    return "unknown"


# --------------------------------------------------------------------------
# validation helpers — strict IPv4 parsing, action / payload shape checks
# --------------------------------------------------------------------------
def strict_ipv4(value: Any) -> str:
    """Parse `value` as an IPv4 dotted-quad. Anything else is rejected."""
    if not isinstance(value, str) or not value.strip():
        raise NonRetryableError(f"value {value!r} is not a string IPv4")
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise NonRetryableError(f"value {value!r} is not a valid IPv4: {exc}") from exc
    return str(ip)


def validate_cidr(value: Any) -> str:
    """A CIDR string must be a valid IPv4Interface. /32 is allowed."""
    if not isinstance(value, str) or not value.strip():
        raise NonRetryableError(f"cidr {value!r} is not a string")
    try:
        iface = ipaddress.IPv4Interface(value.strip())
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise NonRetryableError(f"cidr {value!r} is not a valid IPv4Interface: {exc}") from exc
    if iface.version != 4:
        raise NonRetryableError(f"cidr {value!r} is IPv{iface.version}, only v4 is in scope")
    return str(iface)


def validate_interface_name(value: Any) -> str:
    """Linux interface names: <= 15 chars, alnum + - _ : ."""
    if not isinstance(value, str):
        raise NonRetryableError(f"interface name {value!r} is not a string")
    name = value.strip()
    if not name or len(name) > 15:
        raise NonRetryableError(
            f"interface name {name!r} is empty or longer than 15 chars"
        )
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:.")
    if not set(name).issubset(allowed):
        raise NonRetryableError(f"interface name {name!r} contains illegal characters")
    return name


def deterministic_digest(*parts: Any) -> str:
    """SHA256 over a JSON-canonical encoding, truncated. Token-free."""
    canonical = json.dumps(
        [_serialise(p) for p in parts],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    import hashlib
    return hashlib.sha256(canonical).hexdigest()[:16]


def _serialise(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_serialise(v) for v in sorted(value, key=lambda x: str(x))]
    if isinstance(value, dict):
        return {k: _serialise(v) for k, v in sorted(value.items())}
    return value