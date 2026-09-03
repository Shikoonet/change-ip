#!/usr/bin/env python3
"""A directory of fake system binaries that a DataForest rotation would invoke.

The offline playbook harness prepends this directory to PATH, sets the
`IP_BIN`, `NETPLAN_BIN`, `NMCLI_BIN`, `NETWORKCTL_BIN`, `SYSTEMCTL_BIN`,
`SSH_BIN`, `SSH_KEYSCAN_BIN`, `DF_NETPLAN_DIR`, `DF_SYSTEMD_NETWORK_DIR`,
`DF_INTERFACES_D_DIR`, and `DF_PERSISTENT_DIR` environment variables so
that `dataforest_step.yml` runs against this fake layer instead of
touching real `/etc` or real `/sbin/ip`.

Each fake maintains a small JSON state file under `tmpdir/state/` that
the test driver can inspect between calls. The fakes emit deterministic
output for known inputs and propagate a scriptable error for known
break conditions (set `DF_FAIL_*` env vars before running).
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List


def _state_dir() -> Path:
    p = Path(os.environ.get("DF_FAKEBIN_STATE", "/tmp/_df_fakebin"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _state_path(name: str) -> Path:
    """State files use `.json` so a casual `ls` shows the format."""
    return _state_dir() / f"{name}.json"


def _read_state(name: str) -> Dict[str, Any]:
    p = _state_path(name)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(name: str, data: Dict[str, Any]) -> None:
    p = _state_path(name)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _fail_if_set(name: str) -> None:
    """Optional scripted failure: set DF_FAIL_<NAME>=<rc> to make the
    fake exit with that rc BEFORE doing anything else. The tests use
    this to drive the playbook's fail-closed paths."""
    val = os.environ.get(f"DF_FAIL_{name}")
    if val is not None:
        try:
            rc = int(val)
        except ValueError:
            rc = 1
        sys.stderr.write(f"fake {name}: scripted failure rc={rc}\n")
        sys.exit(rc)


def _argv() -> List[str]:
    return sys.argv[1:]


def _ok(stdout: str = "") -> int:
    if stdout:
        sys.stdout.write(stdout)
    return 0


# ---------------------------------------------------------------------------
# ip (lookup `addr add|del` and `addr show` and `route show`)
# ---------------------------------------------------------------------------
def main_ip() -> int:
    _fail_if_set("IP")
    argv = _argv()
    state = _read_state("ip")
    state.setdefault("addresses", [])
    state.setdefault("routes", [])
    # Find the verb ("addr" or "route"); ignore -o/-4/-6 prefixes.
    verb = None
    for token in argv:
        if token in ("addr", "route"):
            verb = token
            break
    if verb is None:
        sys.stderr.write(f"ip: no verb in argv {argv!r}\n")
        return 1
    idx = argv.index(verb)
    rest = argv[idx + 1:]

    def _strip_cidr(value: str) -> str:
        """`ip addr add 203.0.113.10/32 dev eth0` stores address WITH /32;
        the playbook's verify_guest compares the same string. We accept
        both bare and CIDR forms so the fake matches either."""
        if "/" in value:
            return value.split("/", 1)[0]
        return value

    if verb == "addr":
        if rest[:1] == ["add"] and len(rest) >= 4 and rest[2] == "dev":
            addr = _strip_cidr(rest[1])
            iface = rest[3]
            if (iface, addr) in state["addresses"]:
                sys.stderr.write(f"ip: RTNETLINK answers: File exists\n")
                return 2
            state["addresses"].append((iface, addr))
            _write_state("ip", state)
            return _ok()
        if rest[:1] == ["del"] and len(rest) >= 4 and rest[2] == "dev":
            addr = _strip_cidr(rest[1])
            iface = rest[3]
            state["addresses"] = [
                (i, a) for (i, a) in state["addresses"]
                if not (i == iface and a == addr)
            ]
            _write_state("ip", state)
            return _ok()
        if "show" in rest:
            iface_filter = None
            for i, tok in enumerate(rest):
                if tok == "dev" and i + 1 < len(rest):
                    iface_filter = rest[i + 1]
            lines = []
            for (iface, addr) in state["addresses"]:
                if iface_filter is None or iface == iface_filter:
                    lines.append(f"    inet {addr}/32 brd 255.255.255.255 scope global {iface}")
            return _ok("\n".join(lines) + ("\n" if lines else ""))
    if verb == "route" and "show" in rest:
        return _ok("\n".join(state["routes"]) + ("\n" if state["routes"] else ""))
    sys.stderr.write(f"ip: unsupported argv {argv!r}\n")
    return 1


# ---------------------------------------------------------------------------
# netplan
# ---------------------------------------------------------------------------
def main_netplan() -> int:
    _fail_if_set("NETPLAN")
    argv = _argv()
    if argv[:1] == ["generate"] or argv[:1] == ["apply"]:
        return _ok()
    sys.stderr.write(f"netplan: unsupported argv {argv!r}\n")
    return 1


# ---------------------------------------------------------------------------
# nmcli
# ---------------------------------------------------------------------------
def main_nmcli() -> int:
    _fail_if_set("NMCLI")
    argv = _argv()
    # Accept any con mod invocation; rotate.py just needs it to succeed.
    if argv[:2] == ["con", "mod"]:
        return _ok()
    sys.stderr.write(f"nmcli: unsupported argv {argv!r}\n")
    return 1


# ---------------------------------------------------------------------------
# networkctl
# ---------------------------------------------------------------------------
def main_networkctl() -> int:
    _fail_if_set("NETWORKCTL")
    argv = _argv()
    if argv[:1] == ["reload"]:
        return _ok()
    sys.stderr.write(f"networkctl: unsupported argv {argv!r}\n")
    return 1


# ---------------------------------------------------------------------------
# systemctl
# ---------------------------------------------------------------------------
def main_systemctl() -> int:
    _fail_if_set("SYSTEMCTL")
    argv = _argv()
    if argv[:2] == ["is-active", "NetworkManager.service"]:
        # Match the real systemd behaviour: 0 = active, 3 = inactive.
        if os.environ.get("DF_NM_ACTIVE") == "1":
            return _ok("active\n")
        sys.stderr.write("inactive\n")
        return 3
    sys.stderr.write(f"systemctl: unsupported argv {argv!r}\n")
    return 1


# ---------------------------------------------------------------------------
# ssh-keyscan — fakes a known key matching the `expected_host_key_pattern`
# ---------------------------------------------------------------------------
def main_ssh_keyscan() -> int:
    _fail_if_set("SSH_KEYSCAN")
    argv = _argv()
    host = argv[-1] if argv else "127.0.0.1"
    if os.environ.get("DF_FAIL_KEYSCAN_NO_MATCH") == "1":
        return _ok("")
    key = os.environ.get("DF_KEYSCAN_KEY", f"{host} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE")
    return _ok(f"{key}\n")


# ---------------------------------------------------------------------------
# ssh — used by `wait_for` only as a port probe (it just opens the socket)
# ---------------------------------------------------------------------------
def main_ssh() -> int:
    import socket
    argv = _argv()
    # Naive parse: -p PORT HOST
    port = 22
    host = None
    i = 0
    while i < len(argv):
        if argv[i] == "-p" and i + 1 < len(argv):
            try:
                port = int(argv[i + 1])
            except ValueError:
                pass
            i += 2
            continue
        if not argv[i].startswith("-"):
            host = argv[i]
        i += 1
    if not host:
        host = "127.0.0.1"
    if os.environ.get("DF_SSH_OPEN") == "0":
        sys.stderr.write(f"ssh: connection refused {host}:{port}\n")
        return 1
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return _ok()
    except OSError as exc:
        sys.stderr.write(f"ssh: {exc}\n")
        return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
DISPATCH = {
    "ip": main_ip,
    "netplan": main_netplan,
    "nmcli": main_nmcli,
    "networkctl": main_networkctl,
    "systemctl": main_systemctl,
    "ssh-keyscan": main_ssh_keyscan,
    "ssh": main_ssh,
}


def main() -> int:
    name = Path(sys.argv[0]).name
    fn = DISPATCH.get(name)
    if fn is None:
        sys.stderr.write(f"fakebin: no handler for {name}\n")
        return 1
    return fn()


if __name__ == "__main__":
    sys.exit(main())