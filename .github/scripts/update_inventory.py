#!/usr/bin/env python3
"""Safely replace one fleet node's explicit ``ansible_host``.

The inventory stays human-formatted YAML.  We use the parsed structure to
prove that ``alias`` identifies exactly one explicit ``ansible_host``, then
replace only that scalar in the original text so comments and formatting are
not rewritten by a YAML dumper.  Re-running with ``new_ip`` already present is
an idempotent success.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

import yaml


class InventoryError(RuntimeError):
    """The requested inventory edit cannot be proven safe."""


def _explicit_hosts(node: Any, alias: str) -> Iterable[Any]:
    if isinstance(node, dict):
        hosts = node.get("hosts")
        if isinstance(hosts, dict) and alias in hosts:
            yield hosts[alias]
        for value in node.values():
            yield from _explicit_hosts(value, alias)
    elif isinstance(node, list):
        for value in node:
            yield from _explicit_hosts(value, alias)


def _ipv4(value: str, label: str) -> str:
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise InventoryError(f"{label} is not an IP address: {value!r}") from exc
    if parsed.version != 4:
        raise InventoryError(f"{label} must be IPv4, got {value!r}")
    return str(parsed)


def update_inventory(path: Path, alias: str, old_ip: str, new_ip: str) -> str:
    """Return ``updated``, ``already-current`` or ``absent``.

    ``absent`` is allowed only when neither address appears anywhere in the
    inventory.  If the old address exists under another alias, failing closed
    is safer than silently editing the wrong node.
    """
    old_ip = _ipv4(old_ip, "old_ip")
    new_ip = _ipv4(new_ip, "new_ip")
    if old_ip == new_ip:
        raise InventoryError("old_ip and new_ip are identical")
    if not alias.strip():
        raise InventoryError("alias is empty")

    try:
        text = path.read_text(encoding="utf-8")
        document = yaml.safe_load(text) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise InventoryError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise InventoryError(f"{path} does not contain an inventory mapping")

    entries = list(_explicit_hosts(document, alias))
    explicit = [entry for entry in entries
                if isinstance(entry, dict) and "ansible_host" in entry]
    if not explicit:
        if entries:
            raise InventoryError(
                f"{alias!r} exists in {path}, but it has no explicit "
                "ansible_host; refusing to classify it as a non-fleet node"
            )
        if old_ip in text or new_ip in text:
            raise InventoryError(
                f"{alias!r} has no explicit ansible_host, but {old_ip} or "
                f"{new_ip} exists elsewhere in {path}; refusing a global replacement"
            )
        print(f"inventory: {alias} is not a fleet host; no inventory edit needed")
        return "absent"
    if len(explicit) != 1:
        raise InventoryError(
            f"{alias!r} has {len(explicit)} explicit ansible_host entries; expected exactly one"
        )

    current = _ipv4(str(explicit[0]["ansible_host"]), f"{alias}.ansible_host")
    if current == new_ip:
        print(f"inventory: {alias} already points at {new_ip}")
        return "already-current"
    if current != old_ip:
        raise InventoryError(
            f"{alias}.ansible_host is {current}, expected old_ip {old_ip}; refusing"
        )

    # Locate the alias's block in the original YAML, then match a complete
    # scalar only inside that block. A global replacement is forbidden: the
    # same address may appear in a comment or under another host.
    alias_line = re.compile(
        rf"(?m)^(?P<indent>[ \t]*)(?P<alias_quote>['\"]?)"
        rf"{re.escape(alias)}(?P=alias_quote)[ \t]*:[ \t]*(?:#.*)?$"
    )
    alias_matches = list(alias_line.finditer(text))
    if len(alias_matches) != 1:
        raise InventoryError(
            f"found {len(alias_matches)} block entries for alias {alias!r}; expected one"
        )
    alias_match = alias_matches[0]
    indent = len(alias_match.group("indent").expandtabs(8))
    block_start = alias_match.end()
    block_end = len(text)
    for line_match in re.finditer(
        r"(?m)^(?P<indent>[ \t]*)(?P<body>\S.*)$", text[block_start:]
    ):
        if line_match.group("body").startswith("#"):
            continue
        line_indent = len(line_match.group("indent").expandtabs(8))
        if line_indent <= indent:
            block_end = block_start + line_match.start()
            break

    scalar = re.compile(
        rf"(?m)^(?P<prefix>[ \t]*ansible_host[ \t]*:[ \t]*)"
        rf"(?P<quote>['\"]?){re.escape(old_ip)}(?P=quote)"
        rf"(?P<suffix>[ \t]*(?:#.*)?)$"
    )
    matches = list(scalar.finditer(text, block_start, block_end))
    if len(matches) != 1:
        raise InventoryError(
            f"found {len(matches)} textual ansible_host values equal to {old_ip}; "
            "expected exactly one"
        )
    match = matches[0]
    replacement = (
        match.group("prefix") + match.group("quote") + new_ip
        + match.group("quote") + match.group("suffix")
    )
    updated = text[:match.start()] + replacement + text[match.end():]

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, path.stat().st_mode & 0o777)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise

    print(f"inventory: {alias} {old_ip} -> {new_ip}")
    return "updated"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--old-ip", required=True)
    parser.add_argument("--new-ip", required=True)
    args = parser.parse_args()
    try:
        status = update_inventory(
            args.inventory, args.alias, args.old_ip, args.new_ip
        )
    except InventoryError as exc:
        parser.error(str(exc))
    print(f"inventory_status={status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
