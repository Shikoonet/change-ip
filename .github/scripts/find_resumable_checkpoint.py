#!/usr/bin/env python3
"""Recover the newest resumable checkpoint for one exact server.

GitHub's artifact API exposes metadata but not checkpoint fields, so candidates
are inspected newest-first.  Only the newest artifact for a transaction is
considered; this prevents an old pre-rollback artifact from resurrecting a
transaction whose newer artifact is already terminal.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward GitHub's Authorization header to artifact blob hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        if urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
            redirected.remove_header("authorization")
        return redirected


def _request(opener, url: str, token: str):
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "change-ip-checkpoint-recovery",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    return opener.open(request, timeout=30)


def _artifacts(opener, api_url: str, repo: str, token: str) -> Iterable[Dict[str, Any]]:
    page = 1
    while True:
        url = f"{api_url}/repos/{repo}/actions/artifacts?per_page=100&page={page}"
        with _request(opener, url, token) as response:
            payload = json.load(response)
        batch = payload.get("artifacts") or []
        if not batch:
            return
        for artifact in sorted(
            batch, key=lambda item: (item.get("created_at", ""), int(item.get("id", 0))),
            reverse=True,
        ):
            yield artifact
        if len(batch) < 100:
            return
        page += 1


def _checkpoints(opener, artifact: Dict[str, Any], token: str) -> Iterable[Dict[str, Any]]:
    with _request(opener, artifact["archive_download_url"], token) as response:
        archive = response.read()
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for name in bundle.namelist():
            if name.endswith(".json") and not name.startswith("__MACOSX/"):
                try:
                    checkpoint = json.loads(bundle.read(name))
                except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(checkpoint, dict) and checkpoint.get("txid"):
                    yield checkpoint


def is_resumable(
    checkpoint: Dict[str, Any], provider: str, server_id: str, current_ip: str
) -> bool:
    """Match identity and require a state that can safely advance."""
    if str(checkpoint.get("provider") or "hcloud") != provider:
        return False
    if str((checkpoint.get("server") or {}).get("id")) != str(server_id):
        return False
    if str((checkpoint.get("new_ip") or {}).get("ip")) != current_ip:
        return False
    state = checkpoint.get("state")
    if state == "escalated":
        state = checkpoint.get("resume_state")
    allowed = {
        "connectivity_ok",
        "ansible_done",
        "cloudflare_replaced",
    }
    return state in allowed and bool(checkpoint.get("cloudflare_manifest"))


def find_checkpoint(
    artifacts: Iterable[Dict[str, Any]],
    checkpoint_reader,
    provider: str,
    server_id: str,
    current_ip: str,
) -> Optional[Dict[str, Any]]:
    seen_txids = set()
    for artifact in artifacts:
        if artifact.get("expired") or not str(artifact.get("name", "")).startswith(
            "rotation-state"
        ):
            continue
        try:
            checkpoints = list(checkpoint_reader(artifact))
        except (OSError, urllib.error.HTTPError, zipfile.BadZipFile):
            continue
        checkpoints.sort(key=lambda cp: str(cp.get("updated_at", "")), reverse=True)
        for checkpoint in checkpoints:
            txid = str(checkpoint.get("txid") or "")
            if not txid or txid in seen_txids:
                continue
            seen_txids.add(txid)
            if is_resumable(checkpoint, provider, server_id, current_ip):
                return checkpoint
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("hcloud",), default="hcloud")
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--current-ip", required=True)
    parser.add_argument("--state-dir", type=Path, default=Path("state"))
    parser.add_argument("--api-url", default="https://api.github.com")
    args = parser.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not repo or not token:
        parser.error("GITHUB_REPOSITORY and GITHUB_TOKEN are required")

    opener = urllib.request.build_opener(_SafeRedirect())
    artifacts = _artifacts(opener, args.api_url.rstrip("/"), repo, token)
    checkpoint = find_checkpoint(
        artifacts,
        lambda artifact: _checkpoints(opener, artifact, token),
        args.provider,
        args.server_id.strip(),
        args.current_ip.strip(),
    )
    if checkpoint is None:
        parser.error(
            "no resumable checkpoint matches this provider, server_id and current IP"
        )

    args.state_dir.mkdir(parents=True, exist_ok=True)
    target = args.state_dir / f"{checkpoint['txid']}.json"
    target.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    target.chmod(0o600)
    print(
        f"checkpoint: {checkpoint['txid']} at {checkpoint['state']} for "
        f"server {checkpoint['server']['id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
