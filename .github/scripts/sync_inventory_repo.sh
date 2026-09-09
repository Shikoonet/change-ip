#!/usr/bin/env bash
# Clone the fleet repository, update exactly one alias, and either prove a push
# would work (check) or commit + push it (apply).  The credential is read only
# from the environment and a mode-0600 temporary file; it is never put in a
# URL, git config, argv, output or artifact.
set -euo pipefail

mode="${1:-}"
if [[ "$mode" != "check" && "$mode" != "apply" ]]; then
  echo "usage: sync_inventory_repo.sh <check|apply>" >&2
  exit 2
fi

rotation_root="${ROTATION_ROOT:-$PWD}"
runner_tmp="${RUNNER_TEMP:-/tmp}"
checkout="${SHIKOONET_DIR:-$runner_tmp/shikoonet}"
absent_marker="${checkout}.absent"
repo="${SHIKOONET_REPO:-}"
token="${SHIKOONET_PAT:-${ADMIN_PAT:-}}"

# This script deliberately refreshes its own temporary checkout on retries.
# Never let an accidental SHIKOONET_DIR turn that narrow cleanup into a broad
# deletion outside the runner's temporary directory.
case "$checkout" in
  "$runner_tmp"/*) ;;
  *)
    echo "inventory: SHIKOONET_DIR must be inside RUNNER_TEMP" >&2
    exit 2
    ;;
esac

rm -rf -- "$checkout"
rm -f -- "$absent_marker"

if [[ -z "$repo" ]]; then
  echo "inventory: SHIKOONET_REPO is empty; treating this as a non-fleet node"
  [[ "$mode" == "apply" ]] && touch "$absent_marker"
  exit 0
fi
if [[ -z "$token" ]]; then
  echo "inventory: neither SHIKOONET_PAT nor ADMIN_PAT is set" >&2
  exit 1
fi

token_file="$(mktemp)"
chmod 600 "$token_file"
printf '%s' "$token" > "$token_file"
cleanup() { rm -f -- "$token_file"; }
trap cleanup EXIT
credential_helper="!f() { echo username=x-access-token; echo password=\$(cat '$token_file'); }; f"

attempts=1
[[ "$mode" == "apply" ]] && attempts=3
for ((attempt = 1; attempt <= attempts; attempt++)); do
  rm -rf -- "$checkout"
  git -c "credential.helper=$credential_helper" \
    clone --depth 1 --quiet "$repo" "$checkout"
  inventory="$checkout/inventory/hosts.yml"
  if [[ ! -f "$inventory" ]]; then
    echo "inventory: $repo has no inventory/hosts.yml" >&2
    exit 1
  fi

  result="$(python3 "$rotation_root/.github/scripts/update_inventory.py" \
    --inventory "$inventory" --alias "$ALIAS" \
    --old-ip "$OLD_IP" --new-ip "$NEW_IP")"
  printf '%s\n' "$result"

  if git -C "$checkout" diff --quiet -- inventory/hosts.yml; then
    if [[ "$mode" == "check" && "$result" == *"inventory_status=already-current"* ]]; then
      echo "inventory: it already has NEW_IP while the provider still has OLD_IP; refusing" >&2
      exit 1
    fi
    echo "inventory: no commit required"
    exit 0
  fi

  git -C "$checkout" config user.name "github-actions[bot]"
  git -C "$checkout" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  git -C "$checkout" add -- inventory/hosts.yml
  git -C "$checkout" commit --quiet -m "Update $ALIAS IP to $NEW_IP"
  branch="$(git -C "$checkout" symbolic-ref --short HEAD)"

  if [[ "$mode" == "check" ]]; then
    git -C "$checkout" -c "credential.helper=$credential_helper" \
      push --dry-run origin "HEAD:$branch"
    echo "inventory: write preflight passed; no remote change was made"
    exit 0
  fi

  if git -C "$checkout" -c "credential.helper=$credential_helper" \
       push origin "HEAD:$branch"; then
    echo "inventory: committed and pushed $ALIAS -> $NEW_IP"
    exit 0
  fi
  echo "inventory: push attempt $attempt/$attempts lost a race; cloning the latest branch" >&2
done

echo "inventory: could not push after $attempts attempts" >&2
exit 1
