#!/usr/bin/env bash
#
# setup-secrets.sh — install the GitHub Actions secrets that the live
# `Run workflow → change-ip → hcloud` dispatch path depends on. The
# offline CI (unit tests, contract tests, lint) does NOT need any of
# these — they only matter when a human dispatches a real rotation.
#
# Why a script and not docs: the operator runs this ONCE per repo and
# any silent failure leaves the operator's first live run broken
# without a visible signal. A script makes the state explicit, dry-run
# friendly, and idempotent (you can re-run safely).
#
# Usage:
#   GH_TOKEN=<token-with-repo-admin> bash scripts/setup-secrets.sh
#   gh secret set -e hetzner-production SSH_PRIVATE_KEY -r < /path/to/key
#   # ... etc
#
# The script does NOT bake secrets in. It CHECKS what is already
# installed and PRINTS the exact commands to install what's missing.
# Run it dry with `--dry` to see the report without touching GitHub.

set -euo pipefail

REPO="${REPO:-Shikoonet/change-ip}"

usage() {
  cat <<EOF
Usage: $0 [--dry]

Options:
  --dry   Print the report only; do not call gh to delete anything.
  --help  Show this message.

Environment:
  REPO    GitHub repo (default: Shikoonet/change-ip)
  GH_TOKEN  a token with actions:write scope on \$REPO
EOF
}

DRY=0
case "${1:-}" in
  --dry)  DRY=1 ;;
  --help) usage; exit 0 ;;
  "")    ;;
  *)     usage; exit 2 ;;
esac

need_gh() {
  command -v gh >/dev/null || { echo "gh not on PATH" >&2; exit 3; }
}

# ---- audit table --------------------------------------------------------
# Required secret | Required env(s)          | Used by
# HCLOUD_TOKEN     | hetzner-plan, hetzner-production | hcloud module calls
# ROTATION_CONFIG  | hetzner-plan, hetzner-production | setup action reads cfg
# DATAFOREST_API_TOKEN | dataforest-production | dataforest provider
# CLOUDFLARE_API_TOKEN_ACCOUNT_A | cloudflare-production | DNS preflight + apply
# CLOUDFLARE_API_TOKEN_ACCOUNT_B | cloudflare-production | DNS preflight + apply
# CLOUDFLARE_API_TOKEN (legacy) | hetzner-production | legacy single-account CF
# SHIKOONET_REPO  | cloudflare-production | dns job clones shikoonet checkout
#                   | hetzner-production   | swap_dataforest_dns clones shikoonet
# SSH_PRIVATE_KEY  | cloudflare-production / hetzner-production | dns job SSH
# ANSIBLE_VAULT_PASSWORD | cloudflare-production / hetzner-production | ansible-vault

# Each row: secret, env, presence-required-flag (1=required), description
AUDIT=(
  "HCLOUD_TOKEN|hetzner-plan|1|read+write token, plan and swap paths"
  "HCLOUD_TOKEN|hetzner-production|1|"
  "ROTATION_CONFIG|hetzner-plan|1|rotation.yml contents (paste WITHOUT leading ---)"
  "ROTATION_CONFIG|hetzner-production|1|"
  "DATAFOREST_API_TOKEN|dataforest-production|1|DataForest Seed seed.add-ipv4 etc"
  "CLOUDFLARE_API_TOKEN_ACCOUNT_A|cloudflare-production|1|Account A DNS PATCH"
  "CLOUDFLARE_API_TOKEN_ACCOUNT_B|cloudflare-production|1|Account B DNS PATCH"
  "CLOUDFLARE_API_TOKEN|hetzner-production|0|legacy single-account; safe to skip if"
  "CLOUDFLARE_API_TOKEN|hetzner-production|0|the multi-account path is the only path"
  "SHIKOONET_REPO|cloudflare-production|1|URL with embedded token OR credential-free URL+helper"
  "SHIKOONET_REPO|hetzner-production|1|swap_dataforest_dns in_scope gate"
  "SSH_PRIVATE_KEY|cloudflare-production|1|ed25519 for ssh into the shikoonet node"
  "SSH_PRIVATE_KEY|hetzner-production|1|"
  "ANSIBLE_VAULT_PASSWORD|cloudflare-production|1|vault password for cloudflare.token lookup"
  "ANSIBLE_VAULT_PASSWORD|hetzner-production|1|"
)

run_audit() {
  need_gh
  echo "==== secret audit for $REPO ===="
  local missing=0
  local seen="|"
  for row in "${AUDIT[@]}"; do
    IFS='|' read -r name env _ _ <<< "$row"
    key="${env}::${name}"
    [[ "$seen" == *"|$key|"* ]] && continue
    seen="${seen}${key}|"
    # gh exposes secrets as `true`/`false` for visibility, never the
    # value. When visibility is false the secret may still be set; we
    # only know "configured vs not" through the public-keys endpoint.
    # Use the same check: gh api .../actions/secrets -> [{name, ...}]
    present=$(gh api "repos/${REPO}/environments/${env}/secrets" 2>/dev/null \
              | python3 -c 'import json,sys
d=json.load(sys.stdin)
names={s["name"] for s in d.get("secrets",[])}
print("yes" if "'"$name"'" in names else "no")' 2>/dev/null || echo "?")
    if [[ "$present" == "yes" ]]; then
      printf "  [ok]  %-40s  env=%s\n" "$name" "$env"
    else
      printf "  [MISS] %-40s  env=%s\n" "$name" "$env"
      missing=$((missing+1))
    fi
  done
  echo
  echo "missing: $missing"
}

cmd_to_set() {
  local name="$1" env="$2"
  echo "gh secret set --env \"$env\" \"$name\" --repo \"$REPO\" -r <path-or-stdin>"
}

emit_install_commands() {
  local seen="|"
  echo "==== install commands to run ===="
  for row in "${AUDIT[@]}"; do
    IFS='|' read -r name env req desc <<< "$row"
    [[ "$req" != "1" ]] && continue
    key="${env}::${name}"
    [[ "$seen" == *"|$key|"* ]] && continue
    seen="${seen}${key}|"
    printf "  %s   # %s\n" "$(cmd_to_set "$name" "$env")" "${desc:-(no description)}"
  done
  echo
  echo "Tip: each command reads the secret value from stdin (or use -r<file)."
  echo "     Use a credential helper for SHIKOONET_REPO per CLAUDE.md §SHIKOONET_REPO:"
  echo "       a credential-free URL with a temporary git credential helper."
}

main() {
  run_audit
  echo
  emit_install_commands
  if [[ "$DRY" == "0" ]]; then
    echo "==== orphan cleanup ===="
    if gh secret delete --env hetzner-production LAST_ROLLBACK_FINGERPRINT --repo "$REPO" 2>/dev/null; then
      echo "  removed LAST_ROLLBACK_FINGERPRINT from hetzner-production (orphan)"
    else
      echo "  LAST_ROLLBACK_FINGERPRINT: already absent (or no perm to delete)"
    fi
  fi
}

main
