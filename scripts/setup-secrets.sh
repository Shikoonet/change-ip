#!/usr/bin/env bash
#
# setup-secrets.sh — bring this repo's GitHub Actions configuration to the
# state a live rotation needs, in ONE command.
#
#   bash scripts/setup-secrets.sh --dry     # report only, touches nothing
#   bash scripts/setup-secrets.sh           # create/repair everything
#
# WHY THIS EXISTS
#
# GitHub Actions cannot mint its own credentials. `GITHUB_TOKEN` has no
# secrets:write scope and none can be granted, so the first credential must
# reach GitHub from outside — in any CI system, for anyone. That single act is
# irreducible.
#
# What is NOT irreducible is doing it six times by hand, from six different
# places, and rediscovering which environment needs which name. Every value
# below already exists on the operator's machine: the tokens live in the
# shikoonet Ansible vault, the vault password in a file, the SSH key in
# ~/.ssh. This script reads them from there and installs them, idempotently.
#
# NOTHING IS ECHOED. Values move from `ansible-vault view` straight into
# `gh secret set` over a pipe; they never land in a variable, a temp file, a
# log line, or this script's output. The report prints names and environments,
# never content.
#
# ENVIRONMENT
#   REPO             default Shikoonet/change-ip
#   SHIKOONET_DIR    default ../shikoonet-ansible (holds vault.yml)
#   VAULT_PASS_FILE  default ~/.vault_pass_pasarguard
#   SSH_KEY_FILE     default ~/.ssh/id_ed25519
#   REVIEWER_ID      numeric GitHub user id for required reviewers
#                    (default: whoever `gh api user` says you are)
set -euo pipefail

REPO="${REPO:-Shikoonet/change-ip}"
SHIKOONET_DIR="${SHIKOONET_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/shikoonet-ansible}"
VAULT_FILE="${VAULT_FILE:-$SHIKOONET_DIR/vault.yml}"
VAULT_PASS_FILE="${VAULT_PASS_FILE:-$HOME/.vault_pass_pasarguard}"
# First readable candidate wins. The shikoonet production key is the one the
# `dns` job needs; id_ed25519 is only a fallback for a differently-set-up box.
_default_ssh_key() {
  local c
  for c in "$HOME/.ssh/shikoo_prod_primary_ed25519" "$HOME/.ssh/id_ed25519"; do
    [[ -r "$c" ]] && { printf '%s' "$c"; return; }
  done
  printf '%s' "$HOME/.ssh/id_ed25519"
}
SSH_KEY_FILE="${SSH_KEY_FILE:-$(_default_ssh_key)}"
SHIKOONET_URL="${SHIKOONET_URL:-$(git -C "$SHIKOONET_DIR" remote get-url origin 2>/dev/null || echo '')}"
ROTATION_CONFIG_FILE="${ROTATION_CONFIG_FILE:-$(cd "$(dirname "$0")/.." && pwd)/rotation.yml}"

DRY=0
case "${1:-}" in
  --dry)  DRY=1 ;;
  --help) sed -n '3,32p' "$0"; exit 0 ;;
  "")     ;;
  *)      echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
esac

ok=0; fixed=0; skipped=0; problems=0
say()  { printf '  %s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }

need() { command -v "$1" >/dev/null || { echo "$1 is not on PATH" >&2; exit 3; }; }
need gh; need python3

# ---------------------------------------------------------------- helpers --
# Read ONE key out of the vault and write it to stdout. The value never
# becomes a shell variable, so it cannot be echoed by an accident later.
vault_get() {
  ansible-vault view "$VAULT_FILE" --vault-password-file "$VAULT_PASS_FILE" \
    | python3 -c '
import sys, yaml
key = sys.argv[1]
data = yaml.safe_load(sys.stdin) or {}
val = data.get(key)
if val is None:
    sys.exit(f"vault has no key {key!r}")
sys.stdout.write(str(val))
' "$1"
}

secret_present() {  # secret_present <name> <env>
  gh api "repos/${REPO}/environments/${2}/secrets" 2>/dev/null \
    | python3 -c '
import json, sys
names = {s["name"] for s in (json.load(sys.stdin).get("secrets") or [])}
sys.exit(0 if sys.argv[1] in names else 1)
' "$1"
}

# set_secret <name> <env> <producer-command...>
# The producer writes the value to stdout; it goes straight into gh.
set_secret() {
  local name="$1" env="$2"; shift 2
  if [[ "$DRY" == "1" ]]; then
    if secret_present "$name" "$env"; then
      say "[ok]    $name on $env"; ok=$((ok+1))
    else
      say "[would] $name on $env  <- $*"; skipped=$((skipped+1))
    fi
    return 0
  fi
  if "$@" | gh secret set "$name" --env "$env" --repo "$REPO" >/dev/null 2>&1; then
    say "[set]   $name on $env"; fixed=$((fixed+1))
  else
    say "[FAIL]  $name on $env  (source: $*)"; problems=$((problems+1))
  fi
}

emit_file()   { cat "$1"; }
emit_string() { printf '%s' "$1"; }

ensure_environment() {
  local env="$1"
  if gh api "repos/${REPO}/environments/${env}" >/dev/null 2>&1; then
    say "[ok]    environment $env exists"
  elif [[ "$DRY" == "1" ]]; then
    say "[would] create environment $env"; return 0
  else
    gh api -X PUT "repos/${REPO}/environments/${env}" >/dev/null
    say "[set]   created environment $env"; fixed=$((fixed+1))
  fi
}

# A reviewer is the whole human gate. CLAUDE.md described one on
# hetzner-production for eleven days while none of the four environments had
# any protection at all — which is why this is asserted here rather than
# documented.
ensure_reviewer() {
  local env="$1" uid="$2"
  local current
  current=$(gh api "repos/${REPO}/environments/${env}" 2>/dev/null \
    | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(len([r for r in d.get("protection_rules", [])
           if r.get("type") == "required_reviewers"]))' 2>/dev/null || echo 0)
  if [[ "${current:-0}" != "0" ]]; then
    say "[ok]    $env has a required reviewer"; ok=$((ok+1)); return 0
  fi
  if [[ "$DRY" == "1" ]]; then
    say "[would] add required reviewer to $env"; skipped=$((skipped+1)); return 0
  fi
  # -F with a nested array does not build the right body; JSON on stdin does.
  printf '{"wait_timer":0,"prevent_self_review":false,"reviewers":[{"type":"User","id":%s}],"deployment_branch_policy":null}' "$uid" \
    | gh api -X PUT "repos/${REPO}/environments/${env}" --input - >/dev/null
  say "[set]   required reviewer on $env"; fixed=$((fixed+1))
}

# ------------------------------------------------------------------- main --
REVIEWER_ID="${REVIEWER_ID:-$(gh api user --jq .id)}"

head_ "environments"
for env in hetzner-plan hetzner-production cloudflare-production dataforest-production; do
  ensure_environment "$env"
done

head_ "human gates (required reviewers)"
say "hetzner-plan is read-only and deliberately ungated."
for env in hetzner-production cloudflare-production dataforest-production; do
  ensure_reviewer "$env" "$REVIEWER_ID"
done

head_ "preconditions"
for f in "$VAULT_FILE" "$VAULT_PASS_FILE"; do
  [[ -r "$f" ]] && say "[ok]    $f" || { say "[MISS]  $f"; problems=$((problems+1)); }
done
[[ -r "$SSH_KEY_FILE" ]] && say "[ok]    $SSH_KEY_FILE" \
  || { say "[MISS]  $SSH_KEY_FILE (set SSH_KEY_FILE=...)"; problems=$((problems+1)); }
[[ -r "$ROTATION_CONFIG_FILE" ]] && say "[ok]    $ROTATION_CONFIG_FILE" \
  || { say "[MISS]  $ROTATION_CONFIG_FILE"; problems=$((problems+1)); }
[[ -n "$SHIKOONET_URL" ]] && say "[ok]    shikoonet URL from git remote" \
  || say "[warn]  no shikoonet remote found; set SHIKOONET_URL=..."

if [[ "$problems" != "0" && "$DRY" == "0" ]]; then
  echo
  echo "refusing to continue: fix the [MISS] rows above first." >&2
  exit 4
fi

head_ "provider tokens"
for env in hetzner-plan hetzner-production; do
  set_secret HCLOUD_TOKEN "$env" vault_get hcloud_api_token
done

head_ "rotation config"
# Carries NO expected_ipv4 on purpose: the address is stated per-run on the
# dispatch form, so this file never goes stale and never needs re-uploading.
for env in hetzner-plan hetzner-production; do
  set_secret ROTATION_CONFIG "$env" emit_file "$ROTATION_CONFIG_FILE"
done

head_ "cloudflare tokens"
# Both account tokens go everywhere a job may run the DNS half. The hcloud
# `dns` job sits on hetzner-production and cannot read cloudflare-production,
# so the same values are needed in both places; a job has exactly one
# environment and this half needs a Hetzner token in the same process.
for env in cloudflare-production hetzner-production; do
  set_secret CLOUDFLARE_API_TOKEN_ACCOUNT_A "$env" vault_get cloudflare_miragerunner_api_token
  set_secret CLOUDFLARE_API_TOKEN_ACCOUNT_B "$env" vault_get cloudflare_samsos_api_token
done

head_ "shikoonet access (the inventory half)"
for env in hetzner-production cloudflare-production; do
  set_secret SSH_PRIVATE_KEY        "$env" emit_file "$SSH_KEY_FILE"
  set_secret ANSIBLE_VAULT_PASSWORD "$env" emit_file "$VAULT_PASS_FILE"
  [[ -n "$SHIKOONET_URL" ]] && set_secret SHIKOONET_REPO "$env" emit_string "$SHIKOONET_URL"
done

head_ "summary"
say "ok=$ok  changed=$fixed  pending=$skipped  problems=$problems"
if [[ "$DRY" == "1" ]]; then
  say "dry run: nothing was written. Re-run without --dry to apply."
fi
[[ "$problems" == "0" ]] || exit 5
