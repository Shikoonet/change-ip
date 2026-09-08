#!/usr/bin/env bash
#
# setup-secrets.sh — bring this repo's GitHub Actions configuration to the
# state a live rotation needs, in ONE command.
#
#   bash scripts/setup-secrets.sh --dry     # report only, touches nothing
#   bash scripts/setup-secrets.sh           # create/repair everything
#   bash scripts/setup-secrets.sh --keys    # vault key NAMES only, no values
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

# ---- running inside GitHub Actions ---------------------------------------
# The operator asked for this to live on CI and never be typed again. Every
# input it needs is already a secret there, so on a runner we materialise the
# same files this script reads locally: the vault comes from a clone of
# shikoonet, the password and key from env. Files land in a private temp dir
# at 0600 and the runner is destroyed with them.
#
# The one thing CI cannot supply itself is the token that WRITES secrets:
# GITHUB_TOKEN has no secrets:write scope and none can be granted. That is
# `ADMIN_PAT`, added once through the GitHub web UI — no command, and never
# again.
_ci_tmp=""
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  _ci_tmp="$(mktemp -d)"; chmod 700 "$_ci_tmp"
  if [[ -n "${ANSIBLE_VAULT_PASSWORD:-}" ]]; then
    printf '%s' "$ANSIBLE_VAULT_PASSWORD" > "$_ci_tmp/vault_pass"
    chmod 600 "$_ci_tmp/vault_pass"; VAULT_PASS_FILE="$_ci_tmp/vault_pass"
  fi
  if [[ -n "${SSH_PRIVATE_KEY:-}" ]]; then
    printf '%s\n' "$SSH_PRIVATE_KEY" > "$_ci_tmp/ssh_key"
    chmod 600 "$_ci_tmp/ssh_key"; SSH_KEY_FILE="$_ci_tmp/ssh_key"
  fi
  if [[ -n "${ROTATION_CONFIG:-}" ]]; then
    printf '%s' "$ROTATION_CONFIG" > "$_ci_tmp/rotation.yml"
    chmod 600 "$_ci_tmp/rotation.yml"; ROTATION_CONFIG_FILE="$_ci_tmp/rotation.yml"
  fi
  if [[ -n "${SHIKOONET_REPO:-}" && ! -d "${SHIKOONET_DIR:-/nonexistent}" ]]; then
    # The vault lives in a private repo, so an anonymous clone gets nothing.
    # Authenticate through a credential helper that exists for this one
    # command and is never written to any .git/config — CLAUDE.md forbids a
    # token inside the URL, and for good reason: a URL ends up in remotes,
    # reflogs and error messages.
    _clone_err="$_ci_tmp/clone.err"
    if [[ -n "${SHIKOONET_PAT:-${ADMIN_PAT:-}}" ]]; then
      printf '%s' "${SHIKOONET_PAT:-$ADMIN_PAT}" > "$_ci_tmp/gitpat"
      chmod 600 "$_ci_tmp/gitpat"
      GIT_ASKPASS=/bin/echo \
      git -c "credential.helper=!f() { echo username=x-access-token; echo password=$(cat "$_ci_tmp/gitpat"); }; f" \
        clone --depth 1 --quiet "$SHIKOONET_REPO" "$_ci_tmp/shikoonet" 2>"$_clone_err" \
        && SHIKOONET_DIR="$_ci_tmp/shikoonet"
      rm -f "$_ci_tmp/gitpat"
    else
      git clone --depth 1 --quiet "$SHIKOONET_REPO" "$_ci_tmp/shikoonet" 2>"$_clone_err" \
        && SHIKOONET_DIR="$_ci_tmp/shikoonet"
    fi
  fi
  trap 'rm -rf "$_ci_tmp"' EXIT
fi

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

# Which provider this config drives decides which environments matter. The
# coverage check already skipped jobs gated on the other provider; the install
# loops did not, and kept trying to put Cloudflare tokens on
# dataforest-production for an operator who runs hcloud — failing there on
# every CI run, where the vault is unreachable. One decision, made once.
PROVIDER=$(python3 -c '
import sys, yaml
try:
    print((yaml.safe_load(open(sys.argv[1])) or {}).get("provider") or "hcloud")
except Exception:
    print("hcloud")
' "$ROTATION_CONFIG_FILE" 2>/dev/null || echo hcloud)
if [[ "$PROVIDER" == "dataforest" ]]; then
  PROVIDER_ENVS="dataforest-production"       # provider token + config
  PROD_ENV="dataforest-production"            # where the DNS half runs
else
  PROVIDER_ENVS="hetzner-plan hetzner-production"
  PROD_ENV="hetzner-production"
fi
# The DNS half (Cloudflare tokens, SSH, vault, shikoonet URL) runs on
# cloudflare-production and on the active provider's production env — never
# on a plan env, which is read-only and never reaches DNS.
DNS_ENVS="cloudflare-production $PROD_ENV"

DRY=0; KEYS_ONLY=0
case "${1:-}" in
  --dry)  DRY=1 ;;
  --keys) KEYS_ONLY=1 ;;
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
# Read a key out of the vault and write it to stdout. Takes CANDIDATE names
# and uses the first that exists, because vault.example.yml is a sample and
# the real vault does not have to agree with it — guessing one name and
# failing taught us that. The value never becomes a shell variable, so it
# cannot be echoed by accident later.
vault_get() {
  ansible-vault view "$VAULT_FILE" --vault-password-file "$VAULT_PASS_FILE" \
    | python3 -c '
import sys, yaml
data = yaml.safe_load(sys.stdin) or {}
for key in sys.argv[1:]:
    val = data.get(key)
    if val not in (None, ""):
        sys.stdout.write(str(val))
        sys.exit(0)
sys.exit("vault has none of: " + ", ".join(repr(k) for k in sys.argv[1:]))
' "$@"
}

# Key NAMES only, never values. Run with --keys when a lookup fails, so the
# mapping is fixed from what the vault actually holds rather than guessed.
vault_keys() {
  ansible-vault view "$VAULT_FILE" --vault-password-file "$VAULT_PASS_FILE" \
    | python3 -c '
import sys, yaml
for k in sorted((yaml.safe_load(sys.stdin) or {})):
    print("   ", k)'
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
  # NEVER pipe the producer straight into `gh secret set`. Both sides of a
  # pipe run at once: a producer that fails and writes nothing still lets gh
  # read EOF and store an EMPTY secret, and `pipefail` then reports [FAIL]
  # after the damage. That is not theory — it silently blanked HCLOUD_TOKEN on
  # both Hetzner environments on 2026-09-08 and the next `plan` died with
  # "HCLOUD_TOKEN is not set".
  #
  # Materialise first, check it is non-empty, and only then write. The value
  # goes to a 0600 file inside a 0700 dir and is shredded immediately; it
  # still never becomes a shell variable, so it cannot be echoed later.
  local _vf; _vf="$(mktemp)"; chmod 600 "$_vf"
  if "$@" >"$_vf" 2>/dev/null && [[ -s "$_vf" ]] \
     && gh secret set "$name" --env "$env" --repo "$REPO" < "$_vf" >/dev/null 2>&1; then
    rm -f "$_vf"
    say "[set]   $name on $env"; fixed=$((fixed+1))
    return 0
  fi
  rm -f "$_vf"
  if secret_present "$name" "$env"; then
    # The source could not produce a value, but a good one is already
    # installed. Nothing broke; say so instead of raising an alarm that
    # sends someone looking for damage there isn't any of.
    say "[keep]  $name on $env  (already set; source unavailable: $*)"
    ok=$((ok+1))
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
if [[ "$KEYS_ONLY" == "1" ]]; then
  echo "keys in $VAULT_FILE (names only, no values):"
  vault_keys
  exit 0
fi

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
# The vault is a SOURCE, not a requirement. Without it the secrets whose
# values live there cannot be REFRESHED — but the ones already installed stay
# installed and correct, and set_secret reports those as [keep]. Treating an
# unreachable vault as fatal made a run where every secret was already right
# exit non-zero, which says "broken" about a repo that is fine. A secret that
# is neither in the vault nor on GitHub still fails, below, where it matters.
_vault_ok=1
for f in "$VAULT_FILE" "$VAULT_PASS_FILE"; do
  if [[ -r "$f" ]]; then
    say "[ok]    $f"
  else
    say "[warn]  $f is not readable — vault-sourced secrets can only be kept, not refreshed"
    _vault_ok=0
  fi
done
if [[ "$_vault_ok" == "0" && -s "${_clone_err:-/nonexistent}" ]]; then
  say "        clone said: $(head -1 "$_clone_err")"
fi
[[ -r "$SSH_KEY_FILE" ]] && say "[ok]    $SSH_KEY_FILE" \
  || { say "[MISS]  $SSH_KEY_FILE (set SSH_KEY_FILE=...)"; problems=$((problems+1)); }
[[ -r "$ROTATION_CONFIG_FILE" ]] && say "[ok]    $ROTATION_CONFIG_FILE" \
  || { say "[MISS]  $ROTATION_CONFIG_FILE"; problems=$((problems+1)); }
[[ -n "$SHIKOONET_URL" ]] && say "[ok]    shikoonet URL from git remote" \
  || say "[warn]  no shikoonet checkout to read a remote from (harmless if SHIKOONET_REPO is already set)"

if [[ "$problems" != "0" && "$DRY" == "0" ]]; then
  echo
  echo "refusing to continue: fix the [MISS] rows above first." >&2
  exit 4
fi

head_ "provider tokens"
# The shikoonet vault does NOT hold a Hetzner token — `--keys` on 2026-09-08
# listed nine keys and none of them was one. HCLOUD_TOKEN was installed
# directly on both environments on 2026-08-27 and is the source of truth for
# itself. The candidate list stays so a vault that later grows the key is
# picked up; until then this reports [keep], which is the honest answer.
for env in $PROVIDER_ENVS; do
  set_secret HCLOUD_TOKEN "$env" vault_get \
    hcloud_api_token hetzner_api_token hcloud_token \
    hetzner_cloud_api_token hcloud_api_key hetzner_token
done

head_ "project fingerprint"
# `project_fingerprint` pins the config to ONE Hetzner project: it is
# sha256(HCLOUD_TOKEN)[:12], and every run asserts against it so a rotation
# aimed at production cannot be resumed with a staging token. Rotating the
# Hetzner token is a legitimate event that changes it — and the tool must not
# absorb that silently, or the pin means nothing.
#
# So: always REPORT a mismatch, and only rewrite when REPIN=1 says a human
# decided the new token is the right one. That keeps the guard while removing
# the need to hand-edit a secret.
if [[ -n "${HCLOUD_TOKEN:-}" && -r "$ROTATION_CONFIG_FILE" ]]; then
  _live_fp=$(printf '%s' "$HCLOUD_TOKEN" | python3 -c '
import hashlib, sys
print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()[:12])')
  _cfg_fp=$(python3 -c '
import sys, yaml
print((yaml.safe_load(open(sys.argv[1])) or {}).get("project_fingerprint") or "")
' "$ROTATION_CONFIG_FILE")
  if [[ "$_cfg_fp" == "$_live_fp" ]]; then
    say "[ok]    config pins $_cfg_fp and the token agrees"; ok=$((ok+1))
  elif [[ "${REPIN:-}" == "1" || "${REPIN:-}" == "true" ]]; then
    python3 -c '
import sys, yaml
p, fp = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(p)) or {}
d["project_fingerprint"] = fp
yaml.safe_dump(d, open(p, "w"), sort_keys=False, default_flow_style=False)
' "$ROTATION_CONFIG_FILE" "$_live_fp"
    say "[set]   re-pinned $_cfg_fp -> $_live_fp (REPIN was requested)"
    fixed=$((fixed+1))
  else
    say "[MISS]  config pins ${_cfg_fp:-<empty>} but HCLOUD_TOKEN is $_live_fp"
    say "        The Hetzner token changed. Nothing is broken; this pin is what"
    say "        stops a production rotation resuming with a staging token, so"
    say "        it will not update itself."
    say ""
    # Say what arrived, not just what is wanted. "re-run with REPIN=1" reads
    # like an instruction that was followed when the box simply was not ticked.
    say "        REPIN is currently: '${REPIN:-<unset>}'"
    say "        To accept the new token, dispatch bootstrap again with BOTH:"
    say "            mode:              apply"
    say "            repin_fingerprint: checked"
    say "        Only do that if the new token points at the SAME Hetzner"
    say "        project. If it points at a different one, this refusal is the"
    say "        tool working."
    problems=$((problems+1))
  fi
fi

head_ "rotation config"
# Every environment whose jobs run the setup action needs this, and that list
# is NOT hand-maintained here — it is read out of run.yml below. The hand
# list said hetzner-plan and hetzner-production; dns_scan sits on
# cloudflare-production and died with "ROTATION_CONFIG secret is empty".
for env in $PROVIDER_ENVS cloudflare-production; do
  set_secret ROTATION_CONFIG "$env" emit_file "$ROTATION_CONFIG_FILE"
done

head_ "cloudflare tokens"
# Both account tokens go everywhere a job may run the DNS half. The hcloud
# `dns` job sits on hetzner-production and cannot read cloudflare-production,
# so the same values are needed in both places; a job has exactly one
# environment and this half needs a Hetzner token in the same process.
for env in $DNS_ENVS; do
  set_secret CLOUDFLARE_API_TOKEN_ACCOUNT_A "$env" vault_get cloudflare_miragerunner_api_token
  set_secret CLOUDFLARE_API_TOKEN_ACCOUNT_B "$env" vault_get cloudflare_samsos_api_token
done

head_ "shikoonet access (the inventory half)"
for env in $DNS_ENVS; do
  set_secret SSH_PRIVATE_KEY        "$env" emit_file "$SSH_KEY_FILE"
  set_secret ANSIBLE_VAULT_PASSWORD "$env" emit_file "$VAULT_PASS_FILE"
  # Only when a URL was actually discovered. On a runner with no checkout
  # there is nothing to derive it FROM, and the secret is already set — an
  # empty write would replace a good value with nothing.
  if [[ -n "$SHIKOONET_URL" ]]; then
    set_secret SHIKOONET_REPO "$env" emit_string "$SHIKOONET_URL"
  elif secret_present SHIKOONET_REPO "$env"; then
    say "[keep]  SHIKOONET_REPO on $env  (already set; nothing here to derive it from)"
    ok=$((ok+1))
  else
    say "[FAIL]  SHIKOONET_REPO on $env  (not set, and no checkout to read it from)"
    problems=$((problems+1))
  fi
done

head_ "the bootstrap credential itself"
# ADMIN_PAT is what this script authenticates WITH, so on a runner it already
# holds the value — and jobs on other environments reference it (the inventory
# gate clones a private repo with it). Mirroring it is not circular: the copy
# on hetzner-production is the one a human installed by hand, and this only
# puts the same value where the other jobs can reach it.
if [[ -n "${ADMIN_PAT:-}" ]]; then
  set_secret ADMIN_PAT cloudflare-production emit_string "$ADMIN_PAT"
else
  say "[skip]  ADMIN_PAT is not in this process's env (a local run); nothing to mirror"
fi

head_ "coverage (what run.yml asks for, per environment)"
# The lists above are written by hand and drifted: ROTATION_CONFIG was
# installed on two environments while dns_scan, on a third, needed it and
# died with "ROTATION_CONFIG secret is empty" — after being dispatched.
#
# This reads the workflow instead of trusting the lists: for every job, its
# `environment` and every `secrets.X` it references (job env, step env, and
# anywhere in a run: block), then checks each pair is actually installed.
# A missing pair is a dispatch that will fail, found before dispatching.
_pairs=$(CFG="$ROTATION_CONFIG_FILE" python3 - <<'PY'
import os, re, sys, yaml
try:
    wf = yaml.safe_load(open(".github/workflows/run.yml"))
except OSError:
    sys.exit(0)
# Only the provider this config actually uses. A job gated on the OTHER
# provider can never run, so a secret it references is not a gap. Reporting it
# anyway trains people to skim a list that is mostly noise, and a list nobody
# reads is the same as no list.
try:
    provider = (yaml.safe_load(open(os.environ["CFG"])) or {}).get("provider")
except (OSError, KeyError, ValueError):
    provider = None
other = "dataforest" if (provider or "hcloud") == "hcloud" else "hcloud"
seen = set()
for name, job in (wf.get("jobs") or {}).items():
    env_name = job.get("environment")
    if not isinstance(env_name, str):
        continue
    if f"provider == '{other}'" in str(job.get("if") or ""):
        continue
    blob = yaml.safe_dump(job)
    for secret in sorted(set(re.findall(r"secrets\.([A-Z0-9_]+)", blob))):
        seen.add((env_name, secret))
for env_name, secret in sorted(seen):
    print(f"{env_name} {secret}")
PY
)
_gap=0
while read -r _env _sec; do
  [[ -z "${_env:-}" ]] && continue
  if secret_present "$_sec" "$_env"; then
    :
  elif [[ " CLOUDFLARE_API_TOKEN SHIKOONET_PAT DATAFOREST_API_TOKEN " == *" $_sec "* ]]; then
    # Deliberately optional. The legacy single-account CF name is unused when
    # cloudflare.accounts is set, SHIKOONET_PAT falls back to ADMIN_PAT, and
    # DataForest is a provider this operator does not run. An absent secret
    # expands to an empty string, which each of these paths already handles.
    say "[opt]   $_sec absent on $_env (optional on this path)"
  else
    say "[GAP]   $_sec is referenced by a job on $_env but is not installed there"
    _gap=$((_gap+1))
  fi
done <<< "$_pairs"
if [[ "$_gap" == "0" ]]; then
  say "[ok]    every secret run.yml references exists in the environment that needs it"
  ok=$((ok+1))
else
  say ""
  say "        $_gap gap(s). Each is a dispatch that would fail partway."
  say "        Optional ones (SHIKOONET_PAT, legacy CLOUDFLARE_API_TOKEN) are"
  say "        listed too — a job referencing an absent secret gets an empty"
  say "        string, which is only safe where the code expects that."
fi

head_ "summary"
say "ok=$ok  changed=$fixed  pending=$skipped  problems=$problems"
if [[ "$DRY" == "1" ]]; then
  say "dry run: nothing was written. Re-run without --dry to apply."
fi
[[ "$problems" == "0" ]] || exit 5
