# server-ip-rotation

Replace a fleet node's public IPv4 **at the provider**, with a checkpoint and a
way back. First and only provider: Hetzner Cloud.

> ⚠ **This has never been run against a real server.** It was written
> 2026-08-26 with a full offline test suite and **zero live API calls**. In this
> repo that counts as *untested*, in those words — every one of the four traps
> found on 2026-08-13 (`tmp.mount`, `aide --check`, conntrack buckets,
> node_exporter's listener) surfaced after a completely green `--check`. Worse
> here than usual: **the hcloud modules create no real actions in check mode**,
> so `--check` cannot validate the stop → detach → attach → start ordering at
> all. The first live run needs its own approval and
> `make monitoring-doctor` on both sides of it.

---

## Standalone, and what stayed behind

Extracted from the shikoonet Ansible repo on 2026-08-27 to run on GitLab CI/CD.
This directory is the whole project: `make test`, `make lint` and every
`ip-rotate-*` target work from here with no parent repo.

One dependency did **not** come along, on purpose. The `ansible_done` step
shells `make ip-change HOST=<alias>` inside a shikoonet checkout — that half
already works, is already tested against Cloudflare, and duplicating it here
would be a second implementation of a live DNS path. Point `ansible.repo_dir`
in `rotation.yml` at that checkout; in CI the `dns` job clones it.

`CLAUDE.md`, `.claude/agents/` and `.claude/skills/` travel with the directory.

## CI/CD — the interactive pause became an approval gate

GitHub Actions, in `.github/workflows/`:

```
ci.yml           push / PR    offline suite + lint. No secrets, no cost
ip-rotate.yml    dispatch(target, server_id, server_name, old_ipv4)
                   plan  → swap → dns → verify
                    ↑       ↑      ↑
                    └───────┴──────┴── environment approval, one per job
ip-rollback.yml  dispatch(target, txid, server_id, run_id)
```

### Naming, because this is the first flow and not the last

The file name is `<subject>-<verb>.yml` and the sidebar name is `<subject> ·
<what it does to the box>`. The subject prefix is doing the work: the Actions
sidebar sorts alphabetically, so everything that touches an address stays
together and a node lifecycle flow added later does not interleave with it.

| file | sidebar | exists |
|---|---|---|
| `ci.yml` | `ci · offline checks` | yes |
| `ip-rotate.yml` | `ip · change old IP to new IP` | yes |
| `ip-rollback.yml` | `ip · roll back to the old IP` | yes |
| `node-onboard.yml` | `node · onboard a new box` | not yet |
| `node-update.yml` | `node · update` | not yet |
| `node-monitoring.yml` | `node · add to monitoring` | not yet |

Jobs inside a flow are numbered (`1 · plan`, `2 · swap …`) because GitHub draws
them as a graph with no order of its own, and the order is the whole safety
argument here — a `swap` that ran before `plan` is a different tool.

Two things a new flow should reuse rather than reinvent:
`.github/actions/setup` (python + collection + the config secret + the
does-this-match check), and `rotate.py`'s job-summary table — any state machine
that calls `github_summary` on transition gets the same readable run summary
for free.

`swap` runs `--until connectivity_ok` and stops exactly where the interactive
tool asks a human to edit the inventory. It expects **exit 6** — a deliberate
pause, deliberately not exit 4, because a normal stage boundary showing red is
how a real escalation stops being noticed.

The human gate is not removed and `yes` is not piped blindly at the prompt. It
moves to two things the workflow can fail on:

* **the pause** — `environment: hetzner-production` with *required reviewers*.
  GitHub has no per-job manual button; a protected environment is the button.
  The run sits in *Waiting* until someone approves that specific job, and the
  wait between `swap` and `dns` is the window to commit the inventory edit. The
  node is already up on the new address during it; only DNS still lags.
* **the grep** — before `dns` answers the inventory prompt it clones shikoonet
  and greps `inventory/hosts.yml` for the new address. No commit, no answer, no
  DNS change.

Put `HCLOUD_TOKEN` on the **environment**, not the repository. An environment
secret is only readable by a job that has passed that environment's reviewers;
a repo secret is readable by any workflow on any branch. Masking is not a
boundary.

`rollback` is a separate workflow rather than a job, because GitHub — unlike
GitLab — leaves no clickable button on a run that has finished. It takes the
txid and the `ip · change` run id and pulls that run's checkpoint artifact back
down. Artifacts expire in 30 days; after that a rollback is a hand job.

See the header of `.github/workflows/ip-rotate.yml` for the secrets it needs.

---

## What problem this solves

The DNS half has been solved since 2026-08-21: `make ip-change HOST=<alias>`
PATCHes `<alias>.tinooer.top` in place, reads it back from the Cloudflare API as
a gate, and the PasarGuard panel follows the node by FQDN so it never has to be
told anything.

The **provider** half — power the box down, detach the burned Primary IPv4,
allocate a fresh one in the same datacenter, attach it, power back on — was
entirely a human in the Hetzner console. No dry run, no checkpoint, no rollback,
and a window in the middle where the box is off with no address at all.

This is that half, and it hands off to the half that already works.

## What it will never do

* **Delete anything.** No server, no Primary IP, no DNS record. After a
  rollback the *new* address is retained; after success the *old* address is
  retained. Both cost money and removing either is a separate decision with a
  separate approval. `state: absent` appears nowhere in `hcloud_step.yml` and
  `tests/contract.yml` asserts that by reading the file.
* **Write to `inventory/hosts.yml`.** That file is the single source of truth.
  The tool prints the edit and waits. `auto_edit_inventory: true` is *refused*,
  not silently ignored.
* **Touch a server it cannot re-prove.** Before every mutating step it re-reads
  the server and asserts id, name, location, project fingerprint, and the
  address that phase expects. A mismatch is `escalated` — never "try the other
  one".

---

## Setup, once

```bash
cd server-ip-rotation
cp rotation.example.yml rotation.yml        # gitignored
$EDITOR rotation.yml                        # fill in server.{id,expected_*}
```

`server.id` is the **immutable numeric id** from the Hetzner Cloud Console
(Servers → the server → the number in the URL). Not the name: a name can be
changed by anyone with console access, an id cannot.

The token comes from the vault but is **never read by any playbook**:

```bash
export HCLOUD_TOKEN="$(ansible-vault view /path/to/shikoonet/vault.yml \
    | awk '/^hcloud_api_token:/ {print $2}' | tr -d "\"'")"
```

The `hetzner.hcloud` modules read `HCLOUD_TOKEN` from the environment
themselves, so the value appears in no argv (nothing in `ps`), no var file,
and no checkpoint.

Stated precisely, because the short version — "the token never enters Python" —
is **not true** and would stop a reader from looking for the exceptions:

* **There is no HTTP client to Hetzner in this project's Python.** Every
  provider call is a subprocess running `hcloud_step.yml`.
* **Python opens exactly one socket**, `tcp_probe()` in `rotate.py`, and it
  goes to the **node's** SSH port to confirm the new address is live. Nothing
  here ever connects to `api.hetzner.cloud`.
* **Python reads the token exactly once**, to compute `sha256(token)[:12]` as a
  **project fingerprint**. It is never written anywhere, and the fingerprint is
  not the token — enough to tell "this is the production project" from "this is
  the one I made last week", not enough to recover anything.

Pin the value `plan` prints into `rotation.yml`; every later run asserts
against it.

On top of that, `Rotation.save()` runs `redact_tree()` over the whole
checkpoint **on the way to disk**, not only in the code that builds each field.
Producer-side redaction is a property of today's code; the next field that
carries third-party output would leak silently without the sink-side pass.
There is a test for exactly that (a deliberately non-redacting `ip_change`
stub), and removing the guard makes it fail.

---

## Running it

```bash
make ip-rotate-plan                                       # read-only, mutates nothing
make ip-rotate-apply    SERVER_ID=<the numeric id>
make ip-rotate-resume   TXID=<txid> SERVER_ID=<the numeric id>
make ip-rotate-rollback TXID=<txid> SERVER_ID=<the numeric id>
make ip-rotate-status   TXID=<txid>
```

`SERVER_ID` must equal `server.id` in the config **exactly**. That is the
repo's destructive-confirmation pattern: the confirmation is the target's own
identity, never `true` and never `yes`, so "rotate whatever is configured" has
no spelling. Same shape as `make gre-remove HOST=<alias>`.

Exit codes: `0` success or plan · `1` usage/config/token · `2` identity
mismatch · `3` provider error after retries · `4` escalated · `5` rolled back.

### What apply actually does

```
 1. auto_delete=false on the OLD Primary IP     <- Rule One: protect the way back
 2. power off the server
 3. detach the old address                      <- node unreachable from here
 4. allocate <alias>-ipv4-<txid> in the same datacenter
 5. attach it
 6. power on                                    <- node reachable again
 7. TCP probe :22 on the new address
 8. WAIT for you to edit inventory/hosts.yml
 9. make ip-change HOST=<alias>                 <- Cloudflare PATCH + monitoring-doctor
10. fresh read-back and a second probe
```

Steps 3 to 6 are the outage. Everything before step 2 is reversible for free.

### If it stops

Every transaction writes `state/<txid>.json` atomically after each transition.

| It says | Do |
|---|---|
| `rolled_back` (exit 5) | The old address is back and the box is up. Read the checkpoint's `rollback.reason`. |
| `escalated` (exit 4) | Read the printed recovery commands — they carry the real ids. Nothing was deleted. |
| nothing (crash, Ctrl-C) | `make ip-rotate-resume TXID=… SERVER_ID=…` |

`resume` re-asserts identity first and continues from the recorded state. It is
safe to run repeatedly: the collection's modules are desired-state, and the
deterministic IP name makes allocation idempotent too — a crash between
"allocate" and "write the checkpoint" cannot mint a second billed address,
because the next run *finds* the one already named `<alias>-ipv4-<txid>`.

---

## ⚠ Hetzner guarantees the datacenter, never the prefix

A new Primary IP comes from the same location. It does **not** come from the
same `/24`, and there is no API parameter to ask for one. If an exact prefix
ever becomes a hard requirement — something upstream pinned the old range, a
peer has a route for it — this tool cannot deliver it, and the answer is to
escalate, not to allocate in a loop until something adjacent falls out.

`plan` prints this every time, on purpose.

---

## ⚠ Four things about `hetzner.hcloud` 6.2.1 that are not in its docs

Verified 2026-08-26 by reading the installed source at
`/usr/lib/python3/dist-packages/ansible_collections/hetzner/hcloud/`. Each one
is a **green run that did the wrong thing**.

**1. `primary_ip` cannot assign or unassign an existing address.**
`primary_ip.py:242` `_update_primary_ip()` only ever touches `auto_delete`,
`labels` and `delete_protection`. Its `server:` parameter is read on the
*create* path only — pointing the module at an existing IP with a `server:` is
a silent green no-op. Every assign/unassign here goes through the `server`
module's `ipv4:` parameter instead. `primary_ip` is used for exactly two
things: allocate, and `auto_delete: false`.

**2. `enable_ipv4: false` on its own does not unassign anything.**
`server.py:607` — `_update_server_ip()` is only called `if
self.module.params.get("ipv4") is not None`. The obvious spelling of "take the
address away" changes nothing and reports `ok`. The unassign task passes
**both** `ipv4:` (which address to detach) and `enable_ipv4: false` (do not put
one back).

**3. Every `server` task is `state`-only or names its `ipv4:` explicitly.**
On the create path (`server.py:421`) an omitted `ipv4` with the default
`enable_ipv4: true` allocates a brand-new Primary IP — an address nobody
planned, billed monthly. We never create servers, but the rule is free, it is
what makes #2 work, and the contract test enforces it by parsing the playbook
as YAML rather than grepping (an *omission* is the bug, and no regex can see
one).

**4. `force: true` and `server_type:` must never meet in one task.** `force`
means "power the box off to apply this"; next to `server_type` it also
authorises an irreversible disk resize. `server_type:` appears nowhere in this
project and the contract test keeps it that way.

Two more shapes worth writing down:

* `server_info` returns `ipv4_address` (a string) and **no** Primary IP id. The
  id has to be correlated from `primary_ip_info` by `assignee_id` — that is why
  `read_server` makes two calls.
* `primary_ip_info` calls the datacenter field **`home_location`**
  (`primary_ip_info.py:155` → `primary_ip.datacenter.name`) while `primary_ip`
  calls the same value **`datacenter`**. `providers._ip()` accepts either; code
  that only ever saw one module would read `None` from the other with no error
  anywhere.

And, still binding from the earlier Aug 2026 notes: `assignee_id` is the source
of truth. `assignee_id: null` normalises to `assignee_type: "unassigned"`
whatever the API said; a set `assignee_id` with an assignee type we do not
recognise is a **non-retryable** error, because guessing there means guessing
which machine is about to lose an address. `type != "ipv4"` is rejected on
sight.

---

## Shape

```
rotate.py            CLI, state machine, checkpoint store, audit, --self-test
providers.py         dataclasses, error taxonomy, HcloudProvider(runner), redact()
hcloud_step.yml      the ONLY file that talks to Hetzner. One op per invocation.
ansible_adapter.py   DNS allow-list, print-and-wait inventory step, `make ip-change`
rotation.example.yml placeholders only
state/               checkpoints (gitignored)
tests/               fake_hcloud.py + test_rotation.py
```

**Python owns safety, the collection owns the provider.** Nothing here
reimplements HTTP, action polling or retries — that is vendored, and Hetzner's
own CI exercises it. What the collection has no concept of is what Python
does: re-asserting identity before a mutation, a confirmation gate (`--check`
is not one), a persisted checkpoint, and which failure gets which remedy.

**The seam is one callable**, `runner(op, params) -> dict`. In production it
shells `ansible-playbook hcloud_step.yml`; in tests it is `FakeHcloud`. Reads
go through it too, not just writes — one code path to the provider means one
place a credential can leak and one place to fake.

## Tests

```bash
make test-offline                                   # from the repo root
cd server-ip-rotation && python3 -m unittest discover -s tests -t .
python3 rotate.py --self-test
```

Zero network, zero ansible invocation, zero cost. 55 cases covering identity,
the dry-run/confirm gates, resume from **every** checkpoint (each one asserts
the exact number of remaining mutations, so a resume that repeats or skips a
step fails), the retry split, every row of the rollback table, the ansible
handoff, and redaction.

What they prove and what they don't: they prove *our* half behaves correctly
given a provider that behaves the way the collection's source says it does.
They cannot prove the collection behaves that way. That is exactly why the
first live run is a separate decision.
