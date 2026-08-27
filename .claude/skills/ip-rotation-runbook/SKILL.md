---
name: ip-rotation-runbook
description: Operator runbook for server-ip-rotation — the plan/apply/swap/resume/rollback flow, what each checkpoint state means, what each exit code means, and what to do when a rotation stops mid-way. Use when running a rotation, reading a checkpoint, interpreting an escalation, or deciding whether to resume or roll back.
---

# Running a rotation

## The one thing to know first

**This tool has never been run against a real server.** It was written
2026-08-26 with a full offline suite and **zero live API calls**. `--check`
cannot help: the hcloud modules create no actions in check mode, so the
stop → detach → attach → start ordering is not validated by anything yet.

The first live run — even a `plan` with a real token — needs its own approval.

## Setup, once

```bash
cp rotation.example.yml rotation.yml       # gitignored: it pins a real server id
$EDITOR rotation.yml                       # server.{id,expected_name,expected_ipv4,...}
export HCLOUD_TOKEN=...                    # never passed as an argument
```

`server.id` is the **immutable numeric id** from the console URL. Not the name:
a name can be changed by anyone with console access, an id cannot.

## The commands

```bash
make ip-rotate-plan                          # read everything, change nothing
make ip-rotate-swap    SERVER_ID=<id>        # provider half only, stops before the inventory edit
make ip-rotate-apply   SERVER_ID=<id>        # the whole thing, interactive
make ip-rotate-resume  TXID=<t> SERVER_ID=<id>
make ip-rotate-rollback TXID=<t> SERVER_ID=<id>
make ip-rotate-status  TXID=<t>
```

**`SERVER_ID` must equal `server.id` in the config.** That is the confirmation —
the target's own number, on purpose. `true` and `yes` are not spellings of a
specific server. `plan` prints the id.

## The state machine

| state | what has happened | a failure here means |
|---|---|---|
| `planned` | nothing moved | — |
| `confirmed` | the id gate passed | — |
| `server_off` | box powered down, **address still attached** | `restart_only` — power back on, stop |
| `old_ip_unassigned` | **box has no public address** | `restore` |
| `new_ip_allocated` | new address exists, not attached | `restore` |
| `new_ip_assigned` | new address attached, box still off | `restore` |
| `server_on` | booting | `escalate` — swapping back does not fix a box that will not boot |
| `connectivity_ok` | **TCP answers on the new address.** DNS and inventory still on the old one | `restore` |
| `ansible_done` | Cloudflare moved | `escalate` |
| `done` | verified | — |

**`connectivity_ok` is the safe resting place.** The node is up and serving on
the new address; only DNS and the inventory lag. Nothing is on fire — that is
exactly where `--until connectivity_ok` and the CD `swap` job stop.

## Exit codes

| code | meaning | is it bad |
|---|---|---|
| 0 | done | no |
| 1 | usage / config | nothing was contacted |
| 2 | identity mismatch | **nothing was contacted.** Never "try the other one" |
| 3 | provider error | read the checkpoint |
| 4 | escalated | yes — a human is needed, recovery commands are printed |
| 5 | rolled back | the old address is back. Nothing changed, but read why |
| 6 | paused at `--until` | **no.** A deliberate stop |

⚠ **6 is deliberately not 4.** A normal stage boundary showing red is how a real
escalation stops being noticed.

## When it stops mid-way

1. `make ip-rotate-status TXID=<t>` — the checkpoint says exactly where it is.
2. Look up the state in the table above.
3. `escalated` prints the recovery commands. Run them, do not improvise.
4. `resume` continues from wherever it is. It is safe to run twice.
5. `rollback` puts the **old** address back. It never deletes the new one.

## What it will never do

* **Delete anything.** After rollback the *new* address is retained; after
  success the *old* one is. Both cost money; removing either is a separate
  decision with a separate approval.
* **Write to `inventory/hosts.yml`.** It prints the edit and waits.
  `auto_edit_inventory: true` is *refused*, not silently ignored.
* **Touch a server it cannot re-prove.** Before every mutating step it re-reads
  the server and asserts id, name, location, project fingerprint, and the
  address that phase expects.

## In CI (GitLab)

The interactive pause becomes a stage boundary:

```
offline/lint → plan(manual) → swap(manual) → dns(manual) → verify
                                             rollback(manual)
```

`swap` runs `--until connectivity_ok` and expects **exit 6**. `dns` greps the
shikoonet checkout for the new address before answering the inventory prompt —
no commit, no answer, no DNS change. See `.gitlab-ci.yml`.

## After every rotation

Run `make monitoring-doctor` in the shikoonet repo. It is the only thing that
notices a node that is up but silently unmonitored — and a dashboard showing
green for a box that is not being scraped is worse than an alert.
