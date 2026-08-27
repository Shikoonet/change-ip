---
name: python-ansible-adapter
description: The pattern this project uses to drive Ansible from Python — subprocess-per-operation through a swappable runner seam, credentials never in argv, and redaction applied at the write boundary. Use when editing rotate.py, providers.py, ansible_adapter.py, when adding a new provider operation, or when deciding where a secret is allowed to appear.
---

# Driving Ansible from Python, safely

## The shape

```
rotate.py  ──▶  providers.py  ──▶  runner  ──▶  ansible-playbook hcloud_step.yml   (production)
 (state machine)  (one op per call)      └──▶  FakeHcloud                          (tests)
```

**There is no HTTP client to the provider in this project's Python.** Every
provider call is a subprocess running one Ansible play with one `-e op=<name>`.
That is not a stylistic choice — it is what keeps the credential out of Python
and lets the whole thing be tested offline for free.

`runner` is the only seam. In tests `FakeHcloud` stands exactly where
`ansible-playbook` stands, so the production adapter, the production state
machine and the production argument parsing all run unmodified.

## Rule 1 — the credential never reaches argv

The `hetzner.hcloud` modules read `HCLOUD_TOKEN` from the environment
themselves. So:

* not in `argv` (nothing in `ps`)
* not in a var file
* not in the checkpoint
* `api_token:` as a task parameter is **banned** and the contract test asserts it

**The short form "the token never enters Python" is wrong**, and stating it that
way stops the reader from checking the two real exceptions:

1. Python reads it **once** to compute `sha256(token)[:12]`. That value is
   written nowhere and is not the token's own fingerprint. It exists to catch a
   stale staging token left in a shell being used to `resume` production.
2. Python opens **exactly one socket** — `tcp_probe` in `rotate.py`, to the
   node's own SSH port, to confirm the new address is live. The path to
   `api.hetzner.cloud` really is zero.

## Rule 2 — redact at the write boundary, not at the producer

`redact()` runs inside `Rotation.save()`, over the **whole checkpoint**, at the
moment it is written to disk.

Doing it per-field in each producer would mean any field added tomorrow that
carries third-party output leaks silently. The write boundary is the one place
that sees everything, so it is the only place the rule holds by construction.

Same principle for `register_secret()`: register the value once, at the top, and
every later formatting path is covered.

## Rule 3 — one operation per subprocess

Each `-e op=<name>` invocation does one thing and prints one JSON object. It
never chains. Reasons, in order of how much they cost when violated:

* A crash between two chained steps leaves a state no checkpoint describes.
* `ignore_errors:` and `failed_when: false` are banned in the play, so a module
  failure aborts, writes no JSON, and surfaces as a non-zero rc that Python can
  branch on. A green-but-failed step here is a powered-off box with an address
  nobody knows.
* `FakeHcloud` only has to model one op at a time.

## Rule 4 — human gates are values, not booleans

`--confirm-server-id` takes the **target's own numeric id**, checked against the
config before anything is contacted. `true` and `yes` are not spellings of a
specific server, so "rotate whatever is configured" has no spelling at all.

Same pattern as `make gre-remove HOST=<alias>` in the shikoonet repo.

## Rule 5 — a print-and-wait step is a real step

`ansible_adapter.inventory_step` prints the edit and blocks on `input()`.
`auto_edit_inventory: true` raises rather than being ignored, because a config
key that silently does nothing is worse than one that is missing.

In CI there is no stdin. The gate is **not** removed and `yes` is **not** piped
blindly — it moves to something the pipeline can verify: a `when: manual` button
plus a grep of the shikoonet checkout for the new address. Same guarantee,
different evidence.

**Generalise: when a human gate has to survive automation, replace the prompt
with a check the automation can fail on. Never with an assumption.**

## Testing this shape

* Drive `rotate.main(argv, runner=fake, ...)` — the **real** argument parsing
  and config loading, with only the runner substituted. Never re-implement the
  CLI in a test.
* Inject `probe`, `ip_change`, `prompt`, `out`, `sleep` as callables. They exist
  as constructor parameters for exactly this reason.
* `rotate.py --self-test` reuses `tests/fake_hcloud.py` rather than carrying its
  own fixture: two fakes of the same provider drift, and the one not run by
  `make test` is the one that rots.
* Behaviour tests cannot catch a `state: absent` added to a branch no test
  exercises. That is what `tests/contract.yml` is for — it reads the source as
  text and as YAML. **Keep both kinds.**
