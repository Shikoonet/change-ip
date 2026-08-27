---
name: hetzner-cloud
description: Traps in the hetzner.hcloud Ansible collection and in Hetzner Cloud's Primary IP model. Use whenever touching hcloud_step.yml, writing any hetzner.hcloud task, reasoning about Primary IPv4 attach/detach ordering, or answering "why did that module report ok and change nothing". Also covers why --check proves nothing here.
---

# hetzner.hcloud — what the docs do not say

Every item below was verified 2026-08-26 by **reading the installed source**, not
from memory. Re-read it before trusting any of this:

```bash
find ~/.ansible/collections /usr/lib/python3/dist-packages/ansible_collections \
     -path '*hetzner/hcloud*' -name '*.py' | head
```

Each trap is a **green run that did the wrong thing**. That is the failure mode
of this collection: it does not error, it reports `ok`.

## 1. `primary_ip` cannot assign or unassign an existing address

`primary_ip.py:242` — `_update_primary_ip()` only ever touches `auto_delete`,
`labels`, `delete_protection`. Its `server:` parameter is read on the **create**
path only.

Pointing `primary_ip` at an existing address with a `server:` is a **silent
green no-op**. Assign and unassign both go through the `server` module's `ipv4:`
parameter instead.

`primary_ip` is good for exactly two things: allocate, and `auto_delete: false`.

## 2. `enable_ipv4: false` alone unassigns nothing

`server.py:607` — `_update_server_ip()` is only called when
`params.get("ipv4") is not None`.

So the obvious spelling of "take the address away" changes nothing and reports
`ok`. Unassign needs **both**:

```yaml
- hetzner.hcloud.server:
    id: "{{ server_id }}"
    ipv4: "{{ old_ip_id }}"     # which address to detach
    enable_ipv4: false          # and do not put a new one back
    state: present
    force: true
```

## 3. Every `server` task is `state`-only or names `ipv4:` explicitly

`server.py:421` — on the create path an omitted `ipv4` with the default
`enable_ipv4: true` allocates a **brand-new Primary IP**, billed monthly, that
nobody planned.

The rule is what makes #2 work. `tests/contract.yml` enforces it by parsing the
playbook **as YAML**, not by grepping — the bug here is an *omission*, and no
regex can see one.

## 4. `force: true` and `server_type:` must never meet in one task

`force` means "power the box off to apply this". Next to `server_type` it also
authorises an **irreversible disk resize**. `server_type:` appears nowhere in
this project and the contract test keeps it that way.

## Two shapes that cost time

* **`server_info` returns `ipv4_address` (a string) and no Primary IP id.** The
  id has to be correlated from `primary_ip_info` by `assignee_id`. That is why
  `read_server` makes two calls instead of one.
* **`primary_ip_info` calls the datacenter field `home_location`; `primary_ip`
  calls the same value `datacenter`.** Accept either.

## ⚠ `--check` proves nothing here

**The hcloud modules create no real actions in check mode.** A completely green
`--check` does not validate the stop → detach → attach → start ordering at all —
the only thing that actually matters in a rotation.

Anything validated only by `--check` is **untested**, in those words. Say so.

## ⚠ Hetzner guarantees the datacenter, never the prefix

A new Primary IP comes from the same location. It does **not** come from the
same `/24`, and **there is no API parameter to ask for one**.

If an exact prefix ever becomes a hard requirement — something upstream pinned
the old range, a peer has a route for it — this is not deliverable. Escalate;
do not allocate in a loop until something adjacent falls out.

## The token

The modules read `HCLOUD_TOKEN` from the environment themselves. Never pass
`api_token:` as a parameter — that puts it in a var file or in argv (`ps`).

Masking a GitLab CI variable is **not a boundary**: anyone who can run a job in
that project can read it. Protect the variable and protect the branch.
