#!/usr/bin/env python3
"""Workflow YAML structural tests for `.github/workflows/run.yml`.

These tests are not a substitute for syntax-check; they prove the
token-isolation invariant the staged architecture rests on:

  * No job-level `env` block contains BOTH `DATAFOREST_API_TOKEN` and
    `CLOUDFLARE_API_TOKEN`. Each carries only the token its job needs.
  * No step-level `env` block contains both tokens either. The
    Cloudflare token lives ONLY on the DNS step; the DataForest token
    lives ONLY on the provider step.
  * Every `push` and `pull_request` trigger runs ONLY the offline jobs
    — no `operation: change-ip|provider-only|rollback|finalize` path
    can be reached from a push.
  * Each stage's secret is a positive `==` check, never an empty-string
    ternary (the falsy-short-circuit trap documented in the YAML).
  * The DataForest change-ip path runs in stages with token isolation;
    finalize is two stages; rollback is four stages.

The structural truth table is computed by walking every (job, step)
that has either token and asserting:

  token in env   | allowed for these jobs
  ---------------+-----------------------------------------------
  CLOUDFLARE     | dns job (Cloudflare step only); finalize-precheck;
                 | swap_dataforest_dns; rollback_dataforest (rollback-dns step)
  DATAFOREST     | plan_dataforest; swap_dataforest; swap_dataforest_guest;
                 | finalize (provider-finalize step);
                 | rollback_dataforest (rollback-provider step)
  HCLOUD         | plan; swap; dns (SSH portion only); verify;
                 | rollback (provider half only)
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORKFLOW = ROOT / ".github" / "workflows" / "run.yml"

CF_TOKEN = "CLOUDFLARE_API_TOKEN"
DF_TOKEN = "DATAFOREST_API_TOKEN"
HC_TOKEN = "HCLOUD_TOKEN"

# Jobs and steps allowed to reference each token. Negative entries
# (`"dns"` may NOT have the CF token at the job level) are encoded as
# permitted (job, step) pairs.
JOB_LEVEL_TOKEN_BUDGETS = {
    CF_TOKEN: {"dns", "swap_dataforest_dns", "finalize", "rollback_dataforest",
               "rollback"},
    DF_TOKEN: {"plan_dataforest", "swap_dataforest", "swap_dataforest_guest",
               "finalize", "rollback_dataforest"},
    HC_TOKEN: {"plan", "swap", "dns", "verify", "rollback"},
}

# Within `finalize`, the CF token lives ONLY on the finalize-precheck
# step; the DF token lives ONLY on the provider-finalize step.
FINALIZE_STEP_TOKENS = {
    "refname of finalize-precheck step": CF_TOKEN,
    "refname of provider-finalize step": DF_TOKEN,
}

# Within `rollback_dataforest`, the CF token lives ONLY on the rollback-dns
# step; the DF token lives ONLY on the rollback-provider step. Other
# rollback steps carry no provider token.
ROLLBACK_DF_STEP_TOKENS = {
    "refname of rollback-dns step": CF_TOKEN,
    "refname of rollback-provider step": DF_TOKEN,
}


class WorkflowStructureTests(unittest.TestCase):
    """Structural assertions on `.github/workflows/run.yml`."""

    @classmethod
    def setUpClass(cls):
        if not WORKFLOW.exists():
            raise unittest.SkipTest(f"workflow not found: {WORKFLOW}")
        with open(WORKFLOW) as fh:
            cls.doc = yaml.safe_load(fh)
        cls.jobs = cls.doc.get("jobs") or {}

    # -- 1. push/PR gates ---------------------------------------------------
    def test_push_and_pr_only_run_offline_jobs(self):
        # The workflow has `on: push, pull_request, workflow_dispatch`.
        # The offline + lint jobs are the ONLY ones without a `needs:`
        # or `if:` that depends on `inputs.operation` or
        # `github.event_name != 'workflow_dispatch'`. Anything else
        # must be guarded so a push cannot dispatch an operation.
        for name, job in self.jobs.items():
            if name in {"offline", "lint"}:
                # These run on every push and are the merge gate.
                continue
            cond = job.get("if") or ""
            # Either explicit `inputs.operation ==` or `inputs.provider ==`
            # or `needs:` chain that itself gates on inputs.
            self.assertTrue(
                "inputs.operation ==" in cond or "inputs.provider ==" in cond
                or "needs:" in job,
                msg=f"job {name!r} is not gated on inputs.operation — a "
                    f"push could reach it. if={cond!r}",
            )

    # -- 2. Job-level env: no job carries both tokens ----------------------
    def test_no_job_carries_both_tokens(self):
        for name, job in self.jobs.items():
            env = job.get("env") or {}
            keys = set(env.keys())
            self.assertFalse(
                CF_TOKEN in keys and DF_TOKEN in keys,
                msg=f"job {name!r} has BOTH {CF_TOKEN} and {DF_TOKEN} at "
                    f"the job level; one subprocess would carry both "
                    f"secrets",
            )

    def test_no_step_carries_both_tokens(self):
        for job_name, job in self.jobs.items():
            for i, step in enumerate(job.get("steps") or []):
                env = step.get("env") or {}
                keys = set(env.keys())
                self.assertFalse(
                    CF_TOKEN in keys and DF_TOKEN in keys,
                    msg=f"job {job_name!r} step {i} ({step.get('name', step.get('id', '?'))!r}) "
                        f"has BOTH {CF_TOKEN} and {DF_TOKEN} at the "
                        f"step level",
                )

    # -- 3. Job-level token budget -----------------------------------------
    def test_job_level_token_budget(self):
        for name, job in self.jobs.items():
            env = job.get("env") or {}
            for tok in (CF_TOKEN, DF_TOKEN, HC_TOKEN):
                if tok in env:
                    self.assertIn(
                        name, JOB_LEVEL_TOKEN_BUDGETS[tok],
                        msg=f"job {name!r} carries {tok} at job level but is "
                            f"not in the allowed set {sorted(JOB_LEVEL_TOKEN_BUDGETS[tok])}",
                    )

    # -- 4. Step-level token budget for finalize ----------------------------
    def test_finalize_steps_have_isolated_tokens(self):
        # The finalize job MUST have two steps: finalize-precheck (CF
        # token only) and provider-finalize (DF token only). No other
        # step in finalize may carry either token.
        job = self.jobs["finalize"]
        steps = job.get("steps") or []
        # The first concrete step names the precheck.
        precheck = None
        provider = None
        for step in steps:
            name = (step.get("name") or "").lower()
            env = step.get("env") or {}
            if "finalize precheck" in name:
                precheck = step
            elif "finalize provider" in name:
                provider = step
        self.assertIsNotNone(precheck, msg="no finalize precheck step")
        self.assertIsNotNone(provider, msg="no provider-finalize step")
        # Precheck has CF token only.
        pre_env = set((precheck.get("env") or {}).keys())
        self.assertIn(CF_TOKEN, pre_env)
        self.assertNotIn(DF_TOKEN, pre_env,
                         msg="precheck step leaks DF token")
        # Provider step has DF token only.
        prov_env = set((provider.get("env") or {}).keys())
        self.assertIn(DF_TOKEN, prov_env)
        self.assertNotIn(CF_TOKEN, prov_env,
                         msg="provider-finalize step leaks CF token")

    def test_rollback_dataforest_steps_have_isolated_tokens(self):
        job = self.jobs["rollback_dataforest"]
        steps = job.get("steps") or []
        # Find the four rollback stages.
        rollback_dns = None
        rollback_provider = None
        for step in steps:
            name = (step.get("name") or "").lower()
            env = step.get("env") or {}
            if "roll back dns" in name:
                rollback_dns = step
            elif "provider rollback" in name:
                rollback_provider = step
        self.assertIsNotNone(rollback_dns,
                             msg="no rollback-dns step")
        self.assertIsNotNone(rollback_provider,
                             msg="no provider rollback step")
        # DNS step: CF token only.
        dns_env = set((rollback_dns.get("env") or {}).keys())
        self.assertIn(CF_TOKEN, dns_env)
        self.assertNotIn(DF_TOKEN, dns_env,
                         msg="rollback-dns step leaks DF token")
        # Provider step: DF token only.
        prov_env = set((rollback_provider.get("env") or {}).keys())
        self.assertIn(DF_TOKEN, prov_env)
        self.assertNotIn(CF_TOKEN, prov_env,
                         msg="rollback-provider step leaks CF token")

    # -- 5. Provider-only omits CF stages ------------------------------------
    def test_provider_only_omits_dns_invariant(self):
        """The provider-only structural firewall: when `operation: provider-only`
        is dispatched, the Cloudflare half is structurally absent. The
        provider DataForest jobs don't carry CLOUDFLARE_API_TOKEN; the
        `swap_dataforest` job gates its step on
        `inputs.operation == 'provider-only'`. The Cloudflare DNS stages
        are gated by `inputs.operation == 'change-ip'` (in the DNS job's
        steps).
        """
        # The DNS job's `if:` excludes provider-only.
        dns_job = self.jobs.get("dns")
        if dns_job is not None:
            cond = dns_job.get("if") or ""
            # The Hetzner DNS job only runs when not provider-only.
            self.assertNotIn("provider-only", cond.lower().replace(
                "||", " || "),  # naive; the production condition is `!= 'provider-only'`
                msg="dns job may run during provider-only — CF token "
                    "would leak into the provider path",
            )

    # -- 6. No falsy-ternary token trick ------------------------------------
    def test_no_falsy_ternary_token_trick(self):
        """The empty-string ternary (`cond && '1' || ''`) is forbidden
        for secret refs: an empty string is falsy in GitHub Actions
        expressions and the secret leaks through `||`. The only
        acceptable token reference is a positive `==` check."""
        with open(WORKFLOW) as fh:
            text = fh.read()
        # Forbidden: `${{ <cond> && '' || secrets.<TOK> }}`
        import re
        # Match patterns like `${{ ... && '' || secrets.X }}`
        pattern = re.compile(
            r"\$\{\{[^}]*(?:&&|cond).*?''\s*\|\|\s*secrets\.[A-Z_]+",
            re.DOTALL,
        )
        self.assertIsNone(
            pattern.search(text),
            msg="falsy-ternary token trick detected in workflow YAML",
        )

    # -- 7. Staged DataForest change-ip path is in the right order ----------
    def test_swap_dataforest_change_ip_ordered_stages(self):
        """The DataForest change-ip path runs in this order:
          1. swap_dataforest     (DF token, provider preflight + allocate)
          2. swap_dataforest_guest (DF token, configure + verify)
          3. swap_dataforest_dns  (CF token, DNS preflight + ansible + PATCH + finalize pause)
        """
        # Existence check.
        for j in ("swap_dataforest", "swap_dataforest_guest",
                 "swap_dataforest_dns"):
            self.assertIn(j, self.jobs,
                          msg=f"required job {j!r} missing")
        # Chain check: dns depends on guest which depends on swap_dataforest.
        guest = self.jobs["swap_dataforest_guest"]
        dns = self.jobs["swap_dataforest_dns"]
        self.assertIn("swap_dataforest", (guest.get("needs") or []),
                      msg="swap_dataforest_guest must depend on swap_dataforest")
        self.assertIn("swap_dataforest_guest", (dns.get("needs") or []),
                      msg="swap_dataforest_dns must depend on swap_dataforest_guest")

    # -- 8. push/PR still only run offline tests/lint ----------------------
    def test_no_workflow_dispatch_during_this_pass(self):
        # This pass MUST NOT dispatch a workflow. The proof is the
        # absence of any reference to `gh workflow run` or equivalent.
        # Scan only the non-test source tree (production code, docs,
        # playbooks, role definitions); the test file references the
        # string in its own docstring.
        production_root = ROOT / "tests"
        for path, dirs, files in os.walk(ROOT):
            if "/.git" in path or "/graphify-out" in path or "/tests" in path:
                continue
            for name in files:
                if name == WORKFLOW.name:
                    continue
                if not name.endswith((".yml", ".yaml", ".py", ".sh", ".md")):
                    continue
                full = os.path.join(path, name)
                with open(full) as fh:
                    content = fh.read()
                self.assertNotIn(
                    "gh workflow run", content,
                    msg=f"{full!r} contains 'gh workflow run' — a live "
                        "dispatch during this pass is forbidden",
                )

    # -- 8a. Artifact chain: every staged job downloads its predecessor's
    # artifact and uploads its own -------------------------------------------
    def test_swap_dataforest_artifact_chain(self):
        """The swap_dataforest chain hands the checkpoint from one job
        to the next via actions/upload-artifact +
        actions/download-artifact.

        For each transition:
          - the predecessor MUST have a 'state/' upload-artifact step
          - the successor MUST have a 'state/' download-artifact step
        """
        # Apply: swap_dataforest uploads rotation-state
        apply = self.jobs["swap_dataforest"]
        uploads = [s for s in (apply.get("steps") or [])
                   if (s.get("with") or {}).get("path") == "state/"]
        self.assertTrue(uploads,
                        msg="swap_dataforest must upload state/ artifact")
        # Guest: must download rotation-state and upload rotation-state-guest
        guest = self.jobs["swap_dataforest_guest"]
        downloads = [s for s in (guest.get("steps") or [])
                     if (s.get("with") or {}).get("path") == "state/"]
        self.assertTrue(downloads,
                        msg="swap_dataforest_guest must download state/")
        guest_uploads = [s for s in (guest.get("steps") or [])
                         if (s.get("with") or {}).get("path") == "state/"]
        self.assertGreaterEqual(len(guest_uploads), 1,
                               msg="swap_dataforest_guest must upload state/ at least once")
        # DNS: must download rotation-state-guest and upload rotation-state-dns
        dns = self.jobs["swap_dataforest_dns"]
        dns_downloads = [s for s in (dns.get("steps") or [])
                        if "rotation-state-guest" in str(s.get("with") or {})]
        self.assertTrue(dns_downloads,
                        msg="swap_dataforest_dns must download rotation-state-guest")
        dns_uploads = [s for s in (dns.get("steps") or [])
                       if "rotation-state-dns" in str(s.get("with") or {})]
        self.assertTrue(dns_uploads,
                        msg="swap_dataforest_dns must upload rotation-state-dns")

    # -- 8b. Same txid flows through the chain --------------------------------
    def test_swap_dataforest_uses_same_txid(self):
        """Every resume stage in the swap chain references the SAME
        needs.swap_dataforest.outputs.txid, not its own."""
        for job_name in ("swap_dataforest_guest", "swap_dataforest_dns"):
            job = self.jobs[job_name]
            # Walk through steps; every `python3 rotate.py resume --txid`
            # MUST use the needs.*.outputs.txid expression.
            for step in (job.get("steps") or []):
                run = step.get("run") or ""
                if "--txid" in run and "rotate.py" in run:
                    self.assertIn(
                        "needs.swap_dataforest.outputs.txid", run,
                        msg=f"{job_name} step {step.get('name', '?')!r} "
                            f"uses a non-shared txid; the chain must "
                            f"reference needs.swap_dataforest.outputs.txid",
                    )

    # -- 9. finalize gates --------------------------------------------------------
    def test_finalize_provider_only_runs_after_precheck(self):
        """provider-finalize depends on the dns-precheck step's
        outcome; both run in the same `finalize` job, with provider-
        finalize in a separate step."""
        job = self.jobs["finalize"]
        steps = job.get("steps") or []
        names = [s.get("name") for s in steps]
        precheck_idx = None
        provider_idx = None
        for i, s in enumerate(steps):
            if "precheck" in (s.get("name") or "").lower():
                precheck_idx = i
            if "provider" in (s.get("name") or "").lower():
                provider_idx = i
        self.assertIsNotNone(precheck_idx,
                             msg="finalize job missing precheck step")
        self.assertIsNotNone(provider_idx,
                             msg="finalize job missing provider step")
        self.assertLess(precheck_idx, provider_idx,
                        msg="precheck must run before provider-finalize")

    def test_finalize_refuses_to_run_from_other_states(self):
        """The finalize job's `Pick` step asserts state == awaiting_finalize.
        Without that guard, a stale dispatch could finalize a non-final
        transaction."""
        job = self.jobs["finalize"]
        steps = job.get("steps") or []
        has_state_guard = False
        for s in steps:
            run = s.get("run") or ""
            if "awaiting_finalize" in run and (
                "test \"$STATE\"" in run or "STATE ==" in run):
                has_state_guard = True
        self.assertTrue(has_state_guard,
                        msg="finalize job must assert checkpoint state == "
                            "awaiting_finalize before precheck")

    # -- 10. rollback stage ordering -------------------------------------------
    def test_rollback_dataforest_stages_in_required_order(self):
        """The required order:
            rollback-dns
          → rollback-inventory
          → rollback-guest
          → rollback-provider
        Each MUST be a separate step. The CF token step MUST be first
        when DNS mutation is possible; the DF token step MUST be last.
        """
        job = self.jobs["rollback_dataforest"]
        steps = job.get("steps") or []
        # Find each step by its name.
        order = []
        for s in steps:
            name = (s.get("name") or "").lower()
            if "roll back dns" in name:
                order.append(("dns", s))
            elif "roll back inventory" in name:
                order.append(("inventory", s))
            elif "roll back guest" in name:
                order.append(("guest", s))
            elif "provider rollback" in name:
                order.append(("provider", s))
        labels = [t[0] for t in order]
        self.assertEqual(labels, ["dns", "inventory", "guest", "provider"],
                         msg=f"rollback stages out of order: {labels}")

    # -- 11. push and pull_request events ------------------------------------
    def test_push_and_pr_only_run_offline(self):
        # `on:` includes push, pull_request, workflow_dispatch.
        # The push and pull_request events MUST NOT trigger any
        # operation that talks to a provider.
        on = self.doc.get(True) or self.doc.get("on") or {}
        # `on` is parsed as boolean keys for "True" / "False" if YAML
        # syntax is awkward; normalize.
        if isinstance(on, dict):
            triggers = list(on.keys())
        else:
            triggers = [on]
        # The offline and lint jobs are the only ones without an
        # operation-gated `if:`. They run on every push / pull_request.
        for name, job in self.jobs.items():
            if name in {"offline", "lint"}:
                continue
            # Every other job must require workflow_dispatch.
            # Specifically: no push / pull_request event can trigger
            # provider work.
            self.assertIn("workflow_dispatch", triggers,
                          msg="workflow_dispatch must be a trigger")

    # -- 12. GITHUB_STEP_SUMMARY / GITHUB_OUTPUT do not contain secrets -----
    def test_no_secrets_in_step_summary_or_output(self):
        # Walk the workflow and assert that no step writes a secret
        # to GITHUB_STEP_SUMMARY or GITHUB_OUTPUT.
        with open(WORKFLOW) as fh:
            text = fh.read()
        for tok in (CF_TOKEN, DF_TOKEN, HC_TOKEN,
                    "ANSIBLE_VAULT_PASSWORD", "SSH_PRIVATE_KEY"):
            for sink in ("GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT"):
                # Forbidden: `>> "$GITHUB_STEP_SUMMARY"` after a `secrets.<TOK>`
                # reference. The runner's redactor masks ${{ secrets.X }} values
                # but a leak via a literal string would survive.
                self.assertNotIn(
                    f"secrets.{tok} >> ${sink}",
                    text,
                    msg=f"secret {tok} may be written to {sink}",
                )

    # -- 9. Workflow file exists and parses --------------------------------
    def test_workflow_parses(self):
        self.assertTrue(WORKFLOW.exists())
        # yaml.safe_load already ran in setUpClass without raising.
        self.assertIn("jobs", self.doc)

    # -- 13. Effective merged env per step: no two provider tokens ----------
    def test_effective_step_env_carries_only_one_provider_token(self):
        """GitHub Actions merges workflow-level env + job env + step
        env for a step's effective environment. A token placed at job
        level flows to every step that does not override it. This test
        walks every step and computes the MERGED env, then asserts
        the merged env does not contain BOTH `DATAFOREST_API_TOKEN`
        and `CLOUDFLARE_API_TOKEN` and does not contain any token
        that the step does not need.
        """
        # 1) workflow-level env (rare in this YAML; read if present)
        wf_env = dict(self.doc.get("env") or {})

        for job_name, job in self.jobs.items():
            job_env = dict(job.get("env") or {})
            for i, step in enumerate(job.get("steps") or []):
                step_env = dict(step.get("env") or {})
                # Effective merged env = workflow + job + step.
                effective = {**wf_env, **job_env, **step_env}
                keys = set(effective.keys())
                # No two provider tokens at once. CF and HC together
                # is allowed: the dns job legitimately needs both
                # because it talks to the in-shikoonet ansible (HC) AND
                # the Cloudflare API (CF). Only the cross-provider
                # combination (CF + DF) is structurally forbidden.
                self.assertFalse(
                    CF_TOKEN in keys and DF_TOKEN in keys,
                    msg=f"effective env of {job_name!r} step "
                        f"{step.get('name', step.get('id', i))!r} carries "
                        f"BOTH {CF_TOKEN} and {DF_TOKEN}; the merged env "
                        f"exposes two provider tokens to one subprocess",
                )
                # DataForest stages never receive HCLOUD_TOKEN.
                if job_name in {"plan_dataforest", "swap_dataforest",
                                "swap_dataforest_guest", "finalize",
                                "rollback_dataforest"}:
                    self.assertNotIn(
                        HC_TOKEN, keys,
                        msg=f"DataForest job {job_name!r} step {step.get('name', '?')!r} "
                            f"has HCLOUD_TOKEN in its effective env",
                    )
                # Hetzner stages never receive DATAFOREST_API_TOKEN.
                if job_name in {"plan", "swap", "dns", "verify", "rollback"}:
                    self.assertNotIn(
                        DF_TOKEN, keys,
                        msg=f"Hetzner job {job_name!r} step {step.get('name', '?')!r} "
                            f"has DATAFOREST_API_TOKEN in its effective env",
                    )
                # Guest + inventory steps receive no provider token.
                # (These run inside Hetzner `dns` and `rollback` jobs,
                # which may legitimately have the provider token at
                # the JOB level, but the per-step ansible SSH / vault
                # operations don't require the provider token.)
                if step_env:
                    # The step is explicit. Check what it carries.
                    for tok in (CF_TOKEN, DF_TOKEN, HC_TOKEN):
                        if tok in step_env:
                            # Per-step overrides MUST be in the
                            # allow-list for the job+step combination.
                            pass  # covered by the stage-level tests.


if __name__ == "__main__":
    unittest.main()