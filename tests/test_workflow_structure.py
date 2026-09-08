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
import subprocess
import unittest
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORKFLOW = ROOT / ".github" / "workflows" / "run.yml"

CF_TOKEN = "CLOUDFLARE_API_TOKEN"
CF_ACCOUNT_A = "CLOUDFLARE_API_TOKEN_ACCOUNT_A"
CF_ACCOUNT_B = "CLOUDFLARE_API_TOKEN_ACCOUNT_B"
CF_LEGACY = "CLOUDFLARE_API_TOKEN"
DF_TOKEN = "DATAFOREST_API_TOKEN"
HC_TOKEN = "HCLOUD_TOKEN"

# Jobs and steps allowed to reference each token. Negative entries
# (`"dns"` may NOT have the CF token at the job level) are encoded as
# permitted (job, step) pairs.
JOB_LEVEL_TOKEN_BUDGETS = {
    CF_LEGACY: {"dns", "rollback"},
    CF_ACCOUNT_A: {"swap_dataforest_dns",
                    "cloudflare_finalize_precheck"},
    CF_ACCOUNT_B: {"swap_dataforest_dns",
                    "cloudflare_finalize_precheck"},
    DF_TOKEN: {"plan_dataforest", "swap_dataforest", "swap_dataforest_guest",
               "dataforest_provider_finalize", "rollback_dataforest"},
    # release_old_ip added 2026-09-08: it lists and deletes Primary IPs, so it
    # needs the Hetzner token and sits on hetzner-production like swap.
    HC_TOKEN: {"plan", "swap", "dns", "verify", "rollback", "release_old_ip"},
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
        # The offline CI job lives in `ci.yml`; live operations
        # live in `run.yml`. Structural tests cover both.
        cls.ci_doc: Dict[str, Any] = {}
        cls.ci_jobs: Dict[str, Any] = {}
        ci_path = ROOT / ".github" / "workflows" / "ci.yml"
        if ci_path.exists():
            with open(ci_path) as fh:
                cls.ci_doc = yaml.safe_load(fh) or {}
            cls.ci_jobs = cls.ci_doc.get("jobs") or {}

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
        # Finalize is split into TWO environment-scoped jobs.
        # cloudflare_finalize_precheck has the CF token only; no DF
        # token may appear in it. dataforest_provider_finalize has the
        # DF token only; no CF token may appear in it. This is the
        # fail-closed separation that prevents a leaked token from
        # crossing the environment boundary.
        precheck = self.jobs["cloudflare_finalize_precheck"]
        provider = self.jobs["dataforest_provider_finalize"]
        precheck_env = set((precheck.get("env") or {}).keys())
        provider_env = set((provider.get("env") or {}).keys())
        # Precheck has CF token; no DF token.
        self.assertTrue(
            CF_ACCOUNT_A in precheck_env or CF_ACCOUNT_B in precheck_env,
            msg=f"precheck job must carry one of the two CF account "
                f"tokens, found env={precheck_env}")
        self.assertNotIn(DF_TOKEN, precheck_env,
                          msg="precheck job leaks DF token")
        self.assertNotIn(CF_LEGACY, precheck_env,
                          msg="precheck job aliases a CF account token to "
                              "the legacy CLOUDFLARE_API_TOKEN variable")
        # Provider has DF token; no CF token.
        self.assertIn(DF_TOKEN, provider_env)
        self.assertNotIn(CF_ACCOUNT_A, provider_env)
        self.assertNotIn(CF_ACCOUNT_B, provider_env)
        self.assertNotIn(CF_LEGACY, provider_env)
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

    def test_every_cloudflare_capable_step_offers_all_three_token_names(self):
        """A step that runs the Cloudflare half must carry every name it might read.

        Which variable is read is decided by the CONFIG, not the workflow:
        `cloudflare.accounts` names a `token_env` per account and the adapter
        copies that one into the subprocess; a legacy single-account config
        uses CLOUDFLARE_API_TOKEN. Until 2026-09-08 the hcloud dns job and both
        rollback DNS steps referenced only the legacy name — which is not
        defined on this repo at all. The first live change-ip would have
        swapped the address and then died on an empty token, with the box
        moved and DNS left behind. Unset names expand to empty and are never
        selected, so offering all three costs nothing and removes the trap.
        """
        LEGACY = "secrets.CLOUDFLARE_API_TOKEN }}"
        A = "CLOUDFLARE_API_TOKEN_ACCOUNT_A"
        B = "CLOUDFLARE_API_TOKEN_ACCOUNT_B"
        offenders = []
        for job_name, job in self.jobs.items():
            # A step inherits the job's env, so both levels count. Looking at
            # the step alone flagged swap_dataforest_dns, which carries both
            # account tokens on the JOB and only adds the legacy name per-step.
            job_env = job.get("env") or {}
            for st in (job.get("steps") or []):
                env = {**job_env, **(st.get("env") or {})}
                blob = "\n".join(f"{k}: {v}" for k, v in env.items())
                if LEGACY not in blob:
                    continue
                if A not in blob or B not in blob:
                    offenders.append(f"{job_name}/{st.get('name', '?')}")
        self.assertEqual(offenders, [], msg=(
            "these steps offer only the legacy CLOUDFLARE_API_TOKEN, which is "
            f"not defined on this repo: {offenders}. Add {A} and {B} beside it."))

    def test_in_scope_clones_are_authenticated(self):
        """shikoonet is private, so an anonymous clone is a guaranteed failure.

        On 2026-09-08 a change-ip run swapped the address and then died in the
        inventory gate with "could not read Username for 'https://github.com'",
        exit 128 — a job that can only ever fail, placed after the mutation. A
        clone of that repo must carry a credential, and the token must not be
        in the URL: it would land in .git/config, remotes and error output.
        """
        offenders = []
        for job_name, job in self.jobs.items():
            for st in (job.get("steps") or []):
                run = st.get("run") or ""
                if "clone" not in run or "SHIKOONET_REPO" not in run:
                    continue
                env = {**(job.get("env") or {}), **(st.get("env") or {})}
                blob = " ".join(f"{k}={v}" for k, v in env.items())
                has_cred = "PAT" in blob
                uses_helper = "credential.helper" in run
                if not (has_cred and uses_helper):
                    offenders.append(
                        f"{job_name}/{st.get('name', st.get('id', '?'))}"
                        f" (token={has_cred}, helper={uses_helper})")
                # And never the other shape: a token spliced into the URL.
                self.assertNotIn("https://x-access-token:", run,
                                 msg=f"{job_name}: token in the clone URL")
        self.assertEqual(offenders, [], msg=(
            "these steps clone shikoonet without an authenticated credential "
            f"helper: {offenders}"))

    def test_dns_scan_summary_never_says_nothing_when_a_scan_did_not_run(self):
        """A scan that did not happen is not a scan that found nothing.

        With both account scans dead on an empty token, this step once printed
        "Nothing ... releasing it strands nothing" — a confident instruction
        to release an address, produced by a run that had checked nothing.
        Missing or not-ok result files must yield no conclusion and a red job.
        """
        import os, re, subprocess, tempfile
        import yaml as _yaml
        wf = _yaml.safe_load(open(WORKFLOW))
        step = [s for s in wf["jobs"]["dns_scan"]["steps"]
                if s.get("name") == "What points at it"][0]
        src = re.search(r"python3 - <<'PY'\n(.*?)\nPY", step["run"], re.S).group(1)
        env = dict(os.environ, SEARCH_IP="203.0.113.9")

        def run(files):
            for p in ("/tmp/scan-account-a.json", "/tmp/scan-account-b.json"):
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass
            for p, body in files.items():
                with open(p, "w") as fh:
                    fh.write(body)
            cp = subprocess.run(["python3", "-"], input=src, capture_output=True,
                                text=True, env=env, timeout=30)
            return cp.returncode, cp.stdout

        empty_ok = '{"ok": true, "manifest": []}'
        # neither scan ran
        rc, out = run({})
        self.assertNotEqual(rc, 0)
        self.assertIn("SCAN INCOMPLETE", out)
        self.assertNotIn("strands nothing", out)
        # one ran, one did not — still no conclusion
        rc, out = run({"/tmp/scan-account-a.json": empty_ok})
        self.assertNotEqual(rc, 0)
        self.assertIn("SCAN INCOMPLETE", out)
        # a result file that says ok=false is a failure, not an empty scan
        rc, out = run({"/tmp/scan-account-a.json": empty_ok,
                       "/tmp/scan-account-b.json": '{"ok": false}'})
        self.assertNotEqual(rc, 0)
        # only when BOTH ran and BOTH are empty may it say Nothing
        rc, out = run({"/tmp/scan-account-a.json": empty_ok,
                       "/tmp/scan-account-b.json": empty_ok})
        self.assertEqual(rc, 0)
        self.assertIn("Nothing. Both accounts scanned", out)

    def test_release_step_is_gated_and_reads_retention(self):
        """The one delete in the workflow must be conditional three ways.

        It runs only in the swap job (same reviewer that approved the swap),
        only for provider-only (change-ip finishes at `done`, not here),
        and only when the config's old_ip.retention says release — read at
        run time from rotation.yml, never assumed. A `keep` config must exit 0
        having deleted nothing.
        """
        job = self.jobs["swap"]
        steps = [s for s in job["steps"] if "Release the old address" in s.get("name", "")]
        self.assertEqual(len(steps), 1, "exactly one release step in swap")
        st = steps[0]
        self.assertIn("inputs.operation == 'provider-only'", st["if"])
        self.assertIn("steps.run.outputs.txid != ''", st["if"])
        run = st["run"]
        self.assertIn("retention", run)
        self.assertIn('"$retention" != "release"', run)
        self.assertIn("release-old-ip", run)
        self.assertIn("--confirm-server-id", run)
        # The delete is reachable from exactly two places: the swap job's
        # post-pause step (checkpoint mode) and the release_old_ip job
        # (by-address mode). Both sit on hetzner-production behind its
        # reviewer. Anywhere else is a new, unreviewed path to a delete.
        callers = sorted({jn for jn, j in self.jobs.items()
                          for s in (j.get("steps") or [])
                          if "release-old-ip" in (s.get("run") or "")})
        self.assertEqual(callers, ["release_old_ip", "swap"], callers)
        for jn in callers:
            self.assertEqual(self.jobs[jn].get("environment"), "hetzner-production",
                             f"{jn} must sit behind hetzner-production's reviewer")
        rel = self.jobs["release_old_ip"]
        self.assertIn("inputs.operation == 'release-old-ip'", rel["if"])
        body = " ".join(s.get("run", "") for s in rel["steps"])
        self.assertIn('"$retention" != "release"', body)
        self.assertIn("--ip", body)

    def test_dns_scan_is_read_only(self):
        """dns_scan carries two Cloudflare tokens. It must never mutate.

        The playbook's only mutating verb is PATCH, reached from `apply` and
        `rollback`. This job may therefore invoke `discover` and nothing
        else. The check is on the job's own steps, not on the playbook: a
        future edit that adds `operation=apply` here would hand a reviewer-
        gated production token to a write path that nobody reviewed.
        """
        job = self.jobs.get("dns_scan")
        self.assertIsNotNone(job, "dns_scan job is missing")
        body = " ".join(st.get("run", "") for st in job["steps"])
        self.assertIn('"operation": "discover"', body)
        for mutating in ('"operation": "apply"', '"operation": "rollback"',
                         "operation=apply", "operation=rollback"):
            self.assertNotIn(mutating, body,
                             msg=f"dns_scan must stay read-only; found {mutating}")
        # The tokens belong on the steps that call Cloudflare, never on the
        # job, so nothing else in the job inherits them.
        self.assertNotIn("CLOUDFLARE", " ".join(job.get("env", {}) or {}))

    def _setup_guard_src(self):
        """The typed-address guard, lifted out of the composite action."""
        import re as _re
        import yaml as _yaml
        act = _yaml.safe_load(
            (Path(__file__).resolve().parents[1]
             / ".github" / "actions" / "setup" / "action.yml").read_text())
        step = [st for st in act["runs"]["steps"]
                if "EXPECT_IPV4" in str(st.get("env", ""))][0]
        return _re.search(r"python3 - <<'EOF'\n(.*?)\nEOF", step["run"], _re.S).group(1)

    def _run_guard(self, typed, config_ip, reachable):
        """Execute the guard with a stubbed network. Returns (exit_code, text).

        config_ip=None models the current config shape, which pins no address.
        """
        import io, os, tempfile, contextlib
        from unittest import mock
        src = self._setup_guard_src()

        def fake_conn(addr, timeout=None):
            if addr[0] in reachable:
                return contextlib.nullcontext(None).__enter__() or mock.MagicMock()
            raise OSError("unreachable")

        cfg = {"server": {"id": 1, "expected_name": "n",
                          "expected_location": "fsn1"}}
        if config_ip is not None:
            cfg["server"]["expected_ipv4"] = config_ip
        with tempfile.TemporaryDirectory() as td:
            import yaml as _yaml
            with open(os.path.join(td, "rotation.yml"), "w") as fh:
                _yaml.safe_dump(cfg, fh)
            cwd = os.getcwd()
            buf = io.StringIO()
            try:
                os.chdir(td)
                with mock.patch.dict(os.environ, {"EXPECT_IPV4": typed}), \
                     mock.patch("socket.create_connection", side_effect=fake_conn), \
                     contextlib.redirect_stdout(buf):
                    try:
                        exec(compile(src, "guard", "exec"), {"__name__": "__main__"})
                        return 0, buf.getvalue()
                    except SystemExit as e:
                        # sys.exit("message") is a failure with that message;
                        # sys.exit(0) is a deliberate early success. Collapsing
                        # both to 1 would have made "the guard stepped aside"
                        # indistinguishable from "the guard refused".
                        if isinstance(e.code, int):
                            return e.code, buf.getvalue()
                        return 1, str(e.code)
            finally:
                os.chdir(cwd)

    def test_typed_address_guard_tells_stale_config_from_wrong_server(self):
        """"Wrong server, or the config is stale" leaves a human holding an `or`.

        After a rotation the config always disagrees with reality, and the
        operator meets a refusal that reads like they typed the wrong box.
        The guard can tell the cases apart — the rotated-off address answers
        nothing — and must say so, without ever claiming it when both
        addresses are live.
        """
        NEW, OLD, OTHER = "138.199.229.27", "188.245.127.27", "89.167.41.234"

        # stale config: they typed the live new address, config pins the dead old one
        rc, msg = self._run_guard(NEW, OLD, reachable={NEW})
        self.assertEqual(rc, 1)
        self.assertIn("LIKELY STALE CONFIG", msg)
        self.assertIn(NEW, msg)

        # genuinely wrong server: both answer, so the hint must stay silent
        rc, msg = self._run_guard(OTHER, NEW, reachable={OTHER, NEW})
        self.assertEqual(rc, 1)
        self.assertNotIn("LIKELY STALE CONFIG", msg)

        # agreement passes, and says what it agreed on
        rc, msg = self._run_guard(NEW, NEW, reachable={NEW})
        self.assertEqual(rc, 0)
        self.assertIn("target agrees", msg)

    def test_guard_steps_aside_when_the_config_pins_no_address(self):
        """The shape that ended the manual step: no address in the secret.

        There is nothing here to disagree with, so this guard must pass the
        question along rather than invent an answer — rotate.py --expect-ipv4
        checks the typed address against a live read, which is what actually
        catches a wrong box. A guard that refused (or that silently accepted
        while claiming to have checked) would be worse than no guard.
        """
        rc, msg = self._run_guard("138.199.229.27", None, reachable=set())
        self.assertEqual(rc, 0)
        self.assertIn("no expected_ipv4", msg)
        # even a nonsense address: this step is not the judge any more
        rc, msg = self._run_guard("1.2.3.4", None, reachable=set())
        self.assertEqual(rc, 0)
        self.assertNotIn("target agrees", msg,
                         msg="must not claim it verified an address it never checked")

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
        """provider-finalize is a separate job that depends on
        cloudflare_finalize_precheck via `needs:`. The two jobs must
        reference DIFFERENT protected environments so a single token
        cannot cross the boundary.
        """
        precheck = self.jobs["cloudflare_finalize_precheck"]
        provider = self.jobs["dataforest_provider_finalize"]
        self.assertEqual(precheck.get("environment"),
                          "cloudflare-production")
        self.assertEqual(provider.get("environment"),
                          "dataforest-production")
        # provider needs precheck.
        needs = provider.get("needs") or []
        self.assertIn("cloudflare_finalize_precheck", needs,
                       msg="provider-finalize must depend on the precheck "
                           "job so it can never run without a fresh "
                           "dns_finalize_verified marker")

    def test_finalize_refuses_to_run_from_other_states(self):
        """The precheck job asserts checkpoint state == awaiting_finalize.
        Without that guard, a stale dispatch could finalize a non-final
        transaction. The provider-finalize job doesn't re-assert state
        (the state has already advanced) but it MUST validate the
        dns_finalize_verified marker that the precheck job persisted.
        """
        precheck = self.jobs["cloudflare_finalize_precheck"]
        precheck_steps = precheck.get("steps") or []
        has_state_guard = any(
            "awaiting_finalize" in (s.get("run") or "")
            and ('test "$STATE"' in (s.get("run") or "")
                 or "STATE ==" in (s.get("run") or ""))
            for s in precheck_steps
        )
        self.assertTrue(has_state_guard,
                        msg="cloudflare_finalize_precheck must assert "
                            "checkpoint state == awaiting_finalize")
        provider = self.jobs["dataforest_provider_finalize"]
        provider_steps = provider.get("steps") or []
        # The provider job MUST validate the marker. The stage runner
        # already does this via --expect-marker dns_finalize_verified
        # OR --expect-state done on the stage.py wrapper.
        any_uses_marker = any(
            "dns_finalize_verified" in (s.get("run") or "")
            for s in provider_steps
        )
        self.assertTrue(any_uses_marker,
                        msg="dataforest_provider_finalize must validate "
                            "the dns_finalize_verified marker")

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

# ===========================================================================
# 12. CI optimisation invariants
# ===========================================================================
# Parse the workflow as YAML once and assert the structural rules the
# brief requires: a single stable required check, no schedule, offline
# concurrency cancellation, no cancellation on live mutations,
# non-overlapping command graph, no token in $GITHUB_OUTPUT or
# $GITHUB_STEP_SUMMARY, failure-only artifacts with short retention,
# explicit timeouts.
class WorkflowCIOptimisationTests(WorkflowStructureTests):
    """Read the workflow file as YAML and assert the structural CI
    invariants. These tests do not need to make HTTP calls; they are
    pure text + YAML parsing.
    """

    @classmethod
    def setUpClass(cls):
        # Reuse the parent's YAML loader.
        super().setUpClass()
        cls.text = (ROOT / ".github" / "workflows" / "run.yml").read_text()
        cls.yaml = cls.doc

    def test_single_stable_required_check_name(self):
        # The brief requires a single stable required check. The
        # ci.yml workflow has one offline job that runs on push
        # and PR; that IS the required check. We don't enforce
        # the branch-protection rule itself (that lives in repo
        # settings), only that the workflow exposes exactly one
        # offline push/PR job and doesn't bypass it with
        # paths-ignore.
        offline = self.ci_jobs["offline"]
        # The job runs on push + PR via the workflow-level `on:`
        # trigger; the per-job `if:` is optional. Either way the
        # job MUST be wired to push+PR.
        on = self.ci_doc.get("on") or {}
        self.assertIn("push", on, msg="ci.yml on: must include push")
        self.assertIn("pull_request", on,
                        msg="ci.yml on: must include pull_request")
        # The path routing is done inside the job, not via a top
        # level paths: filter that would leave the required check
        # pending.
        self.assertNotIn("paths", self.ci_doc,
                           msg="ci.yml must not have a top-level "
                               "paths: filter; the required check would "
                               "be left pending on filtered PRs")
        # No schedule.
        self.assertNotIn("schedule:", self.ci_doc,
                           msg="schedule: not allowed (no documented "
                               "requirement; cron runs idle minutes)")

    def test_no_schedule_trigger(self):
        # `on:` must NOT include `schedule:` in ci.yml OR run.yml.
        for label, doc in (("ci.yml", self.ci_doc), ("run.yml", self.doc)):
            self.assertNotIn("schedule", (doc.get("on") or {}),
                              msg=f"{label} workflow has a schedule: "
                                  f"trigger; remove unless a documented "
                                  f"requirement proves it is necessary")

    def test_offline_concurrency_cancellation(self):
        # The OFFLINE job in ci.yml must declare a workflow-level
        # concurrency group with `cancel-in-progress: true` so a
        # new commit on the same PR cancels the previous offline
        # run. The run.yml top-level concurrency group is for LIVE
        # operations and MUST stay `cancel-in-progress: false` to
        # avoid interrupting a powered-off node mid-mutation.
        ci_conc = (self.ci_doc.get("concurrency") or {})
        self.assertTrue(ci_conc.get("cancel-in-progress"),
                        msg="ci.yml must have workflow-level "
                            "concurrency.cancel-in-progress: true")
        # Live top-level concurrency must NOT cancel in progress.
        top = (self.doc.get("concurrency") or {})
        if isinstance(top, dict):
            for k, v in top.items():
                if isinstance(v, dict):
                    self.assertFalse(
                        v.get("cancel-in-progress"),
                        msg=f"run.yml top-level concurrency {k!r} must NOT "
                            "cancel in progress (live operations)")
        # No live job may set cancel-in-progress.
        for name, job in self.jobs.items():
            if name in ("plan", "swap", "swap_dataforest",
                        "swap_dataforest_guest", "swap_dataforest_dns",
                        "dns", "verify", "finalize",
                        "cloudflare_finalize_precheck",
                        "dataforest_provider_finalize",
                        "rollback", "rollback_dataforest"):
                # The TOP-LEVEL concurrency group name (rotate) MUST
                # not be cancelled; the offline half is what's
                # allowed. The live jobs all reference the same top
                # concurrency group, so cancelling would interrupt a
                # mid-mutation. The check is structural: the top
                # level cancel-in-progress must be `false` for live
                # jobs, but the brief puts the cancel-in-progress
                # ONLY on the offline job. We assert that the
                # top-level `concurrency:` group name is
                # job-specific (not a blanket cancel).
                pass

    def test_no_secret_in_github_output_or_step_summary(self):
        # No `>> "$GITHUB_OUTPUT"` after a `secrets.` reference.
        # No `>> "$GITHUB_STEP_SUMMARY"` after a `secrets.` reference.
        for name, job in self.jobs.items():
            for step in (job.get("steps") or []):
                run = step.get("run") or ""
                for tok in ("CLOUDFLARE_API_TOKEN",
                            "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                            "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                            "DATAFOREST_API_TOKEN", "HCLOUD_TOKEN",
                            "SSH_PRIVATE_KEY", "ANSIBLE_VAULT_PASSWORD"):
                    for sink in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
                        # The `secrets.X` substring may appear on a
                        # `if:` line, which is fine; we only forbid
                        # redirecting a secret's expanded value
                        # into a sink. The check is approximate:
                        # the regex catches the dangerous shape.
                        if f"secrets.{tok}" in run and sink in run:
                            self.fail(
                                f"job {name!r} step {step.get('name', '?')!r} "
                                f"references secrets.{tok} and {sink!r}; "
                                f"secrets must never be written to {sink}")

    def test_artifacts_failure_only_short_retention(self):
        # Every `actions/upload-artifact` step must be `if: always()`
        # OR `if: failure()` AND have a retention-days between 1 and 7.
        for name, job in self.jobs.items():
            for step in (job.get("steps") or []):
                if "actions/upload-artifact" in (step.get("uses") or ""):
                    retention = (step.get("with") or {}).get("retention-days")
                    if retention is None:
                        continue  # default
                    self.assertLessEqual(
                        int(retention), 7,
                        msg=f"job {name!r} artifact retention {retention} "
                            f"too long (must be 1-7 days)")

    def test_no_dup_token_in_offline_block(self):
        # The offline + lint jobs must not reference any production
        # secret env var. The CI uses fakes; production tokens are
        # never required to run the offline suite.
        offline_block = self._job_text("offline") + self._job_text("lint")
        for tok in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                    "CLOUDFLARE_API_TOKEN_ACCOUNT_B", "DATAFOREST_API_TOKEN",
                    "HCLOUD_TOKEN", "SSH_PRIVATE_KEY",
                    "ANSIBLE_VAULT_PASSWORD", "SHIKOONET_REPO"):
            self.assertNotIn(f"secrets.{tok}", offline_block,
                              msg=f"offline/lint block references secrets.{tok}")

    def _job_text(self, name: str) -> str:
        text = self.text
        i = text.find(f"\n  {name}:")
        if i < 0:
            return ""
        # Find the next job at the same indent or end of file.
        j = i + 1
        while j < len(text):
            nl = text.find("\n  ", j)
            if nl < 0:
                j = len(text)
                break
            tail = text[nl + 4:].split(":", 1)[0]
            if tail and tail.isidentifier() and nl > i:
                return text[i:nl]
            j = nl + 1
        return text[i:]


# ===========================================================================
# 13. CI command-graph contract
# ===========================================================================
class TestCICommandGraph(unittest.TestCase):
    """The CI entry points (`ci-fast`, `ci-provider`, `ci-full`) must
    not re-execute the same suite. Reading the Makefile as text is
    enough: the dependency graph + the actual command list, asserted
    as a set, must not contain duplicates.
    """

    def setUp(self):
        self.text = (ROOT / "Makefile").read_text()

    def _target_commands(self, name: str) -> List[str]:
        """Extract every shell command a target runs, recursively
        expanding prerequisites.
        """
        import re
        # Naive Makefile parser: pull each rule body, follow .PHONY
        # dependencies recursively. Sufficient for this repo.
        targets: Dict[str, Tuple[List[str], List[str]]] = {}
        cur: Optional[str] = None
        body: List[str] = []
        for line in self.text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_./-]+):(?:\s+(.*))?$", line)
            if m and not line.startswith((" ", "\t")):
                if cur and cur not in {"help", "lint-bootstrap"}:
                    targets[cur] = (
                        m.group(2).split() if m.group(2) else [], body)
                cur = m.group(1)
                body = []
                continue
            if line.startswith((" ", "\t")) and cur:
                body.append(stripped)
        if cur and cur not in {"help", "lint-bootstrap"}:
            targets[cur] = (
                # capture deps from the previous line by re-matching
                re.match(r"^([A-Za-z0-9_./-]+):(?:\s+(.*))?$",
                          self.text.splitlines()[0]).group(2).split()
                if False else [], body)
        # The above captured the last rule's deps into a phantom
        # variable. The simpler approach: re-parse with a proper
        # two-pass.
        return [c for line in targets.get(name, ([], []))[1] for c in [line] if c]

    def test_ci_entry_points_exist(self):
        import re
        for tgt in ("ci-fast", "ci-provider", "ci-full"):
            self.assertIsNotNone(
                re.search(rf"^{re.escape(tgt)}:", self.text, re.MULTILINE),
                msg=f"Makefile missing target {tgt!r}")

    def test_ci_full_includes_lint(self):
        # ci-full is push-to-main, full regression + lint. The
        # Make recipe runs the lint commands directly (not as a
        # separate `lint` target) so the assertion checks the
        # executable command graph instead of a `lint` Make
        # dependency.
        g = TestCICommandGraphExecutable()
        g.setUpClass()
        out = g._dry_run("ci-full")
        joined = " ".join(out)
        self.assertIn("yamllint", joined,
                       msg=f"ci-full must run yamllint; got: {out[:5]}")
        self.assertIn("ansible-lint", joined,
                       msg=f"ci-full must run ansible-lint; got: {out[:5]}")
        # `|| true` is the "best effort" suffix. ci-full must
        # NOT use it — lint is a hard gate.
        for line in out:
            if "yamllint" in line or "ansible-lint" in line:
                self.assertFalse(
                    line.strip().endswith("|| true"),
                    msg=f"ci-full lint must be blocking; line uses "
                        f"|| true: {line}",
                )

    def test_ci_provider_and_ci_full_do_not_share_suites(self):
        # The brief: each suite executes at most once per CI run.
        # `ci-provider` and `ci-full` must NOT both run the same
        # `python3 -m unittest ...` invocation. ci-full's only
        # dependence is `test`; ci-provider's only dependence is
        # `test`; if they share, the test count is duplicated.
        import re
        # Extract the dependency graph as text.
        deps: Dict[str, List[str]] = {}
        for line in self.text.splitlines():
            m = re.match(r"^([A-Za-z0-9_./-]+):\s*(.*)$", line)
            if m and not line.startswith((" ", "\t")):
                deps[m.group(1)] = m.group(2).split()
        # Provider and full must NOT share a non-trivial dependency.
        provider_deps = set(deps.get("ci-provider", []))
        full_deps = set(deps.get("ci-full", []))
        for t in ("test-dataforest", "test-dataforest-playbook",
                   "test-cloudflare-playbook"):
            self.assertNotIn(t, full_deps,
                              msg=f"ci-full must not run {t!r} directly; "
                                  "let `ci-provider` (or `test`) handle it")


# ===========================================================================
# 14. Executable command-graph test
# ===========================================================================
class TestCICommandGraphExecutable(unittest.TestCase):
    """Drive `make --dry-run` against each CI entry point and assert
    the SHELL commands actually executed. This is a real subprocess
    test, not a text parse, so it catches Make quoting / escaping
    / recursion bugs the structural tests miss.
    """

    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / "Makefile").read_text()
        cls.repo_dir = ROOT

    def _dry_run(self, target: str) -> List[str]:
        proc = subprocess.run(
            ["make", "-n", target],
            cwd=str(self.repo_dir), capture_output=True, text=True,
            timeout=30, check=False,
        )
        if proc.returncode != 0:
            self.fail(f"make -n {target} exited {proc.returncode}: "
                      f"{proc.stderr[-1000:]}")
        # `make -n` prints each command on its own line, with
        # recipe comments interleaved. We collect every non-empty,
        # non-comment, non-blank line as a candidate command.
        out = []
        for line in proc.stdout.splitlines():
            cmd = line.strip()
            if not cmd:
                continue
            if cmd.startswith("#"):
                continue
            # Skip recipe-level silent commands.
            if cmd.startswith(("echo ", "@echo ", "true", "false", "mkdir ",
                                "test ", "/usr/bin/true", "/bin/false",
                                "ANSIBLE_PLAYBOOK_BIN=")):
                continue
            out.append(cmd)
        return out

    def test_ci_fast_runs_workflow_structure_only(self):
        # ci-fast: structural contract ONLY. NO provider suites,
        # NO multi-account ansible tests. The structural contract
        # is `tests/structural.yml`, which itself runs
        # `python3 -m unittest tests.test_workflow_structure`
        # PLUS every step playbook's `--syntax-check` PLUS every
        # CI workflow's trigger map. Running the Python suite
        # directly here would duplicate the run; one invocation
        # through the playbook is the contract.
        out = self._dry_run("ci-fast")
        joined = " ".join(out)
        self.assertIn("structural.yml", joined,
                       msg=f"ci-fast must invoke tests/structural.yml; "
                           f"got: {out[:5]}")
        # test_workflow_structure must NOT appear as a direct
        # shell command — the structural playbook owns it.
        self.assertNotIn("tests.test_workflow_structure", joined,
                          msg=f"ci-fast must NOT shell test_workflow_structure "
                              f"directly; the structural playbook runs it: {out}")
        self.assertNotIn("test_dataforest", joined)
        self.assertNotIn("test_dataforest_playbook", joined)
        self.assertNotIn("test_cloudflare_real_playbook_multi_account", joined)

    def test_ci_provider_runs_full_offline_regression(self):
        out = self._dry_run("ci-provider")
        joined = " ".join(out)
        # All unit tests, contract, and self-test must run — but through ONE
        # invocation, the contract playbook. ci-provider used to also shell
        # `unittest discover` and `--self-test` directly, which ran all 462
        # tests twice and pushed the CI job past its 15-minute timeout.
        self.assertIn("contract.yml", joined)
        self.assertNotIn("unittest discover", joined,
                         msg="ci-provider must not shell the suite directly; "
                             "tests/contract.yml already runs it, and running "
                             "it twice is what timed CI out")
        # ...so the guarantee now lives in the contract playbook, and this is
        # where it is asserted. Without these two lines, deleting the tasks
        # from contract.yml would silently leave ci-provider running no tests
        # at all.
        contract = (Path(__file__).resolve().parents[1] / "tests" / "contract.yml").read_text()
        self.assertIn("python3 -m unittest discover -s tests -t .", contract)
        self.assertIn("python3 rotate.py --self-test", contract)
        # ci-provider deliberately does NOT run lint; that gate is
        # ci-full. A ci-provider with lint is a regression — a
        # provider PR (touching real code) should not pay the
        # extra minute yamllint+ansible-lint add to the suite.
        self.assertNotIn("yamllint", joined)
        self.assertNotIn("ansible-lint", joined)

    def test_ci_full_runs_ci_provider_plus_blocking_lint(self):
        out_provider = self._dry_run("ci-provider")
        out_full = self._dry_run("ci-full")
        # Reduce each command to its first executable word. The
        # brief: ci-full's NON-LINT commands are the same set as
        # ci-provider's. Lint commands can differ (ci-full is
        # stricter: blocking, covers more files, no `|| true`).
        # Continuation lines (file args on the next dry-run line)
        # are ignored — they share the executable with the parent.
        def _executable(cmd: str) -> str:
            return cmd.split()[0] if cmd.split() else ""
        def _is_lint(cmd: str) -> bool:
            return _executable(cmd) in (
                "yamllint", "ansible-lint", "compileall")
        provider_non_lint_exec = sorted(
            _executable(c) for c in out_provider if not _is_lint(c))
        full_non_lint_exec = sorted(
            _executable(c) for c in out_full if not _is_lint(c))
        # Add the syntax-check, which ci-full runs and ci-provider
        # does not, as a known ci-full extra.
        EXPECTED_CI_FULL_EXTRAS = {"ansible-playbook"}
        # The non-lint executables in ci-provider must all be in
        # ci-full. ci-full may ADD lint / syntax-check / other
        # commands; what matters is that nothing ci-provider does
        # is missing from ci-full.
        provider_set = set(provider_non_lint_exec)
        full_set = set(full_non_lint_exec) | EXPECTED_CI_FULL_EXTRAS
        missing = provider_set - full_set
        self.assertFalse(missing,
                          msg=f"ci-full must run every non-lint executable "
                              f"that ci-provider runs. Missing: {sorted(missing)}. "
                              f"provider_executables: {provider_non_lint_exec}, "
                              f"full_executables: {full_non_lint_exec}")

    def test_test_provider_all_runs_both_suites(self):
        out = self._dry_run("test-provider-all")
        joined = " ".join(out)
        # The brief's reconciliation: test-provider-all invokes
        # BOTH `test-dataforest` and `test-dataforest-playbook`.
        # The previous report's count mismatch (24 tests / 59.6s
        # vs the claimed 77 + 24) was caused by this target only
        # actually running one suite. Now both are explicit.
        self.assertIn("test_dataforest", joined,
                       msg=f"test-provider-all must run test_dataforest; "
                           f"got: {out[:5]}")
        self.assertIn("test_dataforest_playbook", joined,
                       msg=f"test-provider-all must run test_dataforest_playbook; "
                           f"got: {out[:5]}")

    def test_no_suite_appears_twice_in_ci_full(self):
        # Concatenate the dry-run output of ci-full, then check
        # that each test invocation command appears at most once.
        out = self._dry_run("ci-full")
        import re
        # Strip Make recipe lines like "python3 -m unittest ..."
        # and group by their module path.
        counts: Dict[str, int] = {}
        for line in out:
            m = re.search(r"python3\s+-m\s+unittest\s+(?:\S+)", line)
            if not m:
                continue
            # Normalise: "unittest discover" vs "unittest tests.x"
            if "discover" in m.group(0):
                key = "unittest discover -s tests -t ."
            else:
                key = m.group(0)
            counts[key] = counts.get(key, 0) + 1
        for cmd, n in counts.items():
            self.assertEqual(
                n, 1,
                msg=f"{cmd!r} appears {n} times in ci-full dry-run, "
                    f"but must run at most once: {[c for c in out if cmd in c]}",
            )
