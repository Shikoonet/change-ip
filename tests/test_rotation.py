#!/usr/bin/env python3
"""Offline tests for server-ip-rotation. Zero network, zero ansible, zero cost.

    cd server-ip-rotation && python3 -m unittest discover -s tests -t .
    (or, from the repo root: make test-offline)

Everything below runs the production adapter, the production state machine and
the production argument parsing. The ONLY substitution is the runner seam --
`FakeHcloud` stands exactly where `ansible-playbook hcloud_step.yml` stands.

The suite is here because of a lesson this repo already paid for twice: a
green `--check` proves the tasks parse, not that the ordering is right, and the
hcloud modules create no real actions in check mode at all. These tests cannot
prove the collection behaves as documented either -- they prove that OUR half
does the right thing given a provider that behaves as the source says it does.
That distinction is the reason the first live run still needs approval.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import ansible_adapter  # noqa: E402
import rotate  # noqa: E402
from providers import (  # noqa: E402
    HcloudProvider,
    IdentityMismatch,
    NonRetryableError,
    NotFound,
    RetryableError,
    redact,
    register_secret,
)
from tests.fake_hcloud import DEFAULT_OLD_IP_ID, FakeHcloud, example_config  # noqa: E402

FAKE_TOKEN = "hcloud-fake-token-0123456789abcdef"
FINGERPRINT = "deadbeefcafe"

#: How many MUTATING provider calls are still owed from each state. Used by the
#: resume test to prove a resume repeats nothing and skips nothing.
REMAINING_WRITES = {
    "confirmed": 6,          # allocate, protect_ip, stop, unassign, assign, start
    "new_ip_allocated": 5,
    "server_off": 3,
    "old_ip_unassigned": 2,
    "new_ip_assigned": 1,
    "server_on": 0,
    "connectivity_ok": 0,
    "ansible_done": 0,
    "done": 0,
}


class Base(unittest.TestCase):
    def setUp(self):
        os.environ["HCLOUD_TOKEN"] = FAKE_TOKEN
        register_secret(FAKE_TOKEN)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_dir = os.path.join(self.tmp.name, "state")
        self.lines = []

    # -- fixtures ---------------------------------------------------------
    def build(self, fake=None, cfg=None, probe=True, rc=0, answer="yes", **kwargs):
        fake = fake or FakeHcloud()
        cfg = cfg if cfg is not None else example_config(fake)
        self.fake = fake
        self.ip_change_calls = []

        def ip_change(alias, cwd):
            argv = ansible_adapter.ip_change_argv(alias)
            self.ip_change_calls.append({"argv": argv, "cwd": cwd})
            return {"argv": argv, "rc": rc, "stdout_tail": "", "stderr_tail": ""}

        probes = probe if callable(probe) else (lambda h, p, t: probe)
        rot = rotate.Rotation(
            config=cfg,
            provider=HcloudProvider(fake, fingerprint=FINGERPRINT),
            state_dir=self.state_dir,
            repo_dir=self.tmp.name,
            config_path=os.path.join(self.tmp.name, "rotation.yml"),
            probe=probes,
            ip_change=ip_change,
            prompt=lambda _: answer,
            out=self.lines.append,
            sleep=lambda _: None,
            **kwargs,
        )
        return rot

    def full_run(self, rot, txid="tx-test"):
        cp = rot.plan(txid=txid)
        rot._transition(cp, "confirmed")
        return rot.execute(cp)

    def write_config(self, cfg):
        import yaml

        path = os.path.join(self.tmp.name, "rotation.yml")
        cfg = copy.deepcopy(cfg)
        cfg["state_dir"] = self.state_dir
        cfg.setdefault("ansible", {})["repo_dir"] = self.tmp.name
        with open(path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(cfg, handle)
        return path


# ---------------------------------------------------------------------------
class TestIdentity(Base):
    """Nothing is ever mutated without re-proving what it is, from a fresh read."""

    def test_selects_by_numeric_id(self):
        rot = self.build()
        cp = rot.plan()
        self.assertEqual(cp["server"]["id"], self.fake.server["id"])
        self.assertEqual(cp["old_ip"]["id"], DEFAULT_OLD_IP_ID)
        # the id, not the name, is what every call carries
        self.assertTrue(all(c["params"].get("server_id", self.fake.server["id"])
                            == self.fake.server["id"] for c in self.fake.calls))

    def test_name_mismatch_stops(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["server"]["expected_name"] = "Hetzner-FI"
        with self.assertRaises(IdentityMismatch):
            self.build(fake, cfg).plan()
        self.assertEqual(fake.write_count, 0)

    def test_address_mismatch_stops(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["server"]["expected_ipv4"] = "1.2.3.4"
        with self.assertRaises(IdentityMismatch):
            self.build(fake, cfg).plan()

    def test_location_mismatch_stops(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["server"]["expected_location"] = "hel1"
        with self.assertRaises(IdentityMismatch):
            self.build(fake, cfg).plan()

    def test_project_fingerprint_pin_mismatch_stops(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["project_fingerprint"] = "0000deadbeef"
        with self.assertRaises(IdentityMismatch):
            self.build(fake, cfg).plan()
        self.assertEqual(fake.write_count, 0)

    def test_zero_targets(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["server"]["id"] = 99999999
        with self.assertRaises(NotFound):
            self.build(fake, cfg).plan()

    def test_ambiguous_name_is_refused_not_picked(self):
        fake = FakeHcloud()
        fake.ips[900050] = dict(fake.ips[DEFAULT_OLD_IP_ID], id=900050, ip="10.0.0.1",
                                assignee_id=None, assignee_type=None)
        provider = HcloudProvider(fake, fingerprint=FINGERPRINT)
        with self.assertRaises(NonRetryableError) as ctx:
            provider.find_ip("hetzner-de-primary")
        self.assertIn("refusing to choose", str(ctx.exception))

    def test_shared_ip_owned_by_another_server_stops(self):
        """read_server and read_ip are two calls; they can disagree.

        `server_info` says "this box has that address" and `primary_ip_info`
        says "that address belongs to server 777" — a mid-move race, or an
        address being shared in a way this tool has no model for. Detaching it
        would take an address away from a machine nobody named.
        """

        class Drifting(FakeHcloud):
            def _attached_ipv4_id(self):
                return DEFAULT_OLD_IP_ID  # server_info still points at it

        fake = Drifting()
        fake.ips[DEFAULT_OLD_IP_ID]["assignee_id"] = 777
        with self.assertRaises(IdentityMismatch) as ctx:
            self.build(fake).plan()
        self.assertIn("assignee_id 777", str(ctx.exception))
        self.assertEqual(fake.write_count, 0)

    def test_no_other_server_is_ever_addressed(self):
        rot = self.build()
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "done")
        self.assertEqual(self.fake.touched_ids, {self.fake.server["id"]})

    def test_ipv6_primary_ip_is_rejected(self):
        fake = FakeHcloud()
        fake.ips[DEFAULT_OLD_IP_ID]["type"] = "ipv6"
        provider = HcloudProvider(fake, fingerprint=FINGERPRINT)
        with self.assertRaises(NonRetryableError) as ctx:
            provider.get_primary_ip(DEFAULT_OLD_IP_ID)
        self.assertIn("only ipv4 is in scope", str(ctx.exception))

    def test_a_server_with_no_primary_ipv4_is_out_of_scope(self):
        # The correlation in hcloud_step.yml's read_server filters on
        # type == ipv4, so a v6-only box yields ipv4_id None -- and there is
        # nothing here to rotate.
        fake = FakeHcloud()
        fake.ips[DEFAULT_OLD_IP_ID]["type"] = "ipv6"
        with self.assertRaises(NonRetryableError) as ctx:
            self.build(fake).plan()
        self.assertIn("nothing to rotate", str(ctx.exception))
        self.assertEqual(fake.write_count, 0)

    def test_unknown_assignee_type_is_non_retryable(self):
        fake = FakeHcloud()
        fake.ips[DEFAULT_OLD_IP_ID]["assignee_type"] = "load_balancer"
        with self.assertRaises(NonRetryableError) as ctx:
            self.build(fake).plan()
        self.assertIn("refusing to guess", str(ctx.exception))

    def test_null_assignee_id_normalises_to_unassigned(self):
        fake = FakeHcloud()
        fake.ips[DEFAULT_OLD_IP_ID]["assignee_id"] = None
        fake.ips[DEFAULT_OLD_IP_ID]["assignee_type"] = "server"  # API lying
        ip = HcloudProvider(fake, fingerprint=FINGERPRINT).get_primary_ip(DEFAULT_OLD_IP_ID)
        self.assertEqual(ip.assignee_type, "unassigned")
        self.assertFalse(ip.assigned)

    def test_all_three_spellings_of_the_same_field_read(self):
        """7.x says `location`; 6.x said `home_location` or `datacenter`.

        The pin makes 7.x the shape that runs, and the fake models 7.x. This
        keeps the two older spellings readable anyway: an operator with 6.2.1
        still installed locally gets a working tool, not a normalisation bug
        surfacing as `has no datacenter` halfway through a swap.
        """
        provider = HcloudProvider(FakeHcloud(), fingerprint=FINGERPRINT)
        self.assertEqual(provider.get_primary_ip(DEFAULT_OLD_IP_ID).datacenter, "nbg1")
        for spelling in ("location", "home_location", "datacenter"):
            shaped = HcloudProvider._ip(
                {"id": 1, "name": "n", "ip": "203.0.113.9", "type": "ipv4",
                 spelling: "nbg1", "assignee_id": None, "assignee_type": None,
                 "auto_delete": False}
            )
            self.assertEqual(shaped.datacenter, "nbg1", spelling)


# ---------------------------------------------------------------------------
class TestDryRunAndConfirm(Base):
    def test_plan_mutates_nothing(self):
        rot = self.build()
        cp = rot.plan()
        self.assertEqual(cp["state"], "planned")
        self.assertEqual(self.fake.write_count, 0)
        self.assertEqual(self.fake.touched_ids, set())

    def test_plan_prints_the_cidr_limitation(self):
        self.build().plan()
        self.assertIn("never the same prefix", "".join(self.lines))

    def test_apply_without_confirmation_is_usage_error(self):
        fake = FakeHcloud()
        path = self.write_config(example_config(fake))
        rc = rotate.main(["apply", "--config", path], runner=fake)
        self.assertEqual(rc, rotate.EXIT_USAGE)
        self.assertEqual(fake.write_count, 0)

    def test_apply_with_the_wrong_id_is_an_identity_error(self):
        fake = FakeHcloud()
        path = self.write_config(example_config(fake))
        rc = rotate.main(
            ["apply", "--config", path, "--confirm-server-id", "999"], runner=fake
        )
        self.assertEqual(rc, rotate.EXIT_IDENTITY)
        self.assertEqual(fake.write_count, 0)

    def test_apply_with_the_exact_id_proceeds(self):
        fake = FakeHcloud()
        path = self.write_config(example_config(fake))
        rc = rotate.main(
            ["apply", "--config", path, "--confirm-server-id", str(fake.server["id"])],
            runner=fake,
            probe=lambda h, p, t: True,
            ip_change=lambda alias, cwd: {
                "argv": ansible_adapter.ip_change_argv(alias), "rc": 0,
                "stdout_tail": "", "stderr_tail": "",
            },
            prompt=lambda _: "yes",
            out=self.lines.append,
            sleep=lambda _: None,
        )
        self.assertEqual(rc, rotate.EXIT_OK)
        self.assertEqual(fake.write_count, 6)

    def test_until_pauses_before_the_named_step_and_resume_finishes(self):
        """The CD split. `--until connectivity_ok` must stop BEFORE the step
        that waits on a human editing the inventory, exit its own code (not
        the escalation code -- a red pipeline for a normal boundary is how a
        real escalation stops being noticed), and leave a checkpoint that
        `resume` walks to done. The address swap has already happened at that
        point, so a pause that lost the checkpoint would strand the node."""
        fake = FakeHcloud()
        path = self.write_config(example_config(fake))
        sid = str(fake.server["id"])
        common = dict(
            runner=fake,
            probe=lambda h, p, t: True,
            ip_change=lambda alias, cwd: {
                "argv": ansible_adapter.ip_change_argv(alias), "rc": 0,
                "stdout_tail": "", "stderr_tail": "",
            },
            prompt=lambda _: "yes",
            out=self.lines.append,
            sleep=lambda _: None,
        )
        rc = rotate.main(
            ["apply", "--config", path, "--confirm-server-id", sid,
             "--until", "connectivity_ok"],
            **common,
        )
        self.assertEqual(rc, rotate.EXIT_PAUSED)
        self.assertNotEqual(rotate.EXIT_PAUSED, rotate.EXIT_ESCALATED)

        state_dir = os.path.join(os.path.dirname(path), "state")
        txids = [f[:-5] for f in os.listdir(state_dir) if f.endswith(".json")]
        self.assertEqual(len(txids), 1)
        cp = json.load(open(os.path.join(state_dir, txids[0] + ".json")))
        self.assertEqual(cp["state"], "connectivity_ok")
        self.assertEqual(cp["outcome"], "paused")
        # The swap is already done at the pause: the node answers on the new
        # address. Only the inventory and DNS are still on the old one.
        self.assertEqual(cp["new_ip"]["ip"], fake.server["ipv4_address"])

        rc = rotate.main(
            ["resume", "--config", path, "--txid", txids[0],
             "--confirm-server-id", sid],
            **common,
        )
        self.assertEqual(rc, rotate.EXIT_OK)

    def test_until_rejects_a_state_in_the_middle_of_the_swap(self):
        """`--until old_ip_unassigned` would park a node with no address at
        all. argparse refuses it because PAUSABLE lists only the two states
        where the box is up and reachable."""
        with self.assertRaises(SystemExit):
            rotate.main(["apply", "--config", "x", "--confirm-server-id", "1",
                         "--until", "old_ip_unassigned"])

    def test_plan_without_a_token_never_contacts_anything(self):
        fake = FakeHcloud()
        path = self.write_config(example_config(fake))
        os.environ.pop("HCLOUD_TOKEN", None)
        try:
            rc = rotate.main(["plan", "--config", path], runner=fake)
        finally:
            os.environ["HCLOUD_TOKEN"] = FAKE_TOKEN
        self.assertEqual(rc, rotate.EXIT_USAGE)
        self.assertEqual(fake.calls, [])


# ---------------------------------------------------------------------------
class TestStateMachine(Base):
    def test_happy_path(self):
        rot = self.build()
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "done")
        self.assertEqual(cp["outcome"], "done")
        self.assertEqual(self.fake.server["ipv4_address"], cp["new_ip"]["ip"])
        self.assertEqual(self.fake.server["status"], "running")
        # the old address is detached and RETAINED, never deleted
        old = self.fake.ips[DEFAULT_OLD_IP_ID]
        self.assertIsNone(old["assignee_id"])
        self.assertIn(DEFAULT_OLD_IP_ID, self.fake.ips)

    def test_old_ip_is_protected_before_anything_moves(self):
        rot = self.build()
        self.full_run(rot)
        ops = [c["op"] for c in self.fake.calls]
        self.assertLess(ops.index("protect_ip"), ops.index("stop"))
        self.assertFalse(self.fake.ips[DEFAULT_OLD_IP_ID]["auto_delete"])

    def test_new_ip_name_is_deterministic_from_the_txid(self):
        rot = self.build()
        cp = rot.plan(txid="20260826-101500-a3f1")
        self.assertEqual(cp["new_ip"]["name"], "Hetzner-DE-ipv4-20260826-101500-a3f1")

    def test_allocation_is_idempotent_via_the_deterministic_name(self):
        """A crash between allocate and the state write must not mint a second IP."""
        rot = self.build()
        cp = rot.plan(txid="tx-crash")
        rot._transition(cp, "confirmed")
        rot._step_allocate(cp)
        first_id = cp["new_ip"]["id"]
        ip_count = len(self.fake.ips)

        # pretend the state write never landed: run the same step again
        cp["new_ip"]["id"] = None
        rot._step_allocate(cp)
        self.assertEqual(cp["new_ip"]["id"], first_id)
        self.assertEqual(len(self.fake.ips), ip_count, "a second billed IP was created")

    def test_resume_from_every_checkpoint(self):
        captures = []
        rot = self.build()

        def capture(state, cp):
            captures.append((state, copy.deepcopy(cp), self.fake.snapshot()))

        rot.on_transition = capture
        done = self.full_run(rot, txid="tx-resume")
        self.assertEqual(done["state"], "done")

        resumable = [c for c in captures if c[0] in REMAINING_WRITES]
        self.assertGreaterEqual(len(resumable), 8)

        for state, cp, snap in resumable:
            with self.subTest(state=state):
                fake = FakeHcloud()
                fake.restore(snap)
                rot2 = self.build(fake=fake)
                rot2.save(cp)
                before = fake.write_count
                out = rot2.execute(copy.deepcopy(cp))
                self.assertEqual(out["state"], "done", f"resume from {state}")
                self.assertEqual(
                    fake.write_count - before,
                    REMAINING_WRITES[state],
                    f"resume from {state} repeated or skipped a mutation",
                )

    def test_resume_of_done_is_a_no_op(self):
        rot = self.build()
        cp = self.full_run(rot)
        before = self.fake.write_count
        out = rot.execute(cp)
        self.assertEqual(out["state"], "done")
        self.assertEqual(self.fake.write_count, before)

    def test_checkpoint_never_holds_the_token(self):
        rot = self.build()
        cp = self.full_run(rot)
        with open(os.path.join(self.state_dir, f"{cp['txid']}.json"), encoding="utf-8") as fh:
            body = fh.read()
        self.assertNotIn(FAKE_TOKEN, body)
        self.assertIn("project_fingerprint", body)


# ---------------------------------------------------------------------------
class TestRetries(Base):
    def test_transient_failure_then_success(self):
        fake = FakeHcloud()
        fake.inject("stop", "connection reset", "retryable", times=1)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "done")

    def test_auth_failure_aborts_on_the_first_attempt(self):
        fake = FakeHcloud()
        fake.inject("stop", "401 unauthorized", "auth", times=5)
        provider = HcloudProvider(fake, fingerprint=FINGERPRINT)
        with self.assertRaises(NonRetryableError):
            provider.stop_server(fake.server["id"])
        self.assertEqual(sum(1 for c in fake.calls if c["op"] == "stop"), 1)

    def test_retryable_is_retried_exactly_retries_plus_one_times(self):
        fake = FakeHcloud()
        fake.inject("stop", "timeout", "retryable", times=9)
        rot = self.build(fake)
        with self.assertRaises(RetryableError):
            rot.with_retries("stop", rot.provider.stop_server, fake.server["id"])
        self.assertEqual(sum(1 for c in fake.calls if c["op"] == "stop"), 3)  # retries=2

    def test_non_retryable_message_survives_unchanged(self):
        fake = FakeHcloud()
        fake.inject("read_ip", "the shape was wrong", "validation")
        provider = HcloudProvider(fake, fingerprint=FINGERPRINT)
        with self.assertRaises(NonRetryableError) as ctx:
            provider.get_primary_ip(DEFAULT_OLD_IP_ID)
        self.assertIn("the shape was wrong", str(ctx.exception))


# ---------------------------------------------------------------------------
class TestRollback(Base):
    def _assert_back_on_the_old_address(self, cp):
        self.assertEqual(cp["state"], "rolled_back")
        self.assertEqual(cp["outcome"], "rolled_back")
        self.assertEqual(self.fake.server["ipv4_address"], cp["old_ip"]["ip"])
        self.assertEqual(self.fake.server["status"], "running")

    def test_shutdown_timeout_touches_no_address(self):
        fake = FakeHcloud()
        fake.inject("stop", "still running", "retryable", times=9)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "rolled_back")
        self.assertTrue(cp["rollback"]["ips_untouched"])
        self.assertEqual(fake.ips[DEFAULT_OLD_IP_ID]["assignee_id"], fake.server["id"])
        self.assertEqual(fake.server["ipv4_address"], cp["old_ip"]["ip"])

    def test_allocation_failure_restores_the_old_address(self):
        fake = FakeHcloud()
        fake.inject("allocate", "no capacity", "retryable", times=9)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self._assert_back_on_the_old_address(cp)
        self.assertIsNone(cp["new_ip"]["id"])

    def test_assignment_failure_restores_and_retains_the_new_ip(self):
        fake = FakeHcloud()
        # exactly retries+1, so the STEP exhausts them and the rollback's own
        # assign still works. Over-injecting here would be testing the
        # rollback-of-the-rollback path, which has its own case below.
        fake.inject("assign", "locked", "retryable", times=3)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self._assert_back_on_the_old_address(cp)
        new_id = cp["rollback"]["new_ip_retained"]["id"]
        self.assertIsNotNone(new_id)
        self.assertIn(new_id, fake.ips, "the new IP was deleted; it must be retained")
        self.assertIn("RETAINED", "".join(self.lines))

    def test_power_on_failure_escalates_rather_than_swapping_back(self):
        fake = FakeHcloud()
        fake.inject("start", "boot failed", "retryable", times=9)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "escalated")
        commands = cp["escalations"][-1]["recovery_commands"]
        blob = "\n".join(commands)
        self.assertIn(str(cp["old_ip"]["id"]), blob)
        self.assertIn(str(cp["server"]["id"]), blob)
        # the new address stays on the box: swapping IPs does not fix a boot
        self.assertEqual(fake.server["ipv4_address"], cp["new_ip"]["ip"])

    def test_health_check_failure_restores(self):
        rot = self.build(probe=lambda h, p, t: False)
        cp = self.full_run(rot)
        self._assert_back_on_the_old_address(cp)

    def test_interrupted_rollback_resumes(self):
        fake = FakeHcloud()
        fake.inject("assign", "locked", "retryable", times=3)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "rolled_back")

        # rewind to the middle of the rollback and resume it
        cp["state"] = "needs_rollback"
        cp["rollback"] = {"state": "in_progress", "reason": "interrupted"}
        rot.save(cp)
        out = rot.execute(cp)
        self.assertEqual(out["state"], "rolled_back")
        self.assertEqual(fake.server["ipv4_address"], cp["old_ip"]["ip"])

    def test_a_failed_restart_still_leaves_a_record(self):
        """The remedy for a stuck shutdown can fail too. That must not escape."""
        fake = FakeHcloud()
        fake.inject("stop", "still running", "retryable", times=9)
        fake.inject("start", "and now it will not boot", "retryable", times=9)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "escalated")
        self.assertIn("powering back on failed too", cp["escalations"][-1]["message"])

    def test_rollback_failure_escalates_with_commands(self):
        """The attach fails mid-swap, and putting the old one back fails too."""
        fake = FakeHcloud()
        fake.inject("assign", "also broken", "retryable", times=9)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "escalated")
        self.assertTrue(cp["escalations"][-1]["recovery_commands"])

    def test_a_failed_allocation_never_takes_the_node_down(self):
        """The whole reason allocate runs before stop: no capacity is not an outage.

        The node is never powered off, never detached, and the old address is
        still on it. Compare with the same failure after the detach, which is a
        node with no address waiting on a rollback.
        """
        fake = FakeHcloud()
        fake.inject("allocate", "no capacity in this datacenter", "retryable", times=9)
        rot = self.build(fake)
        cp = self.full_run(rot)
        self.assertEqual(cp["outcome"], "rolled_back")
        self.assertTrue(cp["rollback"]["ips_untouched"])
        self.assertEqual(fake.server["ipv4_address"], cp["old_ip"]["ip"])
        self.assertEqual(fake.server["status"], "running")
        self.assertNotIn("unassign", [h["action"] for h in cp["history"]])

    def test_nothing_in_the_rollback_path_deletes(self):
        fake = FakeHcloud()
        fake.inject("assign", "locked", "retryable", times=3)
        before = set(fake.ips)
        cp = self.full_run(self.build(fake))
        self.assertTrue(before.issubset(set(fake.ips)))
        self.assertEqual(cp["state"], "rolled_back")


# ---------------------------------------------------------------------------
class TestAnsibleStep(Base):
    def test_argv_is_exactly_the_make_target(self):
        seen = {}

        class Completed:
            returncode = 0
            stdout = "ok"
            stderr = ""

        def runner(argv, **kwargs):
            seen["argv"] = argv
            seen["cwd"] = kwargs.get("cwd")
            return Completed()

        result = ansible_adapter.run_ip_change("Hetzner-DE", "/repo", runner=runner)
        self.assertEqual(seen["argv"], ["make", "ip-change", "HOST=Hetzner-DE"])
        self.assertEqual(seen["cwd"], "/repo")
        self.assertEqual(result["rc"], 0)

    def test_the_step_waits_for_the_inventory_edit(self):
        rot = self.build()
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "done")
        blob = "".join(self.lines)
        self.assertIn("EDIT THE INVENTORY NOW", blob)
        self.assertIn(cp["new_ip"]["ip"], blob)

    def test_aborting_at_the_inventory_step_escalates(self):
        rot = self.build(answer="abort")
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "escalated")
        self.assertEqual(self.fake.server["ipv4_address"], cp["new_ip"]["ip"])

    def test_auto_edit_inventory_is_refused_not_ignored(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["ansible"]["auto_edit_inventory"] = True
        with self.assertRaises(rotate.ConfigError):
            rotate.validate_config(cfg)

    def test_nonzero_rc_escalates_without_rolling_the_ip_back(self):
        rot = self.build(rc=2)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "escalated")
        self.assertEqual(self.fake.server["ipv4_address"], cp["new_ip"]["ip"])
        commands = "\n".join(cp["escalations"][-1]["recovery_commands"])
        self.assertIn("make ip-change HOST=", commands)
        self.assertIn("resume --txid", commands)

    def test_dns_allowlist_violation_stops_at_validated(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["dns"]["allowed_records"] = ["something-else.tinooer.top"]
        rot = self.build(fake, cfg)
        from providers import EscalationRequired

        with self.assertRaises(EscalationRequired):
            rot.plan(txid="tx-dns")
        cp = rot.load("tx-dns")
        self.assertEqual(cp["state"], "validated")
        self.assertEqual(fake.write_count, 0)

    def test_empty_allowlist_is_a_stop_not_a_pass(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["dns"]["allowed_records"] = []
        with self.assertRaises(rotate.ConfigError):
            rotate.validate_config(cfg)

    def test_allowlist_check_is_case_insensitive(self):
        self.assertEqual(
            ansible_adapter.check_dns_allowlist(["A.Tinooer.top"], ["a.tinooer.TOP"]), []
        )


# ---------------------------------------------------------------------------
class TestRedaction(Base):
    def test_a_full_run_leaks_the_token_nowhere(self):
        rot = self.build()
        cp = self.full_run(rot)
        with open(os.path.join(self.state_dir, f"{cp['txid']}.json"), encoding="utf-8") as fh:
            body = fh.read()
        self.assertNotIn(FAKE_TOKEN, body + "".join(self.lines))

    def test_a_producer_that_forgets_to_redact_still_cannot_leak(self):
        """The sink-side guard, tested by removing the producer-side one.

        run_ip_change() redacts its own output. This substitutes a stub that
        does not — which is exactly what any new field carrying third-party
        output would look like — and asserts the token still never reaches
        disk. Without redact_tree() in save() this fails, with the raw token
        sitting in ansible.stdout_tail.
        """
        def leaky_ip_change(alias, cwd):
            return {
                "argv": ansible_adapter.ip_change_argv(alias),
                "rc": 0,
                "stdout_tail": f"GET /v1/servers Authorization: Bearer {FAKE_TOKEN}",
                "stderr_tail": f"token={FAKE_TOKEN}",
            }

        rot = self.build()
        rot.ip_change = leaky_ip_change
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "done")
        with open(os.path.join(self.state_dir, f"{cp['txid']}.json"), encoding="utf-8") as fh:
            body = fh.read()
        self.assertNotIn(FAKE_TOKEN, body)
        self.assertIn("[REDACTED]", body)

    def test_redact_tree_leaves_non_strings_alone(self):
        from providers import redact_tree

        tree = {"n": 5, "b": True, "z": None, "l": [1, f"x{FAKE_TOKEN}"], "d": {"k": None}}
        out = redact_tree(tree)
        self.assertEqual(out["n"], 5)
        self.assertIs(out["b"], True)
        self.assertIsNone(out["z"])
        self.assertEqual(out["l"][0], 1)
        self.assertNotIn(FAKE_TOKEN, out["l"][1])
        self.assertEqual(tree["l"][1], f"x{FAKE_TOKEN}", "the input was mutated")

    def test_bearer_headers_are_scrubbed(self):
        self.assertEqual(redact("Authorization: Bearer abc123"),
                         "Authorization: Bearer [REDACTED]")

    def test_a_literal_token_in_an_error_is_scrubbed(self):
        fake = FakeHcloud()
        fake.inject("stop", f"failed with token {FAKE_TOKEN}", "validation")
        provider = HcloudProvider(fake, fingerprint=FINGERPRINT)
        with self.assertRaises(NonRetryableError) as ctx:
            provider.stop_server(fake.server["id"])
        self.assertNotIn(FAKE_TOKEN, str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))

    def test_failure_classification(self):
        self.assertEqual(rotate.classify_failure("HTTP 401 Unauthorized"), "auth")
        self.assertEqual(rotate.classify_failure("primary ip not found"), "not_found")
        self.assertEqual(rotate.classify_failure("connection reset by peer"), "retryable")


# ---------------------------------------------------------------------------
class TestConfig(Base):
    def test_every_required_key_is_named_in_the_error(self):
        for missing in ("id", "expected_name", "expected_ipv4", "expected_location"):
            cfg = example_config(FakeHcloud())
            cfg["server"][missing] = None
            with self.subTest(missing=missing):
                with self.assertRaises(rotate.ConfigError) as ctx:
                    rotate.validate_config(cfg)
                self.assertIn(missing, str(ctx.exception))

    def test_retention_must_be_keep(self):
        cfg = example_config(FakeHcloud())
        cfg["old_ip"] = {"retention": "delete"}
        with self.assertRaises(rotate.ConfigError):
            rotate.validate_config(cfg)

    def test_the_shipped_example_config_parses(self):
        path = os.path.join(ROOT, "rotation.example.yml")
        import yaml

        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        self.assertEqual(data["provider"], "hcloud")
        self.assertFalse(data["ansible"]["auto_edit_inventory"])
        self.assertEqual(data["old_ip"]["retention"], "keep")

    def test_status_prints_a_checkpoint(self):
        rot = self.build()
        cp = self.full_run(rot)
        loaded = rot.load(cp["txid"])
        self.assertEqual(loaded["outcome"], "done")
        json.dumps(loaded)  # must stay serialisable

    def test_job_summary_gets_one_row_per_state(self):
        """The CI table is what a finished run leaves behind once the log scrolls."""
        path = os.path.join(self.tmp.name, "summary.md")
        open(path, "w").close()
        os.environ["GITHUB_STEP_SUMMARY"] = path
        try:
            rot = self.build(on_transition=rotate.github_summary)
            self.full_run(rot)
        finally:
            del os.environ["GITHUB_STEP_SUMMARY"]
        text = open(path, encoding="utf-8").read()
        self.assertIn("| utc | state |", text)  # header, written once
        self.assertEqual(text.count("| utc | state |"), 1)
        # `---` is line one of any YAML document, so a config pasted into a
        # multi-line Actions secret makes GitHub mask every `---` it ever
        # prints — including this table's separator. Live-observed.
        self.assertNotIn("---", text)
        for state in ("server_off", "old_ip_unassigned", "new_ip_assigned",
                      "server_on", "connectivity_ok", "done"):
            self.assertIn(f"`{state}`", text)
            self.assertIn(rotate.STATE_LABELS[state], text)

    def test_job_summary_is_a_no_op_off_ci(self):
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        rotate.github_summary("done", {"txid": "t", "server": {}})  # must not raise

    def test_a_server_payload_without_a_datacenter_still_reads(self):
        """7.0.0's server_info emits `location` and no `datacenter` at all.

        Found live, against a real server, after three green offline runs: the
        suite modelled 6.2.1 while CI installed 7.0.0.
        """
        import providers

        srv = providers.HcloudProvider._server(
            {"id": 1, "name": "n", "status": "running", "location": "nbg1",
             "ipv4_id": 2, "ipv4_address": "203.0.113.1"}
        )
        self.assertEqual(srv.location, "nbg1")
        self.assertEqual(srv.datacenter, "nbg1")

    def test_a_location_and_a_datacenter_in_it_are_the_same_place(self):
        """Allocation answers `nbg1-dc3`; a location-only snapshot says `nbg1`.

        Comparing those raw reports a move that never happened, and the step
        that compares them raises NonRetryableError — a rotation stopped for a
        difference in naming, with the node already detached.
        """
        self.assertTrue(rotate.same_place("nbg1", "nbg1-dc3"))
        self.assertTrue(rotate.same_place("nbg1-dc3", "nbg1"))
        self.assertFalse(rotate.same_place("nbg1", "hel1"))
        self.assertFalse(rotate.same_place("nbg1-dc3", "fsn1-dc14"))

    def test_every_reachable_state_has_a_label(self):
        """A new step without a label would show as a bare identifier in the table."""
        for step in rotate.STEPS:
            self.assertIn(step.to, rotate.STATE_LABELS)


if __name__ == "__main__":
    unittest.main()
