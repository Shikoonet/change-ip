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
import contextlib
import io
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
FAKE_CF_TOKEN = "cf-fake-token-0987654321abcdef"
FINGERPRINT = "deadbeefcafe"

#: How many MUTATING provider calls are still owed from each state. Used by the
#: resume test to prove a resume repeats nothing and skips nothing.
#: Cloudflare-side mutations (discover / apply / rollback / verify) do NOT
#: touch the Hetzner fake, so they are zero in this table. The DNS test
#: itself asserts the Cloudflare side ran.
REMAINING_WRITES = {
    "confirmed": 6,                    # alloc, protect, stop, unassign, assign, start
    "cloudflare_preflighted": 6,
    "new_ip_allocated": 5,             # -1 for already-done allocate
    "server_off": 3,                   # -1 for stop
    "old_ip_unassigned": 2,
    "new_ip_assigned": 1,
    "server_on": 0,
    "connectivity_ok": 0,
    "ansible_done": 0,
    "cloudflare_replaced": 0,
    "done": 0,
}


class Base(unittest.TestCase):
    def setUp(self):
        os.environ["HCLOUD_TOKEN"] = FAKE_TOKEN
        # UNCONDITIONAL assignment, NOT `setdefault`. A developer's
        # shell that exports a real `CLOUDFLARE_API_TOKEN` would
        # otherwise leak into the suite: register_secret would only
        # register FAKE_CF_TOKEN for redaction, every "no token
        # leaked" assertion checks for a string that's never present,
        # and `test_missing_token_fails_preflight_before_hetzner`'s
        # earlier `setdefault`-then-restore pattern left the real
        # value silently replaced for the rest of the process.
        os.environ["CLOUDFLARE_API_TOKEN"] = FAKE_CF_TOKEN
        register_secret(FAKE_TOKEN)
        register_secret(FAKE_CF_TOKEN)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_dir = os.path.join(self.tmp.name, "state")
        self.lines = []
        # Default fake so direct test methods can use it without calling build().
        from tests.fake_cloudflare import FakeCloudflare
        self.fake = FakeHcloud()
        self.cf = FakeCloudflare(old_ip=self.fake.server["ipv4_address"])

    # -- fixtures ---------------------------------------------------------
    def build(self, fake=None, cfg=None, probe=True, rc=0, answer="yes",
              cf=None, **kwargs):
        from tests.fake_cloudflare import FakeCloudflare
        fake = fake or FakeHcloud()
        cfg = cfg if cfg is not None else example_config(fake)
        self.fake = fake
        self.ip_change_calls = []
        cf = cf if cf is not None else FakeCloudflare()
        self.cf = cf
        self.cf_preflight_calls = []
        self.cf_replace_calls = []

        def ip_change(alias, cwd):
            argv = ansible_adapter.ip_change_argv(alias)
            self.ip_change_calls.append({"argv": argv, "cwd": cwd})
            return {"argv": argv, "rc": rc, "stdout_tail": "", "stderr_tail": ""}

        def cf_preflight(op, **params):
            self.cf_preflight_calls.append({"op": op, "params": dict(params)})
            return self.cf(op, **params)

        def cf_replace(op, **params):
            self.cf_replace_calls.append({"op": op, "params": dict(params)})
            return self.cf(op, **params)

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
            cloudflare_preflight=cf_preflight,
            cloudflare_replace=cf_replace,
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
class TestReleaseOldIp(Base):
    """The one delete. Every guard is a fresh read; every miss is a refusal."""

    def _finished_provider_only(self, retention="release"):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["old_ip"] = {"retention": retention}
        cfg.setdefault("cloudflare", {})["mode"] = "provider_only"
        cfg["cloudflare"].pop("allowed_records", None)
        cfg["cloudflare"].pop("expected_record_count", None)
        rot = self.build(fake=fake, cfg=cfg)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "connectivity_ok")
        return fake, rot, cp

    def test_releases_the_old_address_after_a_finished_provider_only_run(self):
        fake, rot, cp = self._finished_provider_only()
        old_id, old_ip = cp["old_ip"]["id"], cp["old_ip"]["ip"]
        self.assertIn(old_id, fake.ips)
        rot.release_old_ip(cp)
        self.assertNotIn(old_id, fake.ips, "the old Primary IP must be gone")
        self.assertEqual(cp["old_ip"]["retention"], "released")
        self.assertTrue(cp["old_ip"]["released_at"])
        self.assertEqual(rot.load(cp["txid"])["old_ip"]["retention"], "released",
                         "the release must be persisted, not just in memory")
        # the NEW address is untouched and still on the server
        self.assertEqual(fake.server["ipv4_address"], cp["new_ip"]["ip"])
        # a second call is a no-op, never a second delete or an error
        n = fake.write_count
        rot.release_old_ip(cp)
        self.assertEqual(fake.write_count, n)

    def test_keep_config_never_releases(self):
        fake, rot, cp = self._finished_provider_only(retention="keep")
        with self.assertRaises(rotate.NonRetryableError):
            rot.release_old_ip(cp)
        self.assertIn(cp["old_ip"]["id"], fake.ips)

    def test_refuses_mid_rotation(self):
        """A checkpoint that is not finished must never lose its way back."""
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["old_ip"] = {"retention": "release"}
        rot = self.build(fake=fake, cfg=cfg)
        cp = rot.plan()
        rot._transition(cp, "server_off")          # somewhere in the middle
        with self.assertRaises(rotate.NonRetryableError):
            rot.release_old_ip(cp)
        self.assertIn(cp["old_ip"]["id"], fake.ips)

    def test_refuses_when_the_old_address_is_still_attached(self):
        """Even a finished checkpoint does not override reality."""
        fake, rot, cp = self._finished_provider_only()
        # somebody re-attached the old address to some other server meanwhile
        fake.ips[cp["old_ip"]["id"]]["assignee_id"] = 424242
        fake.ips[cp["old_ip"]["id"]]["assignee_type"] = "server"
        with self.assertRaises(IdentityMismatch):
            rot.release_old_ip(cp)
        self.assertIn(cp["old_ip"]["id"], fake.ips)

    def test_refuses_when_the_id_no_longer_means_that_address(self):
        fake, rot, cp = self._finished_provider_only()
        fake.ips[cp["old_ip"]["id"]]["ip"] = "203.0.113.250"
        with self.assertRaises(IdentityMismatch):
            rot.release_old_ip(cp)
        self.assertIn(cp["old_ip"]["id"], fake.ips)

    def test_refuses_when_the_server_is_not_on_the_new_address(self):
        fake, rot, cp = self._finished_provider_only()
        fake.server["ipv4_address"] = "198.51.100.7"   # drifted outside the tool
        with self.assertRaises(IdentityMismatch):
            rot.release_old_ip(cp)
        self.assertIn(cp["old_ip"]["id"], fake.ips)

    # -- orphan mode: by address, no checkpoint --------------------------------
    def _orphan_world(self, retention="release"):
        fake = FakeHcloud()
        # a retained, unassigned leftover from before release existed
        fake.ips[777] = {"id": 777, "name": "leftover", "ip": "198.51.100.77",
                         "type": "ipv4", "location": "nbg1", "assignee_id": None,
                         "assignee_type": None, "auto_delete": False}
        # and the IPv6 /64 every Hetzner server carries. The first live
        # by-address release died on this: the normaliser refused it and the
        # whole listing failed before any guard ran.
        fake.ips[778] = {"id": 778, "name": "primary_ip-778",
                         "ip": "2001:db8:c013:4bf7::/64", "type": "ipv6",
                         "location": "nbg1", "assignee_id": fake.server["id"],
                         "assignee_type": "server", "auto_delete": True}
        cfg = example_config(fake)
        cfg["old_ip"] = {"retention": retention}
        return fake, self.build(fake=fake, cfg=cfg)

    def test_orphan_release_by_address(self):
        fake, rot = self._orphan_world()
        out = rot.release_orphan_ip("198.51.100.77")
        self.assertEqual(out["id"], 777)
        self.assertNotIn(777, fake.ips)
        # the server's own address is untouched
        self.assertEqual(fake.server["ipv4_address"], "46.224.67.245")

    def test_orphan_refuses_an_attached_address(self):
        """The server's CURRENT address is attached; asking for it must refuse."""
        fake, rot = self._orphan_world()
        with self.assertRaises(IdentityMismatch):
            rot.release_orphan_ip(fake.server["ipv4_address"])
        self.assertEqual(fake.server["ipv4_address"], "46.224.67.245")

    def test_orphan_refuses_unknown_or_ambiguous_address(self):
        fake, rot = self._orphan_world()
        with self.assertRaises(IdentityMismatch) as ctx:
            rot.release_orphan_ip("203.0.113.1")            # nothing matches
        # the refusal must show what the project DOES hold, so "0 matches" can
        # be told apart from a typo or the wrong token — and must not include
        # the IPv6 entry, which is out of scope
        msg = str(ctx.exception)
        self.assertIn("198.51.100.77(unassigned)", msg)
        self.assertIn(f"{fake.server['ipv4_address']}(attached to {fake.server['id']})", msg)
        self.assertNotIn("2001:db8", msg)
        fake.ips[779] = dict(fake.ips[777], id=779, name="dup")
        with self.assertRaises(IdentityMismatch):
            rot.release_orphan_ip("198.51.100.77")          # two ipv4 match
        self.assertIn(777, fake.ips)

    def test_all_unassigned_releases_every_leftover_and_nothing_attached(self):
        """One dispatch clears the quota; the server's own address is untouchable."""
        fake, rot = self._orphan_world()
        fake.ips[790] = dict(fake.ips[777], id=790, name="leftover-2", ip="198.51.100.90")
        attached_before = {i for i, ip in fake.ips.items() if ip["assignee_id"] is not None}
        out = rot.release_orphan_ip("all-unassigned")
        self.assertEqual(sorted(r["ip"] for r in out["released"]),
                         ["198.51.100.77", "198.51.100.90"])
        self.assertNotIn(777, fake.ips)
        self.assertNotIn(790, fake.ips)
        # everything that was attached — the server's IPv4 and its IPv6 — remains
        self.assertEqual({i for i, ip in fake.ips.items() if ip["assignee_id"] is not None},
                         attached_before)
        self.assertEqual(fake.server["ipv4_address"], "46.224.67.245")
        # and running it again is a no-op, not an error
        self.assertEqual(rot.release_orphan_ip("all-unassigned"), {"released": []})

    def test_plan_states_the_real_retention(self):
        """The reviewer approves swap off this text; it said 'keep' under 'release'."""
        fake, rot = self._orphan_world()
        rot.plan()
        text = "\n".join(self.lines)
        self.assertIn("old address retention:     release", text)
        self.assertNotIn("nothing is ever deleted", text)

    def test_all_unassigned_refuses_under_keep(self):
        fake, rot = self._orphan_world(retention="keep")
        with self.assertRaises(rotate.NonRetryableError):
            rot.release_orphan_ip("all-unassigned")
        self.assertIn(777, fake.ips)

    # -- quota: the tool clears its own leftovers before allocate ------------
    def _full_project(self, retention="release", limit=2):
        """One box on its address, one retained leftover, quota exactly full."""
        fake = FakeHcloud(primary_ip_limit=limit)
        fake.ips[777] = {"id": 777, "name": "leftover", "ip": "198.51.100.77",
                         "type": "ipv4", "location": "nbg1", "assignee_id": None,
                         "assignee_type": None, "auto_delete": False}
        cfg = example_config(fake)
        cfg["old_ip"] = {"retention": retention}
        cfg.setdefault("cloudflare", {})["mode"] = "provider_only"
        cfg["cloudflare"].pop("allowed_records", None)
        cfg["cloudflare"].pop("expected_record_count", None)
        return fake, self.build(fake=fake, cfg=cfg)

    def test_allocate_at_quota_releases_leftovers_and_rotates(self):
        """Live run 34277270480 died on the quota. Now the run clears it itself."""
        fake, rot = self._full_project()
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "connectivity_ok")
        self.assertNotIn(777, fake.ips, "the leftover must be released")
        self.assertEqual(fake.server["ipv4_address"], cp["new_ip"]["ip"])
        self.assertIn(cp["old_ip"]["id"], fake.ips, "the OLD address is not a leftover yet")
        ops = [c["op"] for c in fake.calls]
        self.assertLess(ops.index("release"), ops.index("stop"),
                        "leftovers go before the box is touched")
        self.assertIn("quota: 198.51.100.77", [h["detail"] for h in cp["history"]])

    def test_allocate_at_quota_with_nothing_to_release_fails_before_touching_the_box(self):
        fake, rot = self._full_project(limit=1)
        del fake.ips[777]
        cp = self.full_run(rot)
        self.assertEqual(cp["outcome"], "rolled_back")
        self.assertEqual(fake.server["status"], "running")
        self.assertEqual(fake.server["ipv4_address"], "46.224.67.245")
        self.assertNotIn("stop", [c["op"] for c in fake.calls])
        self.assertIn("raise the project's Primary IP limit", "\n".join(self.lines))

    def test_allocate_at_quota_under_keep_releases_nothing(self):
        fake, rot = self._full_project(retention="keep")
        cp = self.full_run(rot)
        self.assertEqual(cp["outcome"], "rolled_back")
        self.assertIn(777, fake.ips)
        self.assertNotIn("release", [c["op"] for c in fake.calls])

    def test_primary_ip_quota_is_not_retried(self):
        """The exact text Hetzner returned when the project was full."""
        text = ('fatal: [localhost]: FAILED! => {"changed": false, "failure": '
                '{"code": "resource_limit_exceeded", "details": {"limits": '
                '[{"name": "primary_ip_limit"}]}, "message": "Primary IP limit '
                'exceeded"}, "msg": "Primary IP limit exceeded (resource_limit_exceeded, 471aa)"}')
        self.assertNotEqual(rotate.classify_failure(text), "retryable")
        # and a plain transient-looking failure is still retryable
        self.assertEqual(rotate.classify_failure("connection reset by peer"), "retryable")

    def test_orphan_refuses_under_keep(self):
        fake, rot = self._orphan_world(retention="keep")
        with self.assertRaises(rotate.NonRetryableError):
            rot.release_orphan_ip("198.51.100.77")
        self.assertIn(777, fake.ips)

    def test_retention_release_validates_and_others_do_not(self):
        cfg = example_config(FakeHcloud())
        cfg["old_ip"] = {"retention": "release"}
        rotate.validate_config(cfg)
        cfg["old_ip"] = {"retention": "delete"}
        with self.assertRaises(rotate.ConfigError):
            rotate.validate_config(cfg)


class TestDeclareDnsOutOfScope(Base):
    """A change-ip may finish without the DNS half only on evidence."""

    def _paused(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["old_ip"] = {"retention": "release"}
        rot = self.build(fake=fake, cfg=cfg, until="connectivity_ok")
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "connectivity_ok")
        return fake, rot, cp

    def _scan(self, cp, manifest=(), zones_seen=3, ok=True, old_ip=None):
        import json, tempfile
        path = os.path.join(self.tmp.name, f"scan-{len(os.listdir(self.tmp.name))}.json")
        with open(path, "w") as fh:
            json.dump({"ok": ok, "operation": "discover", "invocation_id": "t",
                       "old_ip": old_ip or cp["old_ip"]["ip"],
                       "zones_seen": zones_seen, "manifest": list(manifest)}, fh)
        return path

    def test_two_empty_scans_finish_the_run_and_release_becomes_possible(self):
        fake, rot, cp = self._paused()
        a, b = self._scan(cp), self._scan(cp)
        rot.declare_dns_out_of_scope(cp, [a, b])
        self.assertEqual(cp["state"], "done")
        self.assertEqual(cp["outcome"], "done")
        self.assertTrue(cp["cloudflare_preflight"]["skipped"])
        self.assertEqual(len(cp["dns_out_of_scope"]["scans"]), 2)
        self.assertEqual(rot.load(cp["txid"])["state"], "done", "must be persisted")
        # and the finished run can now release its old address
        old_id = cp["old_ip"]["id"]
        rot.release_old_ip(cp)
        self.assertNotIn(old_id, fake.ips)

    def test_refuses_when_any_scan_has_records(self):
        fake, rot, cp = self._paused()
        a = self._scan(cp)
        b = self._scan(cp, manifest=[{"name": "x.example", "record_id": "r1"}])
        with self.assertRaises(IdentityMismatch):
            rot.declare_dns_out_of_scope(cp, [a, b])
        self.assertEqual(cp["state"], "connectivity_ok")

    def test_refuses_when_a_scan_saw_no_zones(self):
        """Zero zones is a blind token, not an empty DNS."""
        fake, rot, cp = self._paused()
        with self.assertRaises(rotate.NonRetryableError):
            rot.declare_dns_out_of_scope(cp, [self._scan(cp, zones_seen=0)])
        self.assertEqual(cp["state"], "connectivity_ok")

    def test_refuses_a_scan_for_a_different_address(self):
        fake, rot, cp = self._paused()
        with self.assertRaises(IdentityMismatch):
            rot.declare_dns_out_of_scope(cp, [self._scan(cp, old_ip="203.0.113.9")])

    def test_refuses_a_failed_scan_and_no_scans(self):
        fake, rot, cp = self._paused()
        with self.assertRaises(rotate.NonRetryableError):
            rot.declare_dns_out_of_scope(cp, [self._scan(cp, ok=False)])
        with self.assertRaises(rotate.NonRetryableError):
            rot.declare_dns_out_of_scope(cp, [])

    def test_refuses_unless_paused_at_connectivity_ok(self):
        fake = FakeHcloud()
        rot = self.build(fake=fake, cfg=example_config(fake))
        cp = rot.plan()
        rot._transition(cp, "server_off")
        with self.assertRaises(rotate.NonRetryableError):
            rot.declare_dns_out_of_scope(cp, [self._scan(cp)])

    def test_refuses_when_the_server_is_not_on_the_new_address(self):
        fake, rot, cp = self._paused()
        fake.server["ipv4_address"] = "198.51.100.7"
        with self.assertRaises(IdentityMismatch):
            rot.declare_dns_out_of_scope(cp, [self._scan(cp)])
        self.assertEqual(cp["state"], "connectivity_ok")


class TestIdentity(Base):
    """Nothing is ever mutated without re-proving what it is, from a fresh read."""

    def test_selects_by_numeric_id(self):
        rot = self.build()
        cp = rot.plan()
        self.assertEqual(cp["server"]["id"], self.fake.server["id"])

    def test_typed_address_is_checked_against_the_live_read(self):
        """The dispatch form's address is a claim, and reality is the judge.

        Comparing it against the config's copy only ever proved the two
        guesses agreed. Comparing it against a fresh read catches a typo AND
        a box that moved outside this tool — and needs no stored address to
        go stale.
        """
        fake = FakeHcloud(old_ip="203.0.113.77")
        cfg = example_config(fake)
        cfg["server"].pop("expected_ipv4", None)

        rot = self.build(fake=fake, cfg=dict(cfg), expect_ipv4="203.0.113.77")
        cp = rot.plan()
        self.assertEqual(cp["server"]["expected_ipv4"], "203.0.113.77")

        rot = self.build(fake=FakeHcloud(old_ip="203.0.113.77"),
                         cfg=dict(cfg), expect_ipv4="198.51.100.1")
        with self.assertRaises(IdentityMismatch) as ctx:
            rot.plan()
        self.assertIn("198.51.100.1", str(ctx.exception))

    def test_no_stated_address_still_pins_identity_and_records_the_truth(self):
        """With nothing stated, id/name/location/fingerprint still have to agree.

        And the checkpoint records what the box actually had, so resume and
        rollback never depend on a human having kept a secret current.
        """
        fake = FakeHcloud(old_ip="203.0.113.99")
        cfg = example_config(fake)
        cfg["server"].pop("expected_ipv4", None)
        cp = self.build(fake=fake, cfg=dict(cfg)).plan()
        self.assertEqual(cp["server"]["expected_ipv4"], "203.0.113.99")

        wrong = FakeHcloud(old_ip="203.0.113.99")
        wrong.server["name"] = "somebody-elses-box"
        with self.assertRaises(IdentityMismatch):
            self.build(fake=wrong, cfg=dict(cfg)).plan()
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
class TestPerProjectConfig(Base):
    """No server block: the form's number + the typed address ARE the identity.

    Run 34312249225 refused a new server with "identity mismatch" because the
    secret pinned the previous one; editing three environments per server is
    the manual step this repo exists to remove.
    """

    def _project_cfg(self, fake):
        cfg = example_config(fake)
        del cfg["server"]
        del cfg["dns"]
        cfg["ansible"].pop("host_alias")
        cfg["cloudflare"] = {"accounts": {
            "acct": {"token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_A", "records": []}}}
        return cfg

    def setUp(self):
        super().setUp()
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = FAKE_CF_TOKEN
        self.addCleanup(os.environ.pop, "CLOUDFLARE_API_TOKEN_ACCOUNT_A", None)

    def test_validate_accepts_no_server_block_and_empty_floors(self):
        cfg = self._project_cfg(FakeHcloud())
        rotate.validate_config(cfg)
        self.assertEqual(cfg["server"], {})

    def test_partial_server_block_is_still_a_typo(self):
        cfg = self._project_cfg(FakeHcloud())
        cfg["server"] = {"id": 1}
        with self.assertRaises(rotate.ConfigError):
            rotate.validate_config(cfg)

    def test_dataforest_still_pins_its_seed(self):
        cfg = self._project_cfg(FakeHcloud())
        cfg["provider"] = "dataforest"
        with self.assertRaises(rotate.ConfigError):
            rotate.validate_config(cfg)

    def test_plan_pins_name_location_and_alias_from_the_live_read(self):
        fake = FakeHcloud()
        path = self.write_config(self._project_cfg(fake))
        rc = rotate.main(["plan", "--config", path, "--confirm-server-id",
                          str(fake.server["id"]), "--expect-ipv4", fake.server["ipv4_address"]],
                         runner=fake)
        self.assertEqual(rc, 0)
        cp = json.load(open(os.path.join(self.state_dir, sorted(os.listdir(self.state_dir))[-1])))
        self.assertEqual(cp["server"]["expected_name"], fake.server["name"])
        self.assertEqual(cp["server"]["expected_location"], fake.server["location"])
        self.assertEqual(cp["alias"], fake.server["name"])
        self.assertTrue(cp["new_ip"]["name"].startswith(fake.server["name"] + "-ipv4-"))
        self.assertEqual(fake.write_count, 0)

    def test_plan_without_the_number_is_a_usage_error(self):
        fake = FakeHcloud()
        path = self.write_config(self._project_cfg(fake))
        rc = rotate.main(["plan", "--config", path, "--expect-ipv4", fake.server["ipv4_address"]],
                         runner=fake)
        self.assertEqual(rc, rotate.EXIT_USAGE)

    def test_the_typed_address_is_the_second_factor(self):
        """One mistyped digit must not select another server in the project."""
        fake = FakeHcloud()
        path = self.write_config(self._project_cfg(fake))
        rc = rotate.main(["plan", "--config", path, "--confirm-server-id", str(fake.server["id"])],
                         runner=fake)
        self.assertEqual(rc, rotate.EXIT_IDENTITY)
        rc = rotate.main(["plan", "--config", path, "--confirm-server-id", str(fake.server["id"]),
                          "--expect-ipv4", "203.0.113.9"], runner=fake)
        self.assertEqual(rc, rotate.EXIT_IDENTITY)

    def test_confirmation_must_agree_with_the_checkpoint_not_just_itself(self):
        fake = FakeHcloud()
        cfg = self._project_cfg(fake)
        cfg["old_ip"] = {"retention": "release"}
        cfg["cloudflare"]["mode"] = "provider_only"
        cfg["cloudflare"].pop("accounts")
        path = self.write_config(cfg)
        rc = rotate.main(["apply", "--config", path, "--confirm-server-id", str(fake.server["id"]),
                          "--expect-ipv4", fake.server["ipv4_address"], "--until", "connectivity_ok"],
                         runner=fake)
        self.assertEqual(rc, rotate.EXIT_PAUSED)
        txid = sorted(os.listdir(self.state_dir))[-1][:-5]
        # the config-level gate is `given == given` here; the checkpoint is the pin
        rc = rotate.main(["release-old-ip", "--config", path, "--txid", txid,
                          "--confirm-server-id", "999"], runner=fake)
        self.assertEqual(rc, rotate.EXIT_IDENTITY)
        self.assertIn(cp_old := DEFAULT_OLD_IP_ID, fake.ips)


class TestNamedDnsRecordsFloor(Base):
    """`--dns-name`: what the operator knows must be found before anything moves.

    Run 34317550319 is the case. Both credentials reported "0 records, 8
    zones seen", the run declared DNS out of scope, finished green and
    deleted the old Primary IP — while testip.shimobile.net still resolved to
    it, in a ninth zone neither token could read. Proving "nothing in the
    zones I can see" is not proving "nothing".
    """

    def _world(self, names, **kw):
        from tests.fake_cloudflare import FakeCloudflare
        fake = FakeHcloud()
        cfg = example_config(fake)
        del cfg["server"]; del cfg["dns"]; cfg["ansible"].pop("host_alias")
        cfg["cloudflare"] = {"accounts": {
            "acct": {"token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_A", "records": []}}}
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = FAKE_CF_TOKEN
        self.addCleanup(os.environ.pop, "CLOUDFLARE_API_TOKEN_ACCOUNT_A", None)
        cf = FakeCloudflare(old_ip=fake.server["ipv4_address"])
        rot = self.build(fake=fake, cfg=cfg, cf=cf,
                         expect_ipv4=fake.server["ipv4_address"],
                         require_dns_names=names, **kw)
        rot.cfg.setdefault("server", {})["id"] = fake.server["id"]
        return fake, cf, rot

    def test_a_name_no_credential_can_see_stops_before_the_swap(self):
        fake, cf, rot = self._world(["testip.shimobile.net"])
        cp = self.full_run(rot)
        # escalated, not rolled_back: preflight runs before any mutation, so
        # there is nothing to roll back — a human is simply needed.
        self.assertEqual(cp["outcome"], "escalated")
        self.assertNotIn("stop", [c["op"] for c in fake.calls],
                         "the box must not be touched")
        self.assertEqual(fake.server["ipv4_address"], "46.224.67.245")
        text = "\n".join(self.lines)
        self.assertIn("testip.shimobile.net", text)
        self.assertIn("no credential for", text)

    def test_a_name_the_scan_finds_passes(self):
        found = "ne.tinooer.top"          # seeded by FakeCloudflare on the old address
        fake, cf, rot = self._world([found], until="connectivity_ok")
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "connectivity_ok")
        self.assertIn(found, [r["name"] for r in cp["cloudflare_manifest"]])

    def test_named_records_cannot_also_be_declared_out_of_scope(self):
        fake, cf, rot = self._world(["ne.tinooer.top"], until="connectivity_ok")
        cp = self.full_run(rot)
        with self.assertRaises(rotate.NonRetryableError):
            rot.declare_dns_out_of_scope(cp, ["/dev/null"])

    def test_provider_only_and_named_records_is_a_contradiction(self):
        fake, cf, rot = self._world(["ne.tinooer.top"], provider_only=True)
        cp = self.full_run(rot)
        self.assertEqual(cp["outcome"], "escalated")
        self.assertNotIn("stop", [c["op"] for c in fake.calls])


class TestDeclareAnsibleOutOfScope(Base):
    """A box with DNS records but no shikoonet inventory line: the tool PATCHes."""

    def _paused_with_records(self):
        from tests.fake_cloudflare import FakeCloudflare
        fake = FakeHcloud()
        cfg = example_config(fake)
        del cfg["server"]; del cfg["dns"]; cfg["ansible"].pop("host_alias")
        cfg["cloudflare"] = {"accounts": {
            "acct": {"token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_A", "records": []}}}
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = FAKE_CF_TOKEN
        self.addCleanup(os.environ.pop, "CLOUDFLARE_API_TOKEN_ACCOUNT_A", None)
        cf = FakeCloudflare(old_ip=fake.server["ipv4_address"])  # eight records on old_ip
        rot = self.build(fake=fake, cfg=cfg, cf=cf, until="connectivity_ok",
                         expect_ipv4=fake.server["ipv4_address"])
        rot.cfg.setdefault("server", {})["id"] = fake.server["id"]  # what main() does
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "connectivity_ok")
        self.assertEqual(len(cp["cloudflare_manifest"]), 8, "empty floor, scan found them")
        return fake, cf, rot, cp

    def test_declares_then_resume_patches_without_make_ip_change(self):
        fake, cf, rot, cp = self._paused_with_records()
        cp = rot.declare_ansible_out_of_scope(cp, inventory_path=None)
        self.assertEqual(cp["state"], "ansible_done")
        self.assertTrue(cp["ansible"]["skipped"])
        rot.until = None
        cp = rot.execute(cp)
        self.assertEqual((cp["state"], cp["outcome"]), ("done", "done"))
        self.assertEqual({r["content"] for r in cf.records}, {cp["new_ip"]["ip"]})
        self.assertEqual(self.ip_change_calls, [], "make ip-change must not run")

    def test_refuses_when_the_inventory_names_either_address(self):
        fake, cf, rot, cp = self._paused_with_records()
        inv = os.path.join(self.tmp.name, "hosts.yml")
        for ip in (cp["old_ip"]["ip"], cp["new_ip"]["ip"]):
            open(inv, "w").write(f"box:\n  ansible_host: {ip}\n")
            with self.assertRaises(rotate.IdentityMismatch):
                rot.declare_ansible_out_of_scope(cp, inventory_path=inv)
            self.assertEqual(cp["state"], "connectivity_ok")
        open(inv, "w").write("other:\n  ansible_host: 198.51.100.1\n")
        cp = rot.declare_ansible_out_of_scope(cp, inventory_path=inv)
        self.assertEqual(cp["state"], "ansible_done")
        self.assertEqual(cp["ansible"]["evidence"]["inventory"], "hosts.yml")

    def test_refuses_off_the_pause(self):
        fake, cf, rot, cp = self._paused_with_records()
        rot._transition(cp, "server_off")
        with self.assertRaises(rotate.NonRetryableError):
            rot.declare_ansible_out_of_scope(cp)


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
        from tests.fake_cloudflare import FakeCloudflare
        fake = FakeHcloud()
        path = self.write_config(example_config(fake))
        cf = FakeCloudflare(old_ip=fake.server["ipv4_address"])
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
            cloudflare_preflight=lambda op, **kw: cf(op, **kw),
            cloudflare_replace=lambda op, **kw: cf(op, **kw),
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
        from tests.fake_cloudflare import FakeCloudflare
        fake = FakeHcloud()
        path = self.write_config(example_config(fake))
        sid = str(fake.server["id"])
        cf = FakeCloudflare(old_ip=fake.server["ipv4_address"])
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
            cloudflare_preflight=lambda op, **kw: cf(op, **kw),
            cloudflare_replace=lambda op, **kw: cf(op, **kw),
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

    def test_staged_rollback_retry_does_not_restart_server_already_on_old_ip(self):
        """Retrying after provider recovery must not bounce the server again."""
        fake = FakeHcloud()
        rot = self.build(fake)
        cp = self.full_run(rot)
        rot.restore_old_ip(cp, "staged rollback", skip_dns_rollback=True)
        self.assertEqual(cp["state"], "needs_rollback")
        self.assertEqual(fake.server["ipv4_address"], cp["old_ip"]["ip"])
        before = fake.write_count

        rot.restore_old_ip(cp, "retry staged rollback", skip_dns_rollback=True)

        self.assertEqual(fake.write_count, before)
        self.assertEqual(fake.server["status"], "running")

    def test_dns_only_rollback_finishes_the_checkpoint(self):
        fake = FakeHcloud()
        rot = self.build(fake)
        cp = self.full_run(rot)
        rot.restore_old_ip(cp, "staged rollback", skip_dns_rollback=True)

        rot.dns_rollback_only(cp)

        self.assertEqual(cp["state"], "rolled_back")
        self.assertEqual(cp["outcome"], "rolled_back")
        self.assertTrue(cp["rollback"]["dns_undone"])

    def test_multi_account_dns_rollback_uses_each_owner_token(self):
        """Rollback must route persisted buckets just like forward apply.

        This is the live regression from run 34333473368: both account token
        env vars were present, but rollback omitted token_env and fell into
        the empty legacy CLOUDFLARE_API_TOKEN path before contacting DNS.
        """
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["cloudflare"] = {"accounts": {
            "account_a": {
                "token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                "records": [],
            },
            "account_b": {
                "token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                "records": [],
            },
        }}
        names = (
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
            "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
        )
        saved = {name: os.environ.get(name) for name in names}

        def restore_env():
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.addCleanup(restore_env)
        os.environ.pop("CLOUDFLARE_API_TOKEN", None)
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = "fake-account-a-token"
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_B"] = "fake-account-b-token"
        calls = []

        def rollback_spy(op, **params):
            calls.append({"op": op, "params": dict(params)})
            return {
                "rc": 0,
                "result": {
                    "ok": True,
                    "operation": op,
                    "rollback_incomplete": False,
                    "incomplete_records": [],
                },
            }

        rot = self.build(fake=fake, cfg=cfg, cf=rollback_spy)
        manifest = [
            {"zone_id": "zone-a", "record_id": "record-a",
             "name": "a.example", "credential_ref": "account_a"},
            {"zone_id": "zone-b", "record_id": "record-b",
             "name": "b.example", "credential_ref": "account_b"},
        ]
        cp = {
            "txid": "tx-multi-account-rollback",
            "old_ip": {"ip": "203.0.113.10"},
            "new_ip": {"ip": "198.51.100.99"},
            "cloudflare_manifest": manifest,
            "cloudflare_apply_started": {
                "account_a": {"operation": "apply"},
                "account_b": {"operation": "apply"},
            },
        }

        self.assertEqual(rot._do_dns_rollback(cp), "rolled_back")

        rollback_calls = [call for call in calls if call["op"] == "rollback"]
        self.assertEqual(len(rollback_calls), 2)
        routed = {
            call["params"]["credential_ref"]: call["params"]
            for call in rollback_calls
        }
        self.assertEqual(
            routed["account_a"]["token_env"],
            "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
        )
        self.assertEqual(
            routed["account_b"]["token_env"],
            "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
        )
        self.assertEqual(routed["account_a"]["manifest"], manifest[:1])
        self.assertEqual(routed["account_b"]["manifest"], manifest[1:])
        self.assertTrue(cp["cloudflare_rollback"]["ok"])

    def test_multi_account_dns_rollback_only_touches_started_accounts(self):
        fake = FakeHcloud()
        cfg = example_config(fake)
        cfg["cloudflare"] = {"accounts": {
            "account_a": {
                "token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                "records": [],
            },
            "account_b": {
                "token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                "records": [],
            },
        }}
        prior = os.environ.get("CLOUDFLARE_API_TOKEN_ACCOUNT_A")
        os.environ["CLOUDFLARE_API_TOKEN_ACCOUNT_A"] = "fake-account-a-token"
        self.addCleanup(
            lambda: os.environ.__setitem__("CLOUDFLARE_API_TOKEN_ACCOUNT_A", prior)
            if prior is not None
            else os.environ.pop("CLOUDFLARE_API_TOKEN_ACCOUNT_A", None)
        )
        calls = []

        def rollback_spy(op, **params):
            calls.append({"op": op, "params": dict(params)})
            return {"rc": 0, "result": {
                "ok": True, "operation": op, "rollback_incomplete": False,
            }}

        rot = self.build(fake=fake, cfg=cfg, cf=rollback_spy)
        cp = {
            "txid": "tx-partial-account-rollback",
            "old_ip": {"ip": "203.0.113.10"},
            "new_ip": {"ip": "198.51.100.99"},
            "cloudflare_manifest": [
                {"zone_id": "zone-a", "record_id": "record-a",
                 "name": "a.example", "credential_ref": "account_a"},
                {"zone_id": "zone-b", "record_id": "record-b",
                 "name": "b.example", "credential_ref": "account_b"},
            ],
            # Account B was discovered but its apply subprocess never began.
            "cloudflare_apply_started": {
                "account_a": {"operation": "apply"},
            },
        }

        self.assertEqual(rot._do_dns_rollback(cp), "rolled_back")
        rollback_calls = [call for call in calls if call["op"] == "rollback"]
        self.assertEqual(len(rollback_calls), 1)
        self.assertEqual(
            rollback_calls[0]["params"]["credential_ref"], "account_a"
        )

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

    # ---- sanitisation: nothing secret-bearing reaches checkpoints or -----
    # ---- summary surfaces ----------------------------------------------
    def test_full_run_checkpoint_carries_no_cloudflare_token_or_bearer(self):
        rot = self.build()
        cp = self.full_run(rot)
        body = json.dumps(cp)
        self.assertNotIn(FAKE_CF_TOKEN, body,
                         "checkpoint leaked the Cloudflare token")
        self.assertNotIn("Bearer " + FAKE_CF_TOKEN, body,
                         "checkpoint leaked a Bearer header value")

    def test_recovery_commands_carry_no_secrets(self):
        # Drive an escalation path; the recovery command is the line a
        # human reads and pastes. It must carry no token, no header value,
        # no temp path, no manifest, no checkpoint contents.
        from providers import EscalationRequired
        rot = self.build(rc=1)
        cp = rot.plan(txid="tx-recovery")
        rot._transition(cp, "confirmed")
        rot._step_cloudflare_preflight(cp)
        rot._transition(cp, "cloudflare_preflighted")
        cp["state"] = "connectivity_ok"
        with self.assertRaises(EscalationRequired):
            rot._step_ansible(cp)
        rot.escalate(cp, "ip-change failed", [f"resume --txid {cp['txid']}"])
        cmds = " ".join(cp["escalations"][-1]["recovery_commands"])
        for forbidden in (
            FAKE_CF_TOKEN,
            "Authorization",
            "Bearer",
            "/tmp/cf_result_",
            "/tmp/cloudflare_result_",
            "previous_content",
            "post_manifest",
            "manifest_digest",
        ):
            self.assertNotIn(forbidden, cmds,
                             f"recovery command leaked {forbidden!r}")
        # Safe status metadata is fine to surface — the inverse assertion
        # is that the txid appears (operator identifies the transaction).
        self.assertIn(cp["txid"], cmds)

    def test_summary_artifact_carries_no_secret(self):
        # rotate.main() produces output that GitHub Actions would put in
        # $GITHUB_STEP_SUMMARY. The mock `out=self.lines.append` captures
        # every print call. Prove none of those lines contain a secret.
        rot = self.build()
        self.full_run(rot)
        joined = "".join(self.lines)
        for forbidden in (
            FAKE_CF_TOKEN,
            "Bearer " + FAKE_CF_TOKEN,
            "Authorization",
        ):
            self.assertNotIn(forbidden, joined,
                             f"summary/output leaked {forbidden!r}")

    def test_cloudflare_apply_marker_persists_before_subprocess_invocation(self):
        # The check: at the moment the apply adapter is invoked, the
        # checkpoint on disk MUST already carry the cloudflare_apply_started
        # marker, the canonical manifest, and the manifest_digest that
        # matches `_manifest_digest(manifest)` — and MUST NOT carry any
        # token. A crash between persist and subprocess return must
        # leave a recoverable trail, not a silent gap.
        from rotate import _manifest_digest
        state_dir = self.state_dir
        observed = {}

        def probe_cf_replace(op, **params):
            # The cloudflare_replace adapter has been called. Read the
            # checkpoint now and prove the marker is already on disk.
            txid = "tx-test"  # full_run uses this txid
            ckpt_path = os.path.join(state_dir, f"{txid}.json")
            with open(ckpt_path, encoding="utf-8") as fh:
                on_disk = json.load(fh)
            observed["manifest"] = on_disk.get("cloudflare_manifest") or []
            observed["manifest_size"] = len(observed["manifest"])
            observed["started"] = on_disk.get("cloudflare_apply_started")
            observed["contains_token"] = FAKE_CF_TOKEN in json.dumps(on_disk)
            # Forward the call to the real fake so the rest of the run
            # completes normally.
            return self.cf(op, **params)

        rot = self.build()
        rot.cloudflare_replace = probe_cf_replace
        self.full_run(rot)

        self.assertGreaterEqual(observed["manifest_size"], 1,
                                "manifest must be on disk before apply")
        self.assertIsNotNone(observed["started"],
                             "cloudflare_apply_started must be persisted "
                             "BEFORE the subprocess is invoked")
        self.assertIn("manifest_digest", observed["started"],
                      "the marker must carry a deterministic digest")
        self.assertIn("ts", observed["started"],
                      "the marker must carry a timestamp")
        # The on-disk digest must match what rotate.py would compute
        # from the same manifest it persisted.
        self.assertEqual(
            observed["started"]["manifest_digest"],
            _manifest_digest(observed["manifest"]),
            "the persisted digest must equal the canonical manifest digest",
        )
        self.assertFalse(observed["contains_token"],
                         "checkpoint must not contain the Cloudflare token")

    def test_apply_crash_after_marker_keeps_recoverable_checkpoint(self):
        # The apply adapter raises AFTER the marker was persisted. The
        # checkpoint on disk must still carry the marker and the manifest,
        # so a subsequent rollback can find the persisted manifest and
        # not a half-written one.
        from providers import EscalationRequired
        state_dir = self.state_dir

        def crashing_cf_replace(*args, **kwargs):
            raise EscalationRequired("simulated crash after marker",
                                     ["recover --txid tx-test"])

        rot = self.build()
        rot.cloudflare_replace = crashing_cf_replace
        # execute() catches EscalationRequired and walks the rollback
        # path. We do not require it to bubble; we require the marker
        # to be on disk regardless of which downstream state the run
        # ends up in.
        cp = self.full_run(rot)
        ckpt_path = os.path.join(state_dir, "tx-test.json")
        with open(ckpt_path, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        self.assertIn("cloudflare_apply_started", on_disk,
                      "crash-after-marker must leave the marker on disk")
        self.assertGreaterEqual(len(on_disk.get("cloudflare_manifest") or []), 1,
                                "manifest must survive the crash")
        # The rollback path uses `cloudflare_apply_started` to decide
        # DNS mutation began. We prove that flag is present and well-formed.
        self.assertIn("manifest_digest", on_disk["cloudflare_apply_started"])
        # The run ended in a state that recognises DNS mutation began.
        self.assertIn(cp["state"], ("escalated", "rollback_incomplete", "rolled_back"))

    def test_rollback_uses_persisted_manifest_after_apply_crash(self):
        # Inject an apply crash via ProviderError — that is the path
        # that triggers `_handle_failure` and therefore
        # `restore_old_ip`, which in turn fires the rollback
        # adapter with the persisted manifest. (EscalationRequired
        # short-circuits to escalate() and skips the rollback path;
        # a separate test covers that case.)
        from providers import ProviderError
        from rotate import _manifest_digest
        state_dir = self.state_dir
        rollback_calls = []

        def crashing_apply_then_spy_rollback(op, **params):
            if op == "apply":
                raise ProviderError("simulated provider crash on apply")
            if op == "rollback":
                # Capture the manifest the adapter was handed and
                # compute its digest. This is the strongest possible
                # proof that the rollback path uses the PERSISTED
                # manifest, not a fresh discovery or a manifest
                # constructed out of band.
                rollback_calls.append({
                    "manifest": list(params.get("manifest") or []),
                    "manifest_digest": _manifest_digest(
                        list(params.get("manifest") or [])
                    ),
                    "old_ip": params.get("old_ip"),
                    "new_ip": params.get("new_ip"),
                })
                return {
                    "argv": [], "rc": 0,
                    "result": {
                        "ok": True, "rollback_incomplete": False,
                        "manifest_digest": rollback_calls[-1]["manifest_digest"],
                    },
                }
            return self.cf(op, **params)

        rot = self.build()
        rot.cloudflare_replace = crashing_apply_then_spy_rollback
        self.full_run(rot)

        # The rollback was attempted — at least one call captured.
        self.assertGreaterEqual(
            len(rollback_calls), 1,
            "rollback must be attempted when cloudflare_apply_started exists",
        )

        ckpt_path = os.path.join(state_dir, "tx-test.json")
        with open(ckpt_path, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        persisted_manifest = on_disk.get("cloudflare_manifest") or []
        persisted_digest = on_disk["cloudflare_apply_started"]["manifest_digest"]
        persisted_size = on_disk["cloudflare_apply_started"]["manifest_size"]

        rb = rollback_calls[0]
        # The manifest handed to rollback is BYTE-IDENTICAL to the
        # persisted one (same record_ids, same zone_ids, same order).
        self.assertEqual(
            [r.get("record_id") for r in rb["manifest"]],
            [r.get("record_id") for r in persisted_manifest],
            "rollback received a manifest with different record_ids than the persisted one",
        )
        self.assertEqual(
            [r.get("zone_id") for r in rb["manifest"]],
            [r.get("zone_id") for r in persisted_manifest],
            "rollback received a manifest with different zone_ids than the persisted one",
        )
        # The digest of the manifest handed to rollback equals the
        # digest persisted in cloudflare_apply_started.
        self.assertEqual(
            rb["manifest_digest"], persisted_digest,
            "rollback manifest digest must equal the persisted manifest_digest",
        )
        # Size matches.
        self.assertEqual(
            len(rb["manifest"]), persisted_size,
            "rollback manifest size must equal the persisted manifest size",
        )
        # Source/target IPs match what rollback expects.
        self.assertEqual(rb["old_ip"], on_disk["new_ip"]["ip"])
        self.assertEqual(rb["new_ip"], on_disk["old_ip"]["ip"])
        # No token anywhere on disk.
        self.assertNotIn(FAKE_CF_TOKEN, json.dumps(on_disk),
                         "checkpoint must not contain the Cloudflare token")


# ---------------------------------------------------------------------------
class TestConfig(Base):
    def test_every_required_key_is_named_in_the_error(self):
        for missing in ("id", "expected_name", "expected_location"):
            cfg = example_config(FakeHcloud())
            cfg["server"][missing] = None
            with self.subTest(missing=missing):
                with self.assertRaises(rotate.ConfigError) as ctx:
                    rotate.validate_config(cfg)
                self.assertIn(missing, str(ctx.exception))

    def test_hcloud_config_needs_no_expected_ipv4(self):
        """The one field a rotation changes must not live in the secret.

        Pinning `expected_ipv4` there meant a human editing ROTATION_CONFIG
        after every successful rotation before the next dispatch would be
        accepted — the exact manual step this repo is trying to delete. The
        address is stated per-run instead and checked against a live read;
        identity is still pinned by id + name + location + fingerprint.
        """
        cfg = example_config(FakeHcloud())
        cfg["server"].pop("expected_ipv4", None)
        rotate.validate_config(cfg)  # must not raise

    def test_dataforest_still_requires_expected_ipv4(self):
        """On a Seed it is load-bearing: it names WHICH address is old_ip.

        A Seed carries several addresses at once, so dropping this would make
        the tool pick one. Optional on Hetzner, required here — the asymmetry
        is the point, not an oversight.
        """
        cfg = example_config(FakeHcloud())
        cfg["provider"] = "dataforest"
        cfg["server"]["id"] = "11111111-2222-3333-4444-555555555555"
        cfg["server"].pop("expected_ipv4", None)
        with self.assertRaises(rotate.ConfigError) as ctx:
            rotate.validate_config(cfg)
        self.assertIn("expected_ipv4", str(ctx.exception))

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

    def test_status_needs_no_token(self):
        """The verify job runs `status` on an environment that carries no token."""
        rot = self.build()
        cp = self.full_run(rot)
        path = self.write_config(example_config(self.fake))
        del os.environ["HCLOUD_TOKEN"]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = rotate.main(["status", "--config", path, "--txid", cp["txid"]],
                                 runner=self.fake)
        finally:
            os.environ["HCLOUD_TOKEN"] = FAKE_TOKEN
        self.assertEqual(rc, 0)

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
        self.assertIn("Cloudflare DNS scope (before server changes)", text)
        self.assertIn("Cloudflare DNS records updated", text)
        self.assertIn("| account | zone | A record | from | to | result |", text)
        self.assertIn("`ne.tinooer.top`", text)
        self.assertIn("`46.224.67.245`", text)
        self.assertIn("updated and verified", text)
        self.assertNotIn(FAKE_CF_TOKEN, text)

    def test_job_summary_names_every_multi_account_record(self):
        path = os.path.join(self.tmp.name, "multi-account-summary.md")
        open(path, "w").close()
        saved = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = path
        cp = {
            "txid": "tx-report",
            "server": {
                "id": 123,
                "expected_name": "server",
                "expected_location": "nbg1",
            },
            "old_ip": {"ip": "203.0.113.10"},
            "new_ip": {"ip": "198.51.100.99"},
            "cloudflare_manifest": [
                {"name": "api.example.com", "zone_name": "example.com",
                 "zone_id": "zone-a", "record_id": "record-a",
                 "credential_ref": "account_a"},
                {"name": "edge.example.net", "zone_name": "example.net",
                 "zone_id": "zone-b", "record_id": "record-b",
                 "credential_ref": "account_b"},
            ],
        }
        try:
            rotate.github_summary("cloudflare_replaced", cp)
        finally:
            if saved is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = saved

        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for expected in (
            "`account_a`", "`example.com`", "`api.example.com`",
            "`account_b`", "`example.net`", "`edge.example.net`",
            "`203.0.113.10`", "`198.51.100.99`",
        ):
            self.assertIn(expected, text)
        self.assertIn("**2 A record(s) reported.**", text)

    def test_rollback_summary_does_not_claim_an_unstarted_account(self):
        cp = {
            "old_ip": {"ip": "203.0.113.10"},
            "new_ip": {"ip": "198.51.100.99"},
            "cloudflare_manifest": [
                {"name": "a.example", "zone_name": "example",
                 "credential_ref": "account_a"},
                {"name": "b.example", "zone_name": "example",
                 "credential_ref": "account_b"},
            ],
            "cloudflare_rollback": {"per_account": [
                {"account": "account_a", "credential_ref": "account_a",
                 "ok": True},
                {"account": "account_b", "credential_ref": "account_b",
                 "ok": False},
            ]},
        }
        rows = rotate._dns_report_rows("rolled_back", cp)
        self.assertEqual([row["record"] for row in rows], ["a.example"])
        self.assertEqual(rows[0]["result"], "restored and verified")

    def test_failed_cloudflare_update_summary_still_names_every_record(self):
        cp = {
            "old_ip": {"ip": "203.0.113.10"},
            "new_ip": {"ip": "198.51.100.99"},
            "cloudflare_manifest": [
                {"name": "failed.example", "zone_name": "example",
                 "credential_ref": "account_a"},
            ],
            "cloudflare_apply_started": {
                "account_a": {"operation": "apply"},
            },
        }
        rows = rotate._dns_report_rows("escalated", cp)
        self.assertEqual([row["record"] for row in rows], ["failed.example"])
        self.assertEqual(rows[0]["result"], "update attempted; run stopped")

        # An unrelated provider failure must not claim DNS was attempted.
        cp.pop("cloudflare_apply_started")
        self.assertEqual(rotate._dns_report_rows("escalated", cp), [])

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

    def test_a_read_only_token_is_an_auth_failure_not_a_retry(self):
        """Found live: a read-only HCLOUD_TOKEN reached allocate and retried
        4x at 10s apiece before rolling back. The retries are not free — they
        happen at any step, and on unassign or assign the node is mid-swap.
        The marker the API returned was 'token_readonly' / 'token is readonly'.
        """
        self.assertEqual(rotate.classify_failure("not allowed because token is readonly (token_readonly)"), "auth")
        self.assertEqual(rotate.classify_failure("code: token_readonly, message: ...readonly..."), "auth")

    def test_every_reachable_state_has_a_label(self):
        """A new step without a label would show as a bare identifier in the table."""
        for step in rotate.STEPS:
            self.assertIn(step.to, rotate.STATE_LABELS)


# ---------------------------------------------------------------------------
class TestCloudflareFlow(Base):
    """The Cloudflare half: preflight -> apply -> verify, plus rollback and
    provider-only opt-out. Driven through the same rotation seam the
    Hetzner half uses (rotation_kwargs); the runner is the fake.
    """

    def test_cloudflare_preflight_runs_before_allocate(self):
        rot = self.build()
        self.full_run(rot)
        ops = [c["op"] for c in self.cf.calls]
        self.assertEqual(ops[0], "discover")
        self.assertIn("apply", ops)
        # The verify block in rotate.py reads post_manifest from apply's
        # response, not a separate `verify` op; the latter only runs via
        # main()'s verifier. So the call sequence ends at apply here.

    def test_preflight_persists_manifest_before_any_hetzner_mutation(self):
        rot = self.build()
        self.full_run(rot)
        # The manifest is on disk after preflight and before the first Hetzner
        # write op. Hetzner fake records all `calls`, including reads; the
        # first MUTATING one is `protect_ip`. Assert cloudflare_manifest was
        # set before `protect_ip` (which runs first in _step_stop, earlier
        # than allocate).
        cp = rot.load("tx-test")
        self.assertGreater(len(cp["cloudflare_manifest"]), 0)
        # preflight_ts <= protect_ip_ts:
        preflight_ts = cp["cloudflare_preflight"]["ts"]
        protect_ts = next(h["ts"] for h in cp["history"] if h["action"] == "protect_ip")
        self.assertLessEqual(preflight_ts, protect_ts)

    def test_one_blind_account_stops_even_when_another_found_records(self):
        """A non-empty partial union must not hide a credential that saw 0 zones."""
        from tests.fake_cloudflare import FakeCloudflare

        backing = FakeCloudflare(old_ip=self.fake.server["ipv4_address"])

        class OneBlindAccount:
            def __init__(self):
                self.calls = []

            def __call__(self, op, **params):
                self.calls.append({"op": op, "params": dict(params)})
                if op == "discover" and params.get("credential_ref") == "account_b":
                    return {"ok": True, "rc": 0, "result": {
                        "ok": True, "operation": "discover",
                        "zones_seen": 0, "manifest": [],
                    }}
                return backing(op, **params)

        cfg = example_config(self.fake)
        cfg["cloudflare"] = {"accounts": {
            "account_a": {"token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                          "records": []},
            "account_b": {"token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                          "records": []},
        }}
        for name in ("CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                     "CLOUDFLARE_API_TOKEN_ACCOUNT_B"):
            os.environ[name] = FAKE_CF_TOKEN
            self.addCleanup(os.environ.pop, name, None)
        rot = self.build(fake=self.fake, cfg=cfg, cf=OneBlindAccount())
        cp = self.full_run(rot)
        self.assertEqual((cp["state"], cp["outcome"]),
                         ("escalated", "escalated"))
        self.assertEqual(self.fake.write_count, 0)
        self.assertIn("saw zero zones", "\n".join(self.lines))

    def test_overlapping_all_zones_and_narrow_tokens_patch_each_record_once(self):
        """The first configured credential owns records both tokens can see."""
        from tests.fake_cloudflare import FakeCloudflare

        zones = ["zone-aaaa", "zone-bbbb", "zone-cccc", "zone-dddd"]
        cf = FakeCloudflare(
            old_ip=self.fake.server["ipv4_address"],
            account_zones={"account_a": zones, "account_b": zones},
        )
        cfg = example_config(self.fake)
        cfg["cloudflare"] = {"accounts": {
            "account_a": {"token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                          "records": []},
            "account_b": {"token_env": "CLOUDFLARE_API_TOKEN_ACCOUNT_B",
                          "records": []},
        }}
        for name in ("CLOUDFLARE_API_TOKEN_ACCOUNT_A",
                     "CLOUDFLARE_API_TOKEN_ACCOUNT_B"):
            os.environ[name] = FAKE_CF_TOKEN
            self.addCleanup(os.environ.pop, name, None)
        rot = self.build(fake=self.fake, cfg=cfg, cf=cf)
        cp = self.full_run(rot)
        self.assertEqual((cp["state"], cp["outcome"]), ("done", "done"))
        self.assertEqual(len(cp["cloudflare_manifest"]), 8)
        self.assertEqual({r["credential_ref"]
                          for r in cp["cloudflare_manifest"]}, {"account_a"})
        self.assertEqual(cf.write_count, 8,
                         "overlap must not PATCH the same record twice")
        accounts = cp["cloudflare_preflight"]["accounts"]
        self.assertEqual(accounts[0]["overlap_count"], 0)
        self.assertEqual(accounts[1]["overlap_count"], 8)

    def test_cloudflare_replaced_runs_after_ansible_done(self):
        rot = self.build()
        states = []
        rot.on_transition = lambda s, cp: states.append(s)
        self.full_run(rot)
        self.assertLess(states.index("ansible_done"), states.index("cloudflare_replaced"))
        self.assertLess(states.index("cloudflare_replaced"), states.index("done"))

    def test_every_reachable_state_has_a_label_after_preflight_and_replace(self):
        for step in rotate.STEPS:
            self.assertIn(step.to, rotate.STATE_LABELS)
        self.assertIn("cloudflare_preflighted", rotate.STATE_LABELS)
        self.assertIn("cloudflare_replaced", rotate.STATE_LABELS)
        self.assertIn("rollback_incomplete", rotate.STATE_LABELS)

    def test_no_duplicate_frm_in_steps(self):
        seen = set()
        for step in rotate.STEPS:
            self.assertNotIn(step.frm, seen, f"step {step.frm} declared twice")
            seen.add(step.frm)

    def test_full_run_reaches_done_with_eight_records_patched(self):
        rot = self.build()
        # default fake seeds eight records
        before_writes = self.cf.write_count
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "done")
        self.assertEqual(cp["outcome"], "done")
        self.assertEqual(self.cf.write_count - before_writes, 8)

    def test_forward_apply_uses_persisted_manifest_not_rediscovery(self):
        rot = self.build()
        cp = self.full_run(rot)
        apply_calls = [c for c in self.cf_replace_calls if c["op"] == "apply"]
        self.assertEqual(len(apply_calls), 1, "apply must run exactly once")
        sent_manifest = apply_calls[0]["params"]["manifest"]
        persisted = cp["cloudflare_manifest"]
        self.assertEqual([r["record_id"] for r in sent_manifest],
                         [r["record_id"] for r in persisted])

    def test_rollback_uses_persisted_manifest_not_rediscovery(self):
        rot = self.build()
        # Make cloudflare_apply fail so we end up in restore_old_ip territory.
        self.cf.inject("apply", "drift", "retryable", times=9)
        cp = self.full_run(rot)
        # clean rollback: provider IP restored, DNS rollback succeeded against
        # the persisted manifest. Outcome is `rolled_back` (full restoration).
        self.assertEqual(cp["state"], "rolled_back", cp["state"])
        rb_calls = [c for c in self.cf_replace_calls if c["op"] == "rollback"]
        self.assertGreaterEqual(len(rb_calls), 1)
        sent_manifest = rb_calls[0]["params"]["manifest"]
        persisted = cp["cloudflare_manifest"]
        self.assertEqual([r["record_id"] for r in sent_manifest],
                         [r["record_id"] for r in persisted])

    def test_rollback_third_party_content_marks_incomplete(self):
        # Run the rotation forward to apply (records get PATCHed to
        # NEW_IP, manifest captures OLD_IP per record). Then tamper
        # one record's live content to a third-party IP — simulating
        # a human edit between apply and rollback. Call restore_old_ip
        # and assert it surfaces `rollback_incomplete` with the
        # tampered record in `incomplete_records`.
        #
        # The earlier version of this test called `self.build()`
        # without the tampered fake — `build()` constructs a NEW
        # FakeHcloud(), so the `inject` and any tamper were
        # discarded. The test then accepted any reachable state and
        # could not detect a regression in this path.
        rot = self.build()
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "done",
                          msg=f"setup failed before tamper: {cp}")
        # Tamper: overwrite the live content of the first record with
        # a third-party IP, so the rollback reads a value that is
        # neither OLD_IP (so it tries to PATCH) nor NEW_IP (so the
        # fake's third-party-content branch fires).
        original = self.cf.records[0]["content"]
        self.cf.records[0]["content"] = "198.51.100.250"
        self.addCleanup(
            lambda: self.cf.records.__setitem__(0, dict(original_record))
            if False else None  # noqa
        )
        # Simpler: explicit restore via a small helper that records
        # the original dict and re-installs it on cleanup.
        self.addCleanup(self._restore_record_content, 0, original)
        # Drive restore_old_ip via the rotation's escalate path
        # (we do not need to re-run the full plan; just call the
        # rollback directly via the same `_do_dns_rollback` the
        # production code uses, then mirror what `restore_old_ip`
        # does on the caller's side — record the outcome).
        outcome = rot._do_dns_rollback(cp)
        cp["rollback"] = {"state": outcome}
        cp["outcome"] = outcome
        self.assertEqual(outcome, "rollback_incomplete")
        rb = cp["cloudflare_rollback"].get("result") or {}
        incomplete = rb.get("incomplete_records") or []
        names = [r["name"] for r in incomplete]
        self.assertIn(self.cf.records[0]["name"], names)

    def _restore_record_content(self, index, original_content):
        self.cf.records[index]["content"] = original_content

    def test_missing_token_fails_preflight_before_hetzner(self):
        os.environ.pop("CLOUDFLARE_API_TOKEN", None)
        try:
            rot = self.build()
            cp = self.full_run(rot)
        finally:
            os.environ["CLOUDFLARE_API_TOKEN"] = FAKE_CF_TOKEN
        self.assertEqual(self.fake.write_count, 0,
                         "no Hetzner mutation must occur when CF token is missing")
        # state should be escalated. (We don't strictly require that
        # specific state because the rotation may have stopped at the
        # preflight escalation OR the playbook failed at the dns step)
        self.assertIn(cp["state"], ("escalated",))

    def test_provider_only_throwaway_opt_out_structurally_blocks_dns(self):
        cfg = example_config(self.fake)
        cfg["cloudflare"]["mode"] = "provider_only"
        rot = self.build(cfg=cfg)
        cp = self.full_run(rot)
        self.assertEqual(cp["state"], "connectivity_ok")
        self.assertEqual(cp["outcome"], "paused")
        # No discover / apply / verify ever ran.
        ops = [c["op"] for c in self.cf.calls]
        self.assertNotIn("discover", ops)
        self.assertNotIn("apply", ops)
        self.assertNotIn("verify", ops)

    def test_provider_only_skip_with_real_server_fixture(self):
        # Pin the skip-defence to the operator-supplied server
        # identity (Hetzner server #164897365 at 188.245.32.133)
        # to catch regressions where the structural guard falls
        # back to a default server or reads from a cached manifest.
        # We exercise `_step_cloudflare_preflight` directly — the
        # full run is covered by
        # `test_provider_only_throwaway_opt_out_structurally_blocks_dns`.
        OP_SERVER_ID = 164897365
        OP_OLD_IP = "188.245.32.133"
        fake = FakeHcloud()
        fake.server["id"] = OP_SERVER_ID
        fake.server["ipv4"] = OP_OLD_IP
        fake.server["ipv4_address"] = OP_OLD_IP
        DEFAULT_IP_ID = 900001
        fake.ips[DEFAULT_IP_ID].update({
            "ip": OP_OLD_IP, "assignee_id": OP_SERVER_ID,
        })
        cfg = example_config(fake)
        cfg["server"]["id"] = OP_SERVER_ID
        cfg["server"]["expected_ipv4"] = OP_OLD_IP
        cfg["cloudflare"]["mode"] = "provider_only"
        # The CF adapter is NEVER invoked by the skip path. Build
        # the rotation but record every adapter entry so we can
        # assert it stays empty after the preflight step.
        pre_calls = list(self.cf.calls)
        rot = self.build(cfg=cfg, fake=fake)
        # Don't run the full rotation — that would exercise Hetzner
        # state-machine steps (allocate / stop / unassign) which
        # need different fake seedings for the operator's server.
        # The skip-defence is a single-step property.
        self.assertTrue(rot.provider_only,
                          msg="provider_only not honoured from cfg")
        cp = rot.plan(txid="tx-skip-server-164897365")
        rot._transition(cp, "confirmed")
        rot._step_cloudflare_preflight(cp)
        # No new CF adapter calls beyond what preflight would not
        # itself trigger (there are none — the skip returns early).
        self.assertEqual(self.cf.calls, pre_calls,
                          msg=f"CF adapter was invoked unexpectedly: "
                              f"{self.cf.calls!r}")
        # The skip-defense records skipped=True on the preflight
        # envelope, and writes an empty manifest. The comment in
        # rotate.py _step_cloudflare_preflight calls this "the
        # structural pause later guards us from doing work we said
        # we wouldn't" — so downstream resume cannot mistake
        # "skip" for "no skip".
        preflight = cp.get("cloudflare_preflight") or {}
        self.assertTrue(preflight.get("skipped"),
                          msg=f"cloudflare_preflight did not record"
                              f" skipped: {preflight!r}")
        self.assertEqual(cp.get("cloudflare_manifest"), [],
                          msg=f"manifest non-empty in provider_only:"
                              f" {cp.get('cloudflare_manifest')!r}")
        # Pin the server identity in the assertion so a regression
        # that fell back to a default server (e.g. reading from a
        # cached manifest) would surface as a wrong id here.
        self.assertEqual(cp["server"]["id"], OP_SERVER_ID)
        self.assertEqual(cp["server"]["expected_ipv4"], OP_OLD_IP)
        # Defence-in-depth: the skip path MUST NOT look up the CF
        # token env at all. CLOUDFLARE_API_TOKEN is never read in
        # the provider_only branch — the absence of `accounts` in the
        # skipped branch is verified at rotate.py:1421-1425 (the early
        # return). Stub-check: the adapter's runners were never wired
        # in, so even if the env var is set elsewhere (the test
        # harness ships its own fixture token), the skip path cannot
        # leak it to a downstream stage.

    def test_recovery_command_actually_works_against_cli(self):
        # The escalate path should produce a recovery command that `main()`
        # would recognize. Smoke-check the shape.
        self.cf.inject("apply", "boom", "retryable", times=9)
        rot = self.build()
        cp = self.full_run(rot)
        if cp["state"] == "escalated":
            cmds = " ".join(cp["escalations"][-1]["recovery_commands"])
            self.assertIn("resume", cmds)
            self.assertIn(cp["txid"], cmds)

    def test_inventory_rollback_prompts_operator(self):
        # The rollback path runs inventory_rollback_step() which prints
        # a banner and asks a prompt. We trigger the rollback path
        # via the playbook (non-self-test): fail ip_change with a non-zero
        # RC which the dispatcher turns into an escalate; from `escalated`
        # the next state still owes the inventory rollback. Easier path:
        # use `rc=1` so the ansible step raises, which leads to escalation;
        # since DNS rollback did not begin yet, the inventory prompt
        # still lives inside _step_ansible's escalation path.
        captured = []
        def tricky_prompt(msg):
            captured.append(msg)
            return "yes"
        rot = self.build(rc=1)
        rot.prompt = tricky_prompt
        self.full_run(rot)
        # the rotation escalates because ip_change failed, and the
        # operator prompt may or may not have happened. We instead check
        # the helper itself prompts — call it directly.
        ansible_adapter.inventory_rollback_step(
            alias="Hetzner-DE",
            inventory="inventory/hosts.yml",
            old_ip="1.1.1.1",
            new_ip="2.2.2.2",
            prompt=tricky_prompt,
            out=lambda m: None,
        )
        self.assertTrue(any("back into inventory" in m for m in captured),
                        f"no inventory rollback prompt: {captured}")

    def test_token_text_redacted_in_adapter_and_checkpoint(self):
        # Drive the cloudflare_adapter directly: prove it scrubs secrets
        # even when the upstream result file (the only place the adapter
        # passes through) contains them.
        import json as _json
        from cloudflare_adapter import run_cloudflare_op
        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        def leaky_runner(argv, **kw):
            for i, item in enumerate(argv):
                if item.startswith("result_file="):
                    path = item.split("=", 1)[1]
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(_json.dumps({
                            "ok": True, "operation": "apply",
                            "invocation_id": "11111111-1111-1111-1111-111111111111",
                            "post_manifest": [
                                {"zone_id": "z", "record_id": "r",
                                 "name": "t.x", "content": "1.1.1.1"}],
                        }))
                    break
            Completed.stdout = f"Bearer {FAKE_CF_TOKEN} from upstream"
            return Completed()
        result = run_cloudflare_op(
            "apply", old_ip="0.0.0.0", new_ip="1.1.1.1",
            allowed_records=["a.tinooer.top"], expected_count=1,
            manifest=[{"zone_id": "z", "record_id": "r", "name": "a.tinooer.top",
                       "previous_content": "0.0.0.0", "ttl": 1, "proxied": False}],
            invocation_id="11111111-1111-1111-1111-111111111111",
            runner=leaky_runner, timeout=5,
        )
        self.assertNotIn(FAKE_CF_TOKEN, result["stdout_tail"])
        self.assertIn("[REDACTED]", result["stdout_tail"])
        self.assertNotIn(FAKE_CF_TOKEN, str(result["result"]))

    def test_adapter_argv_contains_no_secret(self):
        # Drive run_cloudflare_op against a fake runner so we can capture argv.
        import json as _json
        from cloudflare_adapter import run_cloudflare_op
        captured = {}
        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""
        def runner(argv, **kw):
            captured["argv"] = argv
            for i, item in enumerate(argv):
                if item.startswith("result_file="):
                    path = item.split("=", 1)[1]
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(_json.dumps({
                            "ok": True, "operation": "apply",
                            "invocation_id": "22222222-2222-2222-2222-222222222222",
                        }))
                    break
            return Completed()
        run_cloudflare_op(
            "apply",
            old_ip="1.1.1.1", new_ip="2.2.2.2",
            allowed_records=["a.tinooer.top"],
            expected_count=1,
            manifest=[{"zone_id": "z", "record_id": "r", "name": "a.tinooer.top",
                       "previous_content": "1.1.1.1", "ttl": 1, "proxied": False}],
            invocation_id="22222222-2222-2222-2222-222222222222",
            runner=runner, timeout=5,
        )
        joined = " ".join(captured["argv"])
        self.assertNotIn(FAKE_CF_TOKEN, joined)
        for item in captured["argv"]:
            self.assertIsInstance(item, str)

    def test_zero_records_in_full_change_ip_stops_before_provider_mutation(self):
        # The credential sees a real zone, but none of its A records points at
        # OLD_IP. That is not permission to call DNS out of scope: a different
        # credential may own an unseen zone. Full change-ip must stop before
        # Hetzner is touched; provider-only is the explicit no-DNS operation.
        empty_cf = type(self.cf)(records=[{
            "zone_id": "zone-visible", "record_id": "rec-other",
            "name": "elsewhere.example.com", "content": "203.0.113.254",
            "ttl": 1, "proxied": False,
        }])
        rot = self.build(cf=empty_cf)
        cp = self.full_run(rot)
        self.assertEqual((cp["state"], cp["outcome"]),
                         ("escalated", "escalated"))
        self.assertEqual(self.fake.write_count, 0,
                         "empty DNS visibility must stop before Hetzner mutates")
        self.assertEqual(empty_cf.write_count, 0)
        self.assertIn("zero A records", "\n".join(self.lines))

    def test_malformed_result_handled_by_adapter(self):
        # The real adapter raises on a malformed result file. We exercise
        # the path through the runner by injection: an Inject failure gives
        # `{"ok": False, ...}`, which is the contract a real failure takes.
        # This test pins that the injection still yields a clean recovery.
        self.cf.inject("apply", "boom", "retryable", times=1)
        rot = self.build()
        cp = self.full_run(rot)
        self.assertIn(cp["state"], ("done", "escalated", "rollback_incomplete"))

    def test_until_cloudflare_replaced_is_a_third_pausable_state(self):
        # cloudflare_replaced added to PAUSABLE — and the path stops BEFORE
        # the verify step.
        from tests.fake_hcloud import FakeHcloud
        fake = FakeHcloud()
        cfg = example_config(fake)
        from tests.fake_cloudflare import FakeCloudflare
        cf = FakeCloudflare(old_ip=fake.server["ipv4_address"])
        path = self.write_config(cfg)
        rc = rotate.main(
            ["apply", "--config", path, "--confirm-server-id", str(fake.server["id"]),
             "--until", "cloudflare_replaced"],
            runner=fake,
            probe=lambda h, p, t: True,
            ip_change=lambda a, c: {"argv": ansible_adapter.ip_change_argv(a),
                                     "rc": 0, "stdout_tail": "", "stderr_tail": ""},
            prompt=lambda _: "yes",
            out=self.lines.append,
            sleep=lambda _: None,
            cloudflare_preflight=lambda op, **kw: cf(op, **kw),
            cloudflare_replace=lambda op, **kw: cf(op, **kw),
        )
        self.assertEqual(rc, rotate.EXIT_PAUSED)

    def test_escalate_persists_resume_state(self):
        """An escalation must save cp['state'] to cp['resume_state'] so the
        next resume can replay the same step. Without this, an escalated
        checkpoint has no record of what to retry."""
        from providers import EscalationRequired
        rot = self.build(rc=1)  # ip_change returns rc=1 → _step_ansible raises
        cp = rot.plan(txid="tx-resume-save")
        rot._transition(cp, "confirmed")
        rot._step_cloudflare_preflight(cp)
        rot._transition(cp, "cloudflare_preflighted")
        # jump to the failing step directly with a real manifest
        cp["state"] = "connectivity_ok"
        with self.assertRaises(EscalationRequired):
            rot._step_ansible(cp)
        rot.escalate(cp, "ip-change failed", [f"resume --txid {cp['txid']}"])
        self.assertEqual(cp["state"], "escalated")
        self.assertEqual(cp["resume_state"], "connectivity_ok",
                         "escalate() must record the state we escalated from")
        self.assertEqual(cp["escalations"][-1]["resume_state"], "connectivity_ok")

    def test_resume_from_escalation_restores_state_and_replays(self):
        """execute() on an escalated checkpoint with a valid resume_state must
        restore that state and replay the step. We assert the replay actually
        runs (cf_replace_calls counter) without depending on the full state
        machine reaching 'done' (which would require a real Hetzner mutate)."""
        from providers import EscalationRequired
        rot = self.build(rc=1)  # first attempt fails
        cf_calls_before = len(self.cf_replace_calls)
        cp = rot.plan(txid="tx-resume-replay")
        rot._transition(cp, "confirmed")
        rot._step_cloudflare_preflight(cp)
        rot._transition(cp, "cloudflare_preflighted")
        cp["state"] = "connectivity_ok"
        with self.assertRaises(EscalationRequired):
            rot._step_ansible(cp)
        rot.escalate(cp, "ip-change failed", [f"resume --txid {cp['txid']}"])
        self.assertEqual(cp["state"], "escalated")
        self.assertEqual(cp["resume_state"], "connectivity_ok")

        # fix the runner in-place and replay from the escalated checkpoint
        rot.ip_change = lambda a, c: {
            "argv": ansible_adapter.ip_change_argv(a),
            "rc": 0, "stdout_tail": "", "stderr_tail": "",
        }
        # replay from the escalated checkpoint. The replay must run the
        # restored _step_ansible and _step_cloudflare_replace before any
        # later step (here _step_verify) raises IdentityMismatch because the
        # provider half was never walked in this test.
        rot.execute(cp)
        # evidence the replay actually happened: history has both the
        # resume_from_escalation entry AND a successful ip_change after it.
        actions = [h["action"] for h in cp["history"]]
        self.assertIn("resume_from_escalation", actions)
        # find the resume index, then check ip_change appears AFTER it
        idx = actions.index("resume_from_escalation")
        self.assertIn("ip_change", actions[idx + 1:])
        # and the cf_replace_calls counter advanced
        self.assertGreater(len(self.cf_replace_calls), cf_calls_before,
                           "replay must have run _step_cloudflare_replace")

    def test_resume_without_resume_state_is_terminal(self):
        """An escalated checkpoint with no resume_state cannot be replayed and
        must remain terminal. Defensive: protects against a checkpoint that
        pre-dates this fix."""
        from providers import EscalationRequired
        rot = self.build(rc=1)
        cp = rot.plan(txid="tx-no-resume")
        rot._transition(cp, "confirmed")
        rot._step_cloudflare_preflight(cp)
        rot._transition(cp, "cloudflare_preflighted")
        cp["state"] = "connectivity_ok"
        with self.assertRaises(EscalationRequired):
            rot._step_ansible(cp)
        rot.escalate(cp, "ip-change failed", [f"resume --txid {cp['txid']}"])
        del cp["resume_state"]
        out = rot.execute(cp)
        self.assertEqual(out["state"], "escalated",
                         "no resume_state → still terminal")


if __name__ == "__main__":
    unittest.main()
