"""setup-secrets.sh must never write a secret it could not produce.

A pipeline runs both sides at once. `producer | gh secret set` lets gh read
EOF and store an EMPTY value even when the producer failed, and `pipefail`
then reports the failure AFTER the damage. On 2026-09-08 that blanked
HCLOUD_TOKEN on both Hetzner environments and the next live `plan` died with
"HCLOUD_TOKEN is not set" — a working credential destroyed by a script whose
own output said it had failed.
"""
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup-secrets.sh"


class TestSetupSecretsNeverWritesEmpty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        # A `gh` that records every write, so "did it call gh at all" is a
        # fact rather than an inference from exit codes.
        self.log = self.d / "gh.log"
        fake = self.d / "bin"
        fake.mkdir()
        (fake / "gh").write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            if [ "$1" = "secret" ] && [ "$2" = "set" ]; then
              v=$(cat)
              echo "WROTE $3 bytes=${#v}" >> "$GH_LOG"
              exit 0
            fi
            exit 1
        """))
        (fake / "gh").chmod(0o755)
        self.bin = fake

    def _run(self, producer_body, present=False):
        prod = self.d / "producer.sh"
        prod.write_text("#!/usr/bin/env bash\n" + producer_body)
        prod.chmod(0o755)

        src = SCRIPT.read_text()
        body = src[src.index("set_secret() {"):src.index("emit_file()")]
        harness = self.d / "harness.sh"
        harness.write_text(
            "set -uo pipefail\n"
            "DRY=0; ok=0; fixed=0; skipped=0; problems=0\n"
            'say() { printf "  %s\\n" "$*"; }\n'
            f"secret_present() {{ return {0 if present else 1}; }}\n"
            "REPO=fake/repo\n"
            + body
            + f"\nset_secret HCLOUD_TOKEN hetzner-plan {prod}\n"
        )
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                   GH_LOG=str(self.log))
        cp = subprocess.run(["bash", str(harness)], capture_output=True,
                            text=True, env=env, timeout=60)
        wrote = self.log.read_text() if self.log.exists() else ""
        return cp.stdout, wrote

    def test_failing_producer_never_reaches_gh(self):
        out, wrote = self._run("exit 1\n")
        self.assertEqual(wrote, "", f"gh was called despite a failed producer: {wrote!r}")
        self.assertIn("[FAIL]", out)

    def test_empty_but_successful_producer_never_reaches_gh(self):
        """Exit 0 with no output is the same hazard wearing a success code."""
        out, wrote = self._run("exit 0\n")
        self.assertEqual(wrote, "", f"gh was called with an empty value: {wrote!r}")

    def test_a_real_value_is_written(self):
        out, wrote = self._run("printf 'a-real-token'\n")
        self.assertIn("bytes=12", wrote)
        self.assertIn("[set]", out)

    def test_failed_producer_keeps_an_existing_secret(self):
        out, wrote = self._run("exit 1\n", present=True)
        self.assertEqual(wrote, "")
        self.assertIn("[keep]", out)


class TestScriptHygiene(unittest.TestCase):
    def test_script_parses(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True, timeout=30)

    def test_no_producer_is_piped_into_gh_secret_set(self):
        """The shape itself is banned, not just this one call site."""
        for i, line in enumerate(SCRIPT.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            self.assertNotIn("| gh secret set", line,
                             msg=f"{SCRIPT.name}:{i} pipes into `gh secret set`; "
                                 "materialise and check the value first")


if __name__ == "__main__":
    unittest.main()
