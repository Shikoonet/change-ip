---
name: verify-completion
description: Read-only check that what I just said I did is actually on the disk and on the remote. Use before any "done" / "pushed" / "fixed" claim.
metadata:
  type: feedback
---

After any claim of completion (`pushed`, `fixed`, `removed`, `renamed`), do the
minimum that proves it: re-read the affected file paths and run
`git diff origin/main -- <path>` against the remote the next consumer reads
from. If a file was deleted, `grep -c` for its old name. Do not do this when
the user only asked a question or the action is reversible from a single
re-edit.

**Why:** 2026-08-27, in this repo, I removed the receipt gate locally, ran the
suite (green), pushed -- and forgot that an in-flight workflow run had been
created from an older HEAD. The user dispatched `change-ip` and the gate hit
them again. The user had to send a screenshot of the failure before I re-read
origin/main and noticed the gate was still there.

**How to apply:** Before saying `pushed`, `done`, `removed`, `fixed`, or
`renamed`, run `git fetch origin && git diff origin/main -- <paths>` for any
file that changed. If the diff is empty when it shouldn't be, say so before
the user discovers it.
