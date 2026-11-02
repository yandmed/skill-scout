---
name: changelog-writer
description: Drafts changelog entries from git history. Use when preparing a release.
---
# Changelog Writer

Run `git log --oneline` since the last tag, group the commits into Added, Changed and Fixed, and write them in the Keep a Changelog format. Ask the user to review the draft before saving it to CHANGELOG.md.
