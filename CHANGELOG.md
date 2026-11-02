# Changelog

## 0.1.0

First version.

- `/skill-scout:scout`: project analysis, search across five sources, ranking, two-layer security vetting, recommendations and guarded installation.
- `/skill-scout:manage`: verify, update, remove, and audit local skills.
- `skill-auditor` subagent, run through the internal `audit` skill: read-only AI review of intent versus behavior. Audits must declare their coverage, and a partial audit never counts as benign.
- Install gate with content hash checks, pinned commits and a lockfile.
