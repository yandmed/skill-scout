# Changelog

## 0.2.0

- **Ten sources:** added a catalog of skills from their makers and curated lists, Tessl, GitHub topics and plugin marketplaces. Files always come from Git at a pinned commit.
- **Conversation:** the workflow asks through dialogs, keeps working in the same turn, and picks up typed replies. Paste a link or `owner/repo` to review one skill.
- **Real diagnosis:** an isolated agent reads the project's code for concrete weaknesses. Another can research recommendations on the web.
- **Better ranking:** judged query by query, with the technology's maker ranked first, copies collapsed, and borrowed names marked.
- **Much stronger scanner:** about 25 new rules, look-alike letters, shell deobfuscation, base64 decoding, downloads followed through a file. Far fewer false alarms on real skills.
- **Fixed:** an unknown audit result passed the install gate; a crafted line could hang the scanner; a crafted `.gitignore` could hang the analysis; different candidates could share a quarantine folder; `.gitignore` was misread; YAML keys the parser skipped; a skill named `constructor`; Windows stream and device file names; links added after vetting; corrupt lockfiles being overwritten; redirects to other hosts.
- **Tests:** from 142 to about 4,200 cases, plus CI on Windows, macOS and Linux, and a mutation testing tool.

## 0.1.0

First version.

- `/skill-scout:scout`: project analysis, search across five sources, ranking, two-layer security vetting, recommendations and guarded installation.
- `/skill-scout:manage`: verify, update, remove, and audit local skills.
- `skill-auditor` subagent, run through the internal `audit` skill: read-only AI review of intent versus behavior. Audits must declare their coverage, and a partial audit never counts as benign.
- Install gate with content hash checks, pinned commits and a lockfile.
