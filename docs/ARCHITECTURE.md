# Architecture

Skill Scout splits the work by what each side does well. **Code** handles anything that must be deterministic or enforced. **AI** handles anything that needs judgment. The AI can make the outcome stricter, but never more permissive.

```
 user request
      |
      v
 skills/scout/SKILL.md   orchestrates the conversation, asks through dialogs; never reads candidate files
      |
      |  skill-scout analyze ----> local profile: stack, gaps, what's installed
      |  skills/diagnose (fork) -> agents/project-analyst: reads the real code, returns needs
      |  skill-scout search  ----> 10 sources --> merge --> rank --> collapse copies
      |  skills/research (fork) -> agents/skill-researcher: web, returns GitHub links only (optional)
      |  skill-scout resolve ----> pasted link or owner/repo --> candidate ids
      |  skill-scout vet     ----> pinned download to quarantine --> static scan
      |                                 |
      |  skills/audit (fork) <----------+  the turn waits for it
      |    agents/skill-auditor            read-only; reads the hostile content
      |        | RISK + COVERAGE + CODES
      |        v
      |  skill-scout record-audit       bound to the content hash; partial is never benign
      |
      |  user approves
      v
 skill-scout install     re-hash + re-scan + gate --> .claude/skills + lockfile
```

## Layout

| Path | Purpose |
|---|---|
| `skills/scout/` | Main conversational workflow |
| `skills/manage/` | Verify, update, remove, audit local skills |
| `skills/audit/` | Internal: runs the auditor in isolation and waits for its report |
| `skills/diagnose/`, `skills/research/` | Internal: run the code reader and web researcher in isolation |
| `agents/` | `skill-auditor`, `project-analyst` and `skill-researcher`, each with only the tools it needs |
| `bin/` | Launchers; Claude Code adds this folder to PATH |
| `scripts/scout.mjs` | CLI entry point |
| `scripts/lib/analyze.mjs` | Project profile and gap detection |
| `scripts/lib/sources.mjs` | Source adapters, merging, copy detection |
| `scripts/lib/resolve.mjs` | Pasted links and repository contents |
| `scripts/lib/gitignore.mjs` | Decides whether git would ignore a file, without running git |
| `scripts/build-catalog.mjs` | Maintainer tool that rebuilds `data/catalog.json` |
| `tools/mutation.mjs` | Breaks the code on purpose to measure whether the tests notice |
| `scripts/lib/rank.mjs` | Explainable ranking |
| `scripts/lib/vet.mjs` | Quarantine download and audit record |
| `scripts/lib/scan.mjs`, `rules.mjs` | Static scanner and its rules |
| `scripts/lib/install.mjs` | Install gate, lockfile, lifecycle |
| `scripts/lib/report.mjs` | Keeps CLI output small enough for the model to read |
| `data/taxonomy.json` | Gaps and technologies: **edit this to teach Skill Scout new things** |
| `data/publishers.json` | Known publishers and curated lists |
| `data/catalog.json` | Snapshot of their skills: names and locations only |

## Decisions, and why

**The plugin ships no hooks or MCP server.** Both run outside the sandbox. A tool that warns about them shouldn't need them.

**`bin/` launcher with exact-prefix permissions.** `allowed-tools` pre-approves `skill-scout vet *`, not `node *scout.mjs*`. A pattern on the script path would also match a file named `scout.mjs` inside a quarantined candidate, letting a hostile package run under a pre-approval. `install` and `remove` are left out on purpose, so they prompt.

**Zero runtime dependencies.** A supply-chain tool shouldn't add a supply chain. Node's built-in `fetch`, `crypto` and test runner are enough. This is also why the frontmatter parser is small and non-executing.

**Downloads use raw files pinned to a commit, one at a time.** That avoids unpacking archives (zip slip, symlink tricks) and lets every path be validated. Walking the tree down to the skill's folder also works on monorepos too large for a recursive listing.

**The token goes only to `api.github.com`.** Downloads are unauthenticated, so they can't leak it.

**Scanner severity depends on where a pattern appears.** `curl | bash` in a script runs; in a Markdown file it's a claim that needs reading, and legitimate install guides contain it. It's critical in code, high in docs. On a real corpus, this kind of distinction removed all three false blocks without weakening detection of active commands (see below).

**Comments weaken execution rules, not instruction rules.** A comment can't run, but it's a fine place to hide text aimed at a model.

**Audit results cross into the shell as enums and kebab-case codes.** Free text from a model that has read hostile content must never be interpolated into a command.

**Ranking caps popularity.** Fit is worth up to 45 points, trust 30, adoption 15, maintenance 10. No topical match scores zero, whatever the stars. Skills for technologies the project doesn't use are heavily penalized, unless the user asked for them.

**Auditor runs on Sonnet.** It matched Opus on the adversarial samples at about US$ 0.04 to 0.06 per small skill. It does judge borderline cases differently: on one real skill pre-approving `Bash(security:*)`, Opus said suspicious and Sonnet said a minor oddity. So when a risk can be stated objectively, it belongs in the scanner, which gives the same answer every run. That's why `powerful-preapproval` exists. To change the model, edit `model` in both `agents/skill-auditor.md` and `skills/audit/SKILL.md`.

**The audit runs as a blocking forked skill, not a plain subagent.** This one came from four failed end-to-end runs, so the reasoning is worth keeping:

1. A skill's `allowed-tools` lasts only for the turn that invoked it, and subagents run in the background by default. When the main agent ended its turn, the auditors lost access to the files and `record-audit` lost its pre-approval.
2. `context: fork` with `background: false` makes the turn wait, which solves that.
3. Invoking a skill that has `allowed-tools` itself needs permission, hence `Skill(skill-scout:audit)` in the callers' `allowed-tools`.
4. `agent:` must use the namespaced `skill-scout:skill-auditor`. With the bare name, Claude Code raises no error and **silently falls back to `general-purpose`**, which has shell access and uses the session's model. `tests/plugin.test.mjs` guards this, and the audit prompt tells the agent to stop if it finds itself without its expected instructions and tools.

**A partial audit can't be benign, and that's enforced in code.** In one run an auditor whose reads were denied still answered `benign`. `record-audit` now requires `--coverage` and converts partial + benign to suspicious.

**The quarantine stays outside the project.** Inside the working directory, reads wouldn't need permission, but a candidate's nested `CLAUDE.md` or `.claude/skills` could get loaded automatically. Hostile files must never sit where Claude Code looks for configuration. For the same reason, don't add the quarantine with `--add-dir`, which loads `.claude/skills` from the added folder.

**Discover anywhere, download from Git.** Every source only produces a repository and a path. The files always come from GitHub at a pinned commit, so a site can recommend a skill but can't deliver something different from what gets reviewed. That's also why other Git hosts aren't supported: they have almost no skills and no anonymous search, and each one would be a new download path to defend.

**A catalog snapshot ships with the plugin.** It makes searching known publishers instant, free of API calls, and possible when rate limited. A stale entry costs little, since vetting always reads the current files. It's refreshed through a pull request, so changes get reviewed.

**Sources we chose not to use.** SkillsMP, claudemarketplaces and mdskills disallow automated access in `robots.txt` or their terms, or have terms we couldn't read, so they need the owner's permission first. ClawHub has a record of large malware campaigns, and many of its skills have no Git origin to pin. Smithery's search was returning errors. The rest need credentials or don't name a repository.

**Dialogs keep the permissions alive.** A skill's pre-approvals end when the user sends a new message, but answering `AskUserQuestion` happens inside the turn. So decisions with clear options go through dialogs. For a typed reply, the workflow invokes itself again to get its permissions back.

**The scanner is tuned against both errors.** Attack techniques live in `tests/scanner-attacks.test.mjs` and ordinary text in `tests/scanner-benign.test.mjs`. A pattern only earns a severity after being checked on real public skills: the first run over 400 of them falsely blocked 9, all fixed and kept as regressions.

## How it was validated

- **Automated tests** (`npm test`, about 4,200 cases): every combination of inputs to the install gate, attack techniques in disguise, ordinary text that must not alarm, hostile repositories and registry responses on a fake network, every taxonomy entry, seeded random input, and the real CLI in separate processes. Many cases are generated from tables, so the count says less than it seems. Passing on Windows and on Ubuntu, with Node 20 and 22.
- **Real-world corpus:** 400 public skills sampled from the catalog. The first run falsely blocked 9. After tuning on that same sample: 0 blocked, 92 requiring acknowledgement (61 of them for pre-approving unrestricted shell access, a real capability worth a decision), 68 caution, 240 no known issues. These are mostly reputable skills, not a verified-clean set, so this measures false alarms and says nothing about detection.
- **Detection, measured:** see "Measured results" in `SECURITY.md`. On a public benchmark's held-out sources, the scanner plus auditor flagged 39 of 40 malicious samples and 5 of 40 legitimate ones. The scanner alone flags far fewer, which is why both layers exist.
- **AI auditor, hand-written samples:** a data-theft skill with no detectable pattern, and a skill telling reviewers to report it as benign, were both judged malicious, and a legitimate control benign (`tests/audit-samples/`).
- **Full flow, live,** in Claude Code 2.1.316 against a sample Next.js project: no permission denials, the expected agents and tools, all audits recorded, nothing installed without approval.
- **A simulated customer** answered real dialogs and permission prompts through the Agent SDK: the workflow read the code, opened its dialog, continued in the same turn, hit the permission prompt on install, and installed only the chosen skill, for US$ 0.63 with a Sonnet session. Turning everything down installed nothing, a denied install was reported plainly, and a typed change of direction resumed the workflow with its permissions back.
- **Install from GitHub** with `/plugin marketplace add yandmed/skill-scout`, in an isolated configuration, and the installed launcher ran. CI passes on Windows, macOS and Linux with Node 20 and 22.
- **Install through a marketplace,** from a local folder, in an isolated configuration.

**Not yet tested:** a person using it in a terminal or editor (the simulated customer drives the same prompts through the SDK, not the on-screen dialogs), and the full workflow on macOS or Linux, where only the automated tests have run.

To re-run the auditor samples, see `tests/audit-samples/`.
