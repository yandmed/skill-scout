# Architecture

Skill Scout splits the work by what each side does well. **Code** handles anything that must be deterministic or enforced. **AI** handles anything that needs judgment. The AI can make the outcome stricter, but never more permissive.

```
 user request
      |
      v
 skills/scout/SKILL.md   orchestrates the conversation; never reads candidate files
      |
      |  skill-scout analyze ----> local profile: stack, gaps, what's installed
      |  skill-scout search  ----> 5 sources --> merge --> rank
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
| `agents/skill-auditor.md` | Read-only AI security audit |
| `bin/` | Launchers; Claude Code adds this folder to PATH |
| `scripts/scout.mjs` | CLI entry point |
| `scripts/lib/analyze.mjs` | Project profile and gap detection |
| `scripts/lib/sources.mjs` | Registry adapters |
| `scripts/lib/rank.mjs` | Explainable ranking |
| `scripts/lib/vet.mjs` | Quarantine download and audit record |
| `scripts/lib/scan.mjs`, `rules.mjs` | Static scanner and its rules |
| `scripts/lib/install.mjs` | Install gate, lockfile, lifecycle |
| `scripts/lib/report.mjs` | Keeps CLI output small enough for the model to read |
| `data/taxonomy.json` | Gaps and technologies: **edit this to teach Skill Scout new things** |

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
4. `agent:` must use the namespaced `skill-scout:skill-auditor`. With the bare name, Claude Code raises no error and **silently falls back to `general-purpose`**, which has shell access and uses the session's model. `test/plugin.test.mjs` guards this, and the audit prompt tells the agent to stop if it finds itself without its expected instructions and tools.

**A partial audit can't be benign, and that's enforced in code.** In one run an auditor whose reads were denied still answered `benign`. `record-audit` now requires `--coverage` and converts partial + benign to suspicious.

**The quarantine stays outside the project.** Inside the working directory, reads wouldn't need permission, but a candidate's nested `CLAUDE.md` or `.claude/skills` could get loaded automatically. Hostile files must never sit where Claude Code looks for configuration. For the same reason, don't add the quarantine with `--add-dir`, which loads `.claude/skills` from the added folder.

## How it was validated

- **Unit and adversarial tests** (`npm test`, 142 tests): attack samples, attempts to get past the gate, plugin wiring, and real false positives kept as regressions. Sabotaging the gate, the Unicode normalization and the ranking penalty, and putting the agent-name bug back, each made tests fail.
- **Real-world corpus:** 61 public skills, including official Anthropic ones. The first version falsely blocked 3. After tuning: 0 blocked, 6 requiring acknowledgement, 15 caution, 40 no known issues. These are mostly reputable skills, not a verified-clean set, so this measures false alarms and says nothing about detection on real malware.
- **AI auditor, live:** a data-theft skill with no detectable pattern, disguised as a table formatter (the scanner saw nothing), and a skill telling reviewers to report it as benign were both judged malicious. A legitimate control was judged benign. This is three samples: a sanity check rather than a measured detection rate.
- **Full flow, live,** in Claude Code 2.1.316 against a sample Next.js project: no permission denials, the expected agent, model and tools, all audits recorded, nothing installed without approval, US$ 0.86 to 1.09 per run with an Opus main session.
- **Install through a marketplace,** from a local folder, in an isolated configuration.

**Not yet tested:** an interactive session (all live runs used `claude -p`, where nobody can answer a permission prompt, so the approval step itself hasn't been exercised by a person), installing from GitHub, macOS and Linux.

To re-run the auditor samples, see `test/audit-samples/`.
