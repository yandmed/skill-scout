# Security model

Skill Scout installs third-party instructions and code into an environment that can read your files and run commands. This document states what it defends against, how, and where those defenses stop.

## Threats considered

| Threat | Defense |
|---|---|
| Fake prerequisites ("install this first"), the most common technique in the wild | `pipe-to-shell`, `fake-prerequisite`, `password-protected-payload`, `quarantine-bypass` rules; AI audit question 2 |
| Malicious scripts | Pattern rules; credential + network correlation; AI audit reads every script |
| Prompt injection in natural language | AI audit, which compares stated purpose with actual behavior |
| Hidden text (zero-width, bidi, Unicode tags, HTML comments) | Dedicated rules; text is normalized before matching, so hidden characters can't split a keyword |
| Manipulating the auditor | Auditor has read-only tools and treats manipulation as evidence of malice; its verdict can only raise risk |
| An audit that didn't see everything | The auditor must declare coverage, and `record-audit` converts partial + benign to suspicious |
| The audit starting without its restrictions | The audit prompt tells the agent to stop if its instructions or read-only tools are missing; a test checks the agent wiring |
| Manipulating the orchestrating agent | Only the auditor subagent reads candidate files; registry text is sanitized and truncated; audit results reach the CLI as enums and short codes, with no free text in shell commands |
| Hooks, MCP servers, monitors and `bin/` executables | Flagged as high: they run outside the sandbox. Plugins are never installed by Skill Scout itself |
| Dynamic context (`` !`cmd` ``), which runs with no prompt on invocation | High; critical if it uses the network |
| Self-granted permissions (`allowed-tools: Bash`) | High when unrestricted or scoped to a powerful command such as `curl` or `security`; medium for other scoped grants |
| Malicious update after a trusted install | Pinned commit; updates go through full vetting; `verify` detects tampering |
| Swapping files between review and install | Content hash re-checked and full re-scan at install time; audit bound to the hash |
| Symlinks, path traversal, disguised binaries | Symlinks are never written; paths are validated; executables are detected by magic bytes; execute bits are dropped |

## Design principles

1. **Security is a gate, not a score.** It is never averaged with popularity.
2. **Risk only goes up.** The scanner and auditor are combined by taking the worse result, so a compromised auditor can't clear a scanner finding, and a scanner miss can't clear an auditor's concern.
3. **The gate is code, not a prompt.** `install` re-checks everything against the bytes on disk. There is no flag that overrides a critical finding.
4. **Minimal surface.** No runtime dependencies, no hooks, no MCP servers, nothing running in the background.
5. **Candidates are never executed.** Not during scanning, vetting or auditing.

## Known limits

Please read these. They are real.

- **A clean result is not proof of safety.** Research (MalSkillBench; Cloud Security Alliance, 2026) shows no tool or combination reliably detects everything. The scanner misses anything without a known pattern, and the auditor is an AI model that can be wrong or be fooled by an attack it hasn't seen.
- **Acknowledging high findings relies on the agent's instructions and on Claude Code's permission prompt.** `--ack` is a command-line flag, so the CLI can't tell who chose to pass it. `install` isn't pre-approved, so Claude Code normally asks you first; **in permissive modes (such as auto mode or `bypassPermissions`) that prompt may not appear.** Critical findings stay blocked in every mode.
- **The same applies to `record-audit`.** The CLI verifies an audit exists for the exact content, not that an auditor really ran.
- **AI judgment varies.** The same skill can get different verdicts across runs and models, especially in borderline cases.
- **The auditor's tool restriction depends on Claude Code resolving the agent.** A wrong name fails silently into a general agent with shell access. A test guards the name and the prompt tells the agent to stop, but the prompt is an instruction to a model, not an enforcement.
- **Files outside the candidate aren't reviewed.** Anything a skill fetches at runtime wasn't seen. The auditor flags this as `runtime-code-fetch` when it notices it.
- **A skill that passed can still behave differently depending on context,** since skills are instructions interpreted by a model at runtime.
- **Skill Scout only scans public GitHub repositories,** and plugins it vets can change between vetting and your install through `/plugin`, because Claude Code's plugin manager fetches them itself.
- **Registry signals can be gamed.** Stars and install counts are capped in the ranking and are never treated as evidence of safety.
- **The skills.sh and claude-plugins.dev APIs are not formally documented** as far as we could find. They may change, in which case those sources fail visibly and the search continues without them.

## What it accesses on your machine

- **Reads:** file names in your project, dependency manifests, `.gitignore`, the `enabledPlugins` key of Claude Code settings, and folder names in your skills directories. It never opens `.env` files or `~/.claude/.credentials.json`.
- **Writes:** `~/.skill-scout/` (quarantine and cache). With your approval: `.claude/skills/<name>/` and `.claude/skill-scout.lock.json`, or the same paths under `~/.claude/`.
- **Network:** `api.github.com` (with your `gh` token, sent to this host only), `raw.githubusercontent.com`, `skills.sh`, and `api.claude-plugins.dev`. Search terms go to all of them; project content goes to none.

## Reporting a problem

If you find a way past the install gate, or a malicious skill that passes, please open a private security advisory on this repository rather than a public issue.
