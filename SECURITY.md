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
| Keyword-gated payloads ("if the user mentions X, first run scripts/_x.py") | `gated-trigger` and `hidden-bootstrap-script` rules |
| Reverse shells, secret uploads, DNS exfiltration, built-in Windows download tools, miners | Dedicated rules, critical in scripts and high in documentation |
| Disguised commands (`c"u"r"l`, `${IFS}`, look-alike letters, base64, a download run several lines later) | Text is normalized and deobfuscated before matching; base64 is decoded and scanned; downloaded paths are followed through the file |
| A hostile file built to hang the scanner | Regexes are checked against pathological input by tests, long lines are scanned in bounded windows, and `.gitignore` patterns use a matcher with bounded cost |
| Text in a registry listing aimed at the orchestrating model | Candidates with steering text in the name are dropped, and such descriptions are replaced before the model sees them |
| Web pages and project files steering the agents that read them | Each runs in an isolated, tool-restricted agent. The researcher can only hand back links, which still go through full vetting |
| A repository impersonating a known publisher | Publisher status is matched by exact repository, and a skill reusing a known publisher's name from elsewhere is marked and ranked down |
| File names that mean something else on disk (NTFS streams, device names, case collisions) | Blocked and never written |
| Malicious update after a trusted install | Pinned commit; updates go through full vetting; `verify` detects tampering |
| Swapping files between review and install | Content hash re-checked and full re-scan at install time; audit bound to the hash |
| Symlinks, path traversal, disguised binaries | Symlinks are never written, and any link out of the repository blocks; paths are validated; executables are detected by magic bytes; execute bits are dropped |
| A tampered vetting record or lockfile | An unknown audit result fails closed; a record must match its id; the scan is redone at install; a corrupt lockfile is an error, and impossible entries are ignored |

## Measured results

Measured on the public [MaliciousSkillBench](https://github.com/protectskills/MaliciousSkillBench), using its source-disjoint test split, whose sources were not used to tune anything. Each sample is a single `SKILL.md` text, so bundled scripts aren't part of this measure.

| | Malicious skills | Legitimate skills |
|---|---|---|
| Scanner alone flags (high or critical), all 1,380 samples | 7.5% of 839 | 9.2% of 541 |
| Scanner + AI auditor flags, sample of 80 | 39 of 40 (97.5%) | 5 of 40 (12.5%) |
| Scanner + AI auditor refuses outright, same sample | 22 of 40 (55%) | 0 of 40 |

"Flags" means the user has to read the reason and decide. "Refuses" means it can't be installed.

How to read this:

- **The sample is small.** With 40 per class, the 95% confidence intervals are roughly 87% to 99.6% for flagged malicious, 5% to 26% for flagged legitimate, and 40% to 69% for refused malicious.
- **Most samples in this split come from one source** (SkillHarm), so other kinds of attack may do worse.
- **The auditor was calibrated once.** The first version flagged 36 of 40 malicious and 20 of 40 legitimate samples on another slice of this same split. Its instructions were then changed by looking at a separate validation split, and the numbers above come from samples not used before. The verdict codes of that first slice were seen, but not its texts.
- **The scanner's first frozen run** on this split was 7.5% and 12.6%. The 9.2% comes after later fixes for false alarms found on real public skills, not on this split.
- **False alarms on real skills:** on a fresh random sample of 297 public skills, 4 were falsely blocked (1.3%) before those fixes, which were then kept as regressions. There's no fresh measure after them yet.
- **Other tools' published numbers used different splits, thresholds or settings,** so they aren't directly comparable.

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
- **Skill Scout only reviews public GitHub repositories.** Other hosts hold very little skill content and offer no anonymous search, so they are not supported. Also, plugins it vets can change between vetting and your install through `/plugin`, because Claude Code's plugin manager fetches them itself.
- **Registry signals can be gamed.** Stars and install counts are capped in the ranking and are never treated as evidence of safety.
- **The skills.sh, claude-plugins.dev and Tessl APIs are not formally documented or are marked experimental,** as far as we could find. They may change, in which case those sources fail visibly and the search continues without them. A registry's own quality score is shown as information and never counts as a security result.
- **Being on the publisher list raises ranking, not safety.** A vendor's repository can be compromised, so its skills go through the same review.
- **The project analyst and web researcher are told what not to do, but can't be forced.** A plugin can't restrict file paths, so the instruction not to open `.env` files is followed by a model rather than enforced. The automatic profile (`analyze`) does enforce it, in code.

## What it accesses on your machine

- **Reads, automatically:** file names in your project, dependency manifests, `.gitignore`, the `enabledPlugins` key of Claude Code settings, and folder names in your skills directories. It never opens `.env` files or `~/.claude/.credentials.json`.
- **Reads, through the project analyst:** up to about 15 of your project's files, which pass through your session's AI model as in any Claude Code use.
- **Writes:** `~/.skill-scout/` (quarantine and cache). With your approval: `.claude/skills/<name>/` and `.claude/skill-scout.lock.json`, or the same paths under `~/.claude/`.
- **Network:** `api.github.com` (with your `gh` token, sent to this host only), `raw.githubusercontent.com`, `skills.sh`, `api.claude-plugins.dev`, and `api.tessl.io`, plus whatever pages the web researcher opens when it is used. Search terms go to these services; project content goes to none. Redirects to another host are refused.

## Reporting a problem

If you find a way past the install gate, or a malicious skill that passes, please open a private security advisory on this repository rather than a public issue.
