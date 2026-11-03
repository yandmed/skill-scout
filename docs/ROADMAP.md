# Roadmap

Ideas are ordered by value to the user. Nothing here is built yet.

## Next

- **Measure detection on more data.** The published numbers use 40 samples per class, mostly from one source. A larger run, with whole packages rather than single files, would narrow the uncertainty.
- **Well-known indexes.** Some vendors publish `/.well-known/agent-skills/index.json` with content digests, which could confirm a download matches what the vendor published.
- **Plugin evals.** Add `claude plugin eval` cases so that changes to the `SKILL.md` workflow are tested, not just the CLI.
- **Better fit scoring.** Keyword overlap still ranks some generic matches too high. The agent corrects this when choosing finalists, but a better first pass would reduce cost.

## More sources

- SkillsMP, claudemarketplaces and mdskills, if their owners allow it.
- GitLab and other Git hosts, if meaningful skill content appears there.
- A shared blocklist of confirmed malicious skills.

## More useful recommendations

- **Remembering preferences:** skills the user rejected and why, so they aren't suggested again.
- **Team mode:** a shared policy file listing allowed sources, minimum requirements and banned rules.
- **Overlap detection:** warn when a new skill's description competes for activation with an installed one.
- **Usage feedback:** use `/skill-doctor` data to suggest removing skills that are never activated.
- **Create when nothing fits:** if no public skill covers the gap, offer to draft a project-specific one.

## Staying current

- **Periodic checks:** a scheduled `verify` and `outdated`, with a summary when something changes.
- **New-skill alerts:** tell the user when a strong new skill appears for one of their open gaps.
- **Update diffs:** show what changed between the pinned version and the new one in plain language before re-vetting.

## Distribution

- Submit to the official plugin directory.
- Offer an English README alongside the Portuguese one.
- Support other agents that use the Agent Skills format (Codex, Cursor and others), which mainly means new install paths.
