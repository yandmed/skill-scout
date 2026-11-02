# Judgment calls

Read this when a recommendation isn't obvious.

## A security skill has findings for attack strings

Security skills often quote attacks as examples, so `instruction-override` or `pipe-to-shell` may fire on documentation. Don't dismiss this for the user. Tell them what fired, what the auditor concluded about the context, and let them acknowledge it. A malicious skill would use this same excuse, so "it's a security skill" is never enough on its own: the auditor must have read the context and found it consistent.

## A candidate is `blocked` but looks legitimate

Scanners do have false positives, and Skill Scout still offers no override. Tell the user which rule fired and where, and link to the source so they can judge it themselves. If they insist after reading it, explain that they can copy it manually at their own risk. Do not do that copy for them.

## Several skills cover the same gap

Prefer, in order: the one that fits this stack, the narrower scope, the one with fewer permissions, the better maintained one, then the more popular one. Installing two overlapping skills makes activation unpredictable, so recommend just one and mention the runner-up.

## Skill versus plugin

Prefer a plain skill when both solve the problem: it's instructions and files, and unlike a plugin it has no hooks, servers or monitors running in the background. Recommend a plugin when it provides something a skill can't, such as a real integration with an external service through MCP.

## Too many skills

Every installed skill adds to the context Claude scans for each task and can compete for activation. If the user already has many, say so, and suggest `/skill-doctor` to find ones they never use. Recommend fewer, better skills.

## No good result

Say so. Do not pad the list with weak matches. Offer to retry with different terms, or suggest writing a custom skill with `skill-creator`, since a project-specific need may not have a public skill.

## Maintenance signals

A skill is mostly instructions, so one that hasn't changed in a year may be fine if it covers something stable. For anything tied to a fast-moving API or framework, treat staleness as a real risk and mention it.

## License

No license means no permission to reuse, even when the repository is public. `Proprietary` or source-available terms (some official Anthropic document skills use them) may restrict use. Point these out; don't give legal advice.
