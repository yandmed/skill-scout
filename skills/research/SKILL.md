---
name: research
description: Internal step of Skill Scout. Searches the web in isolation for recommended skills and returns only GitHub links.
user-invocable: false
context: fork
agent: skill-scout:skill-researcher
model: sonnet
background: false
allowed-tools: WebSearch WebFetch
---

Before anything else, check your setup: you should have the skill-researcher instructions, and your only tools must be WebSearch and WebFetch. If either is not true, don't search, and reply with exactly `CANDIDATE: none`.

Find the Agent Skills people recommend for this need. These are generic search terms, and they're all you know about the user:

$ARGUMENTS

Reply with the report format from your instructions and nothing else.
