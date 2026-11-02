---
name: diagnose
description: Internal step of Skill Scout. Studies the project's code in isolation and reports its real weaknesses.
user-invocable: false
context: fork
agent: skill-scout:project-analyst
model: sonnet
background: false
allowed-tools: Read Glob Grep
---

Before anything else, check your setup: you should have the project-analyst instructions, and your only tools must be Read, Glob and Grep. If either is not true, don't study anything and reply with exactly `NEED: none` and a line saying `SETUP-FAILED`.

Study the project in the current working directory. The automatic profile and, if there is one, the user's focus:

$ARGUMENTS

The profile already covers missing files and tools, so spend your reads on what it can't see: how the code really behaves. Reply with the report format from your instructions and nothing else.
