// Static scanner. It only reads bytes: nothing in the scanned directory is ever executed,
// imported or interpreted.
//
// This is one detection layer, not proof of safety. Published research (MalSkillBench, CSA 2026)
// shows pattern scanners miss natural-language attacks, so a clean result is reported as
// "no-known-issues", never as "safe", and the AI auditor reviews intent separately.
import { readFileSync, statSync } from 'node:fs';
import { basename, dirname, relative, sep } from 'node:path';
import { parseFrontmatter } from './frontmatter.mjs';
import {
  AGENT_CONFIG_FILE, ARCHIVE_EXT, BUILTIN_COMMANDS, CODE_EXT, CONFUSABLES, DOC_EXT, EXECUTABLE_EXT, HIDDEN_UNICODE, LINE_RULES, MEDIA_EXT, SEVERITY_ORDER,
} from './rules.mjs';
import { hashDirectory, listFilesRecursive, listLinks, sanitizeText } from './util.mjs';

const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const OFFICIAL_OWNERS = new Set(['anthropics']);

const CODE_COMMENT = /^\s*(?:\/\/|#(?!!)|\/\*|\*(?:\s|$)|--\s|;|REM\s|<#)/i;

const isBinaryBuffer = (buf) => buf.subarray(0, 8000).includes(0);

function hasExecutableMagic(buf) {
  if (buf.length < 4) return false;
  if (buf[0] === 0x4d && buf[1] === 0x5a) return true; // PE (MZ)
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return true; // ELF
  const magic = buf.readUInt32BE(0);
  return [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(magic); // Mach-O
}

/** ZWJ/variation selectors are legitimate inside emoji, so they never count as hidden text. */
const CONFUSABLE_RE = new RegExp('[' + Object.keys(CONFUSABLES).join('') + ']', 'g');
const CYRILLIC_OR_LOOKALIKE = /[\u0400-\u04FF\u03BF\u039F]/;
const WORD_RE = /[\p{L}]{2,}/gu;

/** True when one word mixes Latin letters with Cyrillic ones: real Russian or English text never does. */
export const hasMixedScriptWord = (line) => (line.match(WORD_RE) ?? []).some((word) => /[A-Za-z]/.test(word) && CYRILLIC_OR_LOOKALIKE.test(word));

const normalizeForMatching = (line) => line
  .normalize('NFKC')
  .replace(/[​-‍⁠﻿­]/g, '')
  .replace(/[\u{E0000}-\u{E007F}]/gu, '')
  .replace(CONFUSABLE_RE, (ch) => CONFUSABLES[ch]);

/** The same command with shell obfuscation undone: c"u"r"l, c\url and curl${IFS}x all read as curl. */
export const shellDeobfuscate = (line) => line
  .replace(/\$\{IFS\}|\$IFS\b/g, ' ')
  .replace(/(?<=[A-Za-z0-9_-])(?:""|''|\\)(?=[A-Za-z0-9_-])/g, '')
  .replace(/(?<=[A-Za-z0-9_-])"([A-Za-z0-9_-]{1,8})"(?=[A-Za-z0-9_-]|\s|$|[|;&])/g, '$1')
  .replace(/(?<=[A-Za-z0-9_-])'([A-Za-z0-9_-]{1,8})'(?=[A-Za-z0-9_-]|\s|$|[|;&])/g, '$1');

// A Dockerfile runs inside a container build, and a data literal only describes a command, so
// neither gets the "this will run on your machine" severity. A person still decides.
const CONTAINER_FILE = /(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$/i;
const DATA_LITERAL = /^\s*["'][\w.$-]+["']\s*:\s*["']/;
// Signatures and certificates are long encoded text by nature, and they decode to nothing readable.
const SIGNATURE_FILE = /\.(?:sig|asc|crt|cer|pem|pub)$/i;
// Quoting an attack in order to warn about it is what careful skills do.
// A line that prints a command shows it to a person; it doesn't run it.
const PRINTS_TEXT = /^\s*(?:(?:echo|printf)\s+(?:-\w+\s+)*(["']).*\1|(?:print|console\.(?:log|error))\(\s*(["'\x60]).*\2\s*\)|Write-(?:Host|Output)\s+(["']).*\3)\s*(?:>&2|1>&2)?\s*;?\s*$/;
// "Never do X without asking the user" and "don't show the token to the user" protect the user.
const PROTECTIVE_CONCEALMENT = /\b(?:do\s+not|don't|never|must\s+not|should\s+not)\b[^\n]*\bwithout\s+asking\b|\b(?:do\s+not|don't|never)\s+(?:show|reveal|display)\b[^\n]{0,30}\b(?:user|human)\b[^\n]*\b(?:token|secret|key|password|credential)|\b(?:token|secret|key|password|credential)[^\n]*\b(?:do\s+not|don't|never)\s+(?:show|reveal|display)\b/i;
// A row in a Markdown table describes something; a command to run isn't written that way.
const TABLE_ROW = /^\s*\|/;
// Holding back a draft isn't hiding an action, unless the same line does something too.
const WITHHOLDS_OUTPUT = /\b(?:do\s*n[o']t|never)\s+(?:show|present|display)\b/i;
const NAMES_AN_ACTION = /\b(?:send|upload|post|exfiltrate|curl|wget|install|download|execute|delete|token|secret|credential|password|key)s?\b/i;
const QUOTED_OVERRIDE = /["'\x60\u201C\u2018]\s*(?:ignore|disregard|forget|override)\b/i;

/** Matching is split into windows so a very long line can neither hide a payload nor stall a regex. */
const WINDOW = 20000;
const OVERLAP = 1000;
function* windows(text) {
  if (text.length <= WINDOW) {
    yield text;
    return;
  }
  for (let start = 0; start < text.length; start += WINDOW - OVERLAP) yield text.slice(start, start + WINDOW);
}

/** Base64 runs that decode to readable text are read as what they really say. */
const B64_RE = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])/g;
export function decodeBase64Runs(text) {
  const out = [];
  for (const [run] of text.matchAll(B64_RE)) {
    if (run.length > 100000) continue;
    const decoded = Buffer.from(run, 'base64').toString('utf8');
    if (decoded.includes('\uFFFD') || /[\u0000-\u0008\u000E-\u001F]/.test(decoded)) continue;
    out.push(decoded);
  }
  return out;
}

const EXEC_PATH_CAPTURE = /\b(?:curl|wget)\b[^\n]*?(?:\s-[oO]\s*|--output[=\s]|--output-document[=\s]|>\s*)["']?([~$\w./-]+)|\bbase64\s+(?:-d|-D|--decode)\b[^\n]*?>\s*["']?([~$\w./-]+)/gi;

/** Finds a file that was downloaded or decoded in one place and executed in another. */
export function findDownloadThenRun(text) {
  for (const match of text.matchAll(EXEC_PATH_CAPTURE)) {
    const target = match[1] ?? match[2];
    if (!target || target === '-' || target === '/dev/null') continue;
    const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const after = text.slice(match.index + match[0].length);
    const run = new RegExp(String.raw`(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\b(?:python[0-9.]*|node|perl|ruby)\s+|\bsource\s+|\bchmod\s+\+x\s+|(?:^|[;&|]\s*))["']?${escaped}(?=["'\s;&|]|$)`, 'm');
    if (run.test(after)) return { index: match.index, target };
  }
  return null;
}

function excerpt(line) {
  const visible = line.replace(/[​-‏‪-‮⁠-⁩﻿­]/g, '␣')
    .replace(/[\u{E0000}-\u{E007F}]/gu, '␣');
  return sanitizeText(visible, 160);
}

function scanText({ rel, text, isDoc, isCode, push }) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  // Rejoin shell continuations so a command cannot dodge a rule by spanning two lines.
  const logical = [];
  for (let i = 0; i < lines.length; i += 1) {
    let current = lines[i];
    const start = i;
    while (current.endsWith('\\') && i + 1 < lines.length) {
      i += 1;
      current = `${current.slice(0, -1)} ${lines[i].trim()}`;
    }
    logical.push({ number: start + 1, text: current });
  }

  for (const { number, text: raw } of logical) {
    if (raw.length > 5000 && isCode) {
      push({ ruleId: 'minified-code', severity: 'medium', file: rel, line: number, excerpt: `${raw.length} characters on one line`, message: 'Very long line: minified or obfuscated code cannot be reviewed.' });
    }
    for (const rule of HIDDEN_UNICODE) {
      if (rule.pattern.test(raw)) push({ ruleId: rule.id, severity: rule.severity, file: rel, line: number, excerpt: excerpt(raw), message: rule.message });
    }
    const normalized = normalizeForMatching(raw);
    const deobfuscated = shellDeobfuscate(normalized);
    if (hasMixedScriptWord(raw.normalize('NFKC'))) {
      push({ ruleId: 'mixed-script-word', severity: 'high', file: rel, line: number, excerpt: excerpt(raw), message: 'A word mixes letters from different alphabets, a way to disguise text from people and scanners.' });
    }
    for (const decoded of decodeBase64Runs(normalized)) {
      const payload = LINE_RULES.find((rule) => rule.severity === 'critical' && decoded.split('\n').some((part) => rule.pattern.test(shellDeobfuscate(normalizeForMatching(part)))));
      if (payload) push({ ruleId: 'encoded-payload', severity: 'critical', file: rel, line: number, excerpt: excerpt(decoded), message: `Base64 text decodes to something dangerous (${payload.id}).` });
    }
    for (const rule of LINE_RULES) {
      if (rule.scope === 'code' && !isCode) continue;
      if (rule.scope === 'docs' && !isDoc) continue;
      const hit = [...windows(normalized)].some((w) => rule.pattern.test(w))
        || (rule.executable && [...windows(deobfuscated)].some((w) => rule.pattern.test(w)));
      if (!hit) continue;
      // A comment can't execute, so rules about execution weaken there. Rules about instructions
      // don't: a comment is exactly where text aimed at the model would hide.
      const inert = isCode && rule.executable && CODE_COMMENT.test(normalized);
      let severity = isDoc && rule.severityInDocs ? rule.severityInDocs : rule.severity;
      if (rule.executable && severity === 'critical' && (CONTAINER_FILE.test(rel) || DATA_LITERAL.test(normalized) || PRINTS_TEXT.test(normalized) || (isDoc && TABLE_ROW.test(normalized)))) severity = 'high';
      if (rule.id === 'instruction-override' && QUOTED_OVERRIDE.test(normalized)) severity = 'medium';
      if (inert) severity = 'low';
      let tag = isDoc && 'tagInDocs' in rule ? rule.tagInDocs : rule.tag;
      if (inert) tag = undefined;
      if (rule.id === 'concealment' && WITHHOLDS_OUTPUT.test(normalized) && !NAMES_AN_ACTION.test(normalized)) tag = undefined;
      if (rule.id === 'concealment' && PROTECTIVE_CONCEALMENT.test(normalized)) {
        severity = 'low';
        tag = undefined;
      }
      push({
        ruleId: rule.id,
        severity,
        tag: tag ?? undefined,
        file: rel,
        line: number,
        excerpt: excerpt(raw),
        message: rule.message,
      });
    }
    const blob = normalized.match(/(?<![A-Za-z0-9+/:,])[A-Za-z0-9+/]{240,}={0,2}/);
    if (blob && !SIGNATURE_FILE.test(rel) && !/data:(?:image|font)\//.test(normalized) && !/\b(?:sha(?:1|256|384|512)|integrity)\b/i.test(normalized)) {
      push({ ruleId: 'encoded-blob', severity: 'high', file: rel, line: number, excerpt: `${blob[0].slice(0, 40)}… (${blob[0].length} chars)`, message: 'Long encoded blob: the content cannot be reviewed as written.' });
    }
  }

  const chained = findDownloadThenRun(text);
  if (chained) {
    const line = text.slice(0, chained.index).split('\n').length;
    push({ ruleId: 'download-then-run', severity: 'high', file: rel, line, excerpt: excerpt(chained.target), message: 'Downloads or decodes a file and later runs it.' });
  }

  if (isDoc) {
    // Comments are invisible once rendered, so anything instruction-like inside one is hidden from a human reviewer.
    for (const match of text.matchAll(/<!--([\s\S]*?)-->/g)) {
      const inner = match[1];
      const line = text.slice(0, match.index).split('\n').length;
      // Templates often carry long, harmless comments, so only text addressing the model or
      // performing an action is treated as an attack; other long comments are just worth a look.
      const aimedAtModel = /\b(?:assistant|claude|llm|language model|ai agent|system prompt|disregard|exfiltrate|curl|wget)\b|\bignore\s+(?:all|any|the|previous|above|prior|these|your)\b|\b(?:send|upload|post)\b[^\n]{0,40}\bto\b|\bdo not (?:tell|inform|show)\b/i.test(inner);
      if (aimedAtModel) {
        push({ ruleId: 'hidden-html-comment', severity: 'high', file: rel, line, excerpt: excerpt(inner), message: 'Instruction-like text inside an HTML comment: invisible when rendered, visible to the model.' });
      } else if (inner.length > 200) {
        push({ ruleId: 'long-html-comment', severity: 'medium', file: rel, line, excerpt: excerpt(inner), message: 'Long HTML comment: invisible when rendered, but the model reads it.' });
      }
    }
    const fenced = /^```!\s*$/m.test(text);
    const inlineMatches = [...text.matchAll(/(?<![^\s(])!`([^`\n]+)`/g)];
    for (const match of inlineMatches) {
      const line = text.slice(0, match.index).split('\n').length;
      const networked = /\b(?:curl|wget|nc|iwr|irm|invoke-webrequest|ssh|scp)\b/i.test(match[1]);
      push({
        ruleId: 'dynamic-injection',
        severity: networked ? 'critical' : 'high',
        file: rel,
        line,
        excerpt: excerpt(match[1]),
        message: networked
          ? 'Dynamic injection runs a network command the moment the skill is invoked, with no prompt.'
          : 'Dynamic injection runs a shell command the moment the skill is invoked, with no prompt.',
      });
    }
    if (fenced) {
      const line = text.slice(0, text.search(/^```!\s*$/m)).split('\n').length;
      push({ ruleId: 'dynamic-injection', severity: 'high', file: rel, line, excerpt: '```! block', message: 'Dynamic injection block runs shell commands when the skill is invoked, with no prompt.' });
    }
  }
}

function scanSkillManifest({ rel, text, push, context }) {
  const { data, hasFrontmatter, unparsed } = parseFrontmatter(text);
  const skillName = data.name || basename(dirname(rel)) || '';
  if (!hasFrontmatter) {
    push({ ruleId: 'no-frontmatter', severity: 'medium', file: rel, line: 1, excerpt: '', message: 'SKILL.md has no frontmatter, so it does not follow the Agent Skills spec.' });
    return;
  }
  if (unparsed?.length) {
    push({ ruleId: 'unparsed-frontmatter', severity: 'high', file: rel, line: 1, excerpt: sanitizeText(unparsed[0], 120), message: 'Frontmatter uses YAML this scanner does not read, so settings could be hiding in it.' });
  }
  if (typeof data.name === 'string' && BUILTIN_COMMANDS.has(data.name)) {
    push({ ruleId: 'shadows-builtin', severity: 'medium', file: rel, line: 2, excerpt: data.name, message: 'Name matches a built-in Claude Code command, which it could take the place of.' });
  }
  if (data.name && !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(data.name)) {
    const nonAscii = /[^\u0000-\u007F]/.test(data.name);
    push({ ruleId: nonAscii ? 'homoglyph-name' : 'invalid-name', severity: nonAscii ? 'high' : 'low', file: rel, line: 2, excerpt: sanitizeText(data.name, 80), message: nonAscii ? 'Skill name has non-ASCII characters that can imitate another name.' : 'Name does not follow the Agent Skills spec.' });
  }
  if (!data.description) {
    push({ ruleId: 'no-description', severity: 'medium', file: rel, line: 1, excerpt: '', message: 'No description: you cannot tell what this skill is for or when it activates.' });
  } else {
    if (String(data.description).length > 1536) {
      push({ ruleId: 'long-description', severity: 'low', file: rel, line: 1, excerpt: `${String(data.description).length} chars`, message: 'Description is over the 1,536 characters Claude Code keeps in the skill listing.' });
    }
    if (/\balways\s+(?:use|invoke|activate|load|run|trigger)\s+(?:this\s+(?:skill\s+)?)?(?:(?:for|on|in|at|before)\s+)?(?:all|every|any|each|anything|first)\b|\buse\s+(?:this\s+)?(?:skill\s+)?(?:for|on|in|at)\s+(?:all|every|any)\s+(?:task|request|message|prompt|conversation|session)s?\b|\b(?:always|must)\s+(?:be\s+)?(?:use|load|invoke|activate)d?\b(?:\s+this\s+skill)?\s+(?:first|before)/i.test(String(data.description))) {
      push({ ruleId: 'trigger-hijack', severity: 'high', file: rel, line: 1, excerpt: sanitizeText(data.description, 160), message: 'Description tries to force activation on every task, which would keep its instructions always in play.' });
    }
  }
  if (data.hooks) {
    push({ ruleId: 'skill-hooks', severity: 'high', file: rel, line: 1, excerpt: sanitizeText(data.hooks, 160), message: 'Skill declares hooks: commands that run on agent events, outside Claude\'s tool permissions.' });
  }
  const tools = [].concat(data['allowed-tools'] ?? []).join(' ');
  if (tools) {
    if (/(?:^|[\s,])Bash(?:\(\s*\*(?::\*)?\s*\))?(?=$|[\s,])|(?:^|[\s,])\*(?=$|[\s,])/.test(tools)) {
      push({ ruleId: 'unrestricted-tools', severity: 'high', file: rel, line: 1, excerpt: sanitizeText(tools, 160), message: 'Pre-approves unrestricted shell access, skipping permission prompts while the skill runs.' });
    } else if (/\b(?:Bash|PowerShell)\(\s*(?:security|curl|wget|nc|ncat|ssh|scp|sh|bash|zsh|pwsh|powershell|sudo|rm|printenv|env|eval)(?=[\s:)*])/i.test(tools)) {
      // These reach credentials or the network, or run anything at all, so a "scoped" grant
      // adds little. AI auditors disagree on this between runs, so the rule is deterministic.
      push({ ruleId: 'powerful-preapproval', severity: 'high', file: rel, line: 1, excerpt: sanitizeText(tools, 160), message: 'Pre-approves a command that can reach credentials or the network, or run other commands, with no permission prompt.' });
    } else if (/\b(?:Bash|PowerShell|Write|Edit|WebFetch|mcp__)/.test(tools)) {
      push({ ruleId: 'preapproved-tools', severity: 'medium', file: rel, line: 1, excerpt: sanitizeText(tools, 160), message: 'Pre-approves tools that can change files or run commands.' });
    }
  }
  if (data.license && /proprietary|all rights reserved/i.test(String(data.license))) {
    push({ ruleId: 'restrictive-license', severity: 'medium', file: rel, line: 1, excerpt: sanitizeText(data.license, 120), message: 'License restricts use or redistribution; check its terms.' });
  }
  const owner = (context.repo || '').split('/')[0]?.toLowerCase();
  if (context.repo && !OFFICIAL_OWNERS.has(owner) && /\b(?:official\s+(?:anthropic|claude)|anthropic[- ]official|by\s+anthropic|from\s+anthropic|made\s+by\s+anthropic)\b/i.test(`${skillName} ${data.description ?? ''}`)) {
    push({ ruleId: 'impersonation', severity: 'high', file: rel, line: 1, excerpt: sanitizeText(data.description, 160), message: 'Claims to be from Anthropic, but the repository is not an Anthropic one.' });
  }
}

function scanPluginSurface({ rel, text, push }) {
  const name = basename(rel);
  if (rel.endsWith('hooks/hooks.json')) {
    const runsAtStart = /SessionStart|UserPromptSubmit|PreToolUse/.test(text);
    push({ ruleId: 'plugin-hooks', severity: 'high', file: rel, line: 1, excerpt: '', message: `Plugin hooks run outside the sandbox with your user privileges${runsAtStart ? ', and these fire automatically during normal use' : ''}.` });
  } else if (name === '.mcp.json' || name === '.lsp.json') {
    const unpinned = /@latest|"npx"|"uvx"/.test(text);
    push({ ruleId: 'plugin-server', severity: 'high', file: rel, line: 1, excerpt: '', message: `Declares a local server process running with your user privileges${unpinned ? ', fetched unpinned at launch' : ''}.` });
  } else if (rel.endsWith('monitors/monitors.json')) {
    push({ ruleId: 'plugin-monitor', severity: 'high', file: rel, line: 1, excerpt: '', message: 'Background monitors can start automatically and run outside the sandbox.' });
  } else if (/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/.test(rel) || (name === 'settings.json' && !rel.includes('/'))) {
    push({ ruleId: 'bundled-settings', severity: 'high', file: rel, line: 1, excerpt: '', message: 'Ships Claude Code settings that could alter permissions.' });
  } else if (name === 'package.json' && /"(?:(?:pre|post)?install|prepare)"\s*:/.test(text)) {
    push({ ruleId: 'install-script', severity: 'high', file: rel, line: 1, excerpt: '', message: 'package.json runs code automatically during npm install.' });
  } else if (name === 'setup.py') {
    push({ ruleId: 'install-script', severity: 'medium', file: rel, line: 1, excerpt: '', message: 'setup.py runs code when the package is installed.' });
  }
  if (AGENT_CONFIG_FILE.test(rel) && !/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/.test(rel)) {
    push({ ruleId: 'nested-agent-config', severity: 'high', file: rel, line: 1, excerpt: '', message: 'Ships a file agents load automatically as instructions when working in that folder.' });
  }
  if (rel.startsWith('bin/')) {
    push({ ruleId: 'plugin-bin', severity: 'medium', file: rel, line: 1, excerpt: '', message: 'Added to the PATH of Claude\'s shell while the plugin is enabled.' });
  }
}

/** Two weak signals in one package make a strong one; this is the "lethal trifecta" check. */
function correlate(findings, push) {
  const tags = new Set(findings.map((f) => f.tag).filter(Boolean));
  const inCode = findings.some((f) => f.tag === 'credential' && CODE_EXT.test(f.file));
  if (inCode && tags.has('network')) {
    const source = findings.find((f) => f.tag === 'credential' && CODE_EXT.test(f.file));
    push({ ruleId: 'credential-exfil-combo', severity: 'critical', file: source.file, line: source.line, excerpt: source.excerpt, message: 'Code reads credentials or the environment and the package also makes network calls: the shape of data theft.' });
  }
  if (tags.has('concealment') && (tags.has('credential') || tags.has('network'))) {
    const source = findings.find((f) => f.tag === 'concealment');
    push({ ruleId: 'concealed-sensitive-action', severity: 'critical', file: source.file, line: source.line, excerpt: source.excerpt, message: 'Tells the agent to hide its actions, in a package that also touches credentials or the network.' });
  }
}

export function verdictFrom(findings) {
  if (findings.some((f) => f.severity === 'critical')) return 'blocked';
  if (findings.some((f) => f.severity === 'high')) return 'needs-acknowledgement';
  if (findings.some((f) => f.severity === 'medium')) return 'caution';
  return 'no-known-issues';
}

/**
 * @param {string} root directory to scan
 * @param {{repo?: string, fetchFindings?: object[]}} context
 */
export function scanDirectory(root, context = {}) {
  const findings = [];
  const seen = new Set();
  const push = (finding) => {
    const key = `${finding.ruleId}|${finding.file}|${finding.line}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };
  for (const f of context.fetchFindings ?? []) push(f);

  // Links are invisible to the hash and to the reader, so one appearing here is never innocent.
  for (const link of listLinks(root)) {
    push({ ruleId: 'symlink', severity: 'critical', file: relative(root, link).split(sep).join('/'), line: 0, excerpt: '', message: 'Contains a symbolic link, which can point outside the skill folder.' });
  }

  const files = listFilesRecursive(root);
  const stats = { files: files.length, bytes: 0, code: 0, docs: 0, other: 0, opaque: 0 };

  for (const file of files) {
    const rel = relative(root, file).split(sep).join('/');
    const size = statSync(file).size;
    stats.bytes += size;

    if (EXECUTABLE_EXT.test(rel)) {
      stats.opaque += 1;
      push({ ruleId: 'bundled-executable', severity: 'critical', file: rel, line: 0, excerpt: '', message: 'Ships a compiled executable that cannot be reviewed.' });
      continue;
    }
    if (ARCHIVE_EXT.test(rel)) {
      stats.opaque += 1;
      push({ ruleId: 'bundled-archive', severity: 'high', file: rel, line: 0, excerpt: '', message: 'Ships an archive whose contents were not scanned.' });
      continue;
    }
    if (size > MAX_TEXT_BYTES) {
      stats.opaque += 1;
      push({ ruleId: 'oversized-file', severity: 'high', file: rel, line: 0, excerpt: `${size} bytes`, message: 'File is too large to review and was not scanned.' });
      continue;
    }

    const buf = readFileSync(file);
    if (hasExecutableMagic(buf)) {
      stats.opaque += 1;
      push({ ruleId: 'disguised-executable', severity: 'critical', file: rel, line: 0, excerpt: '', message: 'Executable disguised under another file extension.' });
      continue;
    }
    if (isBinaryBuffer(buf)) {
      if (MEDIA_EXT.test(rel)) {
        stats.other += 1;
      } else {
        stats.opaque += 1;
        push({ ruleId: 'unknown-binary', severity: 'medium', file: rel, line: 0, excerpt: '', message: 'Binary file of unknown type was not scanned.' });
      }
      continue;
    }

    const text = buf.toString('utf8');
    const isDoc = DOC_EXT.test(rel);
    const isCode = CODE_EXT.test(rel) || /^#!/.test(text);
    if (isCode) stats.code += 1;
    else if (isDoc) stats.docs += 1;
    else stats.other += 1;

    scanText({ rel, text, isDoc, isCode, push });
    if (basename(rel).toUpperCase() === 'SKILL.MD') scanSkillManifest({ rel, text, push, context });
    scanPluginSurface({ rel, text, push });
  }

  correlate(findings, push);
  findings.sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);

  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return {
    verdict: verdictFrom(findings),
    contentHash: hashDirectory(root),
    counts,
    stats,
    findings,
    limits: 'Static patterns only. A clean result does not prove the skill is safe.',
  };
}
