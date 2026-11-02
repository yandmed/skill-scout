#!/usr/bin/env node
// Mutation testing with no dependencies: breaks the code on purpose, one small change at a time,
// and checks that the test suite notices. A test count says how many tests exist. This measures
// whether they would catch a bug, and each mutant that survives points at a real gap.
//
// It works on a throwaway copy of the project, so the real source files are never touched.
// Usage: node tools/mutation.mjs [--file scan.mjs] [--limit N] [--out results.json]
import { spawn } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { cpus, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from '../scripts/lib/util.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { flags } = parseArgs(process.argv.slice(2));
const TARGETS = ['install.mjs', 'vet.mjs', 'scan.mjs', 'sources.mjs', 'rank.mjs', 'resolve.mjs', 'gitignore.mjs', 'frontmatter.mjs', 'util.mjs', 'analyze.mjs', 'report.mjs', 'github.mjs'];
const WORKERS = Math.max(2, Math.min(8, cpus().length - 2));
const TIMEOUT_MS = 180000;

// Swaps that change behavior while keeping the program valid.
const OPERATORS = [
  [/===/g, '!=='], [/!==/g, '==='], [/ && /g, ' || '], [/ \|\| /g, ' && '], [/ >= /g, ' > '], [/ <= /g, ' < '], [/ > /g, ' >= '], [/ < /g, ' <= '],
  [/\breturn true\b/g, 'return false'], [/\breturn false\b/g, 'return true'], [/\bif \(!/g, 'if ('], [/\.some\(/g, '.every('], [/\.every\(/g, '.some('],
  [/\bMath\.max\(/g, 'Math.min('], [/\bMath\.min\(/g, 'Math.max('], [/'critical'/g, "'medium'"], [/'high'/g, "'low'"], [/\bcontinue;/g, ';'], [/ \+= 1/g, ' += 2'],
];

function mutantsOf(file) {
  const source = readFileSync(join(ROOT, 'scripts', 'lib', file), 'utf8');
  const lines = source.split('\n');
  const out = [];
  lines.forEach((line, index) => {
    const code = line.trimStart();
    if (!code || code.startsWith('//') || code.startsWith('*') || code.startsWith('/*') || code.startsWith('import ')) return;
    for (const [pattern, replacement] of OPERATORS) {
      for (const match of line.matchAll(pattern)) {
        const mutated = `${line.slice(0, match.index)}${replacement}${line.slice(match.index + match[0].length)}`;
        out.push({ file, line: index + 1, from: match[0].trim(), to: replacement.trim(), code: code.slice(0, 100), source: [...lines.slice(0, index), mutated, ...lines.slice(index + 1)].join('\n') });
      }
    }
  });
  return out;
}

function runTests(dir, home) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-timeout=30000'], { cwd: dir, env: { ...process.env, SKILL_SCOUT_HOME: home, GH_TOKEN: 'fake' }, stdio: 'ignore' });
    const timer = setTimeout(() => {
      child.kill();
      resolve('timeout');
    }, TIMEOUT_MS);
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve(code === 0 ? 'survived' : 'killed');
    });
  });
}

let all = (flags.file ? [String(flags.file)] : TARGETS).flatMap(mutantsOf);
// A seeded shuffle, so a limited run still samples every file and repeats identically.
let seed = 42;
const random = () => {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 4294967296;
};
all = all.map((m) => [random(), m]).sort((a, b) => a[0] - b[0]).map(([, m]) => m);
const total = all.length;
if (flags.limit) all = all.slice(0, Number(flags.limit));

const results = [];
let next = 0;
async function worker() {
  const dir = mkdtempSync(join(tmpdir(), 'skill-scout-mutant-'));
  const home = mkdtempSync(join(tmpdir(), 'skill-scout-mhome-'));
  for (const part of ['scripts', 'tests', 'data', 'skills', 'agents', 'bin', '.claude-plugin', 'package.json']) cpSync(join(ROOT, part), join(dir, part), { recursive: true });
  while (next < all.length) {
    const mutant = all[(next += 1) - 1];
    const target = join(dir, 'scripts', 'lib', mutant.file);
    const original = readFileSync(target, 'utf8');
    writeFileSync(target, mutant.source);
    const outcome = await runTests(dir, home);
    writeFileSync(target, original);
    results.push({ file: mutant.file, line: mutant.line, from: mutant.from, to: mutant.to, code: mutant.code, outcome });
    process.stderr.write(`${results.length}/${all.length} ${outcome.padEnd(8)} ${mutant.file}:${mutant.line} ${mutant.from} -> ${mutant.to}\n`);
    if (flags.out) writeFileSync(String(flags.out), JSON.stringify(results));
  }
  rmSync(dir, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
}
await Promise.all(Array.from({ length: WORKERS }, worker));

const killed = results.filter((r) => r.outcome !== 'survived').length;
const perFile = {};
for (const r of results) {
  perFile[r.file] ??= { killed: 0, survived: 0 };
  perFile[r.file][r.outcome === 'survived' ? 'survived' : 'killed'] += 1;
}
process.stdout.write(`${JSON.stringify({ possible: total, tested: results.length, killed, score: `${((killed / Math.max(results.length, 1)) * 100).toFixed(1)}%`, perFile }, null, 1)}\n`);
for (const r of results.filter((x) => x.outcome === 'survived')) process.stdout.write(`SURVIVED ${r.file}:${r.line} ${r.from} -> ${r.to} | ${r.code}\n`);
