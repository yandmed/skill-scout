// The real command line, as the plugin runs it: separate processes, JSON on stdout, stable error
// codes and exit statuses. The network is replaced by preloading mock-preload.mjs.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const SCOUT = join(ROOT, 'scripts', 'scout.mjs');
const home = mkdtempSync(join(tmpdir(), 'skill-scout-cli-'));
const project = mkdtempSync(join(tmpdir(), 'skill-scout-cli-proj-'));
after(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

function run(args, { cwd = project, env = {} } = {}) {
  const result = spawnSync(process.execPath, ['--import', pathToFileURL(join(HERE, 'mock-preload.mjs')).href, SCOUT, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, SKILL_SCOUT_HOME: home, GH_TOKEN: 'fake-token', ...env },
  });
  let json = null;
  try {
    json = JSON.parse(result.stdout);
  } catch {
    // Left null: the caller's assertion reports the raw output.
  }
  return { status: result.status, json, stdout: result.stdout, stderr: result.stderr };
}

describe('every failure is JSON with a stable code', () => {
  const cases = [
    [['nonsense'], 2, 'bad-command'],
    [['search'], 2, 'no-query'],
    [['search', '--query', 'x', '--source', 'nope'], 2, 'bad-source'],
    [['resolve'], 2, 'no-ref'],
    [['resolve', '--ref', 'https://gitlab.com/a/b'], 2, 'unsupported-host'],
    [['resolve', '--ref', '../../etc'], 2, 'bad-reference'],
    [['resolve', '--ref', 'demo/missing'], 2, 'repo-not-found'],
    [['scan'], 2, 'no-dir'],
    [['vet'], 0, null],
    [['record-audit'], 2, 'no-id'],
    [['record-audit', '--id', 'skill:a/b', '--risk', 'x', '--coverage', 'complete'], 2, 'bad-risk'],
    [['record-audit', '--id', 'skill:a/b', '--risk', 'benign'], 2, 'bad-coverage'],
    [['record-audit', '--id', 'skill:never/vetted', '--risk', 'benign', '--coverage', 'complete'], 2, 'not-vetted'],
    [['install'], 2, 'no-id'],
    [['install', '--id', 'skill:never/vetted', '--scope', 'project'], 2, 'not-vetted'],
    [['remove'], 2, 'no-name'],
    [['remove', '--name', 'x', '--scope', 'project'], 2, 'not-managed'],
    [['remove', '--name', 'x', '--scope', 'galaxy'], 2, 'bad-scope'],
  ];
  for (const [args, status, code] of cases) {
    if (code === null) continue;
    it(args.join(' '), () => {
      const result = run(args);
      assert.equal(result.status, status, result.stdout + result.stderr);
      assert.equal(result.json?.code, code, result.stdout);
    });
  }
  it('vet with no id', () => assert.equal(run(['vet']).json.code, 'no-id'));
  it('no stack trace ever reaches stdout', () => {
    for (const [args] of cases) assert.doesNotMatch(run(args).stdout, /\n\s+at .*:\d+:\d+/);
  });
  it('help prints usage and exits cleanly', () => {
    for (const flag of [[], ['help'], ['--help']]) {
      const result = run(flag);
      assert.equal(result.status, 0);
      assert.match(result.stdout, /skill-scout <command>/);
    }
  });
});

describe('a vet failure for one id does not lose the others', () => {
  it('reports each separately', () => {
    const { json } = run(['vet', '--id', 'skill:demo/clean#demo-skill', '--id', 'skill:demo/missing#x', '--id', 'not-an-id']);
    const byId = Object.fromEntries(json.results.map((r) => [r.id, r]));
    assert.equal(byId['skill:demo/clean#demo-skill'].ok, true);
    assert.equal(byId['skill:demo/missing#x'].code, 'repo-not-found');
    assert.equal(byId['not-an-id'].code, 'bad-id');
  });
  it('the same id twice runs once', () => {
    assert.equal(run(['vet', '--id', 'skill:demo/clean#demo-skill', '--id', 'skill:demo/clean#demo-skill']).json.results.length, 1);
  });
});

describe('the whole flow through the command line', () => {
  const id = 'skill:demo/clean#demo-skill';
  it('refuses before the audit, installs after it, and removes', () => {
    assert.equal(run(['vet', '--id', id]).json.results[0].verdict, 'no-known-issues');
    const early = run(['install', '--id', id, '--scope', 'project']);
    assert.equal(early.status, 3);
    assert.equal(early.json.problems[0].code, 'audit-missing');
    assert.ok(!existsSync(join(project, '.claude/skills/demo-skill')));

    assert.equal(run(['record-audit', '--id', id, '--risk', 'benign', '--coverage', 'complete', '--codes', 'none']).json.recorded, true);
    const done = run(['install', '--id', id, '--scope', 'project']);
    assert.equal(done.status, 0, done.stdout);
    assert.equal(done.json.installed, true);
    assert.ok(statSync(join(project, '.claude/skills/demo-skill/SKILL.md')).isFile());

    assert.equal(run(['list']).json.skills.find((s) => s.name === 'demo-skill').scope, 'project');
    assert.equal(run(['verify']).json.skills.find((s) => s.name === 'demo-skill').status, 'ok');
    assert.ok(run(['outdated']).json.skills.find((s) => s.name === 'demo-skill'));
    assert.equal(run(['remove', '--name', 'demo-skill', '--scope', 'project']).json.removed, true);
    assert.ok(!existsSync(join(project, '.claude/skills/demo-skill')));
  });

  it('a skill with a critical finding can never be installed, whatever is passed', () => {
    const bad = 'skill:demo/malicious#demo-skill';
    assert.equal(run(['vet', '--id', bad]).json.results[0].verdict, 'blocked');
    run(['record-audit', '--id', bad, '--risk', 'benign', '--coverage', 'complete']);
    const result = run(['install', '--id', bad, '--scope', 'project', '--ack', 'pipe-to-shell', '--ack', 'blocked', '--replace']);
    assert.equal(result.status, 3);
    assert.equal(result.json.problems[0].code, 'blocked');
    assert.ok(!existsSync(join(project, '.claude/skills/demo-skill')));
  });

  it('a skill with a high finding needs that exact rule accepted', () => {
    const risky = 'skill:demo/risky#risky-skill';
    run(['vet', '--id', risky]);
    run(['record-audit', '--id', risky, '--risk', 'benign', '--coverage', 'complete']);
    const first = run(['install', '--id', risky, '--scope', 'project']);
    assert.equal(first.status, 3);
    assert.deepEqual(first.json.problems[0].rules, ['unrestricted-tools']);
    assert.equal(run(['install', '--id', risky, '--scope', 'project', '--ack', 'other-rule']).status, 3);
    assert.equal(run(['install', '--id', risky, '--scope', 'project', '--ack', 'unrestricted-tools']).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(join(project, '.claude/skill-scout.lock.json'), 'utf8')).skills['risky-skill'].acknowledged, ['unrestricted-tools']);
    run(['remove', '--name', 'risky-skill', '--scope', 'project']);
  });
});

describe('search and resolve through the command line', () => {
  it('searches, ranks and reports each source', () => {
    const { json } = run(['search', '--query', 'testing', '--source', 'publishers', '--source', 'curated-lists']);
    assert.ok(json.candidates.length > 0);
    assert.ok(json.catalogDate);
    assert.deepEqual(Object.keys(json.sources).sort(), ['curated-lists', 'publishers']);
    assert.match(json.note, /untrusted/);
    for (let i = 1; i < json.candidates.length; i += 1) assert.ok(json.candidates[i - 1].score >= json.candidates[i].score);
  });
  it('keeps its output small enough for the model to read', () => {
    assert.ok(run(['search', '--query', 'security', '--query', 'testing', '--query', 'docker', '--source', 'publishers', '--limit', '50', '--top', '25']).stdout.length < 30000);
  });
  it('without a token, skips the sources that need one', () => {
    const { json } = run(['doctor'], { env: { GH_TOKEN: '', GITHUB_TOKEN: '', PATH: '' } });
    assert.equal(json.sources['github-code'], undefined);
    assert.equal(json.sources['github-plugins'], undefined);
  });
  it('resolves a repository into candidate ids', () => {
    const { json } = run(['resolve', '--ref', 'https://github.com/demo/multi']);
    assert.equal(json.totalInRepository, 2);
    assert.deepEqual(json.candidates.map((c) => c.id).sort(), ['skill:demo/multi/skills/alpha', 'skill:demo/multi/skills/beta']);
  });
  it('resolved ids are accepted by vet', () => {
    const { json } = run(['resolve', '--ref', 'demo/multi', '--query', 'beta']);
    const vet = run(['vet', '--id', json.candidates[0].id]);
    assert.equal(vet.json.results[0].ok, true, vet.stdout);
    assert.equal(vet.json.results[0].path, 'skills/beta');
  });
});

describe('scan never runs what it reads', () => {
  it('a booby-trapped folder leaves no trace', () => {
    const dir = mkdtempSync(join(tmpdir(), 'skill-scout-trap-'));
    const marker = join(dir, 'EXECUTED');
    const payload = `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x')`;
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: a\ndescription: d\n---\nx\n');
    writeFileSync(join(dir, 'index.js'), payload);
    writeFileSync(join(dir, 'index.mjs'), payload);
    writeFileSync(join(dir, 'setup.py'), `open(${JSON.stringify(marker)}, 'w')`);
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ scripts: { postinstall: `node -e "${payload}"` } }));
    try {
      const { json } = run(['scan', '--dir', dir], { cwd: dir });
      assert.ok(json.verdict);
      assert.ok(!existsSync(marker), 'the candidate must never run');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the launchers', () => {
  it('the shell launcher points at the CLI', () => assert.match(readFileSync(join(ROOT, 'bin/skill-scout'), 'utf8'), /scripts\/scout\.mjs/));
  it('the Windows launcher points at the CLI', () => assert.match(readFileSync(join(ROOT, 'bin/skill-scout.cmd'), 'utf8'), /scripts\\scout\.mjs/));
  it('the shell launcher has Unix line endings', () => assert.doesNotMatch(readFileSync(join(ROOT, 'bin/skill-scout'), 'utf8'), /\r/));
});
