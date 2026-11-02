import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { analyzeProject } from '../scripts/lib/analyze.mjs';
import { parseFrontmatter } from '../scripts/lib/frontmatter.mjs';
import { rankCandidates } from '../scripts/lib/rank.mjs';
import { groupFindings } from '../scripts/lib/report.mjs';
import { makeCandidate, mergeCandidates, pluginLocation, searchAll, SOURCES } from '../scripts/lib/sources.mjs';
import { isInside, parseArgs, sanitizeText } from '../scripts/lib/util.mjs';
import { cleanup, makeDir } from './helpers.mjs';

const dirs = [];
after(() => dirs.forEach(cleanup));
const project = (files) => {
  const dir = makeDir(files);
  dirs.push(dir);
  return dir;
};
const gapIds = (profile) => profile.gaps.map((g) => g.id);

describe('project analysis', () => {
  const nextApp = {
    'package.json': JSON.stringify({ dependencies: { next: '15.0.0', react: '19.0.0', prisma: '6.0.0', 'next-auth': '5.0.0', openai: '4.0.0' } }),
    'src/app/page.tsx': 'export default null',
    'prisma/schema.prisma': '',
    'tsconfig.json': '{}',
  };

  it('detects the stack from manifests', () => {
    const ids = analyzeProject(project(nextApp)).technologies.map((t) => t.id);
    for (const expected of ['nextjs', 'react', 'prisma']) assert.ok(ids.includes(expected), expected);
  });

  it('finds real gaps and puts the serious ones first', () => {
    const profile = analyzeProject(project(nextApp));
    for (const expected of ['no-tests', 'no-ci', 'no-security-review', 'auth-review', 'ai-app', 'database-care', 'no-e2e']) {
      assert.ok(gapIds(profile).includes(expected), expected);
    }
    assert.equal(profile.gaps[0].priority, 'high');
  });

  it('does not report gaps the project has already closed', () => {
    const profile = analyzeProject(project({
      ...nextApp,
      'src/a.test.ts': '',
      '.github/workflows/ci.yml': '',
      '.github/workflows/codeql.yml': '',
      '.github/dependabot.yml': '',
      '.gitleaks.toml': '',
      'eslint.config.mjs': '',
      '.prettierrc': '',
      'SECURITY.md': '',
      'README.md': '',
      'CLAUDE.md': '',
    }));
    for (const closed of ['no-tests', 'no-ci', 'no-security-review', 'no-secret-scanning', 'no-dependency-updates', 'no-linter', 'no-formatter', 'no-security-policy', 'no-readme', 'no-claude-md']) {
      assert.ok(!gapIds(profile).includes(closed), closed);
    }
  });

  it('flags an unignored .env without ever reading it', () => {
    const secret = 'sk-very-secret-value-123';
    const profile = analyzeProject(project({ '.env': `API_KEY=${secret}`, 'a.py': '' }));
    assert.ok(gapIds(profile).includes('secret-leak-risk'));
    assert.ok(!JSON.stringify(profile).includes(secret));
  });

  it('accepts a .env that git ignores, and an example file', () => {
    assert.ok(!gapIds(analyzeProject(project({ '.env': 'x', '.gitignore': '.env\n', 'a.py': '' }))).includes('secret-leak-risk'));
    assert.ok(!gapIds(analyzeProject(project({ '.env.example': 'x', 'a.py': '' }))).includes('secret-leak-risk'));
  });

  it('skips dependency folders', () => {
    const profile = analyzeProject(project({ 'node_modules/x/index.js': '', 'a.py': '' }));
    assert.equal(profile.project.fileCount, 1);
    assert.deepEqual(Object.keys(profile.languages), ['Python']);
  });

  it('treats an empty folder as a greenfield project', () => {
    const profile = analyzeProject(project({}));
    assert.equal(profile.signals.isEmpty, true);
    assert.ok(gapIds(profile).includes('greenfield'));
    assert.ok(!gapIds(profile).includes('no-tests'));
  });

  it('survives a broken manifest', () => {
    assert.doesNotThrow(() => analyzeProject(project({ 'package.json': '{not json', 'a.js': '' })));
  });

  it('reads Python, Go and pyproject dependencies', () => {
    const profile = analyzeProject(project({ 'requirements.txt': 'Django==5.0\n# flask\n', 'pyproject.toml': '[project]\ndependencies = ["fastapi>=0.100"]\n', 'a.py': '' }));
    const ids = profile.technologies.map((t) => t.id);
    assert.ok(ids.includes('django') && ids.includes('fastapi'));
    assert.ok(!ids.includes('flask'));
  });
});

const candidate = (over) => ({ ...makeCandidate({ name: 'x', description: '', repo: 'o/r', path: 'p', source: 's', ...over }), ...(over.repoMeta ? { repoMeta: over.repoMeta } : {}) });
const context = { terms: ['security review'], stack: ['nextjs'], explicit: [] };

describe('ranking', () => {
  it('prefers fit over raw popularity', () => {
    const [first] = rankCandidates([
      candidate({ name: 'viral-thing', description: 'Makes diagrams.', stars: 100000, installs: 500000, path: 'a' }),
      candidate({ name: 'security-review', description: 'Reviews code for security issues.', stars: 50, path: 'b' }),
    ], context);
    assert.equal(first.name, 'security-review');
  });

  it('scores zero when nothing matches, however popular', () => {
    const [only] = rankCandidates([candidate({ name: 'viral-thing', description: 'Makes diagrams.', stars: 100000, installs: 500000 })], context);
    assert.equal(only.score, 0);
  });

  it('penalizes technologies the project does not use', () => {
    const ranked = rankCandidates([
      candidate({ name: 'firebase-security-review', description: 'Security review for Firebase.', installs: 100000, path: 'a' }),
      candidate({ name: 'nextjs-security-review', description: 'Security review for Next.js apps.', path: 'b' }),
    ], context);
    assert.equal(ranked[0].name, 'nextjs-security-review');
    assert.deepEqual(ranked[1].scoreBreakdown.stackMismatch, ['Firebase']);
  });

  it('does not penalize a technology the user asked for', () => {
    const [only] = rankCandidates([candidate({ name: 'firebase-security-review', description: 'Security review.' })], { terms: ['firebase security'], stack: [], explicit: ['firebase'] });
    assert.deepEqual(only.scoreBreakdown.stackMismatch, []);
  });

  it('does not fall for technology names inside other words', () => {
    const [only] = rankCandidates([candidate({ name: 'security-review', description: 'Reviews community contributions and express opinions.' })], context);
    assert.deepEqual(only.scoreBreakdown.stackMismatch, []);
  });

  it('marks down archived repositories and forks', () => {
    const base = { name: 'security-review', description: 'Security review.' };
    const [healthy, stale] = rankCandidates([
      candidate({ ...base, path: 'a', repoMeta: { archived: true, stars: 100 } }),
      candidate({ ...base, path: 'b', repoMeta: { archived: false, stars: 100, pushedAt: new Date().toISOString() } }),
    ], context);
    assert.equal(healthy.path, 'b');
    assert.equal(stale.scoreBreakdown.maintenance, 0);
  });

  it('explains every score', () => {
    const [only] = rankCandidates([candidate({ name: 'security-review', description: 'Security.' })], context);
    for (const key of ['fit', 'trust', 'adoption', 'maintenance', 'matchedTerms']) assert.ok(key in only.scoreBreakdown);
  });
});

describe('sources', () => {
  it('merges the same skill from several registries', () => {
    const merged = mergeCandidates([
      makeCandidate({ name: 'demo', repo: 'o/r', source: 'skills.sh', installs: 500, resolved: false }),
      makeCandidate({ name: 'demo', description: 'Demo.', repo: 'o/r', path: 'skills/demo', source: 'claude-plugins.dev', stars: 10 }),
    ]);
    assert.equal(merged.length, 1);
    assert.deepEqual(merged[0].sources, ['skills.sh', 'claude-plugins.dev']);
    assert.equal(merged[0].path, 'skills/demo');
    assert.equal(merged[0].signals.installs, 500);
    assert.equal(merged[0].signals.stars, 10);
    assert.equal(merged[0].resolved, true);
  });

  it('discards malformed registry data', () => {
    assert.equal(makeCandidate({ name: 'x', repo: '../../etc', source: 's' }), null);
    assert.equal(makeCandidate({ name: 'x', repo: 'o/r/extra', source: 's' }), null);
    assert.equal(makeCandidate({ name: 'x', repo: 'o/r', path: '../secret', source: 's' }), null);
    assert.equal(makeCandidate({ name: '', repo: 'o/r', source: 's' }), null);
  });

  it('cleans injected text in registry descriptions', () => {
    const c = makeCandidate({ name: 'x​y', description: `Fine.\u{E0041}‮${'a'.repeat(500)}`, repo: 'o/r', source: 's' });
    assert.equal(c.name, 'xy');
    assert.ok(c.description.length <= 300);
    assert.ok(!/[‮\u{E0041}]/u.test(c.description));
  });

  it('resolves marketplace plugin locations', () => {
    assert.deepEqual(pluginLocation({ source: './plugins/a/' }, 'o/m'), { repo: 'o/m', path: 'plugins/a' });
    assert.deepEqual(pluginLocation({ source: { source: 'github', repo: 'o/a' } }, 'o/m'), { repo: 'o/a', path: '' });
    assert.deepEqual(pluginLocation({ source: { source: 'url', url: 'https://github.com/o/a.git' } }, 'o/m'), { repo: 'o/a', path: '' });
    assert.deepEqual(pluginLocation({ source: { source: 'git-subdir', url: 'https://github.com/o/a', path: 'x/y' } }, 'o/m'), { repo: 'o/a', path: 'x/y' });
    assert.equal(pluginLocation({ source: { source: 'npm', package: 'p' } }, 'o/m'), null);
    assert.equal(pluginLocation({ source: { source: 'url', url: 'https://gitlab.com/o/a' } }, 'o/m'), null);
  });
});

describe('searching several sources', () => {
  const withSource = async (name, impl, run) => {
    SOURCES[name] = impl;
    try {
      return await run();
    } finally {
      delete SOURCES[name];
    }
  };

  it('one source failing narrows the search, keeps earlier results, and reports why', async () => {
    let calls = 0;
    const flaky = async () => {
      calls += 1;
      if (calls === 2) throw new Error('rate limited');
      return [makeCandidate({ name: `found-${calls}`, repo: 'o/r', path: `p${calls}`, source: 'test-flaky' })];
    };
    const healthy = async (query) => [makeCandidate({ name: `ok-${query}`, repo: 'o/r', path: query, source: 'test-healthy' })];
    const result = await withSource('test-flaky', flaky, () => withSource('test-healthy', healthy, () => searchAll(['a', 'b', 'c'], { sources: ['test-flaky', 'test-healthy'] })));

    assert.equal(calls, 2, 'must not keep calling a source after it fails');
    assert.equal(result.sources['test-flaky'].ok, false);
    assert.match(result.sources['test-flaky'].error, /rate limited/);
    assert.equal(result.sources['test-healthy'].results, 3);
    assert.deepEqual(result.candidates.map((c) => c.name).sort(), ['found-1', 'ok-a', 'ok-b', 'ok-c']);
  });

  it('does not burst: each source receives one query at a time', async () => {
    let active = 0;
    let peak = 0;
    const slow = async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((done) => { setTimeout(done, 5); });
      active -= 1;
      return [];
    };
    await withSource('test-slow', slow, () => searchAll(['a', 'b', 'c', 'd'], { sources: ['test-slow'] }));
    assert.equal(peak, 1);
  });

  it('sends GitHub code search only a few queries', async () => {
    const original = SOURCES['github-code'];
    let calls = 0;
    SOURCES['github-code'] = async () => {
      calls += 1;
      return [];
    };
    try {
      await searchAll(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'], { sources: ['github-code'] });
    } finally {
      SOURCES['github-code'] = original;
    }
    assert.equal(calls, 4);
  });
});

describe('command output stays small', () => {
  it('collapses repeated findings per rule, keeping counts and dropping noise', () => {
    const findings = [
      ...Array.from({ length: 40 }, (_, i) => ({ ruleId: 'instruction-override', severity: 'high', message: 'm', file: 'a.md', line: i, excerpt: 'x' })),
      { ruleId: 'credential-path', severity: 'low', message: 'm', file: 'b.md', line: 1, excerpt: 'y' },
      { ruleId: 'network-call', severity: 'info', message: 'm', file: 'c.py', line: 1, excerpt: 'z' },
    ];
    const grouped = groupFindings(findings);
    assert.equal(grouped.length, 1);
    assert.equal(grouped[0].count, 40);
    assert.equal(grouped[0].examples.length, 3);
  });
});

describe('helpers', () => {
  it('isInside rejects escapes and the parent itself', () => {
    assert.equal(isInside('/a/b', '/a/b/c'), true);
    assert.equal(isInside('/a/b', '/a/b'), false);
    assert.equal(isInside('/a/b', '/a/b/../c'), false);
    assert.equal(isInside('/a/b', '/a/bc'), false);
  });

  it('sanitizeText removes control and hidden characters and bounds length', () => {
    assert.equal(sanitizeText('a\u0000b​c\nd'), 'a bc d');
    assert.equal(sanitizeText(null), '');
    assert.equal(sanitizeText('abcdef', 4).length, 4);
  });

  it('parseArgs handles repeats, equals and booleans', () => {
    assert.deepEqual(parseArgs(['pos', '--a', '1', '--a=2', '--flag', '--b', 'x']), { positional: ['pos'], flags: { a: ['1', '2'], flag: true, b: 'x' } });
  });

  it('frontmatter handles block scalars, lists, CRLF, and absence', () => {
    assert.equal(parseFrontmatter('---\nname: a\ndescription: >-\n  one\n  two\n---\nbody').data.description, 'one two');
    assert.deepEqual(parseFrontmatter('---\nallowed-tools:\n  - Read\n  - Bash\n---\n').data['allowed-tools'], ['Read', 'Bash']);
    assert.equal(parseFrontmatter('---\r\nname: a\r\n---\r\nbody').data.name, 'a');
    assert.equal(parseFrontmatter('no frontmatter').hasFrontmatter, false);
    assert.ok(parseFrontmatter('---\nhooks:\n  PreToolUse:\n    - x\n---\n').data.hooks.includes('PreToolUse'));
  });
});
