// The project profiler, driven by the taxonomy itself: every technology and every gap in
// data/taxonomy.json gets its own check, so adding an entry there without it working fails a test.
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { analyzeProject, TAXONOMY } from '../scripts/lib/analyze.mjs';
import { isIgnored, parseGitignore } from '../scripts/lib/gitignore.mjs';
import { cleanup, makeDir } from './helpers.mjs';

const dirs = [];
const profile = (files) => {
  const dir = makeDir(files);
  dirs.push(dir);
  return analyzeProject(dir);
};
after(() => dirs.forEach(cleanup));
const techIds = (result) => result.technologies.map((t) => t.id);
const gapIds = (result) => result.gaps.map((g) => g.id);
const pkg = (deps) => JSON.stringify({ dependencies: Object.fromEntries(deps.map((d) => [d, '1.0.0'])) });

describe('every technology is detected from its dependencies', () => {
  for (const [id, tech] of Object.entries(TAXONOMY.technologies)) {
    for (const dep of tech.deps) {
      it(`${id} from package.json dependency ${dep}`, () => assert.ok(techIds(profile({ 'package.json': pkg([dep]) })).includes(id)));
      it(`${id} from devDependencies ${dep}`, () => assert.ok(techIds(profile({ 'package.json': JSON.stringify({ devDependencies: { [dep]: '1' } }) })).includes(id)));
      if (/^[a-z0-9_.-]+$/.test(dep)) {
        it(`${id} from requirements.txt ${dep}`, () => assert.ok(techIds(profile({ 'requirements.txt': `# comment\n${dep}==1.0\n` })).includes(id)));
      }
    }
  }
  it('a monorepo package counts', () => assert.ok(techIds(profile({ 'apps/web/package.json': pkg(['next']) })).includes('nextjs')));
  it('a dependency too deep in the tree does not count', () => assert.ok(!techIds(profile({ 'a/b/c/d/e/package.json': pkg(['next']) })).includes('nextjs')));
  it('node_modules is ignored', () => assert.ok(!techIds(profile({ 'node_modules/next/package.json': pkg(['stripe']) })).includes('stripe')));
  it('a broken package.json is survivable', () => assert.deepEqual(techIds(profile({ 'package.json': '{ nope' })), []));
});

describe('technologies detected from files', () => {
  const cases = { 'dotnet from csproj': ['dotnet', 'App.csproj'], 'dotnet from sln': ['dotnet', 'App.sln'], 'terraform': ['terraform', 'infra/main.tf'], 'kubernetes k8s': ['kubernetes', 'k8s/deploy.yaml'], 'kubernetes helm': ['kubernetes', 'helm/values.yaml'], 'docker': ['docker', 'Dockerfile'], 'compose': ['docker', 'docker-compose.yml'], 'nested compose': ['docker', 'ops/compose.yaml'], 'android': ['android', 'app/AndroidManifest.xml'], 'ios': ['ios', 'App.xcodeproj/project.pbxproj'], 'prisma schema': ['prisma', 'prisma/schema.prisma'] };
  for (const [label, [id, file]] of Object.entries(cases)) it(label, () => assert.ok(techIds(profile({ [file]: 'x' })).includes(id)));
  const manifests = {
    'pyproject django': ['django', 'pyproject.toml', '[project]\ndependencies = ["django>=4"]\n'],
    'Pipfile flask': ['flask', 'Pipfile', '[packages]\nflask = "*"\n'],
    'composer laravel': ['laravel', 'composer.json', '{"require":{"laravel/framework":"^10"}}'],
    'Gemfile rails': ['rails', 'Gemfile', "gem 'rails', '~> 7'\n"],
    'pom spring': ['spring', 'pom.xml', '<project><artifactId>spring-boot-starter-web</artifactId></project>'],
    'gradle spring': ['spring', 'build.gradle', "implementation 'org.springframework.boot:spring-boot-starter:3.0'\n"],
    'pubspec flutter': ['flutter', 'pubspec.yaml', 'dependencies:\n  flutter:\n    sdk: flutter\n'],
  };
  for (const [label, [id, file, content]] of Object.entries(manifests)) it(label, () => assert.ok(techIds(profile({ [file]: content })).includes(id)));
});

describe('every gap appears and disappears when it should', () => {
  // A minimal project for each signal, built by turning it on or off.
  const code = { 'src/app.js': 'x' };
  const turnsOn = {
    envFileNotIgnored: { ...code, '.env': 'A=1' },
    hasSourceCode: code,
    hasDependencies: { ...code, 'package.json': pkg(['left-pad']) },
    usesJavascript: code,
    hasTests: { ...code, 'test/a.test.js': 'x' },
    hasE2E: { ...code, 'package.json': pkg(['@playwright/test']) },
    hasCI: { ...code, '.github/workflows/ci.yml': 'x' },
    hasLinter: { ...code, 'eslint.config.js': 'x' },
    hasFormatter: { ...code, '.prettierrc': '{}' },
    hasTypecheck: { ...code, 'tsconfig.json': '{}' },
    hasDocker: { ...code, Dockerfile: 'x' },
    hasIaC: { ...code, 'main.tf': 'x' },
    hasDatabase: { ...code, 'migrations/1.sql': 'x' },
    hasFrontend: { ...code, 'package.json': pkg(['react']) },
    hasBackend: { ...code, 'package.json': pkg(['express']) },
    hasApi: { ...code, 'openapi.yaml': 'x' },
    hasAuth: { ...code, 'package.json': pkg(['passport']) },
    hasSecurityPolicy: { ...code, 'SECURITY.md': 'x' },
    hasDependencyBot: { ...code, '.github/dependabot.yml': 'x' },
    hasSecretScan: { ...code, '.gitleaks.toml': 'x' },
    hasSast: { ...code, '.github/workflows/codeql.yml': 'x' },
    hasObservability: { ...code, 'package.json': pkg(['@sentry/node']) },
    usesLlmSdk: { ...code, 'package.json': pkg(['@anthropic-ai/sdk']) },
    hasReadme: { ...code, 'README.md': 'x' },
    hasClaudeMd: { ...code, 'CLAUDE.md': 'x' },
    isEmpty: {},
  };
  for (const [signal, files] of Object.entries(turnsOn)) {
    it(`${signal} turns on`, () => assert.equal(profile(files).signals[signal], true));
  }
  for (const gap of TAXONOMY.gaps) {
    const required = gap.when.all ?? [];
    const forbidden = gap.when.none ?? [];
    const merged = (signals) => Object.assign({}, ...signals.map((s) => turnsOn[s]));
    it(`${gap.id} appears when its conditions hold`, () => {
      const files = gap.when.any ? turnsOn[gap.when.any[0]] : merged(required.length ? required : ['hasSourceCode']);
      assert.ok(gapIds(profile(files)).includes(gap.id), JSON.stringify(files));
    });
    for (const blocker of forbidden) {
      it(`${gap.id} goes away with ${blocker}`, () => assert.ok(!gapIds(profile(merged([...required, blocker]))).includes(gap.id)));
    }
    it(`${gap.id} has searchable, generic queries`, () => {
      assert.ok(gap.queries.length > 0);
      for (const query of gap.queries) assert.match(query, /^[a-z0-9 .+#-]+$/i);
    });
  }
  it('gaps are sorted most important first', () => {
    const rank = { high: 0, medium: 1, low: 2 };
    const list = profile(code).gaps.map((g) => rank[g.priority]);
    assert.deepEqual(list, [...list].sort((a, b) => a - b));
  });
  it('an empty project gets the plan-first gap', () => assert.ok(gapIds(profile({})).includes('greenfield')));
});

describe('test files in every convention are recognized', () => {
  for (const file of ['test/a.js', 'tests/a.py', '__tests__/a.ts', 'spec/a.rb', 'src/a.test.ts', 'src/a.spec.js', 'test_a.py', 'pkg/a_test.go', 'b/test_a.py', 'a_test.py']) {
    it(file, () => assert.equal(profile({ 'src/app.js': 'x', [file]: 'x' }).signals.hasTests, true));
  }
  for (const file of ['src/testing-utils.js', 'latest/a.js', 'contest.py', 'attest/x.py']) {
    it(`${file} is not a test`, () => assert.equal(profile({ [file]: 'x' }).signals.hasTests, false));
  }
});

describe('nothing secret leaves the analyzer', () => {
  const CANARY = 'CANARY-SECRET-7f3a';
  const files = {
    '.env': `API_KEY=${CANARY}`, '.env.local': CANARY, 'config/.env.production': CANARY, 'id_rsa': CANARY, 'secrets.pem': CANARY, 'src/app.js': `const key = "${CANARY}"`, 'README.md': CANARY,
  };
  it('file contents never appear in the output', () => assert.ok(!JSON.stringify(profile(files)).includes(CANARY)));
  it('the project name is the only thing taken from the path', () => {
    const result = profile({ 'src/app.js': 'x' });
    assert.deepEqual(Object.keys(result.project).sort(), ['fileCount', 'name', 'truncated']);
  });
  it('search queries never contain project details', () => {
    const result = profile({ 'package.json': JSON.stringify({ name: 'acme-secret-project', dependencies: { next: '1' } }), 'src/acme.js': 'x' });
    assert.ok(!JSON.stringify(result.gaps).includes('acme'));
  });
  it('a credential key in settings is never read', () => {
    const result = profile({ 'src/a.js': 'x', '.claude/settings.json': JSON.stringify({ apiKey: CANARY, env: { TOKEN: CANARY }, enabledPlugins: { 'p@m': true, 'off@m': false } }) });
    assert.ok(!JSON.stringify(result).includes(CANARY));
    assert.ok(result.installed.plugins.includes('p@m'));
    assert.ok(!result.installed.plugins.includes('off@m'));
  });
});

describe('.env protection, as git really decides it', () => {
  const flagged = (files) => profile({ 'a.js': 'x', '.env': 'A=1', ...files }).signals.envFileNotIgnored;
  for (const [ignore, expected] of Object.entries({
    '': true, '.env': false, '/.env': false, '*.env': false, '.env*': false, '.env.*\n.env': false, '**/.env': false, '# .env': true, '.env.example': true, '.env.local': true, '.envrc': true, 'foo/.env': true, '.env\n!.env': true, '*.env\n!.env': true, '.env/': true, '  ': true,
  })) {
    it(`.gitignore ${JSON.stringify(ignore)} means ${expected ? 'unprotected' : 'protected'}`, () => assert.equal(flagged({ '.gitignore': ignore }), expected));
  }
  it('a template file alone is fine', () => assert.equal(profile({ 'a.js': 'x', '.env.example': 'A=' }).signals.envFileNotIgnored, false));
  for (const file of ['.env.sample', '.env.template', '.env.dist']) it(`${file} is fine`, () => assert.equal(profile({ 'a.js': 'x', [file]: 'A=' }).signals.envFileNotIgnored, false));
  it('a nested .gitignore protects its folder', () => assert.equal(profile({ 'a.js': 'x', 'api/.env': 'A=1', 'api/.gitignore': '.env' }).signals.envFileNotIgnored, false));
  it('a nested file is covered by the root rule', () => assert.equal(profile({ 'a.js': 'x', 'api/.env': 'A=1', '.gitignore': '.env' }).signals.envFileNotIgnored, false));
  it('a deeper file can be re-included', () => assert.equal(profile({ 'a.js': 'x', 'api/.env': 'A=1', '.gitignore': '.env', 'api/.gitignore': '!.env' }).signals.envFileNotIgnored, true));
  it('one exposed file among protected ones is reported', () => assert.equal(profile({ 'a.js': 'x', '.env': 'A=1', 'api/.env.prod': 'B=2', '.gitignore': '.env' }).signals.envFileNotIgnored, true));
});

describe('the .gitignore reader', () => {
  const cases = [
    ['*.log', 'a.log', true], ['*.log', 'dir/a.log', true], ['*.log', 'a.txt', false], ['/a.log', 'a.log', true], ['/a.log', 'dir/a.log', false],
    ['build/', 'build/x', true], ['build/', 'build', false], ['build', 'build/x', true], ['build', 'src/build/x', true], ['src/*.js', 'src/a.js', true], ['src/*.js', 'src/x/a.js', false],
    ['**/x', 'a/b/x', true], ['**/x', 'x', true], ['a/**/z', 'a/b/c/z', true], ['a/**/z', 'a/z', true], ['a/**', 'a/b', true], ['?.md', 'a.md', true], ['?.md', 'ab.md', false],
    ['a.b', 'axb', false], ['a+b', 'a+b', true], ['(x)', '(x)', true], ['#x', '#x', false], ['', 'x', false], ['!x', 'x', false],
  ];
  for (const [pattern, file, expected] of cases) it(`${JSON.stringify(pattern)} on ${file}: ${expected}`, () => assert.equal(isIgnored(file, parseGitignore(pattern)), expected));
  it('the last rule wins', () => {
    assert.equal(isIgnored('a', parseGitignore('a\n!a')), false);
    assert.equal(isIgnored('a', parseGitignore('!a\na')), true);
  });
  it('handles CRLF', () => assert.equal(isIgnored('a', parseGitignore('a\r\nb\r\n')), true));
  it('inherits the parent folder verdict', () => assert.equal(isIgnored('a', parseGitignore('b'), true), true));
  it('stays fast on a hostile pattern', () => {
    const started = Date.now();
    isIgnored('a'.repeat(3000), parseGitignore('*a*a*a*a*a*a*a*a*b'));
    assert.ok(Date.now() - started < 5000);
  });
});
