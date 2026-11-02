// Project profiler. Runs locally and never sends anything anywhere. It reads file NAMES and
// dependency manifests only; the contents of .env files and source code are never opened.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readJson } from './util.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const TAXONOMY = readJson(join(HERE, '..', '..', 'data', 'taxonomy.json'));

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'target', 'vendor', '.next', '.nuxt', '__pycache__', '.venv', 'venv', 'env', '.tox', 'coverage', '.cache', '.idea', '.vscode', 'bin', 'obj', '.terraform', 'Pods', '.gradle', '.dart_tool']);
const MAX_FILES = 30000;
const MAX_MANIFEST_BYTES = 1024 * 1024;

const LANGUAGES = {
  '.ts': 'TypeScript', '.tsx': 'TypeScript', '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
  '.py': 'Python', '.go': 'Go', '.rs': 'Rust', '.java': 'Java', '.kt': 'Kotlin', '.rb': 'Ruby', '.php': 'PHP', '.cs': 'C#',
  '.swift': 'Swift', '.dart': 'Dart', '.c': 'C', '.cpp': 'C++', '.h': 'C/C++', '.sh': 'Shell', '.ps1': 'PowerShell',
  '.vue': 'Vue', '.svelte': 'Svelte', '.sql': 'SQL', '.tf': 'Terraform', '.ipynb': 'Jupyter', '.lua': 'Lua', '.ex': 'Elixir',
};

function walk(root) {
  const files = [];
  let truncated = false;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // Unreadable directories are simply not part of the profile.
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) {
        truncated = true;
        return { files, truncated };
      }
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(join(dir, entry.name));
      } else if (entry.isFile()) {
        files.push(relative(root, join(dir, entry.name)).split(sep).join('/'));
      }
    }
  }
  return { files, truncated };
}

const readSmall = (path) => {
  try {
    return statSync(path).size > MAX_MANIFEST_BYTES ? '' : readFileSync(path, 'utf8');
  } catch {
    return '';
  }
};

/** Dependency names only; versions and the rest of each manifest are ignored. */
function collectDependencies(root, files) {
  const deps = new Set();
  const add = (name) => {
    const clean = String(name).trim().toLowerCase();
    if (clean) deps.add(clean);
  };
  for (const file of files) {
    const name = basename(file);
    if (file.split('/').length > 4) continue;
    const full = join(root, file);
    if (name === 'package.json') {
      const pkg = readJson(full, {});
      for (const key of ['dependencies', 'devDependencies', 'peerDependencies']) Object.keys(pkg[key] ?? {}).forEach(add);
    } else if (/^requirements.*\.txt$/.test(name)) {
      readSmall(full).split(/\r?\n/).forEach((line) => {
        const m = line.match(/^\s*([A-Za-z0-9_.-]+)/);
        if (m && !line.trim().startsWith('#')) add(m[1]);
      });
    } else if (name === 'pyproject.toml' || name === 'Pipfile') {
      for (const m of readSmall(full).matchAll(/^\s*"?([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(?:[=<>~!^]|"|$)/gm)) add(m[1]);
      for (const m of readSmall(full).matchAll(/"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*[=<>~!^][^"]*"/g)) add(m[1]);
    } else if (name === 'composer.json') {
      Object.keys(readJson(full, {}).require ?? {}).forEach(add);
    } else if (name === 'Gemfile') {
      for (const m of readSmall(full).matchAll(/^\s*gem\s+['"]([^'"]+)/gm)) add(m[1]);
    } else if (name === 'go.mod') {
      for (const m of readSmall(full).matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]+\/\S+)\s+v/gm)) add(m[1]);
    } else if (name === 'Cargo.toml') {
      const section = readSmall(full).split(/^\[dependencies\]/m)[1]?.split(/^\[/m)[0] ?? '';
      for (const m of section.matchAll(/^([A-Za-z0-9_-]+)\s*=/gm)) add(m[1]);
    } else if (name === 'pom.xml') {
      for (const m of readSmall(full).matchAll(/<artifactId>([^<]+)<\/artifactId>/g)) add(m[1]);
    } else if (/^build\.gradle(\.kts)?$/.test(name)) {
      for (const m of readSmall(full).matchAll(/['"]([\w.-]+):([\w.-]+)(?::[^'"]*)?['"]/g)) add(m[2]);
    } else if (name === 'pubspec.yaml') {
      if (/^\s*flutter:/m.test(readSmall(full))) add('flutter');
    }
  }
  return deps;
}

const hasDep = (deps, names) => names.some((n) => deps.has(n));
const anyFile = (files, regex) => files.some((f) => regex.test(f));

function detectTechnologies(deps, files) {
  const found = new Set();
  for (const [id, tech] of Object.entries(TAXONOMY.technologies)) {
    if (hasDep(deps, tech.deps)) found.add(id);
  }
  for (const dep of deps) if (dep.startsWith('spring-boot')) found.add('spring');
  if (anyFile(files, /\.(?:csproj|sln|fsproj)$/)) found.add('dotnet');
  if (anyFile(files, /\.tf$/)) found.add('terraform');
  if (anyFile(files, /(?:^|\/)(?:k8s|kubernetes|helm|charts)\//)) found.add('kubernetes');
  if (anyFile(files, /(?:^|\/)(?:Dockerfile|docker-compose\.ya?ml|compose\.ya?ml)$/)) found.add('docker');
  if (anyFile(files, /(?:^|\/)AndroidManifest\.xml$/)) found.add('android');
  if (anyFile(files, /\.xcodeproj\//)) found.add('ios');
  if (anyFile(files, /(?:^|\/)schema\.prisma$/)) found.add('prisma');
  return found;
}

function envIsUnprotected(root, files) {
  const envFiles = files.filter((f) => /(?:^|\/)\.env(?:\.[\w-]+)?$/.test(f) && !/\.(?:example|sample|template|dist)$/.test(f));
  if (!envFiles.length) return false;
  const ignore = readSmall(join(root, '.gitignore'));
  return !/^\s*\/?\.env\b|^\s*\*\.env\b|^\s*\.env\*/m.test(ignore);
}

function computeSignals(root, files, deps, tech, languages) {
  const techList = [...tech];
  const kindIs = (kind) => techList.some((id) => TAXONOMY.technologies[id].kind === kind);
  const sourceFiles = Object.values(languages).reduce((a, b) => a + b, 0);
  const pkgScripts = (() => {
    const pkg = readJson(join(root, 'package.json'), {});
    return JSON.stringify(pkg.scripts ?? {});
  })();

  return {
    isEmpty: files.length === 0,
    hasSourceCode: sourceFiles > 0,
    hasDependencies: deps.size > 0,
    usesJavascript: Boolean(languages.JavaScript) && !languages.TypeScript,
    hasTests: anyFile(files, /(?:^|\/)(?:tests?|__tests__|spec)\/|\.(?:test|spec)\.\w+$|(?:^|\/)test_[^/]+\.py$|_test\.(?:go|py)$/) || hasDep(deps, ['jest', 'vitest', 'mocha', 'pytest', 'junit', 'rspec']),
    hasE2E: hasDep(deps, ['playwright', '@playwright/test', 'cypress', 'puppeteer', 'selenium-webdriver']) || anyFile(files, /(?:^|\/)(?:e2e|cypress|playwright)(?:\/|\.config)/),
    hasCI: anyFile(files, /^\.github\/workflows\/|^\.gitlab-ci\.yml$|^\.circleci\/|^azure-pipelines\.yml$|^Jenkinsfile$|^\.travis\.yml$|^bitbucket-pipelines\.yml$/),
    hasLinter: anyFile(files, /(?:^|\/)(?:\.eslintrc[^/]*|eslint\.config\.[^/]+|\.flake8|\.pylintrc|ruff\.toml|\.ruff\.toml|\.golangci\.ya?ml|\.rubocop\.yml|clippy\.toml|biome\.jsonc?|\.editorconfig)$/) || hasDep(deps, ['eslint', 'ruff', 'flake8', 'pylint', '@biomejs/biome', 'rubocop']),
    hasFormatter: anyFile(files, /(?:^|\/)(?:\.prettierrc[^/]*|prettier\.config\.[^/]+|rustfmt\.toml|\.clang-format|biome\.jsonc?)$/) || hasDep(deps, ['prettier', 'black', 'ruff', '@biomejs/biome']),
    hasTypecheck: anyFile(files, /(?:^|\/)(?:tsconfig\.json|jsconfig\.json)$/) || hasDep(deps, ['typescript']),
    hasDocker: tech.has('docker'),
    hasIaC: tech.has('terraform') || tech.has('kubernetes') || anyFile(files, /(?:^|\/)(?:cdk\.json|pulumi\.ya?ml|serverless\.ya?ml)$/),
    hasDatabase: kindIs('database') || anyFile(files, /(?:^|\/)migrations?\/|\.sql$/),
    hasFrontend: kindIs('frontend') || Boolean(languages.Vue || languages.Svelte),
    hasBackend: kindIs('backend'),
    hasApi: kindIs('backend') || anyFile(files, /(?:^|\/)(?:openapi|swagger)\.(?:ya?ml|json)$|(?:^|\/)app\/api\//),
    hasAuth: hasDep(deps, ['passport', 'next-auth', '@auth/core', 'better-auth', 'jsonwebtoken', 'pyjwt', 'bcrypt', 'argon2', 'django-allauth', 'devise', '@clerk/nextjs', 'firebase-admin']) || anyFile(files, /(?:^|\/)(?:auth|authentication)(?:\/|\.\w+$)/),
    hasSecurityPolicy: anyFile(files, /(?:^|\/)SECURITY\.md$/i),
    hasDependencyBot: anyFile(files, /^\.github\/dependabot\.ya?ml$|(?:^|\/)renovate\.json5?$|^\.renovaterc/),
    hasSecretScan: anyFile(files, /(?:^|\/)\.gitleaks\.toml$|(?:^|\/)\.secrets\.baseline$/) || /gitleaks|trufflehog/.test(pkgScripts) || anyFile(files, /^\.github\/workflows\/[^/]*(?:gitleaks|trufflehog|secret)/i),
    hasSast: anyFile(files, /^\.github\/workflows\/[^/]*(?:codeql|semgrep|snyk|sast|security)/i) || anyFile(files, /(?:^|\/)\.semgrep(?:\.ya?ml|\/)|(?:^|\/)\.snyk$/) || hasDep(deps, ['bandit', 'eslint-plugin-security', 'semgrep']),
    hasObservability: hasDep(deps, ['@sentry/node', '@sentry/nextjs', 'sentry-sdk', 'prom-client', 'winston', 'pino', 'structlog', 'opentelemetry-api', '@opentelemetry/api', 'dd-trace']),
    usesLlmSdk: hasDep(deps, ['anthropic', '@anthropic-ai/sdk', 'openai', 'langchain', '@langchain/core', 'ai', 'llama-index', 'google-generativeai', '@google/genai']),
    hasReadme: anyFile(files, /^readme(?:\.\w+)?$/i),
    hasClaudeMd: anyFile(files, /^(?:\.claude\/)?CLAUDE\.md$/),
    envFileNotIgnored: envIsUnprotected(root, files),
  };
}

function matchesWhen(when, signals) {
  if (when.all && !when.all.every((s) => signals[s])) return false;
  if (when.none && when.none.some((s) => signals[s])) return false;
  if (when.any && !when.any.some((s) => signals[s])) return false;
  return true;
}

function listSkillDir(dir, scope) {
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && existsSync(join(dir, e.name, 'SKILL.md')))
      .map((e) => ({ name: e.name, scope }));
  } catch {
    return [];
  }
}

function installedInventory(root) {
  const skills = [
    ...listSkillDir(join(root, '.claude', 'skills'), 'project'),
    ...listSkillDir(join(homedir(), '.claude', 'skills'), 'user'),
  ];
  const plugins = new Set();
  // Only the documented enabledPlugins key is read. Nothing else in these files is used.
  for (const path of [join(homedir(), '.claude', 'settings.json'), join(root, '.claude', 'settings.json'), join(root, '.claude', 'settings.local.json')]) {
    const enabled = readJson(path, {}).enabledPlugins ?? {};
    for (const [id, on] of Object.entries(enabled)) if (on) plugins.add(id);
  }
  return { skills, plugins: [...plugins].sort() };
}

export function analyzeProject(root) {
  const { files, truncated } = walk(root);
  const languages = {};
  for (const file of files) {
    const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
    if (LANGUAGES[ext]) languages[LANGUAGES[ext]] = (languages[LANGUAGES[ext]] ?? 0) + 1;
  }
  const deps = collectDependencies(root, files);
  const tech = detectTechnologies(deps, files);
  const signals = computeSignals(root, files, deps, tech, languages);

  const priorityRank = { high: 0, medium: 1, low: 2 };
  const gaps = TAXONOMY.gaps
    .filter((gap) => matchesWhen(gap.when, signals))
    .map(({ when, ...gap }) => gap)
    .sort((a, b) => priorityRank[a.priority] - priorityRank[b.priority]);

  return {
    project: { name: basename(root), fileCount: files.length, truncated },
    languages: Object.fromEntries(Object.entries(languages).sort((a, b) => b[1] - a[1])),
    technologies: [...tech].sort().map((id) => ({ id, label: TAXONOMY.technologies[id].label, kind: TAXONOMY.technologies[id].kind })),
    signals,
    gaps,
    installed: installedInventory(root),
    privacy: 'Computed locally. Only generic search terms are sent to public registries; never project names, paths or code.',
  };
}
