// Discovery sources. Each one is independent and allowed to fail: a registry being down narrows
// the search and is reported, but never stops it. Everything here is untrusted text from the
// internet, so it is sanitized at this boundary and shape-checked before use.
import { existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { api, rawText } from './github.mjs';
import { dataDir, readJson, sanitizeText, writeJsonAtomic } from './util.mjs';

const TIMEOUT_MS = 12000;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SAFE_PATH_RE = /^(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_@.+ -]+(?:\/[A-Za-z0-9_@.+ -]+)*$/;

export const isValidRepo = (repo) => REPO_RE.test(repo ?? '') && !repo.split('/').includes('..');
export const isValidRepoPath = (path) => path === '' || SAFE_PATH_RE.test(path ?? '');

export function makeCandidate({ kind = 'skill', name, description, repo, path = '', source, stars, installs, officialSource, marketplace, resolved = true }) {
  if (!isValidRepo(repo) || !isValidRepoPath(path)) return null;
  const cleanName = sanitizeText(name, 80);
  if (!cleanName) return null;
  return {
    id: `${kind}:${repo}${path ? `/${path}` : `#${cleanName}`}`,
    kind,
    name: cleanName,
    description: sanitizeText(description, 300),
    repo,
    path,
    resolved, // false means the path inside the repo still has to be located by `vet`.
    url: `https://github.com/${repo}${path ? `/tree/HEAD/${path}` : ''}`,
    sources: [source],
    signals: {
      stars: Number.isFinite(stars) ? stars : undefined,
      installs: Number.isFinite(installs) ? installs : undefined,
    },
    officialSource: officialSource || undefined,
    marketplace: marketplace || undefined,
  };
}

async function getJson(url) {
  const response = await fetch(url, { headers: { Accept: 'application/json', 'User-Agent': 'skill-scout' }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function searchSkillsSh(query, limit) {
  const data = await getJson(`https://skills.sh/api/search?q=${encodeURIComponent(query)}&limit=${limit}`);
  return (data.skills ?? []).map((s) => makeCandidate({
    name: s.skillId ?? s.name,
    repo: s.source,
    source: 'skills.sh',
    installs: s.installs,
    resolved: false,
  }));
}

async function searchClaudePluginsDev(query, limit) {
  const data = await getJson(`https://api.claude-plugins.dev/api/skills/search?q=${encodeURIComponent(query)}&limit=${limit}`);
  return (data.skills ?? []).map((s) => {
    const owner = s.metadata?.repoOwner;
    const name = s.metadata?.repoName;
    return makeCandidate({
      name: s.name,
      description: s.description,
      repo: owner && name ? `${owner}/${name}` : undefined,
      path: s.metadata?.directoryPath ?? '',
      source: 'claude-plugins.dev',
      stars: s.stars,
      installs: s.installs,
    });
  });
}

async function searchGithubCode(query, limit) {
  // Code search is the most tightly rate limited GitHub endpoint, and it requires a token.
  const q = encodeURIComponent(`${query} filename:SKILL.md`);
  const data = await api(`/search/code?q=${q}&per_page=${Math.min(limit, 20)}`);
  return (data.items ?? []).map((item) => {
    const dir = item.path.includes('/') ? item.path.slice(0, item.path.lastIndexOf('/')) : '';
    return makeCandidate({
      name: dir ? dir.slice(dir.lastIndexOf('/') + 1) : item.repository.name,
      description: item.repository.description,
      repo: item.repository.full_name,
      path: dir,
      source: 'github-code',
      stars: item.repository.stargazers_count,
    });
  });
}

async function cached(key, loader) {
  const path = join(dataDir(), 'cache', `${key}.json`);
  if (existsSync(path) && Date.now() - statSync(path).mtimeMs < CACHE_TTL_MS) return readJson(path);
  const fresh = await loader();
  writeJsonAtomic(path, fresh);
  return fresh;
}

/** Normalizes a marketplace plugin entry to the GitHub location it actually points at. */
export function pluginLocation(entry, marketplaceRepo) {
  const src = entry.source;
  if (typeof src === 'string') return { repo: marketplaceRepo, path: src.replace(/^\.\//, '').replace(/\/$/, '') };
  if (!src || typeof src !== 'object') return null;
  if (src.source === 'github') return { repo: src.repo, path: '' };
  if (src.source === 'url' || src.source === 'git-subdir') {
    const m = String(src.url ?? '').match(/github\.com[/:]([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
    return m ? { repo: m[1], path: src.path ?? '' } : null;
  }
  return null; // npm, archive and command sources can't be inspected before installing.
}

async function officialPluginCatalog() {
  return cached('claude-plugins-official', async () => {
    const repo = 'anthropics/claude-plugins-official';
    const manifest = JSON.parse(await rawText(repo, 'HEAD', '.claude-plugin/marketplace.json', 5 * 1024 * 1024));
    return manifest.plugins.flatMap((entry) => {
      const location = pluginLocation(entry, repo);
      return location ? [{ name: entry.name, description: entry.description, ...location }] : [];
    });
  });
}

async function officialSkillCatalog() {
  return cached('anthropic-skills', async () => {
    const repo = 'anthropics/skills';
    const entries = await api(`/repos/${repo}/contents/skills`);
    const out = [];
    for (const entry of entries.filter((e) => e.type === 'dir')) {
      let description = '';
      try {
        const text = await rawText(repo, 'HEAD', `skills/${entry.name}/SKILL.md`);
        description = text.match(/^description:\s*["']?(.+?)["']?\s*$/m)?.[1] ?? '';
      } catch {
        // A missing description only lowers this candidate's fit score.
      }
      out.push({ name: entry.name, description, repo, path: `skills/${entry.name}` });
    }
    return out;
  });
}

const catalogMatches = (item, query) => {
  const words = query.toLowerCase().split(/\s+/).filter((w) => w.length > 2);
  const haystack = `${item.name} ${item.description}`.toLowerCase();
  return words.length > 0 && words.some((w) => haystack.includes(w));
};

async function searchOfficialPlugins(query, limit) {
  const catalog = await officialPluginCatalog();
  return catalog.filter((item) => catalogMatches(item, query)).slice(0, limit).map((item) => makeCandidate({
    kind: 'plugin',
    name: item.name,
    description: item.description,
    repo: item.repo,
    path: item.path,
    source: 'claude-plugins-official',
    officialSource: 'the Anthropic plugin directory',
    marketplace: 'claude-plugins-official',
  }));
}

async function searchOfficialSkills(query, limit) {
  const catalog = await officialSkillCatalog();
  return catalog.filter((item) => catalogMatches(item, query)).slice(0, limit).map((item) => makeCandidate({
    name: item.name,
    description: item.description,
    repo: item.repo,
    path: item.path,
    source: 'anthropics/skills',
    officialSource: 'anthropics/skills',
  }));
}

export const SOURCES = {
  'anthropics/skills': searchOfficialSkills,
  'claude-plugins-official': searchOfficialPlugins,
  'skills.sh': searchSkillsSh,
  'claude-plugins.dev': searchClaudePluginsDev,
  'github-code': searchGithubCode,
};

const mergeKey = (candidate) => `${candidate.repo}|${candidate.name}`.toLowerCase();

export function mergeCandidates(list) {
  const merged = new Map();
  for (const candidate of list) {
    if (!candidate) continue;
    const key = mergeKey(candidate);
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, candidate);
      continue;
    }
    existing.sources = [...new Set([...existing.sources, ...candidate.sources])];
    existing.description ||= candidate.description;
    existing.officialSource ||= candidate.officialSource;
    existing.marketplace ||= candidate.marketplace;
    existing.signals.stars = Math.max(existing.signals.stars ?? 0, candidate.signals.stars ?? 0) || undefined;
    existing.signals.installs = Math.max(existing.signals.installs ?? 0, candidate.signals.installs ?? 0) || undefined;
    if (!existing.resolved && candidate.resolved) {
      existing.path = candidate.path;
      existing.id = candidate.id;
      existing.url = candidate.url;
      existing.resolved = true;
    }
  }
  return [...merged.values()];
}

// GitHub allows few code searches per minute and penalizes bursts, so this source gets fewer queries.
const MAX_QUERIES_PER_SOURCE = { 'github-code': 4 };

export async function searchAll(queries, { limit = 15, sources = Object.keys(SOURCES) } = {}) {
  const status = Object.fromEntries(sources.map((s) => [s, { ok: true, results: 0 }]));

  // Sources run in parallel, but each one receives its queries in sequence and stops at the first
  // failure: retrying a rate-limited service only makes the limit worse. Results found before the
  // failure are kept.
  const jobs = sources.map(async (source) => {
    const found = [];
    for (const query of queries.slice(0, MAX_QUERIES_PER_SOURCE[source] ?? queries.length)) {
      try {
        const results = (await SOURCES[source](query, limit)).filter(Boolean);
        status[source].results += results.length;
        found.push(...results);
      } catch (error) {
        status[source].ok = false;
        status[source].error = sanitizeText(error.message, 160);
        break;
      }
    }
    return found;
  });
  const results = await Promise.all(jobs);
  return { candidates: mergeCandidates(results.flat()), sources: status };
}
