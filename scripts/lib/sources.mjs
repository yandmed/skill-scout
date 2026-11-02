// Discovery sources. Each one is independent and allowed to fail: a registry being down narrows
// the search and is reported, but never stops it. Everything here is untrusted text from the
// internet, so it is sanitized at this boundary and shape-checked before use.
import { existsSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { api, rawText } from './github.mjs';
import { LINE_RULES } from './rules.mjs';
import { dataDir, readJson, sanitizeText, writeJsonAtomic } from './util.mjs';

const TIMEOUT_MS = 12000;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SAFE_PATH_RE = /^(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_@.+ -]+(?:\/[A-Za-z0-9_@.+ -]+)*$/;

// Listing text reaches the orchestrating model, so text written to steer that model never gets there.
const STEERING_RULES = LINE_RULES.filter((rule) => ['instruction-override', 'concealment', 'fake-authority', 'auditor-manipulation', 'model-control-token', 'permission-bypass'].includes(rule.id));
export const looksLikeSteering = (text) => {
  const value = String(text ?? '').normalize('NFKC');
  return STEERING_RULES.some((rule) => rule.pattern.test(value));
};

export const isValidRepo = (repo) => REPO_RE.test(repo ?? '') && !repo.split('/').includes('..');
export const isValidRepoPath = (path) => path === '' || SAFE_PATH_RE.test(path ?? '');

export function makeCandidate({ kind = 'skill', name, description, repo, path = '', source, stars, installs, officialSource, marketplace, resolved = true, publisher, tier, lists, registryQuality }) {
  if (!isValidRepo(repo) || !isValidRepoPath(path)) return null;
  const cleanName = sanitizeText(name, 80);
  if (!cleanName || looksLikeSteering(cleanName)) return null;
  const steering = looksLikeSteering(description);
  return {
    id: `${kind}:${repo}${path ? `/${path}` : `#${cleanName}`}`,
    kind,
    name: cleanName,
    description: steering ? '[removed: this listing contained text aimed at the AI agent]' : sanitizeText(description, 300),
    steeringListing: steering || undefined,
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
    publisher: publisher ? sanitizeText(publisher, 60) : undefined,
    tier: tier || undefined,
    lists: Number.isFinite(lists) ? lists : undefined,
    registryQuality: Number.isFinite(registryQuality) ? registryQuality : undefined,
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

/** Search within a repository's skills via Tessl's index. Its API is experimental, so it may fail. */
async function searchTessl(query, limit) {
  const data = await getJson(`https://api.tessl.io/experimental/search?q=${encodeURIComponent(query)}&filter%5BhasSkills%5D=true&page%5Bsize%5D=${limit}`);
  return (data.data ?? []).filter((item) => item?.type === 'skill').map((item) => {
    const a = item.attributes ?? {};
    const repo = String(a.sourceUrl ?? '').match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/)?.[1];
    return makeCandidate({
      name: a.name,
      description: a.description,
      repo,
      path: String(a.path ?? '').replace(/\/?SKILL\.md$/i, ''),
      source: 'tessl',
      registryQuality: a.scores?.aggregate,
    });
  });
}

// Repositories whose owners labeled them as skills. Precise, and works without a token.
const SKILL_TOPICS = ['agent-skills', 'claude-skills'];
async function searchGithubTopics(query, limit) {
  const out = [];
  for (const topic of SKILL_TOPICS) {
    const data = await api(`/search/repositories?q=${encodeURIComponent(`${query} topic:${topic}`)}&sort=stars&per_page=${Math.min(limit, 10)}`);
    for (const item of data.items ?? []) {
      if (item.fork || item.archived) continue;
      out.push(makeCandidate({
        name: item.name,
        description: item.description,
        repo: item.full_name,
        source: 'github-topics',
        stars: item.stargazers_count,
        resolved: false,
      }));
    }
  }
  return out;
}

/** Plugin marketplaces: a .claude-plugin/marketplace.json that mentions the query. Needs a token. */
async function searchGithubPlugins(query, limit) {
  const q = encodeURIComponent(`${query} filename:marketplace.json path:.claude-plugin`);
  const data = await api(`/search/code?q=${q}&per_page=${Math.min(limit, 15)}`);
  return (data.items ?? []).map((item) => makeCandidate({
    kind: 'plugin',
    name: item.repository?.name,
    description: item.repository?.description,
    repo: item.repository?.full_name,
    source: 'github-plugins',
    stars: item.repository?.stargazers_count,
    marketplace: item.repository?.full_name,
  }));
}

const HERE = dirname(fileURLToPath(import.meta.url));
let catalogCache;
export const loadCatalog = () => {
  catalogCache ??= readJson(join(HERE, '..', '..', 'data', 'catalog.json'), { entries: [], builtAt: null });
  return catalogCache;
};

const queryWords = (query) => String(query).toLowerCase().split(/[^a-z0-9.#+]+/).filter((w) => w.length > 2);

/** Best matches in a local list. Sorting first matters: the list is alphabetical, so slicing alone would favor the letter A. */
export function topMatches(items, query, limit) {
  const words = queryWords(query);
  if (!words.length) return [];
  return items
    .map((item) => {
      const name = String(item.name).toLowerCase();
      const description = String(item.description ?? '').toLowerCase();
      let score = 0;
      for (const word of words) score += name.includes(word) ? 3 : description.includes(word) ? 1 : 0;
      return { item, score };
    })
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score || (b.item.stars ?? 0) - (a.item.stars ?? 0))
    .slice(0, limit)
    .map((row) => row.item);
}

function searchCatalog(query, limit, wanted, source) {
  const entries = loadCatalog().entries.filter((entry) => wanted(entry.tier));
  return topMatches(entries, query, limit).map((entry) => makeCandidate({
    name: entry.name,
    description: entry.description,
    repo: entry.repo,
    path: entry.path,
    source,
    stars: entry.stars,
    publisher: entry.publisher,
    tier: entry.tier,
    lists: entry.lists,
  }));
}
const searchPublishers = async (query, limit) => searchCatalog(query, limit, (tier) => tier === 'vendor' || tier === 'specialist', 'publishers');
const searchCuratedLists = async (query, limit) => searchCatalog(query, limit, (tier) => tier === 'listed', 'curated-lists');

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

async function searchOfficialPlugins(query, limit) {
  const catalog = await officialPluginCatalog();
  return topMatches(catalog, query, limit).map((item) => makeCandidate({
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
  return topMatches(catalog, query, limit).map((item) => makeCandidate({
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
  publishers: searchPublishers,
  'curated-lists': searchCuratedLists,
  'skills.sh': searchSkillsSh,
  'claude-plugins.dev': searchClaudePluginsDev,
  tessl: searchTessl,
  'github-topics': searchGithubTopics,
  'github-code': searchGithubCode,
  'github-plugins': searchGithubPlugins,
};

// GitHub code search requires a token, so without one these would only report a misleading failure.
export const NEEDS_TOKEN = new Set(['github-code', 'github-plugins']);

/**
 * The same skill is often copied into many repositories. Identical name and description count as
 * one, keeping the first (best ranked) and noting how many copies exist. A skill reusing the name
 * of a known publisher's skill from elsewhere is marked, since that's how impersonation looks too.
 */
export function collapseCopies(ranked, catalogEntries = loadCatalog().entries) {
  const publisherNames = new Map();
  for (const entry of catalogEntries) {
    if (entry.tier === 'vendor') publisherNames.set(String(entry.name).toLowerCase(), entry);
  }
  const seen = new Map();
  const out = [];
  for (const candidate of ranked) {
    const description = String(candidate.description ?? '').toLowerCase().replace(/\s+/g, ' ').trim();
    const key = `${String(candidate.name).toLowerCase()}|${description}`;
    if (description && seen.has(key)) {
      seen.get(key).copies = (seen.get(key).copies ?? 0) + 1;
      continue;
    }
    const known = publisherNames.get(String(candidate.name).toLowerCase());
    if (known && known.repo.toLowerCase() !== String(candidate.repo).toLowerCase() && !candidate.officialSource) {
      candidate.sameNameAs = { publisher: known.publisher, repo: known.repo };
    }
    seen.set(key, candidate);
    out.push(candidate);
  }
  return out;
}

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
    existing.publisher ||= candidate.publisher;
    existing.tier ||= candidate.tier;
    existing.lists ||= candidate.lists;
    existing.registryQuality ??= candidate.registryQuality;
    if (candidate.steeringListing) {
      // One source carrying steering text taints the listing, whichever source came first.
      existing.steeringListing = true;
      existing.description = candidate.description;
    }
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
const MAX_QUERIES_PER_SOURCE = { 'github-code': 3, 'github-plugins': 2, 'github-topics': 3 };

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
