#!/usr/bin/env node
// Maintainer tool: rebuilds data/catalog.json, the snapshot of skills from known publishers and
// curated lists. Shipping it means searching them costs no API calls and works when rate limited.
// It stores names, descriptions and locations only. A skill's files are always downloaded fresh
// at a pinned commit and fully vetted, so a stale or poisoned entry can't reach the user unchecked.
//
// Usage: node scripts/build-catalog.mjs [--max-list-repos N]
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFrontmatter } from './lib/frontmatter.mjs';
import { api, rawText, repoInfo } from './lib/github.mjs';
import { isValidRepo, isValidRepoPath } from './lib/sources.mjs';
import { parseArgs, sanitizeText } from './lib/util.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(readFileSync(join(HERE, '..', 'data', 'publishers.json'), 'utf8'));
const { flags } = parseArgs(process.argv.slice(2));
const MAX_LIST_REPOS = Number(flags['max-list-repos']) || 400;
const MAX_SKILLS_PER_LISTED_REPO = 15;
const MIN_LISTED_STARS = 20;
const STALE_MS = 18 * 30 * 86400000;
const CONCURRENCY = 8;

async function pool(items, worker) {
  const out = [];
  let next = 0;
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (next < items.length) {
      const item = items[(next += 1) - 1];
      out.push(await worker(item));
    }
  }));
  return out;
}

/** Skill folders in a repository. Copies of the same skill for several tools count once. */
async function skillsIn(repo, sha, limit) {
  const tree = await api(`/repos/${repo}/git/trees/${sha}?recursive=1`);
  const paths = tree.tree.filter((e) => e.type === 'blob' && /(?:^|\/)SKILL\.md$/.test(e.path)).map((e) => e.path).filter((p) => isValidRepoPath(p));
  const byName = new Map();
  for (const path of paths.sort((a, b) => a.length - b.length)) {
    const folder = path.split('/').slice(-2, -1)[0] ?? repo.split('/')[1];
    if (!byName.has(folder)) byName.set(folder, path);
  }
  const unique = [...byName.values()].slice(0, limit);
  const entries = await pool(unique, async (path) => {
    try {
      const { data } = parseFrontmatter(await rawText(repo, sha, path, 256 * 1024));
      const dir = path.replace(/\/?SKILL\.md$/, '');
      const name = sanitizeText(data.name || dir.split('/').pop() || repo.split('/')[1], 80);
      return name ? { name, description: sanitizeText(data.description, 300), repo, path: dir } : null;
    } catch {
      return null; // One unreadable file doesn't invalidate the rest of the repository.
    }
  });
  return entries.filter(Boolean);
}

/** Pulls owner/repo out of whatever link format a curated list uses. */
export function reposFromList(text) {
  const repos = new Set();
  for (const match of text.matchAll(/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?(?=[/)\s"',#]|$)/gm)) repos.add(match[1]);
  // VoltAgent's list links to officialskills.sh/<owner>/skills/<skill>; its owner slug alone can't name a repo.
  return [...repos].filter((repo) => isValidRepo(repo) && !/^(?:sponsors|orgs|topics|features|marketplace|apps)\//i.test(repo));
}

async function collect(repo, limit, extra) {
  const info = await repoInfo(repo);
  if (!info || info.private) return { repo, skills: [], skipped: 'not found' };
  const sha = (await api(`/repos/${repo}/commits/${encodeURIComponent(info.default_branch)}`)).sha;
  const skills = await skillsIn(repo, sha, limit);
  return { repo, info, skills: skills.map((s) => ({ ...s, ...extra, stars: info.stargazers_count })) };
}

const publisherRepos = new Set(config.publishers.map((p) => p.repo.toLowerCase()));
const excluded = new Set(config.excludedAggregators.map((r) => r.toLowerCase()));
const entries = [];
const report = { publishers: {}, lists: {}, listedRepos: { considered: 0, used: 0 } };

for (const publisher of config.publishers) {
  try {
    const { skills } = await collect(publisher.repo, 500, { tier: publisher.tier, publisher: publisher.name });
    entries.push(...skills);
    report.publishers[publisher.repo] = skills.length;
  } catch (error) {
    report.publishers[publisher.repo] = `failed: ${error.message}`;
  }
  process.stderr.write(`${publisher.repo}: ${report.publishers[publisher.repo]}\n`);
}

const listed = new Map();
for (const list of config.lists) {
  try {
    const repos = reposFromList(await rawText(list.repo, 'HEAD', list.file, 5 * 1024 * 1024));
    report.lists[list.repo] = repos.length;
    for (const repo of repos) {
      const key = repo.toLowerCase();
      if (publisherRepos.has(key) || excluded.has(key) || key === list.repo.toLowerCase() || key.startsWith('anthropics/')) continue;
      if (!listed.has(key)) listed.set(key, { repo, lists: new Set() });
      listed.get(key).lists.add(list.repo);
    }
  } catch (error) {
    report.lists[list.repo] = `failed: ${error.message}`;
  }
}

// Repositories named by more lists are looked at first.
const candidates = [...listed.values()].sort((a, b) => b.lists.size - a.lists.size).slice(0, MAX_LIST_REPOS);
report.listedRepos.considered = candidates.length;
await pool(candidates, async ({ repo, lists }) => {
  try {
    const info = await repoInfo(repo);
    if (!info || info.private || info.archived || info.fork) return;
    if (info.stargazers_count < MIN_LISTED_STARS || Date.now() - Date.parse(info.pushed_at) > STALE_MS) return;
    const sha = (await api(`/repos/${repo}/commits/${encodeURIComponent(info.default_branch)}`)).sha;
    const skills = await skillsIn(repo, sha, MAX_SKILLS_PER_LISTED_REPO);
    if (!skills.length) return;
    report.listedRepos.used += 1;
    entries.push(...skills.map((s) => ({ ...s, tier: 'listed', lists: lists.size, stars: info.stargazers_count })));
  } catch {
    // A repository that can't be read is simply left out of the snapshot.
  }
});

entries.sort((a, b) => `${a.repo}/${a.path}`.localeCompare(`${b.repo}/${b.path}`));
const catalog = { version: 1, builtAt: new Date().toISOString().slice(0, 10), count: entries.length, entries };
writeFileSync(join(HERE, '..', 'data', 'catalog.json'), `${JSON.stringify(catalog)}\n`);
process.stderr.write(`${JSON.stringify(report, null, 1)}\n${entries.length} skills\n`);
