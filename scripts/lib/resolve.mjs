// Turns whatever a person pastes (a link, owner/repo, an install command) into a location in a Git
// repository. Everything downstream only ever deals with a repository, a path and a pinned commit,
// which is what lets discovery happen anywhere while the files always come from Git.
import { commitSha, fullTree, repoInfo } from './github.mjs';
import { isValidRepo, isValidRepoPath, makeCandidate } from './sources.mjs';
import { UserError } from './util.mjs';

const cleanRepo = (owner, name) => `${owner}/${String(name).replace(/\.git$/, '')}`;
const cleanPath = (segments) => segments.filter(Boolean).join('/').replace(/\/?SKILL\.md$/i, '');
const safeDecode = (value) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

/** Location in a GitHub repository from a URL on github.com or raw.githubusercontent.com, or null. */
export function parseGithubUrl(input) {
  let url;
  try {
    url = new URL(String(input).trim());
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  const host = url.hostname.toLowerCase();
  const parts = url.pathname.split('/').filter(Boolean).map(safeDecode);
  if (host === 'raw.githubusercontent.com') {
    if (parts.length < 3) return null;
    const [owner, name, , ...rest] = parts;
    return { repo: cleanRepo(owner, name), path: cleanPath(rest) };
  }
  if (host !== 'github.com' && host !== 'www.github.com') return null;
  if (parts.length < 2) return null;
  const [owner, name, view, , ...rest] = parts;
  if (parts.length === 2) return { repo: cleanRepo(owner, name), path: '' };
  if (view !== 'tree' && view !== 'blob') return { repo: cleanRepo(owner, name), path: '' };
  return { repo: cleanRepo(owner, name), path: cleanPath(rest) };
}

/**
 * Accepts the forms people really share. Returns { repo, path, hint }, or throws: another host gets
 * its own error, so the user learns why instead of seeing a generic failure.
 */
export function parseReference(input) {
  const text = String(input ?? '').trim();
  if (!text || text.length > 500) throw new UserError('Pass a link or owner/repo.', { code: 'bad-reference' });

  const install = text.match(/^(?:npx\s+(?:-y\s+)?)?skills(?:@\S+)?\s+add\s+(\S+)(?:\s+(?:--skill|-s)\s+([\w.-]+))?/i);
  if (install) {
    const inner = parseReference(install[1]);
    return install[2] ? { ...inner, hint: install[2] } : inner;
  }

  const ssh = text.match(/^(?:ssh:\/\/)?git@github\.com[:/]([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i);
  if (ssh) return finish({ repo: cleanRepo(ssh[1], ssh[2]), path: '' });

  if (/^[a-z][a-z0-9+.-]*:/i.test(text)) {
    const github = parseGithubUrl(text);
    if (github) return finish(github);
    let url;
    try {
      url = new URL(text);
    } catch {
      throw new UserError('That link could not be read.', { code: 'bad-reference' });
    }
    if (url.hostname.toLowerCase() === 'skills.sh' || url.hostname.toLowerCase() === 'www.skills.sh') {
      const [owner, name, skill] = url.pathname.split('/').filter(Boolean);
      if (owner && name) return finish({ repo: cleanRepo(owner, name), path: '', hint: skill });
    }
    throw new UserError(`Only GitHub is supported for now, not ${url.hostname}. Skills are reviewed at a pinned GitHub commit.`, { code: 'unsupported-host' });
  }

  const short = text.match(/^([\w.-]+)\/([\w.-]+)(?:@([\w.-]+))?(?:\/(.+))?$/);
  if (short) return finish({ repo: cleanRepo(short[1], short[2]), path: cleanPath((short[4] ?? '').split('/')), hint: short[3] });
  throw new UserError('Pass a GitHub link or owner/repo.', { code: 'bad-reference' });
}

function finish(reference) {
  if (!isValidRepo(reference.repo) || !isValidRepoPath(reference.path)) throw new UserError('That reference has an unsafe repository or path.', { code: 'bad-reference' });
  return reference;
}

const relevance = (path, terms) => {
  const haystack = path.toLowerCase();
  return terms.filter((term) => haystack.includes(term)).length;
};

/** The skills a repository really contains, best match for the query first. */
export async function listRepoSkills(repo, { terms = [], limit = 20, source = 'resolve' } = {}) {
  const info = await repoInfo(repo);
  if (!info) throw new UserError(`Repository not found: ${repo}`, { code: 'repo-not-found' });
  if (info.private) throw new UserError('Private repositories are not supported.', { code: 'private-repo' });
  const sha = await commitSha(repo, info.default_branch);
  const tree = await fullTree(repo, sha);
  const lowered = terms.map((t) => String(t).toLowerCase()).filter((t) => t.length > 2);
  const paths = tree.tree
    .filter((entry) => entry.type === 'blob' && /(?:^|\/)SKILL\.md$/.test(entry.path))
    .map((entry) => entry.path.replace(/\/?SKILL\.md$/, ''))
    .filter((path) => isValidRepoPath(path))
    .sort((a, b) => relevance(b, lowered) - relevance(a, lowered) || a.length - b.length || a.localeCompare(b));
  const candidates = paths.slice(0, limit).map((path) => makeCandidate({
    name: path ? path.split('/').pop() : repo.split('/')[1],
    description: info.description,
    repo,
    path,
    source,
    stars: info.stargazers_count,
  })).filter(Boolean);
  return { candidates, total: paths.length, truncated: Boolean(tree.truncated) };
}

/** Candidates for one pasted reference. A link to one skill gives one; a repository lists its skills. */
export async function resolveReference(input, { terms = [] } = {}) {
  const reference = parseReference(input);
  const { candidates, total, truncated } = await listRepoSkills(reference.repo, { terms: reference.hint ? [reference.hint, ...terms] : terms, limit: reference.path || reference.hint ? 300 : 20 });
  let chosen = candidates;
  if (reference.path) chosen = candidates.filter((c) => c.path === reference.path);
  else if (reference.hint) chosen = candidates.filter((c) => c.name.toLowerCase() === reference.hint.toLowerCase());
  return { reference, candidates: chosen, totalInRepository: total, truncated };
}
