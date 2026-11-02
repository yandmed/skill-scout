// GitHub access. Public data only. The token is sent to api.github.com and nowhere else:
// downloads go through raw.githubusercontent.com unauthenticated, pinned to a commit SHA.
import { execFileSync } from 'node:child_process';
import { UserError } from './util.mjs';

const API = 'https://api.github.com';
const TIMEOUT_MS = 20000;
let cachedToken;

export function githubToken() {
  if (cachedToken !== undefined) return cachedToken;
  cachedToken = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || null;
  if (!cachedToken) {
    try {
      cachedToken = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true }).trim() || null;
    } catch {
      cachedToken = null;
    }
  }
  return cachedToken;
}

export async function api(path, { allow404 = false } = {}) {
  const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'skill-scout' };
  const token = githubToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API}${path}`, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (response.status === 404 && allow404) return null;
  if (response.status === 403 || response.status === 429) {
    const remaining = response.headers.get('x-ratelimit-remaining');
    const hint = token ? 'Wait a minute and retry.' : 'Run `gh auth login` for a much higher limit.';
    throw new UserError(`GitHub rate limit reached (remaining: ${remaining ?? 'unknown'}). ${hint}`, { code: 'rate-limited' });
  }
  if (!response.ok) throw new UserError(`GitHub API returned ${response.status} for ${path}`, { code: 'github-error' });
  return response.json();
}

export const repoInfo = (repo) => api(`/repos/${repo}`, { allow404: true });

export async function commitSha(repo, ref) {
  const commit = await api(`/repos/${repo}/commits/${encodeURIComponent(ref)}`);
  return commit.sha;
}

/** Recursive listing of a repository at a commit; `truncated` means GitHub cut it short. */
export const fullTree = (repo, sha) => api(`/repos/${repo}/git/trees/${sha}?recursive=1`);

/**
 * List one directory recursively. Walks down path segments so it keeps working on monorepos
 * where the recursive listing of the whole repo would be truncated.
 */
export async function subtree(repo, sha, path) {
  let treeSha = sha;
  for (const segment of path.split('/').filter(Boolean)) {
    const level = await api(`/repos/${repo}/git/trees/${treeSha}`);
    const next = level.tree.find((entry) => entry.path === segment && entry.type === 'tree');
    if (!next) throw new UserError(`Path not found in ${repo}@${sha.slice(0, 7)}: ${path}`, { code: 'path-not-found' });
    treeSha = next.sha;
  }
  const result = await api(`/repos/${repo}/git/trees/${treeSha}?recursive=1`);
  return { treeSha, entries: result.tree, truncated: Boolean(result.truncated) };
}

export async function downloadRaw(repo, sha, path, maxBytes) {
  const url = `https://raw.githubusercontent.com/${repo}/${sha}/${path.split('/').map(encodeURIComponent).join('/')}`;
  const response = await fetch(url, { headers: { 'User-Agent': 'skill-scout' }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new UserError(`Download failed (${response.status}): ${path}`, { code: 'download-failed' });
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) throw new UserError(`File exceeds the ${maxBytes}-byte limit: ${path}`, { code: 'file-too-large' });
  return buffer;
}

export async function rawText(repo, ref, path, maxBytes = 2 * 1024 * 1024) {
  return (await downloadRaw(repo, ref, path, maxBytes)).toString('utf8');
}
