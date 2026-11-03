// Downloads a candidate into quarantine at an immutable commit and scans it. Files are only ever
// written as inert bytes, outside any directory Claude Code discovers skills from.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { parseFrontmatter } from './frontmatter.mjs';
import { commitSha, downloadRaw, fullTree, rawText, repoInfo, subtree } from './github.mjs';
import { scanDirectory } from './scan.mjs';
import { isValidRepo, isValidRepoPath } from './sources.mjs';
import { dataDir, isInside, isUnsafeRepoPath, readJson, sanitizeText, sha256, slugify, UserError, writeJsonAtomic } from './util.mjs';

const MAX_FILES = 300;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 30 * 1024 * 1024;
const CONCURRENCY = 8;
const MAX_NAME_LOOKUPS = 40;

/** ids look like `skill:owner/repo/path/to/skill` or `skill:owner/repo#name` (path still unknown). */
export function parseCandidateId(id) {
  const match = String(id).match(/^(skill|plugin):([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/([^#]*))?(?:#([A-Za-z0-9_.-]+))?$/);
  if (!match) throw new UserError(`Invalid candidate id: ${sanitizeText(id, 120)}`, { code: 'bad-id' });
  const [, kind, repo, path = '', hint] = match;
  if (!isValidRepo(repo) || !isValidRepoPath(path)) throw new UserError('Candidate id has an unsafe repository or path.', { code: 'bad-id' });
  return { kind, repo, path, hint };
}

export const quarantineRoot = () => join(dataDir(), 'quarantine');
// The slug is for humans. The hash keeps different ids apart: "a/b-c" and "a-b/c" have the same slug.
export const recordDir = (id) => join(quarantineRoot(), `${slugify(id).slice(0, 80)}-${sha256(String(id)).slice(0, 12)}`);
export const recordPath = (id) => join(recordDir(id), 'record.json');

export function loadRecord(id) {
  const record = readJson(recordPath(id), null);
  if (!record) throw new UserError(`No vetting record for ${sanitizeText(id, 120)}. Run \`vet\` first.`, { code: 'not-vetted' });
  if (record.id !== id) throw new UserError('This vetting record belongs to another candidate. Vet again.', { code: 'record-mismatch' });
  return record;
}

/** Registries such as skills.sh give only a name, so locate that skill's folder in the repository. */
async function locateSkill(repo, sha, hint) {
  const tree = await fullTree(repo, sha);
  const manifests = tree.tree.filter((e) => e.type === 'blob' && /(?:^|\/)SKILL\.md$/.test(e.path)).map((e) => e.path);
  const wanted = hint.toLowerCase();
  const exact = manifests.filter((p) => p.split('/').slice(-2, -1)[0]?.toLowerCase() === wanted);
  if (exact.length) return exact.sort((a, b) => a.length - b.length)[0].replace(/\/?SKILL\.md$/, '');
  if (manifests.length === 1) return manifests[0].replace(/\/?SKILL\.md$/, '');
  // Registries report the name from the frontmatter, which may differ from the folder's name.
  for (const manifest of manifests.slice(0, MAX_NAME_LOOKUPS)) {
    const text = await rawText(repo, sha, manifest).catch(() => '');
    if (String(parseFrontmatter(text).data.name ?? '').toLowerCase() === wanted) return manifest.replace(/\/?SKILL\.md$/, '');
  }
  throw new UserError(`Could not find a skill named "${sanitizeText(hint, 60)}" in ${repo}.`, { code: 'path-not-found' });
}

/** Git stores a link's target as text, so it can be judged without ever creating the link. */
export function classifySymlink(entryPath, basePath, target) {
  const finding = (ruleId, severity, message) => ({ ruleId, severity, file: sanitizeText(entryPath, 200), line: 0, excerpt: sanitizeText(target, 120), message });
  const outside = finding('symlink', 'critical', 'Contains a symbolic link pointing out of the repository, for example at your private files.');
  if (!target || target.startsWith('/') || target.startsWith('~') || /^[A-Za-z]:/.test(target) || target.includes('\\')) return outside;
  const fromRepoRoot = [...basePath.split('/').filter(Boolean), ...entryPath.split('/').slice(0, -1)];
  const depthOfSkill = basePath.split('/').filter(Boolean).length;
  const walked = [...fromRepoRoot];
  let leftSkill = false;
  for (const part of target.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (!walked.length) return outside;
      walked.pop();
      if (walked.length < depthOfSkill) leftSkill = true;
    } else {
      walked.push(part);
    }
  }
  if (leftSkill) return finding('external-symlink', 'high', 'Contains a link to elsewhere in its repository. That content was not reviewed and will not be copied, so the skill may be incomplete.');
  return finding('internal-symlink', 'medium', 'Contains a link within its own folder. Links are never copied, so the skill may be incomplete.');
}

async function downloadAll(repo, sha, basePath, entries, destination) {
  const fetchFindings = [];
  const blobs = [];
  const seenPaths = new Map();
  for (const entry of entries) {
    if (isUnsafeRepoPath(entry.path)) {
      // Never written: on Windows such a name can hide data in a stream no scanner would read.
      fetchFindings.push({ ruleId: 'unsafe-filename', severity: 'critical', file: sanitizeText(entry.path, 200), line: 0, excerpt: '', message: 'File name is unsafe on some systems and could hide content or escape the skill folder.' });
      continue;
    }
    // On case-insensitive disks these would overwrite each other after being reviewed.
    const folded = entry.path.normalize('NFC').toLowerCase();
    if (entry.type === 'blob' && seenPaths.has(folded)) {
      fetchFindings.push({ ruleId: 'case-collision', severity: 'critical', file: sanitizeText(entry.path, 200), line: 0, excerpt: '', message: `Differs only by letter case from ${sanitizeText(seenPaths.get(folded), 120)}: one would overwrite the other on many disks.` });
      continue;
    }
    if (entry.type === 'blob') seenPaths.set(folded, entry.path);
    if (entry.mode === '120000') {
      // Never written to disk, whatever it points at. Only the severity depends on the target.
      const target = await downloadRaw(repo, sha, basePath ? `${basePath}/${entry.path}` : entry.path, 4096).then((b) => b.toString('utf8').trim()).catch(() => null);
      fetchFindings.push(classifySymlink(entry.path, basePath, target));
    } else if (entry.type === 'commit') {
      fetchFindings.push({ ruleId: 'submodule', severity: 'high', file: entry.path, line: 0, excerpt: '', message: 'Git submodule: its code lives elsewhere and was not reviewed.' });
    } else if (entry.type === 'blob') {
      blobs.push(entry);
    }
  }
  if (blobs.length > MAX_FILES) throw new UserError(`Candidate has ${blobs.length} files; the limit is ${MAX_FILES}.`, { code: 'too-many-files' });
  const declaredTotal = blobs.reduce((sum, b) => sum + (b.size ?? 0), 0);
  if (declaredTotal > MAX_TOTAL_BYTES) throw new UserError(`Candidate is ${declaredTotal} bytes; the limit is ${MAX_TOTAL_BYTES}.`, { code: 'too-large' });

  let next = 0;
  let total = 0;
  const worker = async () => {
    while (next < blobs.length) {
      const entry = blobs[(next += 1) - 1];
      const target = resolve(destination, entry.path);
      if (!isInside(destination, target)) {
        fetchFindings.push({ ruleId: 'path-traversal', severity: 'critical', file: sanitizeText(entry.path, 200), line: 0, excerpt: '', message: 'File path tries to escape the skill folder.' });
        continue;
      }
      const remote = basePath ? `${basePath}/${entry.path}` : entry.path;
      const bytes = await downloadRaw(repo, sha, remote, MAX_FILE_BYTES);
      total += bytes.length;
      if (total > MAX_TOTAL_BYTES) throw new UserError('Candidate exceeded the total download limit.', { code: 'too-large' });
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, bytes, { mode: 0o644 }); // Execute bits are dropped on purpose.
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return fetchFindings;
}

function licenseFinding(meta, skillLicense) {
  if (meta?.license && meta.license !== 'NOASSERTION') return [];
  if (skillLicense) return [];
  return [{ ruleId: 'no-license', severity: 'medium', file: '(repository)', line: 0, excerpt: '', message: 'No license was found, so by default you have no right to copy or reuse this code.' }];
}

export function summarizeRepo(info) {
  if (!info) return null;
  return {
    stars: info.stargazers_count,
    forks: info.forks_count,
    openIssues: info.open_issues_count,
    pushedAt: info.pushed_at,
    createdAt: info.created_at,
    archived: info.archived,
    fork: info.fork,
    license: info.license?.spdx_id ?? null,
    ownerType: info.owner?.type,
    defaultBranch: info.default_branch,
  };
}

export async function vetCandidate(id) {
  const parsed = parseCandidateId(id);
  const info = await repoInfo(parsed.repo);
  if (!info) throw new UserError(`Repository not found: ${parsed.repo}`, { code: 'repo-not-found' });
  if (info.private) throw new UserError('Private repositories are not supported.', { code: 'private-repo' });

  const sha = await commitSha(parsed.repo, info.default_branch);
  // A plugin whose id has no path lives at the repository root; only skills need locating by name.
  const path = parsed.path || (parsed.hint && parsed.kind === 'skill' ? await locateSkill(parsed.repo, sha, parsed.hint) : '');
  const { treeSha, entries, truncated } = await subtree(parsed.repo, sha, path);
  if (truncated) throw new UserError('Candidate is too large to list completely, so it cannot be reviewed.', { code: 'too-large' });

  const root = recordDir(id);
  const filesDir = join(root, 'files');
  rmSync(root, { recursive: true, force: true });
  mkdirSync(filesDir, { recursive: true });

  const fetchFindings = await downloadAll(parsed.repo, sha, path, entries, filesDir);
  const meta = summarizeRepo(info);
  const manifestPath = join(filesDir, 'SKILL.md');
  const skillLicense = existsSync(manifestPath) ? parseFrontmatter(readFileSync(manifestPath, 'utf8')).data.license : null;
  const scan = scanDirectory(filesDir, {
    repo: parsed.repo,
    fetchFindings: [...fetchFindings, ...licenseFinding(meta, skillLicense)],
  });

  const record = {
    id,
    kind: parsed.kind,
    repo: parsed.repo,
    path,
    commit: sha,
    treeSha,
    vettedAt: new Date().toISOString(),
    repoMeta: meta,
    filesDir,
    scan,
    audit: null,
    sourceUrl: `https://github.com/${parsed.repo}/tree/${sha}${path ? `/${path}` : ''}`,
  };
  writeJsonAtomic(recordPath(id), record);
  return record;
}

/** The AI auditor's result, reduced to enums and short codes so no free text reaches a shell. */
export function recordAudit(id, risk, codes, coverage) {
  if (!['benign', 'suspicious', 'malicious'].includes(risk)) throw new UserError('--risk must be benign, suspicious or malicious.', { code: 'bad-risk' });
  if (!['complete', 'partial'].includes(coverage)) throw new UserError('--coverage must be complete or partial.', { code: 'bad-coverage' });
  const clean = codes.flatMap((c) => String(c).split(',')).map((c) => c.trim()).filter((c) => c && c !== 'none');
  for (const code of clean) {
    if (!/^[a-z0-9-]{1,48}$/.test(code)) throw new UserError('Audit codes must be short kebab-case words.', { code: 'bad-codes' });
  }
  const record = loadRecord(id);
  // "I couldn't look" must never read as "I found nothing". An auditor once returned benign after
  // its file reads were denied, so this rule lives here, where no report can talk its way past it.
  const incomplete = coverage === 'partial' && risk === 'benign';
  record.audit = {
    risk: incomplete ? 'suspicious' : risk,
    codes: incomplete ? [...new Set([...clean, 'audit-incomplete'])] : clean,
    coverage,
    contentHash: record.scan.contentHash,
    recordedAt: new Date().toISOString(),
  };
  writeJsonAtomic(recordPath(id), record);
  return record;
}
