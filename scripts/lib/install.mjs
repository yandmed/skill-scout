// The install gate. Every check is re-run here against the bytes on disk, so nothing the model
// says, and nothing the AI auditor concludes, can make a blocked candidate installable.
import { cpSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseFrontmatter } from './frontmatter.mjs';
import { commitSha, repoInfo, subtree } from './github.mjs';
import { scanDirectory } from './scan.mjs';
import { hashDirectory, isInside, isReservedName, readJson, sanitizeText, UserError, writeJsonAtomic } from './util.mjs';
import { loadRecord } from './vet.mjs';

const NAME_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function scopePaths(scope, projectDir) {
  if (scope !== 'project' && scope !== 'user') throw new UserError('--scope must be project or user.', { code: 'bad-scope' });
  const claudeDir = scope === 'user' ? join(homedir(), '.claude') : join(resolve(projectDir), '.claude');
  return { claudeDir, skillsDir: join(claudeDir, 'skills'), lockPath: join(claudeDir, 'skill-scout.lock.json') };
}

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/**
 * The lockfile travels with the project, so a cloned repository can contain a hostile one. A
 * corrupt file is an error rather than an empty list, because saving over it would silently
 * forget what's installed. Entries with impossible names are ignored.
 */
function loadLock(lockPath) {
  if (!existsSync(lockPath)) return { version: 1, skills: Object.create(null) };
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(lockPath, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    throw new UserError(`The lockfile is not valid JSON: ${lockPath}. Fix or delete it.`, { code: 'lock-corrupt' });
  }
  const skills = Object.create(null);
  if (parsed && typeof parsed.skills === 'object' && parsed.skills) {
    for (const [name, entry] of Object.entries(parsed.skills)) {
      if (NAME_RE.test(name) && entry && typeof entry === 'object' && REPO_RE.test(String(entry.repo))) skills[name] = entry;
    }
  }
  return { version: parsed?.version ?? 1, skills };
}

/** Pure decision function: returns what stands between this record and an install. */
export function evaluateGate(record, freshScan, acknowledged = []) {
  const problems = [];
  const acks = new Set(acknowledged);

  if (record.kind !== 'skill') problems.push({ code: 'not-a-skill', message: 'Plugins are installed with Claude Code\'s own plugin manager, not by this command.' });
  if (freshScan.contentHash !== record.scan.contentHash) problems.push({ code: 'content-changed', message: 'Quarantined files changed since vetting. Vet again.' });

  const critical = freshScan.findings.filter((f) => f.severity === 'critical');
  if (critical.length) {
    problems.push({ code: 'blocked', message: 'Critical findings. Skill Scout will not install this.', rules: [...new Set(critical.map((f) => f.ruleId))] });
  }

  if (!record.audit) {
    problems.push({ code: 'audit-missing', message: 'The AI audit has not been recorded for this candidate.' });
  } else if (record.audit.contentHash !== freshScan.contentHash) {
    problems.push({ code: 'audit-stale', message: 'The AI audit was recorded for different content. Audit again.' });
  } else if (record.audit.risk === 'malicious') {
    problems.push({ code: 'audit-malicious', message: 'The AI audit judged this malicious. Skill Scout will not install it.' });
  } else if (record.audit.risk === 'suspicious' && !acks.has('audit-suspicious')) {
    problems.push({ code: 'needs-ack', message: 'The AI audit raised concerns the user must acknowledge.', rules: ['audit-suspicious'] });
  } else if (record.audit.risk !== 'benign' && record.audit.risk !== 'suspicious') {
    // Fail closed: record-audit only writes known values, so anything else means the file was altered.
    problems.push({ code: 'audit-invalid', message: 'The recorded audit has an unknown result. Audit again.' });
  }

  const unacked = [...new Set(freshScan.findings.filter((f) => f.severity === 'high').map((f) => f.ruleId))].filter((rule) => !acks.has(rule));
  if (unacked.length) problems.push({ code: 'needs-ack', message: 'High-severity findings must be acknowledged by the user, one by one.', rules: unacked });

  return problems;
}

export function installSkill({ record: id, scope, projectDir, acknowledged = [], replace = false }) {
  const record = loadRecord(id);
  const freshScan = scanDirectory(record.filesDir, {
    repo: record.repo,
    fetchFindings: record.scan.findings.filter((f) => ['symlink', 'external-symlink', 'internal-symlink', 'submodule', 'unsafe-filename', 'case-collision', 'path-traversal', 'no-license'].includes(f.ruleId)),
  });
  const problems = evaluateGate(record, freshScan, acknowledged);
  if (problems.length) return { installed: false, problems };

  const manifestPath = join(record.filesDir, 'SKILL.md');
  if (!existsSync(manifestPath)) return { installed: false, problems: [{ code: 'no-manifest', message: 'No SKILL.md at the top of this candidate.' }] };
  const { data } = parseFrontmatter(readFileSync(manifestPath, 'utf8'));
  const name = data.name || record.path.split('/').pop() || record.repo.split('/')[1];
  if (!NAME_RE.test(name) || name.length > 64 || isReservedName(name)) return { installed: false, problems: [{ code: 'bad-name', message: 'Skill name is not valid under the Agent Skills spec.' }] };

  const { claudeDir, skillsDir, lockPath } = scopePaths(scope, projectDir);
  const destination = join(skillsDir, name);
  if (!isInside(skillsDir, destination)) return { installed: false, problems: [{ code: 'bad-name', message: 'Skill name escapes the skills folder.' }] };

  const lock = loadLock(lockPath);
  if (existsSync(destination)) {
    if (!lock.skills[name]) return { installed: false, problems: [{ code: 'name-taken', message: `"${name}" already exists and was not installed by Skill Scout, so it was left untouched.` }] };
    if (!replace) return { installed: false, problems: [{ code: 'already-installed', message: `"${name}" is already installed. Pass --replace to update it.` }] };
  }

  // Build next to the target, then swap with rename: Claude Code watches this folder live and
  // must never see a half-copied skill.
  const staging = join(claudeDir, `.skill-scout-staging-${process.pid}`);
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(skillsDir, { recursive: true });
  try {
    cpSync(record.filesDir, staging, { recursive: true, verbatimSymlinks: true });
    if (hashDirectory(staging) !== freshScan.contentHash) throw new UserError('Copy verification failed; nothing was installed.', { code: 'copy-mismatch' });
    rmSync(destination, { recursive: true, force: true });
    renameSync(staging, destination);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }

  lock.skills[name] = {
    id: record.id,
    repo: record.repo,
    path: record.path,
    commit: record.commit,
    treeSha: record.treeSha,
    contentHash: freshScan.contentHash,
    license: data.license ? String(data.license).slice(0, 120) : record.repoMeta?.license ?? null,
    sourceUrl: record.sourceUrl,
    installedAt: new Date().toISOString(),
    scanVerdict: freshScan.verdict,
    auditRisk: record.audit.risk,
    acknowledged: [...new Set(acknowledged)],
  };
  writeJsonAtomic(lockPath, { ...lock, skills: { ...lock.skills } });
  return { installed: true, name, scope, path: destination, entry: lock.skills[name] };
}

export function listManaged(projectDir) {
  const out = [];
  for (const scope of ['project', 'user']) {
    const { skillsDir, lockPath } = scopePaths(scope, projectDir);
    for (const [name, entry] of Object.entries(loadLock(lockPath).skills)) {
      out.push({ name, scope, directory: join(skillsDir, name), ...entry });
    }
  }
  return out;
}

/** Detects files edited or tampered with since install, and re-scans with the current rules. */
export function verifyManaged(projectDir) {
  return listManaged(projectDir).map((skill) => {
    if (!existsSync(skill.directory)) return { name: skill.name, scope: skill.scope, status: 'missing' };
    const scan = scanDirectory(skill.directory, { repo: skill.repo });
    const drifted = scan.contentHash !== skill.contentHash;
    let status = 'ok';
    if (drifted) status = 'modified';
    else if (scan.verdict === 'blocked') status = 'now-blocked';
    return { name: skill.name, scope: skill.scope, status, verdict: scan.verdict, counts: scan.counts, findings: scan.findings.filter((f) => ['critical', 'high'].includes(f.severity)) };
  });
}

/** Tree SHAs change exactly when a folder's content changes, so this is precise and cheap. */
export async function checkOutdated(projectDir) {
  const results = [];
  for (const skill of listManaged(projectDir)) {
    try {
      const info = await repoInfo(skill.repo);
      if (!info) {
        results.push({ name: skill.name, status: 'source-gone', repo: skill.repo });
        continue;
      }
      const head = await commitSha(skill.repo, info.default_branch);
      const { treeSha } = await subtree(skill.repo, head, skill.path);
      results.push({ name: skill.name, id: skill.id, status: treeSha === skill.treeSha ? 'current' : 'update-available', pinned: skill.commit.slice(0, 7), latest: head.slice(0, 7), archived: info.archived });
    } catch (error) {
      results.push({ name: skill.name, status: 'unknown', error: String(error.message).slice(0, 160) });
    }
  }
  return results;
}

export function removeManaged({ name, scope, projectDir }) {
  const { skillsDir, lockPath } = scopePaths(scope, projectDir);
  const lock = loadLock(lockPath);
  if (!lock.skills[name]) throw new UserError(`"${sanitizeText(name, 80)}" was not installed by Skill Scout, so it will not be removed.`, { code: 'not-managed' });
  const target = join(skillsDir, name);
  if (!isInside(skillsDir, target)) throw new UserError('Refusing to remove a path outside the skills folder.', { code: 'bad-name' });
  rmSync(target, { recursive: true, force: true });
  delete lock.skills[name];
  writeJsonAtomic(lockPath, { ...lock, skills: { ...lock.skills } });
  return { removed: true, name, scope };
}
