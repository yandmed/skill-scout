// Shared helpers. Zero runtime dependencies by design: a tool that vets supply-chain
// risk should not bring a supply chain of its own.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

export class UserError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'UserError';
    this.details = details;
  }
}

export function dataDir() {
  const dir = process.env.SKILL_SCOUT_HOME || join(homedir(), '.skill-scout');
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Remove characters that can hide content from a human or smuggle instructions to a model,
 * then bound the length. Anything that came from the internet goes through this before it
 * reaches stdout, because stdout is read by the orchestrating model.
 */
export function sanitizeText(value, max = 300) {
  if (value === null || value === undefined) return '';
  const cleaned = String(value)
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, ' ')
    .replace(/[​-‏‪-‮⁠-⁩﻿]/g, '')
    .replace(/[\u{E0000}-\u{E007F}]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

export function readJson(path, fallback = undefined) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
  } catch (error) {
    if (fallback !== undefined) return fallback;
    throw error;
  }
}

/** Write through a sibling temp file so a crash can never leave a half-written JSON file. */
export function writeJsonAtomic(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
  renameSync(tmp, path);
}

/** True only when `child` resolves strictly inside `parent`. */
export function isInside(parent, child) {
  const rel = relative(resolve(parent), resolve(child));
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

export function listFilesRecursive(root) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(full);
    }
  };
  if (existsSync(root)) walk(root);
  return out.sort();
}

/** Stable digest of a directory: order-independent, covers both paths and bytes. */
export function hashDirectory(root) {
  const lines = listFilesRecursive(root).map((file) => {
    const rel = relative(root, file).split(sep).join('/');
    return `${rel}\0${sha256(readFileSync(file))}`;
  });
  return sha256(lines.sort().join('\n'));
}

export function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf('=');
    const key = eq > -1 ? arg.slice(2, eq) : arg.slice(2);
    let value;
    if (eq > -1) value = arg.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) value = argv[(i += 1)];
    else value = true;
    if (key in flags) flags[key] = [].concat(flags[key], value);
    else flags[key] = value;
  }
  return { positional, flags };
}

export const asArray = (value) => (value === undefined ? [] : [].concat(value));

export function slugify(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120);
}
