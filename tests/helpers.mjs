import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

/** Build a throwaway directory from a { 'relative/path': content } map. */
export function makeDir(files = {}) {
  const root = mkdtempSync(join(tmpdir(), 'skill-scout-test-'));
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

export const cleanup = (dir) => rmSync(dir, { recursive: true, force: true });

export const skill = (body, front = 'name: demo-skill\ndescription: Formats markdown tables. Use when editing markdown.') => `---\n${front}\n---\n\n${body}\n`;
