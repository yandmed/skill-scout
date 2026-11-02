// Checks on how the plugin is wired. These mistakes raise no error at runtime: a wrong agent name,
// for example, silently runs the audit in a general agent that has shell access.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseFrontmatter } from '../scripts/lib/frontmatter.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (path) => readFileSync(join(ROOT, path), 'utf8');
const manifest = (path) => parseFrontmatter(read(path));
const plugin = JSON.parse(read('.claude-plugin/plugin.json'));
const auditor = manifest('agents/skill-auditor.md').data;
const audit = manifest('skills/audit/SKILL.md').data;
const scout = manifest('skills/scout/SKILL.md').data;
const manage = manifest('skills/manage/SKILL.md').data;

describe('the auditor that reads hostile files', () => {
  it('audit skill names the agent with its plugin namespace', () => {
    assert.equal(audit.agent, `${plugin.name}:${auditor.name}`);
  });

  it('runs in isolation, and the invoking turn waits for it', () => {
    assert.equal(audit.context, 'fork');
    assert.equal(audit.background, 'false');
  });

  it('has read-only tools and nothing else', () => {
    assert.deepEqual(auditor.tools.split(',').map((t) => t.trim()).sort(), ['Glob', 'Grep', 'Read']);
    assert.deepEqual(audit['allowed-tools'].split(/\s+/).sort(), ['Glob', 'Grep', 'Read']);
  });

  it('stops instead of auditing when started without its setup', () => {
    const body = read('skills/audit/SKILL.md');
    assert.match(body, /only tools must be Read, Glob and Grep/);
    assert.match(body, /CODES: audit-inconclusive/);
  });

  it('uses the same model through either entry point', () => {
    assert.equal(audit.model, auditor.model);
  });
});

describe('pre-approved commands', () => {
  const CHANGES_THE_PROJECT = /\b(?:install|remove)\b/;
  for (const [name, data] of [['scout', scout], ['manage', manage]]) {
    const tools = data['allowed-tools'];

    it(`${name} never pre-approves changing the user's project`, () => {
      const commands = tools.match(/(?:Bash|PowerShell)\([^)]*\)/g);
      assert.ok(commands.length > 0);
      for (const command of commands) assert.doesNotMatch(command, CHANGES_THE_PROJECT);
    });

    it(`${name} only pre-approves the skill-scout launcher, by exact prefix`, () => {
      for (const command of tools.match(/(?:Bash|PowerShell)\([^)]*\)/g)) {
        assert.match(command, /^(?:Bash|PowerShell)\(skill-scout [a-z-]+(?: \*)?\)$/);
      }
    });

    it(`${name} can call the audit skill without being refused`, () => {
      assert.ok(tools.includes('Skill(skill-scout:audit)'));
    });
  }
});

describe('the plugin itself', () => {
  it('ships no hooks, MCP servers or monitors', () => {
    for (const key of ['hooks', 'mcpServers', 'lspServers', 'monitors']) assert.ok(!(key in plugin), key);
  });

  it('has no runtime dependencies', () => {
    const pkg = JSON.parse(read('package.json'));
    assert.deepEqual(Object.keys(pkg.dependencies ?? {}), []);
  });

  it('keeps versions in sync', () => {
    assert.equal(plugin.version, JSON.parse(read('package.json')).version);
  });
});
