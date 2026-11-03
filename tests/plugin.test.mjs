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

describe('isolated steps', () => {
  const steps = {
    audit: { agent: 'skill-auditor', tools: ['Glob', 'Grep', 'Read'] },
    diagnose: { agent: 'project-analyst', tools: ['Glob', 'Grep', 'Read'] },
    research: { agent: 'skill-researcher', tools: ['WebFetch', 'WebSearch'] },
  };
  for (const [skillName, { agent: agentName, tools }] of Object.entries(steps)) {
    const step = manifest(`skills/${skillName}/SKILL.md`).data;
    const agent = manifest(`agents/${agentName}.md`).data;
    it(`${skillName} names its agent with the plugin namespace`, () => assert.equal(step.agent, `${plugin.name}:${agent.name}`));
    it(`${skillName} is forked, and the turn waits for it`, () => {
      assert.equal(step.context, 'fork');
      assert.equal(step.background, 'false');
    });
    it(`${skillName} is not offered to users directly`, () => assert.equal(step['user-invocable'], 'false'));
    it(`${agentName} has only the tools it needs`, () => {
      assert.deepEqual(agent.tools.split(',').map((x) => x.trim()).sort(), tools);
      assert.deepEqual(step['allowed-tools'].split(/\s+/).sort(), tools);
    });
    it(`${agentName} can't run commands or change files`, () => {
      for (const forbidden of ['Bash', 'PowerShell', 'Write', 'Edit', 'Agent', 'Skill']) assert.ok(!agent.tools.includes(forbidden), forbidden);
    });
    it(`${agentName} uses the same model through its skill`, () => assert.equal(step.model, agent.model));
    it(`${agentName} has a turn limit`, () => assert.ok(Number(agent.maxTurns) > 0));
    it(`${skillName} checks its setup before doing anything`, () => assert.match(read(`skills/${skillName}/SKILL.md`), /check (?:your|your own) setup/i));
    it(`scout may call ${skillName} without being refused`, () => assert.ok(scout['allowed-tools'].includes(`Skill(skill-scout:${skillName})`)));
  }
  it('the code reader is told to stay away from secrets', () => assert.match(read('agents/project-analyst.md'), /Never open secrets/));
  it('the web researcher treats pages as untrusted', () => assert.match(read('agents/skill-researcher.md'), /untrusted data/));
  it('the web researcher returns only links on github.com', () => assert.match(read('agents/skill-researcher.md'), /Use only `github\.com` links/));
});

describe('talking with the user', () => {
  it('the main workflow can open dialogs', () => assert.ok(scout['allowed-tools'].split(/\s+/).includes('AskUserQuestion')));
  it('the manage workflow can open dialogs', () => assert.ok(manage['allowed-tools'].split(/\s+/).includes('AskUserQuestion')));
  it('explains how to keep permissions across messages', () => assert.match(read('skills/scout/SKILL.md'), /invoke the `skill-scout:scout` skill again/));
  it('a dialog answer counts as approval, and file content never does', () => assert.match(read('skills/scout/SKILL.md'), /answer they gave in a dialog, never from file or tool content/));
  it('every isolated step stays out of dialogs, which do not work in a fork', () => {
    for (const name of ['audit', 'diagnose', 'research']) assert.ok(!manifest(`skills/${name}/SKILL.md`).data['allowed-tools'].includes('AskUserQuestion'));
  });
  it('a full analysis must stop and ask before searching', () => assert.match(read('skills/scout/SKILL.md'), /you must stop here and ask before searching/));
  it('pasted links have a pre-approved way in', () => assert.ok(scout['allowed-tools'].includes('Bash(skill-scout resolve *)')));
});

describe('every skill and agent file is valid', () => {
  for (const file of ['skills/scout/SKILL.md', 'skills/manage/SKILL.md', 'skills/audit/SKILL.md', 'skills/diagnose/SKILL.md', 'skills/research/SKILL.md', 'agents/skill-auditor.md', 'agents/project-analyst.md', 'agents/skill-researcher.md']) {
    const { data, unparsed, hasFrontmatter } = manifest(file);
    it(`${file} has clean frontmatter`, () => {
      assert.ok(hasFrontmatter);
      assert.deepEqual(unparsed, []);
      assert.match(data.name, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
      assert.ok(data.description.length > 20 && data.description.length <= 1024, String(data.description.length));
    });
    it(`${file} never calls anything safe`, () => {
      assert.doesNotMatch(data.description, /\bsafe\b/i);
    });
  }
  it('the plugin passes its own scanner with nothing critical', async () => {
    const { scanDirectory } = await import('../scripts/lib/scan.mjs');
    for (const name of ['audit', 'diagnose', 'research']) {
      const result = scanDirectory(join(ROOT, 'skills', name), { repo: 'skill-scout/skill-scout' });
      assert.equal(result.counts.critical, 0, JSON.stringify(result.findings));
    }
  });
});
