// The install gate is the one piece that must never be wrong, so instead of examples this walks
// every combination of its inputs and compares the result with an independent statement of the
// policy, written out below without looking at how evaluateGate is implemented.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { evaluateGate } from '../scripts/lib/install.mjs';

const KINDS = ['skill', 'plugin'];
const CONTENT = ['same', 'changed'];
const SCANS = [
  { label: 'clean', findings: [] },
  { label: 'medium', findings: [{ severity: 'medium', ruleId: 'm1' }] },
  { label: 'one high', findings: [{ severity: 'high', ruleId: 'h1' }] },
  { label: 'two highs', findings: [{ severity: 'high', ruleId: 'h1' }, { severity: 'high', ruleId: 'h2' }] },
  { label: 'critical', findings: [{ severity: 'critical', ruleId: 'c1' }] },
  { label: 'critical and high', findings: [{ severity: 'critical', ruleId: 'c1' }, { severity: 'high', ruleId: 'h1' }] },
];
const AUDITS = ['missing', 'stale', 'benign', 'suspicious', 'malicious'];
const ACKS = [[], ['h1'], ['h1', 'h2'], ['audit-suspicious'], ['h1', 'h2', 'audit-suspicious'], ['c1', 'h1', 'h2', 'audit-suspicious', 'blocked', 'audit-malicious']];

/** The policy, stated independently: when may this install go ahead? */
function mayInstall({ kind, content, scan, audit, acks }) {
  if (kind !== 'skill' || content !== 'same') return false;
  if (scan.findings.some((f) => f.severity === 'critical')) return false;
  if (audit === 'missing' || audit === 'stale' || audit === 'malicious') return false;
  if (audit === 'suspicious' && !acks.includes('audit-suspicious')) return false;
  return scan.findings.filter((f) => f.severity === 'high').every((f) => acks.includes(f.ruleId));
}

function build({ kind, content, scan, audit }) {
  const recordHash = 'hash-a';
  const freshHash = content === 'same' ? recordHash : 'hash-b';
  const auditHash = audit === 'stale' ? 'hash-old' : freshHash;
  return {
    record: { kind, scan: { contentHash: recordHash }, audit: audit === 'missing' ? null : { risk: audit === 'stale' ? 'benign' : audit, contentHash: auditHash } },
    fresh: { contentHash: freshHash, findings: scan.findings },
  };
}

describe('install gate: every combination of inputs', () => {
  for (const kind of KINDS) for (const content of CONTENT) for (const scan of SCANS) for (const audit of AUDITS) for (const acks of ACKS) {
    it(`${kind}, ${content}, ${scan.label}, audit ${audit}, acks [${acks.join(' ')}]`, () => {
      const { record, fresh } = build({ kind, content, scan, audit });
      const problems = evaluateGate(record, fresh, acks);
      assert.equal(problems.length === 0, mayInstall({ kind, content, scan, audit, acks }), JSON.stringify(problems));
    });
  }
});

describe('install gate: what it reports', () => {
  const clean = { contentHash: 'h', findings: [] };
  const ok = { kind: 'skill', scan: { contentHash: 'h' }, audit: { risk: 'benign', contentHash: 'h' } };

  it('names exactly the rules still waiting for acknowledgement', () => {
    const fresh = { contentHash: 'h', findings: [{ severity: 'high', ruleId: 'a' }, { severity: 'high', ruleId: 'b' }, { severity: 'high', ruleId: 'a' }] };
    const [problem] = evaluateGate(ok, fresh, ['a']);
    assert.equal(problem.code, 'needs-ack');
    assert.deepEqual(problem.rules, ['b']);
  });

  it('acknowledging a critical rule id changes nothing', () => {
    const fresh = { contentHash: 'h', findings: [{ severity: 'critical', ruleId: 'c' }] };
    assert.equal(evaluateGate(ok, fresh, ['c', 'blocked'])[0].code, 'blocked');
  });

  it('acknowledging cannot clear a malicious audit', () => {
    const record = { ...ok, audit: { risk: 'malicious', contentHash: 'h' } };
    assert.equal(evaluateGate(record, clean, ['audit-malicious', 'audit-suspicious'])[0].code, 'audit-malicious');
  });

  for (const risk of ['', 'BENIGN', 'safe', 'none', null, undefined, 0, true]) {
    it(`an audit risk of ${JSON.stringify(risk)} is not silently accepted as a pass, or else is flagged`, () => {
      const record = { ...ok, audit: { risk, contentHash: 'h' } };
      assert.notDeepEqual(evaluateGate(record, clean, []), [], 'unknown risk values must not pass the gate');
    });
  }
});
