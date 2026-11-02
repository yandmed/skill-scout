// Shapes CLI output for the model that reads it.

/**
 * One entry per rule with a few examples. A security guide can trigger the same rule dozens of
 * times; repeating each hit would overflow the model's tool output and hide the other rules.
 */
export function groupFindings(findings, examplesPerRule = 3) {
  const groups = new Map();
  for (const finding of findings) {
    if (finding.severity === 'info' || finding.severity === 'low') continue;
    const key = `${finding.severity}|${finding.ruleId}`;
    if (!groups.has(key)) groups.set(key, { ruleId: finding.ruleId, severity: finding.severity, message: finding.message, count: 0, examples: [] });
    const group = groups.get(key);
    group.count += 1;
    if (group.examples.length < examplesPerRule) group.examples.push({ file: finding.file, line: finding.line, excerpt: finding.excerpt });
  }
  return [...groups.values()];
}

/** The fields the model needs to choose finalists, and nothing else: this list costs context. */
export function compactCandidate(c) {
  const b = c.scoreBreakdown;
  return {
    id: c.id,
    kind: c.kind,
    name: c.name,
    description: c.description,
    url: c.url,
    sources: c.sources,
    score: c.score,
    fit: b.fit,
    trust: b.trust,
    adoption: b.adoption,
    maintenance: b.maintenanceNote,
    stackMismatch: b.stackMismatch.length ? b.stackMismatch : undefined,
    stars: c.repoMeta?.stars ?? c.signals?.stars,
    installs: c.signals?.installs,
    license: c.repoMeta?.license ?? undefined,
    archived: c.repoMeta?.archived || undefined,
    official: c.officialSource,
    marketplace: c.marketplace,
  };
}
