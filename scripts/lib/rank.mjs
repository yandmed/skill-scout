// Explainable ranking. Popularity is capped because stars and install counts can be gamed and,
// as our own probe of the claude-skills topic showed, say little about whether a skill fits.
// Security is deliberately NOT part of this score: it is a gate, not a number that a high
// star count could average away.
import { TAXONOMY } from './analyze.mjs';

const STOPWORDS = new Set(['a', 'an', 'and', 'the', 'for', 'of', 'to', 'in', 'on', 'with', 'best', 'practices', 'skill', 'skills', 'use', 'using', 'claude', 'code', 'agent', 'when']);
const clamp = (value, max) => Math.max(0, Math.min(max, value));
const tokenize = (text) => String(text).toLowerCase().split(/[^a-z0-9.#+]+/).filter((t) => t.length > 1 && !STOPWORDS.has(t));
const logScale = (value, reference) => (value > 0 ? clamp(Math.log10(value + 1) / Math.log10(reference + 1), 1) : 0);

const hasTerm = (text, term) => new RegExp(`(?<![a-z0-9])${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![a-z0-9])`, 'i').test(text);

/**
 * Technologies a candidate is specifically about, judged from its name first: a description that
 * merely mentions Firebase in a list of examples does not make it a Firebase skill.
 */
export function candidateTechnologies(candidate) {
  const name = String(candidate.name).replace(/[-_]/g, ' ');
  const description = String(candidate.description ?? '').slice(0, 160);
  const found = new Set();
  for (const [id, tech] of Object.entries(TAXONOMY.technologies)) {
    if (tech.terms.some((term) => hasTerm(name, term) || hasTerm(description, term))) found.add(id);
  }
  return found;
}

function fitScore(candidate, { terms, stack, explicit }) {
  const nameTokens = new Set(tokenize(String(candidate.name).replace(/[-_]/g, ' ')));
  const descTokens = new Set(tokenize(candidate.description ?? ''));
  const wanted = [...new Set(terms.flatMap(tokenize))];
  if (!wanted.length) return { score: 0, matched: [], mismatch: [] };

  const weight = (token) => (nameTokens.has(token) ? 2 : descTokens.has(token) ? 1 : 0);
  const matched = wanted.filter((token) => weight(token) > 0);
  // Judged query by query, since "security review" should beat one stray "review" in a long list of
  // terms. The best single query sets the base, and each further query it answers adds a little.
  const coverage = terms.map((term) => {
    const tokens = [...new Set(tokenize(term))];
    if (!tokens.length) return 0;
    return tokens.reduce((sum, token) => sum + weight(token), 0) / (tokens.length * 2);
  }).sort((a, b) => b - a);
  const best = coverage[0] ?? 0;
  const breadth = coverage.slice(1).filter((c) => c >= 0.5).length;
  let score = clamp(best * 40 + Math.min(breadth, 3) * 2, 45);

  const about = candidateTechnologies(candidate);
  const explicitText = explicit.join(' ').toLowerCase();
  const mismatch = [...about].filter((id) => !stack.has(id)
    && !TAXONOMY.technologies[id].terms.some((term) => hasTerm(explicitText, term)));
  const matchesStack = [...about].some((id) => stack.has(id));
  if (matchesStack) score = clamp(score + 10, 45);
  else if (mismatch.length) score *= 0.3; // A Firebase skill is not a fit for a project without Firebase.
  return { score, matched, mismatch: mismatch.map((id) => TAXONOMY.technologies[id].label) };
}

function trustScore(candidate) {
  const repo = candidate.repoMeta;
  const reasons = [];
  let score = 0;
  if (candidate.officialSource) {
    score += 15;
    reasons.push(`listed in ${candidate.officialSource}`);
  }
  if (candidate.tier === 'vendor') {
    score += 15;
    reasons.push(`published by ${candidate.publisher}, who make this technology`);
  } else if (candidate.tier === 'specialist') {
    score += 10;
    reasons.push(`published by ${candidate.publisher}, a known author`);
  } else if (candidate.lists > 0) {
    score += Math.min(candidate.lists, 3);
    reasons.push(`named in ${candidate.lists} curated list${candidate.lists > 1 ? 's' : ''}`);
  }
  // Independent indexes agreeing is weak evidence of a real project, so it stays small.
  const independent = (candidate.sources ?? []).length;
  if (independent > 1) score += Math.min(independent - 1, 2);
  const stars = repo?.stars ?? candidate.signals?.stars ?? 0;
  score += logScale(stars, 5000) * 10;
  if (repo?.ownerType === 'Organization') {
    score += 3;
    reasons.push('owned by an organization');
  }
  if (repo?.license) {
    score += 2;
    reasons.push(`license ${repo.license}`);
  }
  if (repo?.fork) {
    score -= 8;
    reasons.push('is a fork');
  }
  if (candidate.sameNameAs) {
    score -= 10;
    reasons.push(`same name as a skill by ${candidate.sameNameAs.publisher}, from a different repository`);
  }
  return { score: clamp(score, 30), stars, reasons };
}

function maintenanceScore(candidate, now) {
  const repo = candidate.repoMeta;
  if (!repo) return { score: 5, note: 'not yet checked' };
  if (repo.archived) return { score: 0, note: 'archived' };
  const days = repo.pushedAt ? (now - Date.parse(repo.pushedAt)) / 86400000 : Infinity;
  if (days <= 90) return { score: 10, note: `updated ${Math.round(days)} days ago` };
  if (days <= 365) return { score: 6, note: `updated ${Math.round(days)} days ago` };
  if (days <= 730) return { score: 2, note: `updated ${Math.round(days)} days ago` };
  return { score: 0, note: 'no updates in over 2 years' };
}

export function rankCandidates(candidates, context, now = Date.now()) {
  const stack = new Set(context.stack ?? []);
  const terms = context.terms ?? [];
  const explicit = context.explicit ?? [];
  return candidates
    .map((candidate) => {
      const fit = fitScore(candidate, { terms, stack, explicit });
      const trust = trustScore(candidate);
      const adoption = logScale(candidate.signals?.installs ?? 0, 50000) * 15;
      const maintenance = maintenanceScore(candidate, now);
      // Without any topical match the candidate is noise, whatever its popularity.
      const total = fit.score === 0 ? 0 : fit.score + trust.score + adoption + maintenance.score;
      return {
        ...candidate,
        score: Math.round(total),
        scoreBreakdown: {
          fit: Math.round(fit.score),
          trust: Math.round(trust.score),
          adoption: Math.round(adoption),
          maintenance: maintenance.score,
          matchedTerms: fit.matched,
          stackMismatch: fit.mismatch,
          trustReasons: trust.reasons,
          maintenanceNote: maintenance.note,
        },
      };
    })
    .sort((a, b) => b.score - a.score || (b.signals?.installs ?? 0) - (a.signals?.installs ?? 0) || a.id.localeCompare(b.id));
}
