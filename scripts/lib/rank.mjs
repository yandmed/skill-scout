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

  let hits = 0;
  const matched = [];
  for (const token of wanted) {
    if (nameTokens.has(token)) {
      hits += 2;
      matched.push(token);
    } else if (descTokens.has(token)) {
      hits += 1;
      matched.push(token);
    }
  }
  // Coverage saturates: matching three strong terms is already a good fit, so long query lists don't dilute it.
  let score = clamp((hits / Math.min(wanted.length * 2, 6)) * 45, 45);

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
