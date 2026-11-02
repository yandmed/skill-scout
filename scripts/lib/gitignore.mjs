// A small reader for .gitignore, enough to answer one question: would git ignore this file?
// Git itself isn't always available, and running it inside an unknown project can execute that
// project's configuration, so patterns are evaluated here without spawning anything.
//
// Patterns come from the project being analyzed, which may be hostile, and a regex built from
// "*a*a*a*a*b" can hang for hours. So matching uses dynamic programming, whose cost is bounded by
// pattern length times path length.

const MAX_PATTERN = 256;
const MAX_PATH = 4096;

function tokenize(pattern) {
  const tokens = [];
  for (let i = 0; i < pattern.length; i += 1) {
    if (pattern.startsWith('**/', i)) {
      tokens.push({ type: 'any-dirs' });
      i += 2;
    } else if (pattern.startsWith('**', i)) {
      tokens.push({ type: 'any' });
      i += 1;
    } else if (pattern[i] === '*') {
      tokens.push({ type: 'star' });
    } else if (pattern[i] === '?') {
      tokens.push({ type: 'one' });
    } else {
      tokens.push({ type: 'char', value: pattern[i] });
    }
  }
  return tokens;
}

/** Does the whole of `text` match these tokens? Each token only scans forward over `reach`. */
function matches(tokens, text) {
  let reach = new Uint8Array(text.length + 1);
  reach[0] = 1;
  for (const token of tokens) {
    const next = new Uint8Array(text.length + 1);
    if (token.type === 'char' || token.type === 'one') {
      for (let i = 0; i < text.length; i += 1) {
        if (reach[i] && (token.type === 'one' ? text[i] !== '/' : text[i] === token.value)) next[i + 1] = 1;
      }
    } else {
      let open = false;
      for (let i = 0; i <= text.length; i += 1) {
        if (reach[i]) open = true;
        if (token.type === 'any') {
          if (open) next[i] = 1;
        } else if (token.type === 'star') {
          if (open) next[i] = 1;
          if (text[i] === '/') open = false;
        } else {
          // "**/" matches nothing, or anything that ends at a folder boundary.
          if (reach[i] || (open && i > 0 && text[i - 1] === '/')) next[i] = 1;
        }
      }
    }
    reach = next;
  }
  return reach[text.length] === 1;
}

const boundaries = (file) => {
  const out = [];
  for (let i = 0; i < file.length; i += 1) if (file[i] === '/') out.push(i);
  return out;
};

function ruleMatches(rule, file) {
  if (file.length > MAX_PATH) return false;
  const slashes = boundaries(file);
  const starts = rule.anchored ? [0] : [0, ...slashes.map((i) => i + 1)];
  // A rule can name the file itself or any folder above it. A directory rule can only name a folder.
  const ends = rule.directoryOnly ? slashes : [...slashes, file.length];
  for (const start of starts) {
    for (const end of ends) {
      if (end > start && matches(rule.tokens, file.slice(start, end))) return true;
    }
  }
  return false;
}

/** Parses .gitignore text into ordered rules; the last matching rule wins, as in git. */
export function parseGitignore(text) {
  const rules = [];
  for (const rawLine of String(text).split(/\r?\n/)) {
    let line = rawLine.replace(/\s+$/, '');
    if (!line || line.startsWith('#')) continue;
    const negated = line.startsWith('!');
    if (negated) line = line.slice(1);
    const directoryOnly = line.endsWith('/');
    if (directoryOnly) line = line.slice(0, -1);
    const anchored = line.includes('/');
    if (line.startsWith('/')) line = line.slice(1);
    if (!line || line.length > MAX_PATTERN) continue;
    rules.push({ negated, directoryOnly, anchored, tokens: tokenize(line) });
  }
  return rules;
}

/** `file` is relative to the folder holding the rules; `inherited` is the verdict from parent folders. */
export function isIgnored(file, rules, inherited = false) {
  let ignored = inherited;
  for (const rule of rules) if (ruleMatches(rule, file)) ignored = !rule.negated;
  return ignored;
}
