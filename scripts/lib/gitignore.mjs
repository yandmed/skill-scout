// A small reader for .gitignore, enough to answer one question: would git ignore this file?
// Git itself isn't always available, and running it inside an unknown project can execute that
// project's configuration, so patterns are evaluated here without spawning anything.

function patternToRegex(pattern) {
  let source = '';
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === '*' && pattern[i + 1] === '*') {
      if (pattern[i + 2] === '/') {
        source += '(?:.*/)?';
        i += 2;
      } else {
        source += '.*';
        i += 1;
      }
    } else if (ch === '*') {
      source += '[^/]*';
    } else if (ch === '?') {
      source += '[^/]';
    } else {
      source += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return source;
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
    if (!line) continue;
    const body = patternToRegex(line);
    const prefix = anchored ? '^' : '^(?:.*/)?';
    // A directory pattern ignores what's inside it; a plain pattern also matches inside a matching folder.
    const suffix = directoryOnly ? '/.*$' : '(?:/.*)?$';
    rules.push({ negated, regex: new RegExp(`${prefix}${body}${suffix}`) });
  }
  return rules;
}

/** `file` is relative to the folder holding the rules; `inherited` is the verdict from parent folders. */
export function isIgnored(file, rules, inherited = false) {
  let ignored = inherited;
  for (const rule of rules) if (rule.regex.test(file)) ignored = !rule.negated;
  return ignored;
}
