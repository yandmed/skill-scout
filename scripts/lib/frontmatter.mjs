// Minimal, non-executing frontmatter reader. It deliberately supports only the YAML subset
// skills use (scalars, block scalars, simple lists, one level of nesting): a real YAML parser
// is unnecessary attack surface here, and tags/anchors have no legitimate use in a SKILL.md.

const stripQuotes = (value) => {
  const v = value.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  return v;
};

export function parseFrontmatter(text) {
  const source = text.replace(/^﻿/, '').replace(/\r\n/g, '\n');
  const match = source.match(/^---[ \t]*\n([\s\S]*?)\n---[ \t]*(?:\n|$)/);
  if (!match) return { data: {}, body: source, hasFrontmatter: false, bodyStartLine: 1 };

  const data = {};
  const lines = match[1].split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const kv = line.match(/^([A-Za-z0-9_-]+):[ \t]*(.*)$/);
    if (!kv) continue;
    const [, key, rawValue] = kv;
    const value = rawValue.trim();

    const nested = [];
    let j = i + 1;
    while (j < lines.length && (/^[ \t]+\S/.test(lines[j]) || /^-\s/.test(lines[j]) || lines[j].trim() === '')) {
      nested.push(lines[j]);
      j += 1;
    }

    if (/^[|>][+-]?\d*$/.test(value)) {
      const parts = nested.map((l) => l.trim());
      data[key] = (value.startsWith('>') ? parts.join(' ') : parts.join('\n')).trim();
      i = j - 1;
    } else if (value === '' && nested.some((l) => l.trim())) {
      const items = nested.filter((l) => /^\s*-\s+/.test(l));
      // A nested map is kept as raw text: callers only need to detect its presence and contents.
      data[key] = items.length && items.length === nested.filter((l) => l.trim()).length
        ? items.map((l) => stripQuotes(l.replace(/^\s*-\s+/, '')))
        : nested.join('\n');
      i = j - 1;
    } else if (value.startsWith('[') && value.endsWith(']')) {
      data[key] = value.slice(1, -1).split(',').map(stripQuotes).filter(Boolean);
    } else {
      data[key] = stripQuotes(value);
    }
  }
  const consumed = source.slice(0, match[0].length).split('\n').length - 1;
  return { data, body: source.slice(match[0].length), hasFrontmatter: true, bodyStartLine: consumed + 1 };
}
