// A fake GitHub and registries behind global fetch, so whole flows run with no network. Hostile
// behavior (symlinks, oversized files, redirects, malformed JSON) is set up per test. The real code
// runs unchanged: production has no test hook or configurable host a token could leak through.
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
const sha = (text) => Buffer.from(text).toString('hex').padEnd(40, '0').slice(0, 40);

/** repos: { 'owner/name': { files: {path: content}, info: {...}, extraEntries: [...], truncated } } */
export function fakeInternet({ repos = {}, routes = {} } = {}) {
  const requests = [];
  const original = globalThis.fetch;

  const treeFor = (repo) => {
    const entries = Object.entries(repo.files ?? {}).map(([path, content]) => ({ path, type: 'blob', mode: '100644', sha: sha(path + content), size: Buffer.byteLength(content) }));
    return [...entries, ...(repo.extraEntries ?? [])];
  };

  const subTree = (repo, prefix) => {
    const direct = new Map();
    for (const entry of treeFor(repo)) {
      if (prefix && !entry.path.startsWith(`${prefix}/`)) continue;
      const rest = prefix ? entry.path.slice(prefix.length + 1) : entry.path;
      const head = rest.split('/')[0];
      if (rest.includes('/')) direct.set(head, { path: head, type: 'tree', mode: '040000', sha: `tree:${prefix ? `${prefix}/` : ''}${head}` });
      else direct.set(head, { ...entry, path: head });
    }
    return [...direct.values()];
  };

  const recursive = (repo, prefix) => treeFor(repo)
    .filter((e) => !prefix || e.path.startsWith(`${prefix}/`))
    .map((e) => ({ ...e, path: prefix ? e.path.slice(prefix.length + 1) : e.path }));

  globalThis.fetch = async (input, options = {}) => {
    const url = new URL(String(input));
    requests.push({ url: url.href, host: url.host, headers: options.headers ?? {} });
    for (const [pattern, handler] of Object.entries(routes)) {
      if (url.href.includes(pattern)) // A clone can't be used for bodies read partially: cancelling one side of a tee waits for the other.
      return typeof handler === 'function' ? handler(url, options) : handler.clone();
    }
    if (url.host === 'raw.githubusercontent.com') {
      const [owner, name, , ...rest] = url.pathname.split('/').filter(Boolean);
      const content = repos[`${owner}/${name}`]?.files?.[rest.map(decodeURIComponent).join('/')];
      return content === undefined ? new Response('missing', { status: 404 }) : new Response(content);
    }
    if (url.host === 'api.github.com') {
      const match = url.pathname.match(/^\/repos\/([^/]+\/[^/]+)(\/.*)?$/);
      if (!match) return json({ items: [] });
      const repo = repos[match[1]];
      if (!repo) return json({ message: 'Not Found' }, 404);
      const rest = match[2] ?? '';
      if (!rest) return json({ full_name: match[1], default_branch: 'main', stargazers_count: 10, forks_count: 0, open_issues_count: 0, pushed_at: new Date().toISOString(), created_at: '2025-01-01T00:00:00Z', archived: false, fork: false, private: false, license: { spdx_id: 'MIT' }, owner: { type: 'Organization' }, ...repo.info });
      if (rest.startsWith('/commits/')) return json({ sha: repo.head ?? sha(match[1]) });
      const treeId = rest.match(/^\/git\/trees\/(.+)$/)?.[1];
      if (treeId) {
        const prefix = treeId.startsWith('tree:') ? decodeURIComponent(treeId).slice(5) : '';
        const isRecursive = url.searchParams.get('recursive') === '1';
        const tree = isRecursive ? recursive(repo, prefix) : subTree(repo, prefix);
        return json({ sha: treeId, tree, truncated: Boolean(repo.truncated) });
      }
      return json({ message: 'Not Found' }, 404);
    }
    return json({ error: `no route for ${url.href}` }, 404);
  };

  return { requests, restore: () => { globalThis.fetch = original; } };
}

export const skillFile = (name = 'demo-skill', description = 'Formats markdown tables. Use when editing markdown.', body = 'Align the columns.') => `---\nname: ${name}\ndescription: ${description}\n---\n\n${body}\n`;
