// Detection rules for the static scanner.
//
// Severity contract (enforced by the install gate, see install.mjs):
//   critical  installation refused; Skill Scout offers no override.
//   high      installation refused until the user acknowledges this exact rule id.
//   medium    shown to the user, never blocks.
//   low/info  context for the auditor and the report.
//
// `scope` limits where a rule applies: 'code' (scripts), 'docs' (markdown), or 'any'.
// A rule may set `severityInDocs` because a pattern in documentation is weaker evidence than
// the same pattern in an executable. It is still surfaced: fake "prerequisite" instructions in
// prose are the most common real-world attack, so docs can never be treated as harmless.
// `executable` marks rules about running code: they weaken on a comment-only line of a script.
// `tagInDocs` overrides `tag` in docs: tags feed the correlation checks in scan.mjs, and merely
// mentioning a credential path in documentation shouldn't count as touching it.
// Every severity below was checked against real public skills; test/scan.test.mjs keeps both
// the attack samples and the real false positives we found as regressions.

export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

const RAW = [
  // --- Remote code execution ---------------------------------------------------------------
  {
    id: 'pipe-to-shell',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby)\b/i,
    message: 'Downloads code and pipes it straight into an interpreter.',
  },
  {
    id: 'powershell-download-exec',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\b(?:iex|invoke-expression)\b[^\n]*\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*(?:iex|invoke-expression)\b/i,
    message: 'PowerShell downloads code and executes it.',
  },
  {
    id: 'encoded-shell-exec',
    severity: 'critical',
    executable: true,
    pattern: /base64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|powershell[^\n]*\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}/i,
    message: 'Decodes an obfuscated payload and runs it in a shell.',
  },
  {
    id: 'encoded-code-exec',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\beval\s*\(\s*(?:atob|Buffer\.from)\b|\bexec\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|zlib\.decompress)\b/i,
    message: 'Decodes an obfuscated payload and executes it as code.',
  },
  {
    id: 'destructive-command',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$|\*)|~(?:\/?\s|\/?$|\/\*)|\$HOME\b)|\bformat\s+c:|\bdel\s+\/[sf]\s+[^\n]*\bc:\\/i,
    message: 'Destructive command aimed at the root or home directory.',
  },

  // --- Fake prerequisites: the dominant in-the-wild technique --------------------------------
  {
    id: 'password-protected-payload',
    severity: 'critical',
    pattern: /\b(?:unzip|7z|7za|unrar)\b[^\n]*\s-p\s*\S+|\b(?:zip|archive|rar)\b[^\n]{0,60}\bpassword\s*(?:is|:|=)\s*\S+|\bsenha\s*(?:do|da)?\s*(?:zip|arquivo)?\s*[:=]\s*\S+/i,
    message: 'Password-protected archive: a classic way to get malware past scanners.',
  },
  {
    id: 'quarantine-bypass',
    severity: 'critical',
    severityInDocs: 'high', // Real install docs do this too (Anthropic's own CLI guide), so a human decides.
    executable: true,
    pattern: /\bxattr\s+(?:-[a-z]+\s+)*com\.apple\.quarantine\b|\bspctl\s+--master-disable\b|\bSet-MpPreference\b[^\n]*-Disable|\bAdd-MpPreference\b[^\n]*-ExclusionPath/i,
    message: 'Disables operating-system malware protection.',
  },
  {
    id: 'fake-prerequisite',
    severity: 'high',
    pattern: /(?:prerequisite|pr[eé]-?requisito|required|must|first|before|antes)[^\n]{0,80}(?:download|install|run|baixe|instale|execute)[^\n]{0,80}https?:\/\/(?!(?:www\.)?(?:github\.com\/(?:anthropics|microsoft|python|nodejs)\b|nodejs\.org|python\.org|docs\.|developer\.))[^\s)]+\.(?:exe|msi|dmg|pkg|zip|rar|7z|sh|ps1|bat|cmd|tar\.gz|tgz)\b/i,
    message: 'Tells the reader to download and run a file as a "prerequisite".',
  },

  // --- Exfiltration endpoints -----------------------------------------------------------------
  {
    id: 'exfil-endpoint',
    severity: 'critical',
    pattern: /https?:\/\/(?:[\w-]+\.)*(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|interact\.sh|oast\.(?:fun|live|me|site|online|pro)|burpcollaborator\.net|canarytokens\.com)\b|(?:discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot)[\w$\{<]/i,
    message: 'Sends data to an endpoint commonly used to receive stolen data.',
  },
  {
    id: 'tunnel-endpoint',
    severity: 'high',
    pattern: /https?:\/\/(?:[\w-]+\.)+(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com)\b/i,
    message: 'Uses a temporary tunnel address, which can point at anyone\'s machine.',
  },
  {
    id: 'opaque-host',
    severity: 'high',
    pattern: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|pastebin\.com|paste\.ee|glot\.io|rentry\.(?:co|org)|hastebin\.com|transfer\.sh|file\.io|anonfiles\.com|temp\.sh)\b/i,
    message: 'Link hides its destination (URL shortener, paste site or anonymous file host).',
  },
  {
    id: 'raw-ip-url',
    severity: 'high',
    pattern: /https?:\/\/(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)\d{1,3}(?:\.\d{1,3}){3}\b/,
    message: 'Connects to a bare public IP address.',
  },

  // --- Credentials ----------------------------------------------------------------------------
  {
    id: 'credential-path',
    severity: 'high',
    severityInDocs: 'low',
    tag: 'credential',
    tagInDocs: null,
    executable: true,
    pattern: /(?:~|\$HOME|%USERPROFILE%|\/home\/\w+|\/Users\/\w+)[/\\]\.(?:ssh|aws|gnupg|kube|docker\/config|netrc|npmrc|pypirc|git-credentials)\b|\.claude[/\\]\.credentials|\bid_(?:rsa|ed25519|ecdsa)\b(?!\.pub)|\.aws\/credentials\b|\bLogin Data\b|\blogins\.json\b|\bwallet\.dat\b|\bmetamask\b|\bKeychains?\/|\bsecurity\s+find-generic-password\b/i,
    message: 'Touches credential, key or wallet locations.',
  },
  {
    id: 'credential-read-instruction',
    severity: 'high',
    tag: 'credential',
    scope: 'docs',
    pattern: /\b(?:read|cat|open|copy|send|upload|post|include|attach|exfiltrate|leia|copie|envie|inclua)\b[^\n]{0,60}(?:~|\$HOME|%USERPROFILE%)[/\\]\.(?:ssh|aws|gnupg|kube|netrc|npmrc|pypirc|git-credentials)\b|\b(?:read|cat|send|upload|post|include|attach|exfiltrate|leia|envie)\b[^\n]{0,40}\b(?:private\s+keys?|id_rsa|id_ed25519|\.aws\/credentials|\.claude[/\\]\.credentials|wallet\.dat|chaves?\s+privadas?)\b/i,
    message: 'Instructs the agent to read or send credentials or private keys.',
  },
  {
    id: 'env-harvest',
    severity: 'medium',
    executable: true,
    tag: 'credential',
    scope: 'code',
    pattern: /\bJSON\.stringify\(\s*process\.env\b|\bdict\(\s*os\.environ\b|\bjson\.dumps\(\s*(?:dict\()?os\.environ\b|\bprintenv\s*(?:\||>)|\benv\s*\|\s*(?:curl|nc|base64)\b|\bGet-ChildItem\s+env:/i,
    message: 'Collects the whole process environment, which usually contains secrets.',
  },
  {
    id: 'network-call',
    severity: 'info',
    tag: 'network',
    executable: true,
    scope: 'code',
    pattern: /\b(?:fetch\(|axios\.|https?\.request|requests\.(?:get|post|put)|urllib\.request|http\.client|curl\s|wget\s|Invoke-WebRequest|Invoke-RestMethod|socket\.connect|net\.connect|\bnc\s+-)/,
    message: 'Makes network calls.',
  },

  // --- Instructions aimed at the agent --------------------------------------------------------
  {
    id: 'instruction-override',
    severity: 'high',
    pattern: /\b(?:ignore|disregard|forget|override)\b[^\n]{0,30}\b(?:previous|prior|above|earlier|system|all(?:\s+other)?)\b[^\n]{0,20}\b(?:instructions?|prompts?|rules?|guidelines?)\b|\bignore\s+(?:as\s+)?instru[cç][oõ]es\s+anteriores\b|\byour\s+new\s+(?:instructions|role|goal)\b|\bfrom\s+now\s+on,?\s+you\s+(?:are|must)\b|\byou\s+are\s+no\s+longer\b/i,
    message: 'Tries to override the agent\'s existing instructions.',
  },
  {
    id: 'concealment',
    severity: 'high',
    tag: 'concealment',
    pattern: /\b(?:do\s*n[o']t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|notify(?:ing)?|alert(?:ing)?|show(?:ing)?|reveal(?:ing)?|mention(?:ing)?)\s+(?:this\s+|it\s+|anything\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|developer|operator)(?:\s*[.,;:)!]|\s*$|\s+(?:about|what\s+you|that\s+you|you\s+(?:did|have|are)))|\bwithout\s+asking\s+(?:the\s+)?(?:user|human)\s+(?:for\s+)?(?:permission|confirmation|approval|first)\b|\bhide\s+(?:this|it|the\s+\w+)\s+from\s+the\s+(?:user|human)\b|\bsilently\s+(?:send|upload|post|exfiltrate|copy|install|download|execute|run)\b|\bn[aã]o\s+(?:conte|informe|mencione|avise)\b[^\n]{0,20}\busu[aá]rio\b/i,
    message: 'Tells the agent to act without the user knowing.',
  },
  {
    id: 'permission-bypass',
    severity: 'high',
    pattern: /--dangerously-skip-permissions|\bbypassPermissions\b|\bdisableAllHooks\b|\bdefaultMode\b[^\n]{0,10}\b(?:bypass|acceptEdits|auto)\b/i,
    message: 'Tries to turn off Claude Code\'s permission system.',
  },
  {
    id: 'agent-config-tamper',
    severity: 'high',
    pattern: /(?:>>?|tee(?:\s+-a)?|append|write|add|modify|edit|update|overwrite|echo)\b[^\n]{0,60}(?:\.claude[/\\](?:settings|hooks|agents|skills)|~[/\\]\.claude[/\\]CLAUDE\.md|\bMEMORY\.md\b|\.cursorrules\b)/i,
    message: 'Modifies the agent\'s own configuration or memory, which persists beyond this skill.',
  },
  {
    id: 'persistence',
    severity: 'high',
    executable: true,
    pattern: /(?:>>|tee\s+-a)\s*[^\n]*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|authorized_keys)\b|\bcrontab\s+-|\bLaunchAgents\b|\bschtasks\s+\/create\b|CurrentVersion\\Run\b|\bsystemctl\s+enable\b/i,
    message: 'Installs something that survives reboots or new shells.',
  },

  // --- Risky but common in legitimate code ----------------------------------------------------
  {
    id: 'dynamic-code',
    severity: 'low',
    executable: true,
    scope: 'code',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(|\bexec\s*\(\s*(?:compile|open)\b|\bos\.system\s*\(|\bshell\s*=\s*True\b/,
    message: 'Runs dynamically built code or shell strings.',
  },
  {
    id: 'global-package-install',
    severity: 'medium',
    pattern: /\bnpm\s+(?:i|install)\s+(?:-g|--global)\b|\bpip3?\s+install\s+(?!-r\b|-e\b|\.)(?:--user\s+)?[a-z0-9_.-]+|\bbrew\s+install\b|\bnpx\s+(?:-y|--yes)\s+\S+@latest\b/i,
    message: 'Installs third-party packages on the user\'s machine; check that the names are genuine.',
  },
];

export const LINE_RULES = RAW;

// Unicode that renders as nothing or reorders text: invisible to a reviewer, visible to a model.
export const HIDDEN_UNICODE = [
  { id: 'unicode-tag-chars', severity: 'critical', pattern: /[\u{E0000}-\u{E007F}]/u, message: 'Unicode tag characters: invisible text that models can read.' },
  { id: 'bidi-control', severity: 'critical', pattern: /[‪-‮⁦-⁩]/, message: 'Bidirectional control characters can make text display differently from what it says (Trojan Source).' },
  { id: 'zero-width', severity: 'high', pattern: /[​‌⁠⁡-⁤­]|(?!^)﻿/, message: 'Zero-width characters can hide instructions or split keywords to dodge detection.' },
];

export const EXECUTABLE_EXT = /\.(?:exe|dll|so|dylib|msi|scr|com|pif|jar|class|pyc|pyo|node|wasm|deb|rpm|apk|app|bin)$/i;
export const ARCHIVE_EXT = /\.(?:zip|rar|7z|tar|gz|tgz|bz2|xz|dmg|pkg|iso)$/i;
export const CODE_EXT = /\.(?:sh|bash|zsh|fish|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|tsx|jsx|rb|pl|php|go|rs|lua)$/i;
export const DOC_EXT = /\.(?:md|markdown|mdx|txt|rst)$/i;
export const MEDIA_EXT = /\.(?:png|jpe?g|gif|webp|ico|bmp|pdf|woff2?|ttf|otf|eot|mp[34]|wav|mov|docx|xlsx|pptx)$/i;
