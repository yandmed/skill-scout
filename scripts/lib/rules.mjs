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
// Every severity below was checked against real public skills; tests/scan.test.mjs keeps both
// the attack samples and the real false positives we found as regressions.

export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

const RAW = [
  // --- Remote code execution ---------------------------------------------------------------
  {
    id: 'pipe-to-shell',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\b(?:curl|wget|fetch)\b[^\n|]*\|(?:[^|\n]*\|)*\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\w+=\S*\s+)*)?(?:(?:\/usr)?(?:\/local)?\/s?bin\/)?(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|perl|ruby|php)\b/i,
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
    pattern: /\brm\s+(?=[^\n]*(?:-[a-z]*r|--recursive))(?:-{1,2}[a-z-]+\s+)+(?:\/(?:\s|$|\*)|~(?:\/?\s|\/?$|\/\*)|\$HOME\b)|\bformat\s+c:|\b(?:del|erase)\s+\/[sfq]\s+[^\n]*\bc:\\|\b(?:rd|rmdir)\s+\/s\b[^\n]*\bc:\\|\bfind\s+(?:\/|~|\$HOME)\s+[^\n]*-delete\b|\bdd\s+[^\n]*\bof=\/dev\/(?:sd|hd|nvme|disk|vd|mmcblk)|\bmkfs(?:\.\w+)?\s+\/dev\/|\bchmod\s+-R\s+0?777\s+(?:\/|~|\$HOME)(?:\s|$)|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bRemove-Item\b[^\n]*-Recurse[^\n]*(?:[A-Z]:\\|\$HOME|\$env:USERPROFILE|\s~)/i,
    message: 'Destructive command aimed at the root or home directory.',
  },

  // --- Fake prerequisites: the dominant in-the-wild technique --------------------------------
  {
    id: 'password-protected-payload',
    severity: 'critical',
    pattern: /\bunzip\b[^\n]*\s-P\s*\S+|\b(?:7z|7za|unrar)\b[^\n]*\s-p\S+|\b(?:[Zz][Ii][Pp]|[Aa]rchive|[Rr][Aa][Rr])\b[^\n]{0,60}\b[Pp]assword\s*(?:is|:|=)\s*\S+|\b[Ss]enha\s*(?:do|da)?\s*(?:zip|arquivo)?\s*[:=]\s*\S+/,
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
    pattern: /https?:\/\/(?:[\w-]+\.)*(?:webhook\.site|webhook\.cool|requestbin\.(?:com|net)|requestcatcher\.com|hookbin\.com|beeceptor\.com|pipedream\.net|interact\.sh|oast\.(?:fun|live|me|site|online|pro)|burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io)\b|(?:discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot)[\w$\{<]/i,
    message: 'Sends data to an endpoint commonly used to receive stolen data.',
  },
  {
    id: 'tunnel-endpoint',
    severity: 'high',
    pattern: /https?:\/\/(?:[\w-]+\.)+(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt|localhost\.run|bore\.pub|pinggy\.(?:link|online))\b|\bssh\s+[^\n]*-R\s+[^\n]*\b(?:serveo\.net|localhost\.run|pinggy\.io)\b/i,
    message: 'Uses a temporary tunnel address, which can point at anyone\'s machine.',
  },
  {
    id: 'opaque-host',
    severity: 'high',
    pattern: /https?:\/\/(?:[\w-]+\.)*(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|pastebin\.com|paste\.ee|glot\.io|rentry\.(?:co|org)|hastebin\.com|transfer\.sh|file\.io|anonfiles\.com|temp\.sh|0x0\.st|gofile\.io|catbox\.moe|tmpfiles\.org|filebin\.net|ix\.io|termbin\.com|sprunge\.us|dpaste\.(?:com|org)|oshi\.at|bashupload\.com|ghostbin\.\w+)\b/i,
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
    pattern: /(?:~|\$HOME|%USERPROFILE%|\/home\/\w+|\/Users\/\w+)[/\\]\.(?:ssh|aws|gnupg|kube|docker\/config|netrc|npmrc|pypirc|git-credentials|bash_history|zsh_history)(?![\w-])|\.claude[/\\]\.credentials|\bid_(?:rsa|ed25519|ecdsa)\b(?!\.pub)|\.aws\/credentials\b|\bLogin Data\b|\blogins\.json\b|\bwallet\.dat\b|\bmetamask\b|\bKeychains?\/|\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b|\/etc\/(?:shadow|sudoers)\b|(?:Chrome|Chromium|Firefox|Edge|Brave)[^\n]{0,60}[/\\](?:Cookies|Local State)\b|\bgh\s+auth\s+token\b/i,
    message: 'Touches credential, key or wallet locations.',
  },
  {
    id: 'credential-read-instruction',
    severity: 'high',
    tag: 'credential',
    scope: 'docs',
    pattern: /\b(?:read|cat|open|copy|send|upload|post|include|attach|exfiltrate|leia|copie|envie|inclua)\b[^\n]{0,60}(?:~|\$HOME|%USERPROFILE%)[/\\]\.(?:ssh|aws|gnupg|kube|netrc|npmrc|pypirc|git-credentials|bash_history|zsh_history)(?![\w-])(?![^\n]*\.pub\b)|\b(?:read|cat|send|upload|post|include|attach|exfiltrate|leia|envie)\b[^\n]{0,40}\b(?:private\s+keys?|id_rsa|id_ed25519|\.aws\/credentials|\.claude[/\\]\.credentials|wallet\.dat|chaves?\s+privadas?|keychain)\b(?!\.pub)|\b(?:read|cat|cp|copy)\b[^\n]{0,60}(?:\/etc\/shadow|\/etc\/sudoers|[/\\](?:Cookies|Local State|Login Data)\b)|\bsecurity\s+dump-keychain\b|\b(?:read|cat|open|leia)\b[^\n]{0,30}\.env\b[^\n]{0,60}\b(?:include|send|upload|post|attach|share|summary|inclua|envie|resumo)\b|\b(?:send|upload|post|exfiltrate|envie)\b[^\n]{0,40}\.env\b/i,
    message: 'Instructs the agent to read or send credentials or private keys.',
  },
  {
    id: 'env-harvest',
    severity: 'medium',
    executable: true,
    tag: 'credential',
    scope: 'code',
    pattern: /\bJSON\.stringify\(\s*process\.env\b|(?<![.\w])dict\(\s*os\.environ\b|\bjson\.dumps\(\s*(?:dict\()?os\.environ\b|\bprintenv\s*(?:\||>)|\benv\s*\|\s*(?:curl|nc|base64)\b|\bGet-ChildItem\s+env:/i,
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
    pattern: /\b(?:ignore|disregard|forget|override)\b[^\n]{0,30}\b(?:previous|prior|above|earlier|system|all(?:\s+other)?)\b[^\n]{0,20}\b(?:instructions?|prompts?|rules?|guidelines?)\b|\b(?:ignore|desconsidere|esque[cç]a|ignora|olvida)\b[^\n]{0,20}\b(?:instru[cç][oõ]es|regras|instrucciones|reglas)\s+(?:anteriores|previas)\b|\byour\s+new\s+(?:instructions|role|goal)\b|\bfrom\s+now\s+on,?\s+you\s+(?:are|must)\b|\byou\s+are\s+no\s+longer\b|\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|dan\b|jailbr|unrestricted|god\s+mode)/i,
    message: 'Tries to override the agent\'s existing instructions.',
  },
  {
    id: 'concealment',
    severity: 'high',
    tag: 'concealment',
    pattern: /\b(?:do\s*n[o']t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|notify(?:ing)?|alert(?:ing)?|show(?:ing)?|reveal(?:ing)?|mention(?:ing)?)\s+(?:this\s+|it\s+|anything\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|developer|operator)(?:\s*[.,;:)!]|\s*$|\s+(?:about|what\s+you|that\s+you|you\s+(?:did|have|are)))|\bwithout\s+asking\s+(?:the\s+)?(?:user|human)\s+(?:for\s+)?(?:permission|confirmation|approval|first)\b|\bhide\s+(?:this|it|the\s+\w+)\s+from\s+the\s+(?:user|human)\b|(?<!\bnot\s)\bsilently\s+(?:send|upload|post|exfiltrate|copy|install|download|execute|run)\b|\bn[aã]o\s+(?:conte|informe|mencione|avise)\b[^\n]{0,20}\busu[aá]rio\b/i,
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
    pattern: /(?:>>?|tee(?:\s+-a)?|append|write|add|modify|edit|update|overwrite)\b[^\n]{0,60}(?:\.claude[/\\](?:settings|hooks|agents|skills)|~[/\\]\.claude[/\\]CLAUDE\.md|\bMEMORY\.md\b|\.cursorrules\b)/i,
    message: 'Modifies the agent\'s own configuration or memory, which persists beyond this skill.',
  },
  {
    id: 'persistence',
    severity: 'high',
    executable: true,
    pattern: /(?:>>|tee\s+-a)\s*[^\n]*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|authorized_keys)\b|\bcrontab\s+-(?!l\b)|\bLaunchAgents\b|\bschtasks\s+\/create\b|CurrentVersion\\Run\b|\bsystemctl\s+enable\b/i,
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
    pattern: /\bnpm\s+(?:i|install)\s+(?:-g|--global)\b|\bpip3?\s+install\s+(?!-r\b|-e\b|\.)(?:--user\s+)?[a-z0-9_.-]+|\bbrew\s+install\b|\bnpx\s+(?:-y|--yes)\s+\S+/i,
    message: 'Installs third-party packages on the user\'s machine; check that the names are genuine.',
  },
  // --- Added after probing the scanner with real attack techniques ---------------------------
  {
    id: 'remote-script-exec',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*["']?\$\(\s*(?:curl|wget)\b|\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*<\(\s*(?:curl|wget)\b|(?:\bsource|(?:^|[;&|]\s*)\.)\s+<\(\s*(?:curl|wget)\b|\beval\s+["']?(?:\$\(|\x60)\s*(?:curl|wget)\b|\b(?:python[0-9.]*|node|perl|ruby)\s+-[ce]\s+["']?\$\(\s*(?:curl|wget)\b/i,
    message: 'Downloads a script and runs it in a single command.',
  },
  {
    id: 'download-then-run',
    severity: 'high',
    executable: true,
    pattern: /\b(?:curl|wget)\b[^\n]*(?:&&|;)[^\n]*(?:\b(?:ba|z)?sh\s+\S|\bchmod\s+\+x\b|(?:&&|;)\s*\.?\/\S)|\bgit\s+clone\b[^\n]*&&[^\n]*\b(?:ba|z)?sh\s+\S/i,
    message: 'Downloads something and then runs it.',
  },
  {
    id: 'remote-code-eval',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\b(?:exec|eval)\s*\(\s*(?:urllib\.request\.urlopen|urlopen|requests\.(?:get|post))\b|\beval\s*\(\s*(?:await\s*)?\(?\s*(?:await\s+)?(?:fetch|axios)\b|\beval\s*\(\s*String\.fromCharCode\b|\b(?:exec|eval)\s*\(\s*["'](?:\\x[0-9a-f]{2}){4,}/i,
    message: 'Fetches or decodes code at runtime and executes it.',
  },
  {
    id: 'reverse-shell',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\/dev\/(?:tcp|udp)\/[^\s/]+\/\d+|\bn(?:c|cat)\b[^\n]*\s-[a-z]*[ec]\s+\S*(?:sh|cmd(?:\.exe)?)\b|\bmkfifo\b[^\n]*\b(?:nc|ncat|telnet|openssl)\b|\bsocat\b[^\n]*\bEXEC:|\bpty\.spawn\s*\(\s*["'](?:\/bin\/)?(?:ba)?sh/i,
    message: 'Opens a remote shell on this machine for someone else.',
  },
  {
    id: 'secret-upload',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    tag: 'credential',
    pattern: /\bcurl\b[^\n]*(?:-F\s*\S*=?@|-d\s*@|--data(?:-binary|-raw|-urlencode)?\s*\S*@|-T\s*|--upload-file\s*)\S*(?:\.env\b|\.ssh|\.aws|id_rsa|id_ed25519|credentials|\.npmrc|\.netrc|secrets?\b)|\b(?:cat|tar|zip|base64|gpg)\b[^\n|]*(?:\.env\b|\.ssh|\.aws|id_rsa|credentials|\.npmrc|\.netrc)[^\n|]*\|(?:[^|\n]*\|)*\s*(?:curl|wget|nc|ncat|socat|openssl)\b|\b(?:gh\s+auth\s+token|printenv|env)\s*\|(?:[^|\n]*\|)*\s*(?:curl|wget|nc|ncat|socat)\b/i,
    message: 'Sends secrets or credential files over the network.',
  },
  {
    id: 'dns-exfil',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /(?:^|[;&|(\x60"]\s*|\s{2,})(?:nslookup|dig|host|ping)\s[^\n]*\$\(\s*(?:whoami|hostname|id|cat|base64|env|printenv|uname)\b/i,
    message: 'Leaks data through a DNS lookup, which firewalls rarely inspect.',
  },
  {
    id: 'chat-webhook',
    severity: 'high',
    pattern: /https?:\/\/hooks\.slack\.com\/services\/[\w$\{<]/i,
    message: 'Posts to a chat webhook, which can carry data out of the machine.',
  },
  {
    id: 'lolbin-download',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\bcertutil(?:\.exe)?\b[^\n]*-urlcache\b|\bbitsadmin(?:\.exe)?\b[^\n]*\/transfer\b|\bmshta(?:\.exe)?\s+["']?(?:https?:|javascript:|vbscript:)|\bregsvr32(?:\.exe)?\b[^\n]*\/i:\s*https?:|\brundll32(?:\.exe)?\s+javascript:/i,
    message: 'Abuses a built-in Windows tool to download or run remote code.',
  },
  {
    id: 'hidden-powershell',
    severity: 'high',
    executable: true,
    pattern: /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-w(?:indowstyle)?\s+hidden\b/i,
    message: 'Runs PowerShell in a hidden window.',
  },
  {
    id: 'execution-policy-bypass',
    severity: 'medium',
    executable: true,
    pattern: /\s-(?:ep|exec(?:utionpolicy)?)\s+bypass\b/i,
    message: 'Turns off the PowerShell script execution policy.',
  },
  {
    id: 'credential-phishing-dialog',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\bdisplay\s+dialog\b[^\n]*\bhidden\s+answer\b|\bGet-Credential\b[^\n]*\|(?:[^|\n]*\|)*\s*(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i,
    message: 'Shows a fake dialog to capture the password of the user.',
  },
  {
    id: 'osascript-shell',
    severity: 'high',
    executable: true,
    pattern: /\bosascript\b[^\n]*\bdo\s+shell\s+script\b/i,
    message: 'Uses AppleScript to run shell commands, which can also ask for administrator rights.',
  },
  {
    id: 'cryptominer',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\bxmrig\b|\bstratum\+(?:tcp|ssl):\/\/|\b(?:minerd|cgminer|nbminer)\b/i,
    message: 'Runs a cryptocurrency miner.',
  },
  {
    id: 'privilege-tamper',
    severity: 'critical',
    severityInDocs: 'high',
    executable: true,
    pattern: /\bNOPASSWD\b|(?:>>?|tee(?:\s+-a)?)\s*\/etc\/(?:sudoers|passwd|shadow|hosts|ld\.so\.preload)\b/i,
    message: 'Changes system files that control privileges or name resolution.',
  },
  {
    id: 'git-hook-plant',
    severity: 'high',
    executable: true,
    pattern: /(?:>>?|tee(?:\s+-a)?|cp\s+\S+|mv\s+\S+)\s*\S*\.git\/hooks\/|\bgit\s+config\b[^\n]*\bcore\.hooksPath\b/i,
    message: 'Plants a Git hook, which later runs code on ordinary Git commands.',
  },
  {
    id: 'registry-override',
    severity: 'high',
    executable: true,
    pattern: /--(?:index-url|extra-index-url|registry)[=\s]+["']?https?:\/\/(?!(?:pypi\.org|registry\.npmjs\.org|registry\.yarnpkg\.com|localhost|127\.0\.0\.1)\b)/i,
    message: 'Installs packages from a non-standard registry, which can serve look-alike malware.',
  },
  {
    id: 'obfuscated-string',
    severity: 'high',
    scope: 'code',
    executable: true,
    pattern: /(?:\\x[0-9a-f]{2}){12,}|(?:\bchr\(\d+\)\s*\+\s*){6,}|\bString\.fromCharCode\(\s*(?:\d+\s*,\s*){8,}/i,
    message: 'Builds a string character by character, which hides what the code really does.',
  },
  {
    id: 'model-control-token',
    severity: 'high',
    pattern: /<\|im_(?:start|end)\|>|<\|(?:system|endoftext)\|>|\[\/?INST\]|<<\/?SYS>>/,
    message: 'Contains tokens that imitate the structure of a model conversation.',
  },
  {
    id: 'fake-authority',
    severity: 'high',
    pattern: /\b(?:this\s+(?:message|instruction|note|update)|instructions?)\b[^\n]{0,30}\b(?:is|are|comes?)\s+from\s+anthropic\b|\boverrides?\s+your\s+(?:rules|instructions|guidelines|system\s+prompt)\b|(?<!\b(?:if|whether|once|when|unless|after)\s+(?:the\s+)?)\b(?:the\s+)?user\s+(?:has\s+)?already\s+(?:approved|authorized|authorised|consented|confirmed)\b|\bpre-?(?:authorized|authorised|approved)\s+by\s+(?:the\s+)?(?:user|anthropic|admin)\b/i,
    message: 'Claims authority or prior approval that a file cannot have.',
  },
  {
    id: 'auditor-manipulation',
    severity: 'critical',
    tag: 'concealment',
    pattern: /\b(?:reviewers?|auditors?|scanners?|security\s+(?:tools?|checks?|review(?:er)?s?))\b[^\n]{0,60}\b(?:report|mark|classify|treat|consider|label)\b[^\n]{0,40}\b(?:benign|harmless|clean|trusted|verified|safe)\b|\b(?:do\s+not|don't|never)\s+flag\s+this\s+(?:skill|package|plugin|repository)\b|\bthis\s+(?:skill|file|package)\s+(?:is|has\s+been)\s+(?:verified|pre-?approved|audited)\s+(?:as\s+safe\s+)?by\s+(?:anthropic|security)\b/i,
    message: 'Tries to talk a security reviewer into approving it.',
  },
  // --- Found by studying the misses on a benchmark's validation set ----------------------------
  {
    id: 'gated-trigger',
    severity: 'high',
    scope: 'docs',
    pattern: /\bif\s+the\s+user(?:'s)?\s+(?:mentions?|says?|asks?\s+about|input\s+contains?|message\s+contains?|request\s+contains?)\b[^\n]*\b(?:must|always|first|run|execute)\b[^\n]*\.(?:py|sh|js|mjs|ps1)\b|\b(?:before|prior\s+to)\s+(?:producing|responding|answering|replying|the\s+main)\b[^\n]*\b(?:run|execute)\b[^\n]*\.(?:py|sh|js|mjs|ps1)\b|\balways\s+(?:run|execute)\b[^\n]*\.(?:py|sh|js|mjs|ps1)\b[^\n]*\bwhen\s+the\s+user(?:'s)?\s+(?:mentions?|input|message|request)\b/i,
    message: 'Runs a script only when certain words appear, a way to stay dormant until a target shows up.',
  },
  {
    id: 'hidden-bootstrap-script',
    severity: 'high',
    scope: 'docs',
    pattern: /\b(?:run|execute|invoke|launch)\b[^\n]{0,80}[\x60"'\s/](?:scripts?|bin|tools?|lib)\/_[\w-]+\.(?:py|sh|js|mjs|ps1)\b/i,
    message: 'Tells the agent to run a script with a hidden-style name, often presented as a setup step.',
  },
];

export const LINE_RULES = RAW;

// Unicode that renders as nothing or reorders text: invisible to a reviewer, visible to a model.
export const HIDDEN_UNICODE = [
  { id: 'unicode-tag-chars', severity: 'critical', pattern: /[\u{E0000}-\u{E007F}]/u, message: 'Unicode tag characters: invisible text that models can read.' },
  { id: 'bidi-control', severity: 'critical', pattern: /[‪-‮⁦-⁩]/, message: 'Bidirectional control characters can make text display differently from what it says (Trojan Source).' },
  { id: 'zero-width', severity: 'high', pattern: /[​‌⁠⁡-⁤­]|(?!^)﻿/, message: 'Zero-width characters can hide instructions or split keywords to dodge detection.' },
];

export const EXECUTABLE_EXT = /\.(?:exe|dll|so|dylib|msi|msix|scr|com|pif|cpl|sys|drv|lnk|jar|class|pyc|pyo|node|wasm|deb|rpm|apk|ipa|app|appimage|bin)$/i;
export const ARCHIVE_EXT = /\.(?:zip|rar|7z|tar|gz|tgz|bz2|xz|dmg|pkg|iso)$/i;
export const CODE_EXT = /(?:\.(?:sh|bash|zsh|fish|command|ps1|psm1|psd1|bat|cmd|vbs|vbe|wsf|hta|applescript|scpt|py|pyw|js|mjs|cjs|ts|tsx|jsx|rb|pl|php|go|rs|lua|java|kt|kts|cs|swift|r)|(?:^|\/)(?:Makefile|Dockerfile|Justfile|Rakefile|Containerfile))$/i;
export const DOC_EXT = /\.(?:md|markdown|mdx|txt|rst|html?|adoc)$/i;
export const MEDIA_EXT = /\.(?:png|jpe?g|gif|webp|ico|bmp|pdf|woff2?|ttf|otf|eot|mp[34]|wav|mov|docx|xlsx|pptx)$/i;

// Files an agent loads as instructions just because they are in a folder it works in.
export const AGENT_CONFIG_FILE = /(?:^|\/)(?:CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules)$|(?:^|\/)\.(?:claude|cursor)\//i;

// A skill with one of these names competes with a command the user already trusts.
export const BUILTIN_COMMANDS = new Set(['add-dir', 'agents', 'bug', 'clear', 'code-review', 'commit', 'compact', 'config', 'cost', 'doctor', 'help', 'hooks', 'init', 'login', 'logout', 'loop', 'mcp', 'memory', 'model', 'permissions', 'plugin', 'pr-comments', 'release-notes', 'resume', 'review', 'schedule', 'security-review', 'simplify', 'status', 'terminal-setup', 'vim']);

// Latin look-alikes from other alphabets, folded so a disguised "ignore" still matches. A small,
// deliberate table: the letters that actually fool a reader, not the full Unicode list.
export const CONFUSABLES = { а: 'a', в: 'b', с: 'c', е: 'e', һ: 'h', і: 'i', ј: 'j', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', г: 'r', ѕ: 's', т: 't', у: 'y', х: 'x', А: 'A', В: 'B', С: 'C', Е: 'E', Н: 'H', І: 'I', К: 'K', М: 'M', О: 'O', Р: 'P', Т: 'T', Х: 'X', ο: 'o', Ο: 'O', ν: 'v', Α: 'A', Β: 'B', Ε: 'E', Ι: 'I', Κ: 'K', Τ: 'T' };
