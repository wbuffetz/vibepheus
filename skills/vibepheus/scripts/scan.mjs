#!/usr/bin/env node
// vibepheus scanner: finds the security mistakes AI-built web apps make most often.
// Copyright (c) 2026 wbuffetz. MIT License. https://github.com/wbuffetz/vibepheus
// Zero dependencies, Node 18+. Read-only: it never modifies the project it scans.
//
// Usage: node scan.mjs [project-dir] [--json] [--out FILE] [--offline] [--no-external] [--fail-on LEVEL]

import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const VERSION = '0.2.0'
const HOMEPAGE = 'https://github.com/wbuffetz/vibepheus'
const HERE = path.dirname(fileURLToPath(import.meta.url))
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const SENSITIVE_COLUMNS = /\b(email|phone|address|password|token|secret|ssn|birth|dob|salary|payment|card|iban|full_name|first_name|last_name|ip_address|user_id|owner_id|stripe_customer\w*|api_key|billing\w*)\b/i

// ---------------------------------------------------------------- arguments

function parseArgs(argv) {
  const opts = { target: '.', json: false, out: null, offline: false, external: true, failOn: null, only: null }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--json') opts.json = true
    else if (a === '--out') opts.out = argv[++i]
    else if (a === '--offline') opts.offline = true
    else if (a === '--no-external') opts.external = false
    else if (a === '--fail-on') opts.failOn = argv[++i]
    else if (a === '--only') opts.only = argv[++i]
    else if (a === '-h' || a === '--help') {
      console.log('Usage: node scan.mjs [project-dir] [--json] [--out FILE] [--offline] [--no-external] [--fail-on critical|high|medium|low] [--only secrets|RULE,RULE...]')
      process.exit(0)
    } else if (!a.startsWith('-')) opts.target = a
    else { console.error(`Unknown option: ${a}`); process.exit(2) }
  }
  if (opts.only) {
    const names = opts.only.split(',').flatMap((x) => RULE_GROUPS[x.trim()] ?? [x.trim().toUpperCase()])
    const unknown = names.filter((n) => !RULES[n])
    if (unknown.length) { console.error(`--only: unknown rule(s) ${unknown.join(', ')}. Use a group (${Object.keys(RULE_GROUPS).join(', ')}) or rule names.`); process.exit(2) }
    opts.only = new Set(names)
  }
  if (opts.failOn && !SEVERITIES.includes(opts.failOn)) { console.error(`--fail-on must be one of ${SEVERITIES.join(', ')}`); process.exit(2) }
  return opts
}

// Named groups for --only.
const RULE_GROUPS = {
  secrets: ['HARDCODED_SECRET', 'SECRET_IN_GIT_HISTORY', 'SECRET_IN_PUBLIC_ENV', 'ENV_FILE_NOT_IGNORED', 'SERVICE_ROLE_IN_CLIENT', 'PUBLIC_API_KEY'],
}

// ---------------------------------------------------------------- rule catalogue
// "why" is written for someone who has never heard of the vulnerability.

const RULES = {
  HARDCODED_SECRET: {
    title: 'Secret key written directly in the code',
    why: 'Anyone who can see this code (a teammate, a public GitHub repo, or the browser if this file ships to the frontend) can copy the key and use your account.',
    fix: 'Move the key to an environment variable that is NOT prefixed with NEXT_PUBLIC_/VITE_, then rotate (revoke and re-create) the key, because the old one should be treated as leaked.',
  },
  SECRET_IN_GIT_HISTORY: {
    title: 'Secret key still present in git history',
    why: 'Deleting a key from the code does not delete it from git history. Anyone with the repo can find it in old commits.',
    fix: 'Rotate the key now. Rewriting history (git filter-repo) is optional; rotating is what actually protects you.',
  },
  SECRET_IN_PUBLIC_ENV: {
    title: 'Secret stored in a public (browser-exposed) environment variable',
    why: 'Variables starting with NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ or PUBLIC_ are copied into the JavaScript sent to every visitor. Anyone can open DevTools and read them.',
    fix: 'Rename it without the public prefix, only use it in server code (API routes, server actions), and rotate the key.',
  },
  ENV_FILE_NOT_IGNORED: {
    title: '.env file is not ignored by git',
    why: 'The next `git add .` will commit your secrets. If the repo is public, bots find leaked keys within minutes.',
    fix: 'Add `.env*` (and `!.env.example`) to .gitignore. If the file was already committed, remove it with `git rm --cached` and rotate every key in it.',
  },
  SERVICE_ROLE_IN_CLIENT: {
    title: 'Supabase service_role (admin) key used in browser code',
    why: 'The service_role key ignores every Row Level Security rule. In browser code, any visitor can extract it and read, change or delete your entire database.',
    fix: 'Use the anon key in the browser and fix your RLS policies instead. Keep the service_role key in server-only files (add `import "server-only"`) and rotate it.',
  },
  RLS_DISABLED: {
    title: 'Database table without Row Level Security',
    why: 'Supabase tables in the public schema can be queried straight from the browser with the anon key. Without RLS, anyone can read and modify every row.',
    fix: 'Run `alter table <name> enable row level security;` and add policies that only let users access their own rows, e.g. `using (auth.uid() = user_id)`.',
  },
  RLS_PERMISSIVE_POLICY: {
    title: 'Row Level Security policy lets everyone through',
    why: 'A policy with `using (true)` or `with check (true)` allows access to every row, which is the same as having no protection.',
    fix: 'Restrict the policy to the row owner, e.g. `using (auth.uid() = id)`, or to the `authenticated` role if the data really is shared.',
  },
  FIREBASE_OPEN_RULES: {
    title: 'Firebase security rules allow anyone to read or write',
    why: 'Your Firebase config is public by design, so the rules are the only thing protecting your data. Open rules mean anyone can dump or wipe the database.',
    fix: 'Require sign-in and ownership, e.g. `allow read, write: if request.auth != null && request.auth.uid == userId;`',
  },
  API_ROUTE_NO_AUTH: {
    title: 'API route with no authentication check',
    why: 'Anyone on the internet can call this endpoint directly with curl. Hiding the button in your UI does not protect the API.',
    fix: 'At the top of the handler, get the current user (e.g. `supabase.auth.getUser()`, `auth()`, `getServerSession()`) and return 401 if there is none. For admin routes, also check the user\'s role.',
  },
  PAID_API_UNPROTECTED: {
    title: 'Endpoint that spends your money can be called without limits (denial of wallet)',
    why: 'Every call to this endpoint makes a paid API call (AI, email or SMS) billed to your account. Without a login check and a rate limit, anyone can call it in a loop: a simple script making 10 requests per second makes 864,000 calls a day. People have woken up to bills of thousands of dollars this way.',
    fix: 'Require login, then add a per-user rate limit (e.g. @upstash/ratelimit: 20 requests per minute). Cap output size (max_tokens), and set a monthly spending limit in the provider\'s dashboard as a safety net.',
  },
  WEBHOOK_NO_SIGNATURE: {
    title: 'Webhook does not verify its signature',
    why: 'Anyone can send fake events to this URL (for example a fake "payment succeeded") unless you verify the provider\'s signature.',
    fix: 'Verify the signature with the provider SDK, e.g. `stripe.webhooks.constructEvent(body, sig, secret)`.',
  },
  POSSIBLE_IDOR: {
    title: 'Users may be able to access other users\' data by changing an ID',
    why: 'This route loads a record by the ID in the URL but never checks that it belongs to the logged-in user. Changing /orders/123 to /orders/124 may show someone else\'s data.',
    fix: 'Add an ownership filter, e.g. `.eq("id", id).eq("user_id", user.id)`, or query with the user\'s own client so RLS applies.',
  },
  CORS_WILDCARD: {
    title: 'API allows requests from any website (CORS *)',
    why: 'Any website can call your API from a visitor\'s browser. Combined with credentials, this setup is often "fixed" by reflecting the caller\'s origin, which lets malicious sites act as your logged-in users.',
    fix: 'Allow only your own domain(s), e.g. `Access-Control-Allow-Origin: https://yourapp.com`, and never combine a wildcard or reflected origin with credentials.',
  },
  XSS_UNSANITIZED_HTML: {
    title: 'User content rendered as raw HTML (XSS)',
    why: 'If an attacker puts `<img src=x onerror=...>` into this content, their JavaScript runs in every visitor\'s browser and can steal sessions.',
    fix: 'Render it as text, or sanitize first: `DOMPurify.sanitize(html)`.',
  },
  VULNERABLE_DEPENDENCY: {
    title: 'Dependency with a known vulnerability',
    why: 'Attackers scan for apps running versions with published exploits.',
    fix: 'Upgrade to a fixed version (shown below), then re-run your tests.',
  },
  // The rules below are reported through the optional Semgrep integration (rules/semgrep.yml).
  SQL_INJECTION: {
    title: 'Database query built from user input (SQL injection)',
    why: 'If user input is pasted into a query string, an attacker can change the query to read or delete any data.',
    fix: 'Use parameterized queries: Prisma `$queryRaw` with a tagged template, `$1` placeholders, or the query builder. Never `Unsafe` variants with user input.',
  },
  CODE_INJECTION: {
    title: 'Strings executed as code (eval)',
    why: 'If any part of the string comes from a user, they can run any JavaScript on your server or in the browser.',
    fix: 'Remove eval/new Function. Use JSON.parse for data, or a lookup table for dynamic behaviour.',
  },
  COMMAND_INJECTION: {
    title: 'Shell command built from user input (command injection)',
    why: 'An attacker can add `; rm -rf /` or similar to the input and run commands on your server.',
    fix: 'Use `execFile`/`spawn` with an argument array instead of a shell string, and validate inputs against an allowlist.',
  },
  OPEN_REDIRECT: {
    title: 'Redirect destination taken from the URL (open redirect)',
    why: 'Attackers send links like yourapp.com/login?next=https://evil.com, and your trusted domain forwards victims to a phishing site.',
    fix: 'Only allow relative paths (starting with a single "/") or an allowlist of your own domains.',
  },
  JWT_NOT_VERIFIED: {
    title: 'Token decoded without checking its signature',
    why: '`jwt.decode` just reads the token. Anyone can create a token saying they are an admin.',
    fix: 'Use `jwt.verify(token, secret)` (or `jose.jwtVerify`) before trusting anything inside the token.',
  },
  INSECURE_COOKIE: {
    title: 'Cookie readable by JavaScript',
    why: 'Without httpOnly, any XSS bug can steal the cookie and take over the session.',
    fix: 'Set `httpOnly: true, secure: true, sameSite: "lax"` on session cookies.',
  },
  WEAK_RANDOM_TOKEN: {
    title: 'Predictable random value used for a token',
    why: 'Math.random() is not cryptographically secure; tokens made with it can be guessed.',
    fix: 'Use `crypto.randomUUID()` or `crypto.randomBytes(32).toString("hex")`.',
  },
  PUBLIC_API_KEY: {
    title: 'Public client API key (usually fine)',
    why: 'Firebase/Google web API keys are meant to be public. They are only safe if your security rules and API key restrictions are set correctly.',
    fix: 'In Google Cloud Console, restrict the key to your domains and the APIs you use. Make sure your Firebase rules are not open.',
  },
}

// ---------------------------------------------------------------- file walking

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', '.nuxt', '.svelte-kit', '.output', 'dist', 'build', 'out',
  'coverage', '.vercel', '.netlify', '.turbo', 'vendor', '.venv', 'venv', '__pycache__', '.expo', '.cache'])
const TEXT_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json', '.sql', '.rules', '.yml', '.yaml',
  '.toml', '.vue', '.svelte', '.astro', '.html', '.py'])
const MAX_FILE_BYTES = 1_000_000

function isEnvFile(name) { return /^\.env(\..+)?$/.test(name) }
function isEnvExample(name) { return /^\.env(\..+)?\.(example|sample|template|defaults|dist)$/.test(name) }

function walk(root) {
  const files = []
  const stack = ['']
  while (stack.length) {
    const relDir = stack.pop()
    let entries
    try { entries = fs.readdirSync(path.join(root, relDir), { withFileTypes: true }) } catch { continue }
    for (const e of entries) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(rel); continue }
      if (!e.isFile()) continue
      const ext = path.extname(e.name).toLowerCase()
      if (!(TEXT_EXT.has(ext) || isEnvFile(e.name))) continue
      if (/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(rel)) continue
      const abs = path.join(root, rel)
      try {
        if (fs.statSync(abs).size > MAX_FILE_BYTES) continue
        files.push({ rel, abs, name: e.name, content: fs.readFileSync(abs, 'utf8') })
      } catch { /* unreadable: skip */ }
    }
  }
  return files.sort((a, b) => a.rel.localeCompare(b.rel))
}

// ---------------------------------------------------------------- helpers

const lineOf = (text, index) => text.slice(0, index).split('\n').length
const lineText = (text, line) => (text.split('\n')[line - 1] ?? '').trim()

function redact(s) {
  const mask = (m) => `${m.slice(0, 8)}…[redacted ${m.length} chars]`
  for (const p of Scan.SECRET_PATTERNS) s = s.replace(new RegExp(p.re.source, 'g'), (m) => (m.startsWith('-----') ? m : mask(m)))
  // Long tokens that mix letters and digits look like keys; plain identifiers (dangerouslySetInnerHTML) do not.
  return s.replace(/(?<![…\w])[A-Za-z0-9_\-.+/=]{24,}/g, (m) => (/\d/.test(m) && /[A-Za-z]/.test(m) ? mask(m) : m))
}
function evidence(text, line) {
  const l = redact(lineText(text, line))
  return l.length > 160 ? `${l.slice(0, 157)}...` : l
}

function readJSON(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')) } catch { return null } }

function run(cmd, cmdArgs, opts = {}) {
  const r = spawnSync(cmd, cmdArgs, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 180_000, ...opts })
  return { ok: !r.error, status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '', error: r.error }
}
const have = (cmd) => run(process.platform === 'win32' ? 'where' : 'which', [cmd]).status === 0

function decodeJwtPayload(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) } catch { return null }
}

function cmpVer(a, b) {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0)
  return 0
}

// ---------------------------------------------------------------- scanner

class Scan {
  constructor(root, opts) {
    this.root = root
    this.opts = opts
    this.files = walk(root)
    this.byRel = new Map(this.files.map((f) => [f.rel, f]))
    this.findings = []
    this.tools = {}
    this.pkg = readJSON(path.join(root, 'package.json')) ?? {}
    this.deps = { ...(this.pkg.dependencies ?? {}), ...(this.pkg.devDependencies ?? {}) }
    this.isGit = run('git', ['-C', root, 'rev-parse', '--is-inside-work-tree']).stdout.trim() === 'true'
    this.stack = this.detectStack()
  }

  add(rule, severity, file, line, extra = {}) {
    const meta = RULES[rule] ?? { title: rule, why: '', fix: '' }
    this.findings.push({
      rule, severity, title: extra.title ?? meta.title, file, line,
      evidence: extra.evidence ?? (file && line && this.byRel.get(file) ? evidence(this.byRel.get(file).content, line) : ''),
      why: extra.why ?? meta.why, fix: extra.fix ?? meta.fix,
      confidence: extra.confidence ?? 'high', source: extra.source ?? 'vibepheus',
      ...(extra.details ? { details: extra.details } : {}),
    })
  }

  detectStack() {
    const d = this.deps
    const has = (n) => n in d
    return {
      framework: has('next') ? 'nextjs' : has('@sveltejs/kit') ? 'sveltekit' : has('nuxt') ? 'nuxt'
        : has('vite') ? 'vite' : has('react-scripts') ? 'create-react-app' : has('expo') ? 'expo'
        : has('express') ? 'express' : 'unknown',
      supabase: has('@supabase/supabase-js') || has('@supabase/ssr') || fs.existsSync(path.join(this.root, 'supabase'))
        || this.files.some((f) => f.rel.endsWith('.sql') && /auth\.uid\(\)|auth\.users/.test(f.content)),
      firebase: has('firebase') || has('firebase-admin') || this.files.some((f) => /\.rules$|database\.rules\.json$/.test(f.rel)),
      prisma: has('@prisma/client') || has('prisma'),
      stripe: has('stripe'),
      auth: ['next-auth', '@clerk/nextjs', '@auth/core', 'lucia', 'better-auth', '@kinde-oss/kinde-auth-nextjs'].filter(has),
      middleware: this.files.some((f) => /^(src\/)?middleware\.(t|j)s$/.test(f.rel)),
    }
  }

  // ---------- secrets

  static SECRET_PATTERNS = [
    { id: 'Stripe secret key', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g, sev: 'critical' },
    { id: 'Stripe test secret key', re: /\b[sr]k_test_[0-9a-zA-Z]{20,}\b/g, sev: 'medium' },
    { id: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, sev: 'critical' },
    { id: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, sev: 'critical' },
    { id: 'OpenAI API key', re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}/g, sev: 'critical' },
    { id: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b/g, sev: 'critical' },
    { id: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, sev: 'high' },
    { id: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, sev: 'critical' },
    { id: 'Private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, sev: 'critical' },
    { id: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, sev: 'jwt' },
  ]

  matchSecrets(text) {
    const hits = []
    for (const p of Scan.SECRET_PATTERNS) {
      for (const m of text.matchAll(p.re)) {
        let sev = p.sev, id = p.id, demo = false
        if (sev === 'jwt') {
          const payload = decodeJwtPayload(m[0])
          if (payload?.role !== 'service_role') continue // anon keys are public by design
          demo = payload.iss === 'supabase-demo' // the well-known local-development key
          sev = demo ? 'low' : 'critical'; id = demo ? 'Supabase local-development service_role key' : 'Supabase service_role key'
        }
        hits.push({ id, sev, index: m.index, value: m[0], demo })
      }
    }
    return hits
  }

  checkSecrets() {
    for (const f of this.files) {
      if (isEnvFile(f.name)) continue // secrets belong in .env files; covered by ENV_FILE_NOT_IGNORED
      for (const h of this.matchSecrets(f.content)) {
        this.add('HARDCODED_SECRET', h.sev, f.rel, lineOf(f.content, h.index), {
          title: `${h.id} written directly in the code`,
          ...(h.demo ? {
            why: 'This is the publicly known key of the Supabase local development stack, so it is not a leak by itself. But code that hardcodes it will break or behave unexpectedly in production, and it shows the pattern of putting keys in code.',
            fix: 'Read the key from configuration (e.g. Supabase Vault or a setting) instead of hardcoding it, so production uses its own key.',
          } : {}),
        })
      }
      // Generic "password = '...'" style assignments
      for (const m of f.content.matchAll(/\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["']([^"'\s]{12,})["']/gi)) {
        const val = m[2]
        if (/your|example|changeme|placeholder|xxxx|\*\*\*|process\.env|^env\(|<.*>|^\$\{/i.test(val)) continue
        if (this.matchSecrets(val).length) continue // already reported above
        if (/^AIza[0-9A-Za-z_-]{30,40}$/.test(val)) continue // public Google/Firebase key, reported below as info
        this.add('HARDCODED_SECRET', 'medium', f.rel, lineOf(f.content, m.index), { title: `Possible hardcoded ${m[1]}`, confidence: 'low' })
      }
      // Google / Firebase web API keys: public by design
      for (const m of f.content.matchAll(/\bAIza[0-9A-Za-z_-]{30,40}\b/g)) {
        const firebase = /firebase|initializeApp|authDomain/i.test(f.content)
        this.add('PUBLIC_API_KEY', firebase ? 'info' : 'low', f.rel, lineOf(f.content, m.index), {
          title: firebase ? 'Firebase web API key (public by design)' : 'Google API key in code: check it is restricted',
        })
      }
    }
  }

  checkGitHistory() {
    if (!this.isGit) return
    const r = run('git', ['-C', this.root, 'log', '-p', '--all', '--no-color', '-n', '500', '--', '.'])
    if (!r.ok || r.status !== 0) return
    const current = this.files.map((f) => f.content).join('\n')
    let commit = '', file = ''
    const seen = new Set()
    for (const line of r.stdout.split('\n')) {
      if (line.startsWith('commit ')) { commit = line.slice(7, 19); continue }
      if (line.startsWith('+++ b/')) { file = line.slice(6); continue }
      if (!line.startsWith('+') || line.startsWith('+++')) continue
      for (const h of this.matchSecrets(line)) {
        if (h.demo || seen.has(h.value) || current.includes(h.value)) continue
        seen.add(h.value)
        this.add('SECRET_IN_GIT_HISTORY', 'critical', file, null, {
          title: `${h.id} found in git history`, evidence: `commit ${commit}: ${redact(line.slice(1).trim()).slice(0, 140)}`,
        })
      }
    }
  }

  checkPublicEnv() {
    const re = /\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|ADMIN)[A-Z0-9_]*\b/g
    const vars = new Map() // var -> [{file,line}]
    for (const f of this.files) {
      for (const m of f.content.matchAll(re)) {
        const list = vars.get(m[0]) ?? []
        list.push({ file: f.rel, line: lineOf(f.content, m.index), env: isEnvFile(f.name) })
        vars.set(m[0], list)
      }
    }
    for (const [name, locs] of vars) {
      locs.sort((a, b) => Number(b.env) - Number(a.env))
      const first = locs[0]
      const others = [...new Set(locs.slice(1).map((l) => l.file))]
      this.add('SECRET_IN_PUBLIC_ENV', /SERVICE_ROLE|SECRET|PRIVATE/.test(name) ? 'critical' : 'high', first.file, first.line, {
        title: `${name} is exposed to the browser`,
        evidence: `${redact(lineText(this.byRel.get(first.file).content, first.line))}${others.length ? `  (also used in: ${others.join(', ')})` : ''}`,
      })
    }
  }

  gitignoreMatches(rel) {
    const toRe = (pat) => new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\u0000/g, '.*') + '$')
    const dirs = ['', path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel)]
    let ignored = false
    for (const dir of [...new Set(dirs)]) {
      const gi = this.byRel.get(dir ? `${dir}/.gitignore` : '.gitignore')?.content
        ?? (() => { try { return fs.readFileSync(path.join(this.root, dir, '.gitignore'), 'utf8') } catch { return '' } })()
      const relToDir = dir ? rel.slice(dir.length + 1) : rel
      for (let raw of gi.split('\n')) {
        raw = raw.trim()
        if (!raw || raw.startsWith('#')) continue
        const neg = raw.startsWith('!')
        let pat = neg ? raw.slice(1) : raw
        pat = pat.replace(/\/$/, '')
        const target = pat.includes('/') ? relToDir : path.posix.basename(relToDir)
        if (toRe(pat.replace(/^\//, '')).test(target)) ignored = !neg
      }
    }
    return ignored
  }

  checkEnvFiles() {
    for (const f of this.files) {
      if (!isEnvFile(f.name) || isEnvExample(f.name)) continue
      if (!/=\s*\S/.test(f.content)) continue // empty file
      let ignored, tracked = false
      if (this.isGit) {
        ignored = run('git', ['-C', this.root, 'check-ignore', '-q', f.rel]).status === 0
        tracked = run('git', ['-C', this.root, 'ls-files', '--error-unmatch', f.rel]).status === 0
      } else ignored = this.gitignoreMatches(f.rel)
      if (tracked) this.add('ENV_FILE_NOT_IGNORED', 'critical', f.rel, null, { title: `${f.rel} is committed to git`, evidence: 'git ls-files lists this file' })
      else if (!ignored) this.add('ENV_FILE_NOT_IGNORED', 'high', f.rel, null, { evidence: '.gitignore has no rule covering this file' })
    }
  }

  // ---------- client / server separation

  resolveImport(fromRel, spec) {
    let bases
    if (spec.startsWith('.')) bases = [path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec))]
    else if (/^[@~]\//.test(spec)) bases = [spec.slice(2), `src/${spec.slice(2)}`]
    else return null
    for (const b of bases) {
      for (const ext of ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '/index.ts', '/index.tsx', '/index.js']) {
        if (this.byRel.has(b + ext)) return b + ext
      }
    }
    return null
  }

  clientFiles() {
    const code = this.files.filter((f) => /\.(t|j)sx?$|\.mjs$|\.vue$|\.svelte$/.test(f.rel))
    // 'server-only' modules can't be bundled for the browser; 'use server' modules are server actions:
    // a client importing them only gets an RPC stub, so their code (and imports) stay on the server.
    const isServerOnly = (f) => /^\s*import\s+['"]server-only['"]/m.test(f.content) || /^['"]use server['"]/m.test(f.content)
    let seeds
    if (this.stack.framework === 'nextjs') seeds = code.filter((f) => /^\s*['"]use client['"]/m.test(f.content))
    else if (['vite', 'create-react-app', 'expo'].includes(this.stack.framework)) {
      seeds = code.filter((f) => /^src\//.test(f.rel) && !/(^|\/)(server|api)\//.test(f.rel))
    } else return new Set()
    const client = new Set()
    const queue = seeds.map((f) => f.rel)
    while (queue.length) {
      const rel = queue.shift()
      if (client.has(rel)) continue
      const f = this.byRel.get(rel)
      if (!f || isServerOnly(f)) continue
      client.add(rel)
      for (const m of f.content.matchAll(/(?:from\s*|import\s*\(?\s*|require\(\s*)['"]([^'"]+)['"]/g)) {
        const r = this.resolveImport(rel, m[1])
        if (r) queue.push(r)
      }
    }
    return client
  }

  checkServiceRoleInClient() {
    for (const rel of this.clientFiles()) {
      const f = this.byRel.get(rel)
      const m = /service_role|SERVICE_ROLE/.exec(f.content)
      if (m) this.add('SERVICE_ROLE_IN_CLIENT', 'critical', rel, lineOf(f.content, m.index))
    }
  }

  // ---------- database rules

  checkSupabaseSql() {
    if (!this.stack.supabase) return
    const sqlFiles = this.files.filter((f) => f.rel.endsWith('.sql'))
    const norm = (n) => { n = n.replace(/"/g, '').toLowerCase(); return n.includes('.') ? n : `public.${n}` }
    const created = new Map(), enabled = new Set()
    for (const f of sqlFiles) {
      for (const m of f.content.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."]+)/gi)) {
        const n = norm(m[1])
        const end = f.content.indexOf(');', m.index)
        const columns = f.content.slice(m.index, end < 0 ? undefined : end).replace(/--.*$/gm, '')
        if (!created.has(n)) created.set(n, { file: f.rel, line: lineOf(f.content, m.index), columns })
      }
      for (const m of f.content.matchAll(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."]+)\s+enable\s+row\s+level\s+security/gi)) enabled.add(norm(m[1]))
      for (const m of f.content.matchAll(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."]+)\s+disable\s+row\s+level\s+security/gi)) {
        this.add('RLS_DISABLED', 'high', f.rel, lineOf(f.content, m.index), { title: `Row Level Security switched off for ${norm(m[1])}` })
      }
      for (const m of f.content.matchAll(/create\s+policy\s+("[^"]*"|\w+)\s+on\s+([\w."]+)([\s\S]*?);/gi)) {
        const body = m[3].toLowerCase()
        if (!/(using|with\s+check)\s*\(\s*true\s*\)/.test(body)) continue
        const cmd = (/\bfor\s+(select|insert|update|delete|all)\b/.exec(body) ?? [])[1] ?? 'all'
        const roles = (/\bto\s+([\w,\s]+?)(?=\s+(using|with)\b|$)/.exec(body) ?? [])[1]?.split(',').map((s) => s.trim()) ?? ['public']
        const authedOnly = roles.every((r) => r === 'authenticated')
        const table = norm(m[2]), line = lineOf(f.content, m.index)
        if (cmd === 'select' && authedOnly) {
          this.add('RLS_PERMISSIVE_POLICY', 'info', f.rel, line, {
            title: `Any logged-in user can read every row of ${table}`,
            why: 'Fine for shared content (comments, posts). Not fine if this table holds private data.', confidence: 'medium',
          })
        } else if (cmd === 'select' && created.has(table) && !SENSITIVE_COLUMNS.test(created.get(table).columns)) {
          this.add('RLS_PERMISSIVE_POLICY', 'low', f.rel, line, {
            title: `Anyone (even logged out) can read every row of ${table}`,
            why: 'No obviously private columns (email, address, user_id...), so this may be intentional public data such as a product catalog. Make sure nothing private is stored here later.',
            confidence: 'medium',
          })
        } else {
          this.add('RLS_PERMISSIVE_POLICY', cmd === 'select' ? 'high' : 'critical', f.rel, line, {
            title: cmd === 'select' ? `Anyone (even logged out) can read every row of ${table}` : `${authedOnly ? 'Any logged-in user' : 'Anyone'} can ${cmd === 'all' ? 'read and write' : cmd} any row of ${table}`,
          })
        }
      }
    }
    for (const [table, loc] of created) {
      if (table.startsWith('public.') && !enabled.has(table)) this.add('RLS_DISABLED', 'high', loc.file, loc.line, { title: `Table ${table} has no Row Level Security` })
    }
  }

  checkFirebaseRules() {
    for (const f of this.files) {
      if (/\.rules$/.test(f.rel)) {
        for (const m of f.content.matchAll(/allow\s+([\w,\s]+?)\s*(?::\s*if\s+true\s*)?;/g)) {
          if (/:\s*if\s+(?!true)/.test(m[0])) continue
          this.add('FIREBASE_OPEN_RULES', 'critical', f.rel, lineOf(f.content, m.index), { title: `Anyone can ${m[1].trim()} this Firebase data` })
        }
        for (const m of f.content.matchAll(/allow\s+[\w,\s]+:\s*if\s+request\.time\s*<\s*timestamp/g)) {
          this.add('FIREBASE_OPEN_RULES', 'high', f.rel, lineOf(f.content, m.index), { title: 'Firebase "test mode" rules: open to everyone until a date' })
        }
      }
      if (/database\.rules\.json$/.test(f.rel)) {
        for (const m of f.content.matchAll(/"\.(read|write)"\s*:\s*"?true"?/g)) {
          this.add('FIREBASE_OPEN_RULES', 'critical', f.rel, lineOf(f.content, m.index), { title: `Realtime Database: anyone can ${m[1]}` })
        }
      }
    }
  }

  // ---------- API routes

  static AUTH_RE = /auth\.getUser|getSession|getServerSession|getServerAuthSession|\bauth\(\s*\)|currentUser\(|getAuth\(|getToken\(|verifyIdToken|jwt\.verify|jwtVerify|withAuth|requireAuth|requireUser|validateRequest|getKindeServerSession|CRON_SECRET|headers\.get\(\s*['"]authorization['"]|req\.headers\.authorization/i
  static SIG_RE = /constructEvent|verifySignature|webhooks?\.verify|svix|createHmac|verifyWebhook|validateWebhook/i

  static PUBLIC_ROUTE_RE = /exchangeCodeForSession|verifyOtp|Cache-Control["']?\s*[:,]\s*["'][^"']*\bpublic\b/i

  // Real apps wrap auth in helpers (getServerProfile(), requireAdmin()...). If the route calls a function
  // imported from a local module that itself performs an auth check, count the route as authenticated.
  authViaHelper(f) { return this.callsImportedWhere(f, (content) => Scan.AUTH_RE.test(content)) }

  // True if `f` calls a function imported from a local module whose source satisfies `test`.
  callsImportedWhere(f, test) {
    for (const m of f.content.matchAll(/import\s+(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]/g)) {
      const target = this.resolveImport(f.rel, m[3])
      if (!target || !test(this.byRel.get(target).content)) continue
      const names = [m[1], ...(m[2] ?? '').split(',').map((s) => s.trim().split(/\s+as\s+/).pop())].filter(Boolean)
      if (names.some((n) => /^\w+$/.test(n) && new RegExp(`\\b${n}\\s*[.(]`).test(f.content))) return true
    }
    return false
  }

  // ---------- denial of wallet: endpoints that spend money on paid APIs

  static PAID_SDKS = [
    { re: /openai/, name: 'OpenAI', kind: 'ai' }, { re: /@anthropic-ai\/sdk/, name: 'Anthropic', kind: 'ai' },
    { re: /@google\/(generative-ai|genai)/, name: 'Google Gemini', kind: 'ai' }, { re: /groq-sdk/, name: 'Groq', kind: 'ai' },
    { re: /@mistralai\/mistralai/, name: 'Mistral', kind: 'ai' }, { re: /cohere-ai/, name: 'Cohere', kind: 'ai' },
    { re: /replicate/, name: 'Replicate', kind: 'ai' }, { re: /@fal-ai\/[\w-]+/, name: 'fal.ai', kind: 'ai' },
    { re: /elevenlabs|@elevenlabs\/[\w-]+/, name: 'ElevenLabs', kind: 'ai' },
    { re: /@aws-sdk\/client-bedrock-runtime/, name: 'AWS Bedrock', kind: 'ai' },
    { re: /resend/, name: 'Resend', kind: 'email' }, { re: /@sendgrid\/mail/, name: 'SendGrid', kind: 'email' },
    { re: /@aws-sdk\/client-sesv?2?/, name: 'AWS SES', kind: 'email' },
    { re: /twilio/, name: 'Twilio', kind: 'sms' }, { re: /@aws-sdk\/client-sns/, name: 'AWS SNS', kind: 'sms' },
  ]
  static PAID_HOSTS = [
    ['api.openai.com', 'OpenAI', 'ai'], ['api.anthropic.com', 'Anthropic', 'ai'], ['generativelanguage.googleapis.com', 'Google Gemini', 'ai'],
    ['api.groq.com', 'Groq', 'ai'], ['api.mistral.ai', 'Mistral', 'ai'], ['api.replicate.com', 'Replicate', 'ai'],
    ['openrouter.ai/api', 'OpenRouter', 'ai'], ['api.together.xyz', 'Together AI', 'ai'], ['api.perplexity.ai', 'Perplexity', 'ai'],
    ['api.deepseek.com', 'DeepSeek', 'ai'], ['api.x.ai', 'xAI', 'ai'], ['api.elevenlabs.io', 'ElevenLabs', 'ai'],
    ['api.resend.com', 'Resend', 'email'], ['api.sendgrid.com', 'SendGrid', 'email'], ['api.twilio.com', 'Twilio', 'sms'],
  ]
  static RATE_LIMIT_RE = /@upstash\/ratelimit|\bRatelimit\b|rate[-_ ]?limit|rateLimiter|slidingWindow|fixedWindow|tokenBucket|express-rate-limit|arcjet|\bthrottle|\bquota\b|usage[-_]?limit|maxMessages|entitlements?\b/i

  // Which paid API (if any) this source calls directly.
  static paidApiUse(content) {
    for (const [host, name, kind] of Scan.PAID_HOSTS) if (content.includes(`https://${host}`)) return { name, kind }
    for (const m of content.matchAll(/import\s+(type\s+)?[^'"]*?from\s*['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      if (m[1]) continue // type-only import
      const spec = m[2] ?? m[3]
      // Vercel AI SDK: only server-side generation calls cost money (not UI hooks or types)
      if (/^(ai|@ai-sdk\/(?!react|ui-utils|svelte|vue)[\w-]+)$/.test(spec)) {
        if (/\b(generateText|streamText|generateObject|streamObject|embedMany|embed|generateImage|generateSpeech)\s*\(/.test(content)) return { name: 'an AI model (Vercel AI SDK)', kind: 'ai' }
        continue
      }
      const sdk = Scan.PAID_SDKS.find((s) => new RegExp(`^(${s.re.source})$`).test(spec))
      if (sdk) return { name: sdk.name, kind: sdk.kind }
    }
    return null
  }

  checkDenialOfWallet() {
    const middlewareLimits = this.files.some((f) => /^(src\/)?middleware\.(t|j)s$/.test(f.rel) && Scan.RATE_LIMIT_RE.test(f.content))
    const candidates = [...this.routeFiles(), ...this.files.filter((f) => /\.(t|j)sx?$/.test(f.rel) && /^['"]use server['"]/m.test(f.content))]
    for (const f of new Set(candidates)) {
      let paid = Scan.paidApiUse(f.content)
      if (!paid) {
        // one level of local helpers, e.g. lib/ai.ts wrapping the OpenAI client
        for (const m of f.content.matchAll(/from\s*['"]([^'"]+)['"]/g)) {
          const t = this.resolveImport(f.rel, m[1])
          const use = t && Scan.paidApiUse(this.byRel.get(t).content)
          if (use && this.callsImportedWhere(f, (c) => c === this.byRel.get(t).content)) { paid = use; break }
        }
      }
      if (!paid) continue

      // Bring-your-own-key: the user's key is passed in, so the app owner isn't paying.
      // Owner pays: a provider key from the environment (ignoring unrelated keys like SUPABASE_SERVICE_ROLE_KEY),
      // or an SDK constructed with no arguments, which reads its key from the environment.
      const ownerKey = /process\.env\.(?![A-Z0-9_]*(SUPABASE|STRIPE|DATABASE|POSTGRES|REDIS|UPSTASH|NEXTAUTH|JWT|CLERK|WEBHOOK|CRON))[A-Z0-9_]*(API_?KEY|TOKEN|SECRET)/.test(f.content)
        || /new\s+(OpenAI|Anthropic|Groq|Resend|Replicate)\(\s*\)/.test(f.content)
      // User pays: the key is read from user data, e.g. profile.openai_api_key or model.api_key.
      const byoKey = !ownerKey && /(?<!process\.)\b\w+\??\.\w*api_?key\b/i.test(f.content)
      const auth = Scan.AUTH_RE.test(f.content) || Scan.SIG_RE.test(f.content) || this.authViaHelper(f)
      const limited = middlewareLimits || Scan.RATE_LIMIT_RE.test(f.content) || this.callsImportedWhere(f, (c) => Scan.RATE_LIMIT_RE.test(c))
      if (auth && limited) continue

      const line = lineOf(f.content, Math.max(0, f.content.search(/export\s+(async\s+)?(function|const|default)/)))
      const what = paid.kind === 'sms' ? 'sends paid SMS' : paid.kind === 'email' ? 'sends paid email' : `calls ${paid.name}`
      const capped = /max_?tokens|maxTokens|maxOutputTokens|max_output_tokens/.test(f.content)
      const details = [`provider: ${paid.name}`, `login check: ${auth ? 'yes' : 'no'}`, `rate limit: ${limited ? 'yes' : 'no'}`, ...(paid.kind === 'ai' ? [`output cap (max_tokens): ${capped ? 'yes' : 'no'}`] : [])]

      if (byoKey && !auth) {
        this.add('PAID_API_UNPROTECTED', 'high', f.rel, line, {
          title: `${f.rel} ${what} using users' stored API keys, with no login check`, details,
          why: 'This endpoint uses an API key stored for a user, but anyone can call it without logging in. If the caller can choose whose key is used (for example by passing an ID), they can spend other users\' money.',
          fix: 'Require login, and only ever load the key that belongs to the logged-in user (filter by user_id, or use the user\'s own client so Row Level Security applies). Add a rate limit too.',
        })
      } else if (byoKey) {
        this.add('PAID_API_UNPROTECTED', 'info', f.rel, line, {
          title: `${f.rel} ${what} using a key the user supplies`, details, confidence: 'medium',
          why: 'The API key appears to come from the user (their profile or the request), so abuse spends their money, not yours. Make sure users can only use their own key.',
        })
      } else if (!auth && !limited) {
        this.add('PAID_API_UNPROTECTED', paid.kind === 'sms' ? 'critical' : 'high', f.rel, line, {
          title: `${f.rel} ${what} with no login check and no rate limit`, details,
          ...(paid.kind === 'sms' ? { why: `${RULES.PAID_API_UNPROTECTED.why} SMS is the worst case: attackers run "SMS pumping" fraud, sending messages to premium numbers they profit from.` } : {}),
        })
      } else if (auth) {
        this.add('PAID_API_UNPROTECTED', 'medium', f.rel, line, {
          title: `${f.rel} ${what}: logged-in users can call it without any limit`, details, confidence: 'medium',
          why: 'Only logged-in users can call this, but nothing limits how often. If anyone can sign up for free, an attacker can create an account and call it in a loop, billed to you.',
        })
      } else {
        this.add('PAID_API_UNPROTECTED', 'low', f.rel, line, {
          title: `${f.rel} ${what} without a login check (rate limited)`, details, confidence: 'medium',
          why: 'A rate limit is in place, which caps the damage, but anyone on the internet can still use this endpoint at your expense up to that limit.',
        })
      }
    }
  }

  routeFiles() {
    return this.files.filter((f) => /(^|\/)app\/(.+\/)?route\.(t|j)sx?$/.test(f.rel) || /(^|\/)pages\/api\/.+\.(t|j)sx?$/.test(f.rel))
  }

  checkApiRoutes() {
    // Only trust middleware that actually blocks: redirects to a login page or returns 401/403.
    const middlewareAuth = this.files.some((f) => /^(src\/)?middleware\.(t|j)s$/.test(f.rel) && Scan.AUTH_RE.test(f.content)
      && /redirect\([^)]*(login|sign-?in|auth)|status:\s*40[13]|clerkMiddleware|withAuth|auth\.protect/i.test(f.content))
    for (const f of this.routeFiles()) {
      const methods = [...f.content.matchAll(/export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE)\b/g)].map((m) => m[1])
      const pagesDefault = /pages\/api\//.test(f.rel) && /export\s+default/.test(f.content)
      if (!methods.length && !pagesDefault) continue
      const mutating = methods.some((m) => m !== 'GET') || pagesDefault && /req\.method\s*===?\s*['"](POST|PUT|PATCH|DELETE)/.test(f.content)
      const firstLine = lineOf(f.content, f.content.search(/export\s+(async\s+)?(function|const|default)/))

      if (/webhook/i.test(f.rel)) {
        if (!Scan.SIG_RE.test(f.content)) this.add('WEBHOOK_NO_SIGNATURE', 'high', f.rel, firstLine)
        continue
      }
      if (Scan.AUTH_RE.test(f.content) || this.authViaHelper(f)) { this.checkIdor(f); continue }
      if (Scan.PUBLIC_ROUTE_RE.test(f.content)) continue // login callbacks, explicitly cacheable public responses
      if (!/await|supabase|prisma|\bdb\b|fetch\(|process\.env|\.query\(/.test(f.content)) continue // stub: touches no data

      const adminClient = /SERVICE_ROLE|supabaseAdmin|serviceRole/i.test(f.content)
      let sev = mutating || adminClient || /admin|internal|cron|delete|manage/i.test(f.rel) ? 'high' : 'medium'
      let why = adminClient ? `${RULES.API_ROUTE_NO_AUTH.why} This route also uses the Supabase service_role (admin) client, which ignores Row Level Security, so whatever it reads or writes is open to anyone who calls it.` : undefined
      if (middlewareAuth) {
        sev = sev === 'high' ? 'medium' : 'low'
        why = `${RULES.API_ROUTE_NO_AUTH.why} A middleware file checks auth, so this may be covered, but middleware-only auth is fragile (see CVE-2025-29927). Check the route itself too.`
      }
      this.add('API_ROUTE_NO_AUTH', sev, f.rel, firstLine, {
        title: `${methods.join('/') || 'API'} ${f.rel} has no authentication check`, confidence: sev === 'high' ? 'high' : 'medium', ...(why ? { why } : {}),
      })
    }
  }

  checkIdor(f) {
    if (!/\[[^\]]+\]/.test(f.rel)) return
    const lookup = /\.eq\(\s*['"]id['"]\s*,|\.(findUnique|findFirst|findById|findOne)\(|\bdoc\([^)]*params|where\(\s*\{?\s*['"]?id/.exec(f.content)
    if (!lookup) return
    if (/user\.id|userId|user_id|owner_?id|session\.user|auth\.uid|\.uid\b/i.test(f.content)) return
    const admin = /admin|service/i.test(f.content.slice(Math.max(0, lookup.index - 200), lookup.index))
    this.add('POSSIBLE_IDOR', admin ? 'high' : 'medium', f.rel, lineOf(f.content, lookup.index), {
      confidence: admin ? 'high' : 'medium',
      ...(admin ? {} : { why: `${RULES.POSSIBLE_IDOR.why} If this query uses the logged-in user's Supabase client and the table has correct RLS, the database may already block it. Verify.` }),
    })
  }

  // ---------- browser-side issues

  checkCors() {
    for (const f of this.files) {
      if (!/\.(t|j)sx?$|\.mjs$|\.cjs$|\.json$|\.toml$|\.ya?ml$/.test(f.rel)) continue
      const wild = /Access-Control-Allow-Origin["']?\s*(?:,\s*value\s*:|:|,|=)\s*["']\*["']|\borigin\s*:\s*(?:["']\*["']|true)\b|\bcors\(\s*\)/i.exec(f.content)
      if (!wild) continue
      const creds = /Allow-Credentials["']?\s*(?:,\s*value\s*:|:|,|=)\s*["']?true|\bcredentials\s*:\s*true/i.test(f.content)
      this.add('CORS_WILDCARD', creds ? 'high' : 'medium', f.rel, lineOf(f.content, wild.index), {
        title: creds ? 'Any website can call your API, with credentials enabled' : 'Any website can call your API (CORS *)',
      })
    }
  }

  checkXss() {
    const patterns = [
      /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}/g,
      /\bv-html\s*=\s*"([^"]+)"/g,
      /\{@html\s+([^}]+)\}/g,
      /\.innerHTML\s*=(?!=)\s*([^;\n]+)/g,
    ]
    for (const f of this.files) {
      if (!/\.(t|j)sx?$|\.vue$|\.svelte$|\.astro$|\.html$/.test(f.rel)) continue
      for (const re of patterns) {
        for (const m of f.content.matchAll(re)) {
          const expr = m[1].trim().replace(/,$/, '').trim()
          if (/sanitize|purify|xss\(|escape/i.test(expr)) continue
          if (/^(['"`])[^$]*\1$/.test(expr)) continue // static string literal
          if (/^[A-Z][A-Z0-9_]*$/.test(expr)) continue // module constant, e.g. an inline theme script
          // HTML produced by React's renderToString is escaped by React: worth a look, not a confident finding
          const rendered = /renderToString\(/.test(f.content)
          const userish = !rendered && /comment|body|message|content|bio|input|query|param|description|text|html|markdown|post/i.test(expr)
          this.add('XSS_UNSANITIZED_HTML', userish ? 'high' : rendered ? 'low' : 'medium', f.rel, lineOf(f.content, m.index), {
            confidence: userish ? 'high' : rendered ? 'low' : 'medium',
            ...(rendered ? { why: 'This HTML comes from renderToString, which escapes text. It is only dangerous if the rendered component itself outputs raw HTML (for example a markdown renderer with HTML enabled). Check that component.' } : {}),
          })
        }
      }
    }
  }

  // ---------- dependencies (small built-in list; osv-scanner / npm audit give full coverage)

  static KNOWN_VULNS = [
    {
      pkg: 'next', id: 'CVE-2025-29927', sev: 'critical', middlewareOnly: true,
      summary: 'Middleware authorization bypass: attackers can skip middleware with the x-middleware-subrequest header.',
      ranges: [['11.1.4', '12.3.5'], ['13.0.0', '13.5.9'], ['14.0.0', '14.2.25'], ['15.0.0', '15.2.3']],
    },
    {
      pkg: 'next', id: 'CVE-2025-66478 / CVE-2025-55182', sev: 'critical',
      summary: 'Remote code execution in React Server Components ("React2Shell") affecting App Router apps.',
      ranges: [['15.0.0', '15.0.5'], ['15.1.0', '15.1.9'], ['15.2.0', '15.2.6'], ['15.3.0', '15.3.6'], ['15.4.0', '15.4.8'], ['15.5.0', '15.5.7'], ['16.0.0', '16.0.7']],
    },
    ...['react-server-dom-webpack', 'react-server-dom-parcel', 'react-server-dom-turbopack'].map((pkg) => ({
      pkg, id: 'CVE-2025-55182', sev: 'critical',
      summary: 'Remote code execution in React Server Components ("React2Shell").',
      ranges: [['19.0.0', '19.0.1'], ['19.1.0', '19.1.2'], ['19.2.0', '19.2.1']],
    })),
  ]

  installedVersions() {
    const out = {}
    const lock = readJSON(path.join(this.root, 'package-lock.json'))
    for (const [name, spec] of Object.entries(this.deps)) {
      const locked = lock?.packages?.[`node_modules/${name}`]?.version ?? lock?.dependencies?.[name]?.version
      const fromPkg = /(\d+\.\d+\.\d+)/.exec(String(spec))?.[1]
      if (locked) out[name] = { version: locked, exact: true }
      else if (fromPkg) out[name] = { version: fromPkg, exact: /^\d/.test(String(spec)) }
    }
    return out
  }

  checkDependencies() {
    const versions = this.installedVersions()
    const pkgFile = this.byRel.get('package.json')
    for (const v of Scan.KNOWN_VULNS) {
      const inst = versions[v.pkg]
      if (!inst) continue
      const hit = v.ranges.find(([lo, hi]) => cmpVer(inst.version, lo) >= 0 && cmpVer(inst.version, hi) < 0)
      if (!hit) continue
      let sev = v.sev
      let why = v.summary
      if (v.middlewareOnly && !this.stack.middleware) { sev = 'medium'; why += ' You have no middleware file today, so you are not directly exposed, but upgrade before you add one.' }
      const idx = pkgFile ? pkgFile.content.indexOf(`"${v.pkg}"`) : -1
      this.add('VULNERABLE_DEPENDENCY', sev, 'package.json', idx >= 0 ? lineOf(pkgFile.content, idx) : null, {
        title: `${v.pkg}@${inst.version} is affected by ${v.id}`, why,
        fix: `Upgrade ${v.pkg} to ${hit[1]} or later in that release line (or the latest version).`,
        confidence: inst.exact ? 'high' : 'medium',
      })
    }
  }

  // ---------- optional external tools

  runExternal() {
    if (!this.opts.external) { this.tools.external = 'skipped (--no-external)'; return }
    this.runSemgrep(); this.runGitleaks(); this.runOsv(); this.runNpmAudit()
  }

  runSemgrep() {
    if (!have('semgrep')) { this.tools.semgrep = 'not installed'; return }
    const rules = path.join(HERE, '..', 'rules', 'semgrep.yml')
    const r = run('semgrep', ['scan', '--config', rules, '--json', '--quiet', '--metrics=off', this.root])
    const data = (() => { try { return JSON.parse(r.stdout) } catch { return null } })()
    if (!data) { this.tools.semgrep = `failed: ${r.stderr.split('\n')[0] || 'no output'}`; return }
    const sevMap = { ERROR: 'high', WARNING: 'medium', INFO: 'low' }
    for (const res of data.results ?? []) {
      const rel = path.relative(this.root, path.resolve(res.path)).split(path.sep).join('/')
      const meta = res.extra?.metadata ?? {}
      this.add(meta.vibe_rule ?? 'SEMGREP', sevMap[res.extra?.severity] ?? 'medium', rel, res.start?.line, {
        title: res.extra?.message?.split('\n')[0] ?? res.check_id, source: 'semgrep', confidence: 'medium',
        ...(meta.vibe_rule ? {} : { why: res.extra?.message ?? '', fix: '' }),
      })
    }
    this.tools.semgrep = `ran (${(data.results ?? []).length} results)`
  }

  runGitleaks() {
    if (!have('gitleaks')) { this.tools.gitleaks = 'not installed'; return }
    const report = path.join(os.tmpdir(), `vibepheus-gitleaks-${process.pid}.json`)
    const common = ['--report-format', 'json', '--report-path', report, '--no-banner', '--redact']
    let r = run('gitleaks', ['dir', this.root, ...common])
    if (r.status !== 0 && r.status !== 1) r = run('gitleaks', ['detect', '--source', this.root, '--no-git', ...common])
    const data = readJSON(report)
    try { fs.unlinkSync(report) } catch {}
    if (!Array.isArray(data)) { this.tools.gitleaks = `failed: ${r.stderr.split('\n')[0] || 'no report'}`; return }
    for (const leak of data) {
      const rel = path.relative(this.root, path.resolve(this.root, leak.File)).split(path.sep).join('/')
      if (isEnvFile(path.basename(rel))) continue
      if (this.findings.some((x) => x.rule === 'HARDCODED_SECRET' && x.file === rel && x.line === leak.StartLine)) continue
      this.add('HARDCODED_SECRET', 'high', rel, leak.StartLine, { title: `${leak.Description ?? leak.RuleID} (gitleaks)`, source: 'gitleaks', confidence: 'medium' })
    }
    this.tools.gitleaks = `ran (${data.length} results)`
  }

  runOsv() {
    if (!have('osv-scanner')) { this.tools['osv-scanner'] = 'not installed'; return }
    if (this.opts.offline) { this.tools['osv-scanner'] = 'skipped (--offline: it looks up package versions online)'; return }
    let r = run('osv-scanner', ['scan', 'source', '-r', '--format', 'json', this.root])
    let data = (() => { try { return JSON.parse(r.stdout) } catch { return null } })()
    if (!data) { r = run('osv-scanner', ['--format', 'json', '-r', this.root]); try { data = JSON.parse(r.stdout) } catch {} }
    if (!data) { this.tools['osv-scanner'] = `failed: ${r.stderr.split('\n')[0] || 'no output'}`; return }
    let n = 0
    for (const res of data.results ?? []) {
      const src = path.relative(this.root, res.source?.path ?? '').split(path.sep).join('/') || 'package.json'
      for (const p of res.packages ?? []) {
        for (const g of p.groups ?? []) {
          const score = parseFloat(g.max_severity) || 0
          const sev = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low'
          const vuln = (p.vulnerabilities ?? []).find((v) => g.ids?.includes(v.id))
          n++
          this.add('VULNERABLE_DEPENDENCY', sev, src, null, {
            title: `${p.package?.name}@${p.package?.version} is affected by ${(g.aliases ?? g.ids ?? []).join(', ')}`,
            why: vuln?.summary ?? RULES.VULNERABLE_DEPENDENCY.why, source: 'osv-scanner',
          })
        }
      }
    }
    this.tools['osv-scanner'] = `ran (${n} results)`
  }

  runNpmAudit() {
    if (this.opts.offline) { this.tools['npm audit'] = 'skipped (--offline)'; return }
    if (!fs.existsSync(path.join(this.root, 'package-lock.json'))) { this.tools['npm audit'] = 'skipped (no package-lock.json)'; return }
    if (!have('npm')) { this.tools['npm audit'] = 'not installed'; return }
    const r = run('npm', ['audit', '--json', '--package-lock-only'], { cwd: this.root })
    const data = (() => { try { return JSON.parse(r.stdout) } catch { return null } })()
    if (!data?.vulnerabilities) { this.tools['npm audit'] = `failed: ${r.stderr.split('\n')[0] || 'no output'}`; return }
    let n = 0
    for (const [name, v] of Object.entries(data.vulnerabilities)) {
      const adv = (v.via ?? []).filter((x) => typeof x === 'object')
      if (!adv.length) continue // only transitive; reported under the root package
      n++
      const sev = v.severity === 'moderate' ? 'medium' : v.severity
      this.add('VULNERABLE_DEPENDENCY', SEVERITIES.includes(sev) ? sev : 'medium', 'package-lock.json', null, {
        title: `${name} (${v.range}) has known vulnerabilities`, why: adv.map((a) => a.title).join('; '),
        fix: v.fixAvailable ? 'Run `npm audit fix` (check for breaking changes), or upgrade manually.' : 'No automatic fix yet: check the advisory for workarounds.',
        source: 'npm audit', details: adv.map((a) => a.url).filter(Boolean),
      })
    }
    this.tools['npm audit'] = `ran (${n} packages)`
  }

  // ---------- run everything

  runAll() {
    this.checkSecrets(); this.checkGitHistory(); this.checkPublicEnv(); this.checkEnvFiles()
    this.checkServiceRoleInClient(); this.checkSupabaseSql(); this.checkFirebaseRules()
    this.checkApiRoutes(); this.checkDenialOfWallet(); this.checkCors(); this.checkXss(); this.checkDependencies()
    this.runExternal()
    // A high/critical denial-of-wallet finding already says "no login check": don't report the same route twice.
    const walletNoAuth = new Set(this.findings.filter((f) => f.rule === 'PAID_API_UNPROTECTED' && ['critical', 'high'].includes(f.severity)).map((f) => f.file))
    this.findings = this.findings.filter((f) => !(f.rule === 'API_ROUTE_NO_AUTH' && walletNoAuth.has(f.file)))
    if (this.opts.only) this.findings = this.findings.filter((f) => this.opts.only.has(f.rule))
    const seen = new Set()
    this.findings = this.findings.filter((f) => { const k = `${f.rule}|${f.file}|${f.line}|${f.title}`; if (seen.has(k)) return false; seen.add(k); return true })
    this.findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || String(a.file).localeCompare(String(b.file)) || (a.line ?? 0) - (b.line ?? 0))
    this.findings.forEach((f, i) => { f.id = `VP-${String(i + 1).padStart(3, '0')}` })
    return this
  }

  report() {
    const summary = Object.fromEntries(SEVERITIES.map((s) => [s, this.findings.filter((f) => f.severity === s).length]))
    return {
      tool: 'vibepheus', version: VERSION, homepage: HOMEPAGE, scannedAt: new Date().toISOString(), target: this.root,
      stack: this.stack, filesScanned: this.files.length, gitRepo: this.isGit, externalTools: this.tools,
      summary, findings: this.findings,
      note: 'Automated checks only. "No findings" means these checks passed, not that the app is secure.',
    }
  }
}

function toMarkdown(r) {
  const icon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }
  const out = [`# vibepheus report`, '', `Scanned ${r.filesScanned} files in \`${path.basename(r.target)}\` (${r.stack.framework}${r.stack.supabase ? ' + Supabase' : ''}${r.stack.firebase ? ' + Firebase' : ''}).`, '',
    SEVERITIES.map((s) => `${icon[s]} ${r.summary[s]} ${s}`).join(' · '), '']
  for (const f of r.findings) {
    out.push(`## ${icon[f.severity]} ${f.id} ${f.title}`, '', `**Where:** \`${f.file ?? '-'}${f.line ? `:${f.line}` : ''}\` · severity ${f.severity} · confidence ${f.confidence}${f.source !== 'vibepheus' ? ` · via ${f.source}` : ''}`)
    if (f.evidence) out.push('', '```', f.evidence, '```')
    out.push('', `**Why it matters:** ${f.why}`, '', `**How to fix:** ${f.fix}`, '')
  }
  out.push('---', `External tools: ${Object.entries(r.externalTools).map(([k, v]) => `${k}: ${v}`).join(' · ')}`, '', `_${r.note}_`, '', `_Generated by [vibepheus](${r.homepage}) v${r.version}, made by wbuffetz._`)
  return out.join('\n')
}

// ---------------------------------------------------------------- main

const opts = parseArgs(process.argv.slice(2))
const root = path.resolve(opts.target)
if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) { console.error(`Not a directory: ${root}`); process.exit(2) }
const report = new Scan(root, opts).runAll().report()
const text = opts.json ? JSON.stringify(report, null, 2) : toMarkdown(report)
if (opts.out) fs.writeFileSync(opts.out, text)
else process.stdout.write(text + '\n')
if (opts.failOn) {
  const limit = SEVERITIES.indexOf(opts.failOn)
  if (report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit)) process.exit(1)
}
