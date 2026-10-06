// Pure detection: no `$`, so every rule is testable on its own.
// A Finding names the rule and what was at risk, never the secret itself.

export type Finding = { rule: string; reason: string; hint?: string }
export type Known = { name: string; value: string }

export type Config = {
  secretName: RegExp
  forbidden: RegExp[]
  allowed: RegExp[]
}

const BUILTIN_FORBIDDEN = [
  /(^|\/)\.(bashrc|zshrc|profile|bash_profile|bash_aliases|netrc)$/,
  /(^|\/)\.env(\.[^/]*)?$/,
  /[^/]\.env$/,
  /(^|\/)\.aws\/(credentials|config)$/,
  /(^|\/)(secrets|credentials)\/|(^|\/)(\.psst|\.gnupg|\.ssh)(\/|$)/,
]

export const DEFAULT_SECRET_NAMES =
  '(^|_)(KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|AUTH)(_|$)'

function globToRegex(glob: string): RegExp {
  const body = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*\/?/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\u0000/g, '(.*/)?')
  return new RegExp(`(^|/)${body}(/|$)`)
}

function globs(list: string): RegExp[] {
  return list
    .split(',')
    .map(one => one.trim())
    .filter(one => one.length > 0)
    .map(globToRegex)
}

export function makeConfig(o: {
  secretNames?: string
  extraForbiddenPaths?: string
  allowPaths?: string
}): Config {
  let secretName: RegExp
  try {
    secretName = new RegExp(o.secretNames || DEFAULT_SECRET_NAMES, 'i')
  } catch {
    secretName = new RegExp(DEFAULT_SECRET_NAMES, 'i')
  }
  return {
    secretName,
    forbidden: [...BUILTIN_FORBIDDEN, ...globs(o.extraForbiddenPaths ?? '')],
    allowed: globs(o.allowPaths ?? ''),
  }
}

export function isForbiddenPath(path: string, c: Config): boolean {
  const p = path.replace(/^['"]|['"]$/g, '').replace(/\/+$/, '')
  if (p.length === 0) return false
  if (c.allowed.some(r => r.test(p))) return false
  return c.forbidden.some(r => r.test(p))
}

// ---------------------------------------------------------------- shapes

const SHAPES: { name: string; re: RegExp }[] = [
  { name: 'AWS access key', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/g },
  { name: 'Anthropic key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'OpenAI-style key', re: /\bsk-(proj-)?[A-Za-z0-9_-]{32,}/g },
  { name: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'Ex Libris API key', re: /\bl7xx[0-9a-f]{32}\b/g },
  { name: 'private key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  {
    name: 'hard-coded credential',
    re: /\b(api[_-]?key|secret|token|passw(or)?d)\b["']?\s*[:=]\s*["'][^"'\s$<{]{12,}["']/gi,
  },
]

export function findShapes(text: string): string[] {
  const hits: string[] = []
  for (const { name, re } of SHAPES) {
    re.lastIndex = 0
    if (re.test(text)) hits.push(name)
  }
  return hits
}

export function findKnown(text: string, known: readonly Known[]): string[] {
  return known.filter(k => text.includes(k.value)).map(k => k.name)
}

/** Scan any text bound for somewhere it would persist or leave the machine. */
export function scanText(text: string, known: readonly Known[], where: string): Finding[] {
  const out: Finding[] = []
  const names = findKnown(text, known)
  if (names.length > 0) {
    out.push({
      rule: 'secret-value',
      reason: `the value of ${names.join(', ')} would appear in ${where}`,
      hint: 'refer to the variable by name, or pipe it: printenv NAME | cmd --stdin',
    })
  }
  const shapes = findShapes(text)
  if (shapes.length > 0) {
    out.push({
      rule: 'secret-shape',
      reason: `text shaped like a ${shapes.join(', ')} would appear in ${where}`,
      hint: 'use a <placeholder> instead of a real-looking value',
    })
  }
  return out
}

export function redact(text: string, known: readonly Known[]): { text: string; count: number } {
  let count = 0
  let out = text
  // Longest first, so a value that contains another is replaced whole.
  for (const k of [...known].sort((a, b) => b.value.length - a.value.length)) {
    if (out.includes(k.value)) {
      count += out.split(k.value).length - 1
      out = out.split(k.value).join(`[redacted:${k.name}]`)
    }
  }
  for (const { name, re } of SHAPES) {
    if (name === 'hard-coded credential') continue
    re.lastIndex = 0
    out = out.replace(re, () => {
      count += 1
      return `[redacted:${name}]`
    })
  }
  return { text: out, count }
}

// ---------------------------------------------------------------- bash

/** Split into simple commands, keeping the separator that followed each. */
export function segments(command: string): { text: string; then: string }[] {
  const out: { text: string; then: string }[] = []
  const re = /(\|\||&&|\||;|\n)/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(command)) !== null) {
    const sep = m[1] ?? ''
    out.push({ text: command.slice(last, m.index).trim(), then: sep })
    last = m.index + sep.length
  }
  out.push({ text: command.slice(last).trim(), then: '' })
  return out.filter(s => s.text.length > 0)
}

export function words(segment: string): string[] {
  return segment
    .split(/[\s<>()]+/)
    .map(w => w.replace(/^['"]+|['"]+$/g, ''))
    .filter(w => w.length > 0)
}

const READ_VERB =
  /^(cat|head|tail|less|more|bat|batcat|grep|egrep|fgrep|rg|ag|sed|awk|gawk|strings|xxd|od|hexdump|base64|nl|tac|cut|sort|uniq|diff|cmp|cp|mv|scp|rsync|tee|vi|vim|nvim|nano|emacs|code|jq|yq|python|python3|node|ruby|perl|php|curl|wget|zip|tar|gzip)$/

const DUMP = /^(env|printenv|set|export|declare\s+-[px]+|export\s+-p|typeset\s+-[px]+)$/

const SAFE_DUMP_FILTER = /cut\s+-d\s*['"]?=['"]?\s+-f\s*1\b|sed\s+-E?\s*['"]s\/=\.\*|grep\s+-c\b|wc\b/

function isRedactingPipeline(rest: string): boolean {
  return /<redacted>/.test(rest) || SAFE_DUMP_FILTER.test(rest)
}

export function checkBash(command: string, known: readonly Known[], c: Config): Finding[] {
  const out: Finding[] = []
  const segs = segments(command)

  segs.forEach((seg, i) => {
    const w = words(seg.text)
    const verb = w[0] ?? ''
    const rest = segs.slice(i + 1).map(s => s.text).join(' | ')
    const piped = seg.then === '|'

    // 1. reading a secret file
    const paths = w.slice(1).filter(x => isForbiddenPath(x, c))
    if (paths.length > 0 && READ_VERB.test(verb) && !isRedactingPipeline(seg.text + ' ' + rest)) {
      out.push({
        rule: 'secret-file-read',
        reason: `${verb} would print ${paths.join(', ')}, a file that holds secrets`,
        hint: "check for a name only: grep -nE '^export NAME=' FILE | sed -E 's/=.*/=<redacted>/'",
      })
    }

    // 2. dumping the whole environment
    const dumpOf = w.slice(0, 2).join(' ')
    if ((DUMP.test(verb) && w.length === 1) || DUMP.test(dumpOf) && w.length === 2) {
      if (!piped || !isRedactingPipeline(rest)) {
        out.push({
          rule: 'env-dump',
          reason: `${seg.text} would print every variable's value`,
          hint: 'list names only: env | cut -d= -f1 | sort',
        })
      }
    }

    // 3. printenv NAME of a secret, not piped onward
    if (verb === 'printenv' && w.length >= 2 && !piped) {
      const named = w.slice(1).filter(n => c.secretName.test(n))
      if (named.length > 0) {
        out.push({
          rule: 'printenv-secret',
          reason: `printenv ${named.join(' ')} would print the value`,
          hint: 'compare digests instead: printenv NAME | sha256sum | cut -c1-12',
        })
      }
    }

    // 4. expanding a secret variable
    const refs = [...seg.text.matchAll(/\$\{?(#?)([A-Za-z_][A-Za-z0-9_]*)(\}|:[+\-=0]|[-=]|)?/g)]
    for (const r of refs) {
      const [whole, hash, name = '', after] = r
      if (!c.secretName.test(name) || hash === '#') continue
      if (after === ':+' || after === ':0') continue
      if (after === ':-' || after === '-' || after === ':=' || after === '=') {
        out.push({
          rule: 'default-expansion',
          reason: `${whole}… expands to the value of ${name} when it is set`,
          hint: 'test presence with ${NAME:+set} or length with ${#NAME}',
        })
        continue
      }
      const before = seg.text.slice(0, r.index)
      if (/<<<\s*["']?$/.test(before)) continue
      if (/(\[\[?|test)\s+-[nz]\s+["']?$/.test(before)) continue
      if (/^(export|local|declare|readonly|typeset)\b/.test(verb) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(verb)) {
        continue
      }
      if (/^(echo|printf|print)$/.test(verb)) {
        out.push({
          rule: 'echo-secret',
          reason: `${verb} would print the value of ${name}`,
          hint: 'show presence only: [ -n "$NAME" ] && echo set || echo unset',
        })
      } else {
        out.push({
          rule: 'secret-on-argv',
          reason: `${verb} would receive the value of ${name} on its command line (visible in ps and logs)`,
          hint: 'pass it on stdin: printenv NAME | cmd --stdin, or cmd <<< "$NAME"',
        })
      }
    }

    // 5. staging a secret file
    if (verb === 'git' && w.includes('add')) {
      const staged = w.slice(w.indexOf('add') + 1).filter(x => !x.startsWith('-') && isForbiddenPath(x, c))
      if (staged.length > 0) {
        out.push({
          rule: 'git-add-secret-file',
          reason: `git add would stage ${staged.join(', ')}, a file that holds secrets`,
        })
      }
    }
  })

  out.push(...scanText(command, known, 'the command'))
  return dedupe(out)
}

export function dedupe(list: Finding[]): Finding[] {
  const seen = new Set<string>()
  return list.filter(f => {
    const k = f.rule + '|' + f.reason
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
}

/** Only the added lines of a unified diff, skipping file headers. */
export function addedLines(diff: string): string {
  return diff
    .split('\n')
    .filter(l => l.startsWith('+') && !l.startsWith('+++'))
    .map(l => l.slice(1))
    .join('\n')
}

// ---------------------------------------------------------------- git / gh shapes

export type GitIntent =
  | { kind: 'add-all'; cwd?: string }
  | { kind: 'commit'; cwd?: string; all: boolean }
  | { kind: 'push'; cwd?: string }
  | { kind: 'gh'; files: string[] }

export function gitIntents(command: string): GitIntent[] {
  const out: GitIntent[] = []
  let cwd: string | undefined
  for (const seg of segments(command)) {
    const w = words(seg.text)
    if (w[0] === 'cd' && w[1]) cwd = w[1]
    if (w[0] === 'git') {
      let i = 1
      let here = cwd
      while (i < w.length && (w[i] ?? '').startsWith('-')) {
        if (w[i] === '-C') {
          here = w[i + 1]
          i += 2
        } else if (w[i] === '-c') {
          i += 2
        } else i += 1
      }
      const sub = w[i]
      const args = w.slice(i + 1)
      if (sub === 'add' && args.some(a => a === '-A' || a === '--all' || a === '.' || a === '-u' || a === '--update')) {
        out.push({ kind: 'add-all', cwd: here })
      }
      if (sub === 'commit') {
        const all = args.some(a => a === '--all' || /^-[a-zA-Z]*a[a-zA-Z]*$/.test(a))
        out.push({ kind: 'commit', cwd: here, all })
      }
      if (sub === 'push') out.push({ kind: 'push', cwd: here })
    }
    if (w[0] === 'gh') {
      const files: string[] = []
      w.forEach((x, j) => {
        const nextWord = w[j + 1]
        if (/^(--body-file|-F|--notes-file|--input)$/.test(x) && nextWord) files.push(nextWord)
        const eq = /^(--body-file|--notes-file|--input)=(.+)$/.exec(x)
        if (eq?.[2]) files.push(eq[2])
      })
      if (w[1] === 'gist' && w[2] === 'create') {
        files.push(...w.slice(3).filter(x => !x.startsWith('-')))
      }
      out.push({ kind: 'gh', files })
    }
  }
  return out
}
