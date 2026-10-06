import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { GuardEvent } from '../types'
import {
  addedLines,
  checkBash,
  dedupe,
  gitIntents,
  isForbiddenPath,
  makeConfig,
  redact,
  scanText,
} from './rules'
import type { Finding, GitIntent, Known } from './rules'

type $ = EngineInterface

const events = atom({ plugin: 'secret-guard', key: 'events' } as const, [] as GuardEvent[])
const knownCount = atom({ plugin: 'secret-guard', key: 'knownCount' } as const, 0)
const isCompact = atom({ plugin: 'secret-guard', key: 'isCompact' } as const, false)

const SHIELD = '\u{1F6E1}'
const LOG_KEY = 'log'

type Settings = {
  mode: 'block' | 'warn'
  banner: string
  redactOutput: boolean
  guardGit: boolean
  loadEnvValues: boolean
  cfg: ReturnType<typeof makeConfig>
}

let S: Settings = settingsOf({})
// The real values live in this module's memory only: never in state, the
// store, a log line, a toast or anything the model reads.
let known: Known[] = []
let loading: Promise<void> | undefined

function settingsOf(options: Record<string, unknown>): Settings {
  return {
    mode: options.mode === 'warn' ? 'warn' : 'block',
    banner: String(options.banner ?? 'full'),
    redactOutput: options.redactOutput !== false,
    guardGit: options.guardGit !== false,
    loadEnvValues: options.loadEnvValues !== false,
    cfg: makeConfig({
      secretNames: String(options.secretNames ?? ''),
      extraForbiddenPaths: String(options.extraForbiddenPaths ?? ''),
      allowPaths: String(options.allowPaths ?? ''),
    }),
  }
}

async function loadKnown($: $): Promise<void> {
  if (!S.loadEnvValues) return
  let run = await $.process.run(['env', '-0'])
  let sep = '\u0000'
  if (run.exitCode !== 0) {
    run = await $.process.run(['env'])
    sep = '\n'
  }
  known = run.stdout
    .split(sep)
    .map(line => {
      const at = line.indexOf('=')
      return { name: line.slice(0, at), value: line.slice(at + 1) }
    })
    .filter(k => k.name.length > 0 && S.cfg.secretName.test(k.name))
    .filter(k => k.value.length >= 8 && !k.value.startsWith('/'))
  await update($, knownCount, () => known.length)
}

function ready($: $): Promise<void> {
  loading ??= loadKnown($).catch(() => undefined)
  return loading
}

async function record($: $, event: Omit<GuardEvent, 'at'>): Promise<void> {
  const full: GuardEvent = { ...event, at: await $.clock.now() }
  const list = await update($, events, all => [...all, full].slice(-50))
  const blocked = list.filter(x => x.kind === 'blocked').length
  $.ui.status(`${SHIELD} guard on · ${blocked} blocked`)
  const verb = event.kind === 'blocked' ? 'blocked' : event.kind === 'warned' ? 'flagged' : 'redacted'
  $.ui.toast(`${SHIELD} secret-guard ${verb} ${event.tool}: ${event.reason}`, { timeoutMs: 8000 })
  const log = ((await $.store.get(LOG_KEY)) as GuardEvent[] | undefined) ?? []
  await $.store.set(LOG_KEY, [...log, full].slice(-200))
}

// -------------------------------------------------------------- inspection

function strings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value)
  else if (Array.isArray(value)) value.forEach(v => strings(v, out))
  else if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (k !== 'tool' && k !== 'tool_use_id' && k !== 'consent') strings(v, out)
    }
  }
  return out
}

function within(base: string, dir: string | undefined): string {
  if (dir === undefined || dir.startsWith('~')) return base
  return dir.startsWith('/') ? dir : `${base}/${dir}`
}

async function git($: $, cwd: string, args: string[]): Promise<string> {
  const run = await $.process.run(['git', '-C', cwd, ...args], { timeoutMs: 20000 })
  return run.exitCode === 0 ? run.stdout : ''
}

function tagged(list: Finding[], tag: string): Finding[] {
  return list.map(f => ({ ...f, rule: `${tag}:${f.rule}` }))
}

async function checkGit($: $, intent: GitIntent, base: string): Promise<Finding[]> {
  const cfg = S.cfg
  if (intent.kind === 'gh') {
    const out: Finding[] = []
    for (const file of intent.files) {
      if (isForbiddenPath(file, cfg)) {
        out.push({ rule: 'gh:secret-file', reason: `gh would upload ${file}, a file that holds secrets` })
        continue
      }
      const text = await $.fs.read(file).catch(() => undefined)
      if (typeof text === 'string') out.push(...tagged(scanText(text, known, `the GitHub text from ${file}`), 'gh'))
    }
    return out
  }

  const cwd = within(base, intent.cwd)
  if (intent.kind === 'add-all') {
    const status = await git($, cwd, ['status', '--porcelain', '--untracked-files=all'])
    const files = status
      .split('\n')
      .filter(l => l.length > 3)
      .map(l => l.slice(3).split(' -> ').pop() ?? '')
      .filter(p => isForbiddenPath(p, cfg))
    return files.length === 0
      ? []
      : [{ rule: 'git-add-secret-file', reason: `git add would stage ${files.join(', ')}, files that hold secrets` }]
  }

  if (intent.kind === 'commit') {
    const range = intent.all ? ['HEAD'] : ['--cached']
    const names = (await git($, cwd, ['diff', ...range, '--name-only']))
      .split('\n')
      .filter(p => p.length > 0 && isForbiddenPath(p, cfg))
    const diff = await git($, cwd, ['diff', ...range, '--no-color', '-U0'])
    const out = tagged(scanText(addedLines(diff), known, 'the commit'), 'commit')
    if (names.length > 0) {
      out.push({ rule: 'commit:secret-file', reason: `the commit would include ${names.join(', ')}` })
    }
    return out
  }

  // push: every commit not yet on any remote
  const log = await git($, cwd, ['log', '-p', '--no-color', '--format=', 'HEAD', '--not', '--remotes'])
  return tagged(scanText(addedLines(log), known, 'the pushed commits'), 'push')
}

async function inspect($: $, e: { tool: string } & Record<string, unknown>): Promise<Finding[]> {
  const cfg = S.cfg
  const tool = e.tool
  const path = typeof e.file_path === 'string' ? e.file_path : typeof e.notebook_path === 'string' ? e.notebook_path : ''

  if (tool === 'Bash' && typeof e.command === 'string') {
    const out = checkBash(e.command, known, cfg)
    if (S.guardGit) {
      const base = await $.session.cwd()
      for (const intent of gitIntents(e.command)) out.push(...(await checkGit($, intent, base)))
    }
    return dedupe(out)
  }
  if (tool === 'Read' && isForbiddenPath(path, cfg)) {
    return [{ rule: 'secret-file-read', reason: `Read would load ${path}, a file that holds secrets`, hint: 'ask the user to check it in their own terminal' }]
  }
  if (tool === 'Write' && isForbiddenPath(path, cfg)) {
    return [{ rule: 'secret-file-write', reason: `Write would overwrite ${path}, a file that holds secrets`, hint: 'give the user the line to add, with a <placeholder> for the value' }]
  }
  if ((tool === 'Edit' || tool === 'NotebookEdit') && isForbiddenPath(path, cfg)) {
    // Structural edits of a secrets file are allowed; carrying a value is not.
    return scanText(strings([e.old_string, e.new_string]).join('\n'), known, `an edit of ${path}`)
  }
  if (tool === 'Write' || tool === 'Edit' || tool === 'NotebookEdit') {
    const text = strings([e.content, e.new_string, e.new_source]).join('\n')
    return scanText(text, known, `the file ${path}`)
  }
  return scanText(strings(e).join('\n'), known, `a call to ${tool}`)
}

function explain(findings: Finding[]): string {
  return findings.map(f => `- [${f.rule}] ${f.reason}${f.hint ? ` (instead: ${f.hint})` : ''}`).join('\n')
}

export const register: Register = (on, options) => {
  S = settingsOf(options)
  loading = undefined
  const { mode, banner, redactOutput, guardGit } = S

  // ------------------------------------------------------------ hooks

  on('session.start', async ($, e, next) => {
    await ready($)
    await $.command.register({
      name: 'guard',
      description: 'Secret guard: status, log, or set mode (block|warn) and banner (full|compact|off)',
      argumentHint: '[log | block | warn | full | compact | off]',
    })
    $.ui.status(`${SHIELD} guard on · ${mode}`)
    if (banner === 'off') $.ui.toast(`${SHIELD} Secret guard is on (${mode} mode)`)
    return next(e)
  })

  on('tool.call', async ($, e, next) => {
    await ready($)
    const findings = await inspect($, e as unknown as { tool: string } & Record<string, unknown>)
    if (findings.length === 0) return next(e)

    const reason = findings.map(f => f.reason).join('; ')
    const rule = findings.map(f => f.rule).join(', ')
    if (mode === 'warn') {
      await record($, { kind: 'warned', rule, reason, tool: e.tool })
      if (e.tool_use_id) $.ui.notice(e.tool_use_id, `${SHIELD} secret-guard flagged: ${reason}`)
      return next(e)
    }
    await record($, { kind: 'blocked', rule, reason, tool: e.tool })
    if (e.tool_use_id) $.ui.notice(e.tool_use_id, `${SHIELD} secret-guard blocked this call`)
    return {
      deny:
        `secret-guard blocked this ${e.tool} call because it could expose a secret:\n${explain(findings)}\n` +
        'Do not retry it in another form. If the user needs the value checked, let them do it in their own terminal.',
    }
  }).catch(($, e, next) =>
    next.called || mode === 'warn'
      ? next(e)
      : { deny: 'secret-guard could not check this call, so it was held back. The user can run /guard warn to let calls through.' },
  )

  on('session.append', async ($, e, next) => {
    if (!redactOutput) return next(e)
    await ready($)
    let count = 0
    const scrub = (text: string): string => {
      const r = redact(text, known)
      count += r.count
      return r.text
    }
    const content = e.message.content.map(block => {
      const b = block as unknown as Record<string, unknown>
      if (b.type === 'text' && typeof b.text === 'string') return { ...b, text: scrub(b.text) }
      if (b.type === 'tool_result') {
        const inner = b.content
        if (typeof inner === 'string') return { ...b, content: scrub(inner) }
        if (Array.isArray(inner)) {
          return {
            ...b,
            content: inner.map(c =>
              c && typeof c === 'object' && (c as { type?: string }).type === 'text'
                ? { ...c, text: scrub(String((c as { text?: string }).text ?? '')) }
                : c,
            ),
          }
        }
      }
      return block
    })
    if (count === 0) return next(e)
    await record($, {
      kind: 'redacted',
      rule: 'redact',
      reason: `${count} secret ${count === 1 ? 'value' : 'values'} scrubbed before it was stored`,
      tool: e.door,
    })
    return next({ ...e, message: { ...e.message, content: content as typeof e.message.content } })
  }).catch(($, e, next) => next(e))

  on('command.run', { command: 'guard' }, async ($, e) => {
    const arg = e.args.trim().toLowerCase()
    const rows = await $.config.list()
    const keyOf = (field: string) => rows.find(r => new RegExp(`^secret-guard(@[^.]+)?\\.${field}$`).test(r.key))?.key

    if (arg === 'block' || arg === 'warn' || arg === 'full' || arg === 'compact' || arg === 'off') {
      const field = arg === 'block' || arg === 'warn' ? 'mode' : 'banner'
      const key = keyOf(field)
      if (key === undefined) return { text: `Could not find the ${field} setting; change it in /config.` }
      const set = await $.config.set({ key, value: arg })
      return { text: set.deny ? `Not changed: ${set.deny}` : `Secret guard ${field} is now ${arg}.` }
    }

    if (arg === 'log') {
      const log = ((await $.store.get(LOG_KEY)) as GuardEvent[] | undefined) ?? []
      if (log.length === 0) return { text: 'Secret guard has nothing on record.' }
      const lines = log.slice(-20).map(x => `${new Date(x.at).toISOString().slice(0, 16)}  ${x.kind.padEnd(8)} ${x.tool.padEnd(10)} ${x.reason}`)
      return { text: `Secret guard, last ${lines.length} events (all sessions):\n${lines.join('\n')}` }
    }

    const list = await read($, events)
    const n = (k: GuardEvent['kind']) => list.filter(x => x.kind === k).length
    return {
      text: [
        `${SHIELD} Secret guard is ON, ${mode} mode.`,
        `Secret variables known by name: ${await read($, knownCount)} (values kept in memory only).`,
        `This session: ${n('blocked')} blocked, ${n('warned')} flagged, ${n('redacted')} redacted.`,
        `Watching: secret files, env dumps, echoed/argv secrets, file writes, every outbound tool call${guardGit ? ', git add/commit/push, gh bodies' : ''}${redactOutput ? ', stored output' : ''}.`,
        'Options: /guard log · /guard block|warn · /guard full|compact|off · more in /config.',
      ].join('\n'),
    }
  })

  // ------------------------------------------------------------ banner

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (banner === 'off' || e.props.hasSurvey) return next(e)
    const { Box, Text, Button } = $.ui.resolve(e)
    const list = await read($, events)
    const count = await read($, knownCount)
    const compact = banner === 'compact' || (await read($, isCompact))
    const blocked = list.filter(x => x.kind === 'blocked').length
    const flagged = list.filter(x => x.kind === 'warned').length
    const redacted = list.filter(x => x.kind === 'redacted').length
    const last = list[list.length - 1]
    const accent = mode === 'block' ? 'success' : 'warning'
    const lastColor = last?.kind === 'blocked' ? 'error' : last?.kind === 'warned' ? 'warning' : 'suggestion'
    const width = Math.max(20, e.props.bodyColumns)

    if (compact) {
      return (
        <Box flexDirection="row">
          <Text color={accent} bold>{SHIELD} SECRET GUARD ON</Text>
          <Text dimColor wrap="truncate-end">
            {' '}· {mode} · {blocked} blocked · {redacted} redacted
            {last ? ` · last: ${last.kind} ${last.tool}` : ''}{' '}
          </Text>
          <Button key="expand" plain label="[+]" onPress={() => update($, isCompact, () => false)} />
        </Box>
      )
    }

    return (
      <Box flexDirection="column" borderStyle="round" borderColor={accent} paddingX={1} width={Math.min(width, 100)}>
        <Box flexDirection="row" justifyContent="space-between">
          <Text>
            <Text color={accent} bold>{SHIELD}  SECRET GUARD </Text>
            <Text backgroundColor={accent} color="inverseText" bold> ON </Text>
            <Text dimColor>  mode </Text>
            <Text color={accent} bold>{mode.toUpperCase()}</Text>
          </Text>
          <Button key="compact" plain label="[–]" onPress={() => update($, isCompact, () => true)} />
        </Box>
        <Text dimColor wrap="truncate-end">
          watching: secret files · env · echo/argv · writes · outbound calls{guardGit ? ' · git · gh' : ''}{redactOutput ? ' · output' : ''}
        </Text>
        <Text wrap="truncate-end">
          <Text color="suggestion">{count}</Text><Text dimColor> secret vars known · </Text>
          <Text color={blocked > 0 ? 'error' : undefined} bold={blocked > 0}>{blocked}</Text><Text dimColor> blocked · </Text>
          <Text color={flagged > 0 ? 'warning' : undefined}>{flagged}</Text><Text dimColor> flagged · </Text>
          <Text color={redacted > 0 ? 'suggestion' : undefined}>{redacted}</Text><Text dimColor> redacted</Text>
        </Text>
        {last ? (
          <Text wrap="truncate-end">
            <Text color={lastColor} bold>last: {last.kind} </Text>
            <Text>{last.tool} </Text>
            <Text dimColor>— {last.reason}</Text>
          </Text>
        ) : (
          <Text dimColor>nothing blocked yet · /guard for status and options</Text>
        )}
      </Box>
    )
  })
}
