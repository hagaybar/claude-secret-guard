import { describe, expect, mock, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On } from 'claude-code'

// Fake values only: nothing here is a real credential.
const FAKE_VALUE = 'fake-value-for-tests-0123456789'
const FAKE_ALMA = 'l7xx' + '0123456789abcdef0123456789abcdef'

const BAND = {
  plugin: 'secret-guard',
  component: 'AbovePrompt',
  props: {
    hasSurvey: false,
    isWorking: false,
    maxRows: 12,
    bodyColumns: 90,
    scroll: { offset: 0, bodyRows: 11 },
    view: {},
  },
} as const

/** The world beneath the plugin: env, git, cwd, and a tool that just runs. */
function world(on: On, git: Record<string, string> = {}): string[] {
  const ran: string[] = []
  mock.clock(on)
  mock.store(on)
  on('session.cwd', () => ({ value: '/repo' }))
  on('process.run', ($, e) => {
    const argv = e.argv
    if (argv[0] === 'env') {
      return { value: { exitCode: 0, stdout: `HOME=/home/x\u0000FAKE_API_KEY=${FAKE_VALUE}\u0000SHORT_TOKEN=abc\u0000`, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
    }
    const key = argv.slice(3).join(' ')
    return { value: { exitCode: 0, stdout: git[key] ?? '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
  })
  on('tool.call', ($, e) => {
    ran.push(e.tool)
    return { result: 'ran' } as never
  })
  return ran
}

async function call($: Engine, input: Record<string, unknown>): Promise<{ deny?: string }> {
  return (await $.tool.call(input as never)) as { deny?: string }
}

describe('bash', () => {
  test('blocks echoing a secret variable, without naming its value', async ($, on) => {
    world(on)
    const r = await call($, { tool: 'Bash', command: 'echo "$FAKE_API_KEY"' })
    expect(r.deny).toBeDefined()
    expect(String(r.deny)).toContain('echo-secret')
    expect(String(r.deny).includes(FAKE_VALUE)).toBe(false)
  })

  test('allows the safe presence checks', async ($, on) => {
    const ran = world(on)
    for (const command of [
      '[ -n "$FAKE_API_KEY" ] && echo set || echo unset',
      'echo "${FAKE_API_KEY:+set}" ${#FAKE_API_KEY}',
      'printenv FAKE_API_KEY | sha256sum | cut -c1-12',
      'env | cut -d= -f1 | sort',
      "grep -nE '^export FAKE_API_KEY=' ~/.bashrc | sed -E 's/=.*/=<redacted>/'",
    ]) {
      const r = await call($, { tool: 'Bash', command })
      expect(r.deny).toBeUndefined()
    }
    expect(ran).toHaveLength(5)
  })

  test('blocks reading a shell rc file, a default expansion and an env dump', async ($, on) => {
    world(on)
    for (const [command, rule] of [
      ['cat ~/.bashrc', 'secret-file-read'],
      ['echo ${FAKE_API_KEY:-none}', 'default-expansion'],
      ['env', 'env-dump'],
      ['printenv FAKE_API_KEY', 'printenv-secret'],
      ['curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com', 'secret-on-argv'],
      ['git add .env', 'git-add-secret-file'],
    ]) {
      const r = await call($, { tool: 'Bash', command })
      expect(String(r.deny)).toContain(rule)
    }
  })
})

test('does not mistake a bare word like a topic tag for a secrets folder', async ($, on) => {
  world(on)
  const r = await call($, { tool: 'Bash', command: 'gh repo edit o/r --add-topic secrets --add-topic credentials' })
  expect(r.deny).toBeUndefined()
  expect((await call($, { tool: 'Bash', command: 'cat secrets/prod.txt' })).deny).toBeDefined()
})

describe('files', () => {
  test('blocks Read of .env but not .env.example', async ($, on) => {
    world(on)
    expect((await call($, { tool: 'Read', file_path: '/repo/.env' })).deny).toBeDefined()
    expect((await call($, { tool: 'Read', file_path: '/repo/.env.example' })).deny).toBeUndefined()
  })

  test('blocks writing a known secret value into a file', async ($, on) => {
    world(on)
    const r = await call($, { tool: 'Write', file_path: '/repo/config.py', content: `KEY = "${FAKE_VALUE}"` })
    expect(String(r.deny)).toContain('FAKE_API_KEY')
    expect(String(r.deny).includes(FAKE_VALUE)).toBe(false)
  })
})

describe('git and GitHub', () => {
  test('blocks a gh issue whose body holds a secret-shaped key', async ($, on) => {
    world(on)
    const r = await call($, { tool: 'Bash', command: `gh issue create --title x --body "key is ${FAKE_ALMA}"` })
    expect(String(r.deny)).toContain('Ex Libris API key')
  })

  test('blocks a commit whose staged diff adds a secret', async ($, on) => {
    world(on, {
      'diff --cached --name-only': 'src/app.py\n',
      'diff --cached --no-color -U0': `+++ b/src/app.py\n+TOKEN = "${FAKE_VALUE}"\n`,
    })
    const r = await call($, { tool: 'Bash', command: 'git commit -m "add client"' })
    expect(String(r.deny)).toContain('commit:secret-value')
  })

  test('blocks a push whose outgoing commits add a secret', async ($, on) => {
    world(on, { 'log -p --no-color --format= HEAD --not --remotes': `+x = "${FAKE_ALMA}"\n` })
    const r = await call($, { tool: 'Bash', command: 'git push origin dev' })
    expect(String(r.deny)).toContain('push:secret-shape')
  })

  test('lets a clean commit through', async ($, on) => {
    const ran = world(on, { 'diff --cached --no-color -U0': '+print("hello")\n' })
    const r = await call($, { tool: 'Bash', command: 'git commit -m "hello"' })
    expect(r.deny).toBeUndefined()
    expect(ran).toEqual(['Bash'])
  })

  test('blocks an outbound MCP call carrying a secret value', async ($, on) => {
    world(on)
    const r = await call($, { tool: 'mcp__github__create_issue', body: `token ${FAKE_VALUE}` })
    expect(String(r.deny)).toContain('secret-value')
  })
})

describe('config', () => {
  test('warn mode flags but lets the call run', { options: { mode: 'warn' } }, async ($, on) => {
    const ran = world(on)
    const r = await call($, { tool: 'Bash', command: 'echo $FAKE_API_KEY' })
    expect(r.deny).toBeUndefined()
    expect(ran).toEqual(['Bash'])
  })

  test('extra forbidden paths are honoured', { options: { extraForbiddenPaths: 'config/prod.yaml' } }, async ($, on) => {
    world(on)
    expect((await call($, { tool: 'Read', file_path: '/repo/config/prod.yaml' })).deny).toBeDefined()
  })
})

describe('banner', () => {
  test('shows the guard is on, on every surface that draws the band', async ($, on) => {
    world(on)
    for (const surface of ['terminal', 'desktop'] as const) {
      const ui = await $.ui.mount({ ...BAND, surface })
      expect(await ui.find({ text: /SECRET GUARD/ })).toBeDefined()
      await ui.unmount()
    }
  })

  test('shows the last block', async ($, on) => {
    world(on)
    await call($, { tool: 'Bash', command: 'cat ~/.bashrc' })
    const ui = await $.ui.mount({ ...BAND, surface: 'terminal' })
    expect(await ui.find({ text: /last: blocked/ })).toBeDefined()
    await ui.unmount()
  })
})

describe('redaction', () => {
  test('scrubs a known value before a row is stored', async ($, on) => {
    world(on)
    const stored: string[] = []
    on('session.append', ($, e) => {
      stored.push(JSON.stringify(e.message.content))
      return { value: { message: e.message, uuid: 'row-1' } } as never
    })
    // Nothing beneath the test stores rows, so the call itself rejects; what
    // matters is the row the guard handed down.
    await $.session
      .append({ message: { type: 'user', content: [{ type: 'text', text: `output: ${FAKE_VALUE}` }] } } as never)
      .catch(() => undefined)
    expect(stored).toHaveLength(1)
    expect(String(stored[0]).includes(FAKE_VALUE)).toBe(false)
    expect(String(stored[0])).toContain('[redacted:FAKE_API_KEY]')
  })
})
