# 🛡 secret-guard

**A Claude Code mod that keeps API keys, tokens and passwords out of the agent's reach —
enforced by code on your machine, not by instructions in a prompt.**

It watches every tool call Claude makes and every row written to the conversation, and
refuses (or flags) anything that would print, store, commit, push or send a secret.

📖 **[See how it decides — interactive flow diagram](https://hagaybar.github.io/claude-secret-guard/)**

---

> ### ⚠️ First draft — read this before relying on it
>
> This is a first attempt at making secret handling *local and rigorous by code*, not by
> prompt. Instructions in a `CLAUDE.md` ask the model to behave; a hook runs on every tool
> call whether the model remembers the instruction or not. This mod moves those rules into
> code that runs on this machine.
>
> It is **best effort, not a guarantee**:
> - The checks are pattern lists (file paths, command shapes, token formats). A command
>   written in a form they don't anticipate — an alias, a script file, `eval`, unusual
>   quoting — can get past them.
> - Secret *values* are recognised only for environment variables whose names match
>   `secretNames`, and only those present when the session started.
> - Secret-shaped strings are recognised only for the token formats listed below.
> - Nothing it does can remove a value that already reached a transcript, a commit or a
>   remote. **If a secret leaks, rotate it.**
>
> Treat it as a seatbelt alongside careful habits, not as a replacement for them.
> Bypass reports and ideas are welcome as [issues](https://github.com/hagaybar/claude-secret-guard/issues).

---

## Why

An agent with a shell can leak a secret in many small ways: `cat ~/.bashrc` to "check a
variable", `echo $API_KEY` to debug, `${TOKEN:-default}` in a test, a key pasted into a
config file, a commit, a PR body. Each lands in the transcript, and once there it cannot be
scrubbed — the only fix is rotating the key.

The usual defence is a rule in the prompt. Prompts are advice: they can be forgotten,
summarised away, or out-argued. secret-guard turns the same rules into
Claude Code function hooks that run on every
call, locally, before anything executes.

## What it does

| Layer | When | What happens |
| --- | --- | --- |
| **Know** | Session start | Reads the environment once and keeps the *values* of variables whose names look secret (`…_KEY`, `…_TOKEN`, `SECRET`, `PASSWORD`, `AUTH`, …). In memory only — never displayed, logged or stored. |
| **Guard** | Before every tool call | Inspects what the call would do. A risk → **block** (or **flag** in warn mode) with the reason and a safe alternative. No risk → it runs. |
| **Scrub** | Before every row is stored | Replaces known values and token-shaped strings in tool output, replies and prompts with `[redacted:NAME]`. |
| **Show** | Always | A banner above the prompt, a status-line entry, a toast per event, a note on each blocked call, and `/guard`. |

### What gets blocked

| Rule | Stops | Do this instead |
| --- | --- | --- |
| `secret-file-read` | `cat` / `grep` / `sed` / `cp` / … or **Read** on `.bashrc`, `.zshrc`, `.profile`, `.env*`, `~/.aws/*`, `.netrc`, `secrets/`, `credentials/`, `.ssh/`, `.gnupg/`, `.psst/` | `grep -nE '^export NAME=' FILE \| sed -E 's/=.*/=<redacted>/'` |
| `secret-file-write` | **Write** over a secret file | Hand the user the line with a `<placeholder>` |
| `env-dump` | `env`, `printenv`, `set`, `export -p` printing values | `env \| cut -d= -f1 \| sort` |
| `printenv-secret` | `printenv API_KEY` to the screen | `printenv API_KEY \| sha256sum \| cut -c1-12` |
| `echo-secret` | `echo $API_KEY` | `[ -n "$API_KEY" ] && echo set`, `${API_KEY:+set}`, `${#API_KEY}` |
| `default-expansion` | `${API_KEY:-x}`, `${API_KEY:=x}` (they expand to the value) | `${API_KEY:+set}` |
| `secret-on-argv` | `curl -H "Authorization: Bearer $TOKEN"` (visible in `ps` and logs) | `printenv TOKEN \| cmd --stdin`, `cmd <<< "$TOKEN"` |
| `git-add-secret-file` | Staging a secret file, explicitly or through `git add -A` / `.` | — |
| `commit:*` | A commit whose staged diff adds a known value or a token shape | — |
| `push:*` | A push of commits (not yet on any remote) that add one | — |
| `gh:*` | `gh pr` / `issue` / `release` / `gist` text or body files holding one | — |
| `secret-value` | A real value anywhere in a command, a file write, or any tool's input (MCP tools included) | Refer to the variable by name |
| `secret-shape` | A string that looks like a token, even an unknown one | Use a `<placeholder>` |

**Token shapes recognised:** AWS access keys · GitHub tokens and fine-grained PATs ·
Anthropic keys · OpenAI-style keys · Slack tokens · Google API keys · Ex Libris (Alma) API
keys · PEM private-key headers · JWTs · `password = "…"`-style hard-coded credentials.

### What it looks like

When Claude tries `echo "$ALMA_API_KEY"`, the call never runs. Claude receives:

```
secret-guard blocked this Bash call because it could expose a secret:
- [echo-secret] echo would print the value of ALMA_API_KEY
  (instead: show presence only: [ -n "$NAME" ] && echo set || echo unset)
Do not retry it in another form. If the user needs the value checked, let them do it in their own terminal.
```

and you see a toast, a note on the call, and the banner above the prompt:

```
╭──────────────────────────────────────────────────────────────────╮
│ 🛡  SECRET GUARD  ON   mode BLOCK                             [–] │
│ watching: secret files · env · echo/argv · writes · outbound …   │
│ 12 secret vars known · 1 blocked · 0 flagged · 0 redacted        │
│ last: blocked Bash — echo would print the value of ALMA_API_KEY  │
╰──────────────────────────────────────────────────────────────────╯
```

## Install

In a Claude Code terminal session:

```
/plugin install secret-guard --marketplace hagaybar/claude-secret-guard
```

Answer `y` to add the marketplace, then choose the **user** scope so it loads in every
session. Requires a Claude Code build with function-hook mods; tested on 2.1.291.

To work on it locally instead:

```
git clone https://github.com/hagaybar/claude-secret-guard ~/claude-mods/secret-guard
claude plugin marketplace add ~/claude-mods/secret-guard
claude plugin install secret-guard@hagay-mods --scope user
```

Edits to that folder take effect with `/reload-plugins`.

## Use

| Command | Does |
| --- | --- |
| `/guard` | Status: mode, secret variables known (count only), this session's blocks / flags / redactions |
| `/guard log` | The last 20 events across sessions |
| `/guard block` · `/guard warn` | Refuse risky calls, or let them run and only declare them |
| `/guard full` · `/guard compact` · `/guard off` | Banner style |

## Settings

All in `/config` (or `/plugin configure secret-guard@hagay-mods`):

| Setting | Default | Meaning |
| --- | --- | --- |
| `mode` | `block` | `block` refuses a risky call; `warn` runs it and declares it |
| `banner` | `full` | `full`, `compact` or `off` |
| `secretNames` | `(^\|_)(KEY\|APIKEY\|TOKEN\|SECRET\|PASSWORD\|PASSWD\|PASSPHRASE\|CREDENTIALS?\|AUTH)(_\|$)` | Regex (case-insensitive) for variable names whose values are secrets |
| `extraForbiddenPaths` | *(empty)* | Comma-separated globs added to the built-in list, e.g. `config/prod.yaml,**/*.pem` |
| `allowPaths` | `.env.example,.env.sample,.env.template` | Globs never treated as secret files |
| `redactOutput` | `true` | Scrub values and token shapes from stored rows |
| `guardGit` | `true` | Scan staged changes, outgoing commits and `gh` bodies |
| `loadEnvValues` | `true` | Learn real values at session start (in memory only) |

## How it works

Three hooks do the work (see the **[flow diagram](https://hagaybar.github.io/claude-secret-guard/)**):

- **`session.start`** — runs `env` once through Claude Code's process API, keeps matching
  values in a module variable, registers `/guard`.
- **`tool.call`** — routes by tool: **Bash** gets the shell rules plus a scan of the
  command, and for `git add` / `commit` / `push` / `gh` it runs `git status`, `git diff
  --cached` or `git log … --not --remotes` and scans the *added lines*. **Read** / **Write**
  / **Edit** check the path and the new content. **Every other tool** (MCP, WebFetch,
  Agent, …) has all its text inputs scanned. The hook has a `.catch` that **fails closed**
  in block mode: if the check itself crashes, the call is held back (`/guard warn` is the
  escape hatch).
- **`session.append`** — rewrites text and tool-result blocks before they are stored.

The display is a `ui.render` hook on the band above the prompt, plus `$.ui.status`,
`$.ui.toast` and `$.ui.notice`.

### Files

```
.claude-plugin/plugin.json        manifest + userConfig settings
.claude-plugin/marketplace.json   makes this repo installable
hooks/hooks.json                  points at the hooks module
hooks/register.tsx                the hooks: start, tool.call, append, /guard, banner
hooks/rules.ts                    pure detection logic (no engine calls) — the rules live here
types/index.d.ts                  the mod's state contract
tests/guard.test.ts               15 behaviour tests (fake values only)
docs/index.html                   the flow diagram (GitHub Pages)
```

## Develop

```
claude plugin validate .
claude plugin test .
```

The tests cover each rule family, warn mode, extra forbidden paths, the banner on terminal
and desktop surfaces, and redaction. They use fake values only.

To add a token format, add an entry to `SHAPES` in `hooks/rules.ts` and a test.

## Known gaps

- Commands in forms the patterns don't anticipate (aliases, script files, `eval`, unusual
  quoting) can pass.
- Only variables present at session start, with secret-looking names, are known by value.
- Git checks run in the session folder, or one named by a leading `cd` / `git -C`. In a
  single command like `git add x && git commit`, the commit is checked against what was
  staged *before* the command ran.
- Redaction can't reach anything already stored, committed or pushed.
- Reading the environment means the values sit in the mod's memory for the session. They
  never leave it, but turn `loadEnvValues` off if you'd rather they weren't read at all
  (token-shape detection still works).

## Background

Built while working on Ex Libris Alma integrations at Tel Aviv University Libraries, after
seeing how many quiet paths can carry a key into an agent transcript. The rules mirror a "strict secret-handling mode" that had been living in a
`CLAUDE.md` — this is the attempt to make them hold without depending on the model
remembering them.
