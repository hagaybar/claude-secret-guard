# secret-guard

A Claude Code mod that keeps API keys, tokens and passwords out of the agent's context,
tool output, files, commits, pushes, PRs and issues.

## What it does

- **Blocks risky calls** (or only flags them, in `warn` mode):
  - reading secret files: `~/.bashrc`, `.env*`, `~/.aws/credentials`, `~/.netrc`, `secrets/`, `.ssh/`, …
  - dumping the environment (`env`, `printenv`, `set`), unless piped to a names-only filter
  - `echo $SECRET`, `${SECRET:-default}` expansions, `printenv SECRET` to stdout, a secret on a command line
  - writing a known secret value or a secret-shaped string into any file
  - `git add` of secret files, `git commit` whose staged diff adds a secret, `git push` of such commits
  - `gh` PR/issue/release/gist bodies and body files holding a secret
  - any other tool call (MCP included) whose input carries a secret
- **Redacts** secret values and secret-shaped strings from every row before it is stored.
- **Shows it is on**: a banner above the prompt, a status-line entry, and a toast on each block.
- `/guard` shows status · `/guard log` shows history · `/guard block|warn` · `/guard full|compact|off`.

Real secret values are read once from the session's environment (variable names matching
`secretNames`), held in memory only, and never displayed, logged or stored.

## Install

```
/plugin install secret-guard --marketplace hagaybar/claude-secret-guard
```

Answer `y` to add the marketplace, then choose the user scope.

## Settings

Change them in `/config`: `mode` (block|warn), `banner` (full|compact|off), `secretNames` (regex),
`extraForbiddenPaths` and `allowPaths` (comma-separated globs), `redactOutput`, `guardGit`,
`loadEnvValues`.

## Develop

```
claude plugin validate .
claude plugin test .
```

Tests use fake values only.
