export type GuardEvent = {
  /** 'blocked' refused the call; 'warned' let it run (warn mode); 'redacted' scrubbed stored text. */
  kind: 'blocked' | 'warned' | 'redacted'
  rule: string
  /** What was at risk, never the secret itself. */
  reason: string
  tool: string
  at: number
}

declare module 'claude-code' {
  interface PluginState {
    'secret-guard': { events: GuardEvent[]; knownCount: number; isCompact: boolean }
  }
}
