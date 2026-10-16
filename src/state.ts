import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * What survives a restart, in the data volume. The token has its own file because `lesha-vpn-gw login`
 * writes it from a second process while the daemon owns state.json.
 */
export interface PersistentState {
  user?: { tgId: number, username: string | null }
  /** Our config on the coordinator and the last `.conf` we got for it. */
  config?: { id: string, name: string, revision: string, awg: string }
  /** Set when the coordinator revoked our config: we don't issue a new one on our own. */
  configRevoked?: boolean
  /** Last known IPv4 addresses of the coordinator API, used when DNS is unreachable. */
  apiAddrs?: string[]
}

export class Store {
  constructor(private dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
  }

  private path(name: string) {
    return join(this.dir, name)
  }

  readToken(): string | null {
    try {
      return readFileSync(this.path('token'), 'utf8').trim() || null
    } catch {
      return null
    }
  }

  writeToken(token: string) {
    atomicWrite(this.path('token'), `${token}\n`)
  }

  clearToken() {
    rmSync(this.path('token'), { force: true })
  }

  read(): PersistentState {
    try {
      return JSON.parse(readFileSync(this.path('state.json'), 'utf8')) as PersistentState
    } catch {
      return {}
    }
  }

  write(state: PersistentState) {
    atomicWrite(this.path('state.json'), `${JSON.stringify(state, null, 2)}\n`)
  }

  update(fn: (s: PersistentState) => void): PersistentState {
    const s = this.read()
    fn(s)
    this.write(s)
    return s
  }
}

export function atomicWrite(path: string, content: string, mode = 0o600) {
  const tmp = `${path}.tmp-${process.pid}`
  writeFileSync(tmp, content, { mode })
  chmodSync(tmp, mode)
  renameSync(tmp, path)
}
