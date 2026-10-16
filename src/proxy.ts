import { ChildProcess, spawn } from 'node:child_process'
import { log } from './log'
import type { Settings } from './settings'

/** gost arguments: SOCKS5 and HTTP (CONNECT) listeners; names resolve in the container, so via the tunnel. */
export function gostArgs(s: Pick<Settings, 'socksPort' | 'httpPort' | 'proxyUser' | 'proxyPassword'>): string[] {
  const auth = s.proxyUser && s.proxyPassword
    ? `${encodeURIComponent(s.proxyUser)}:${encodeURIComponent(s.proxyPassword)}@`
    : ''
  const args: string[] = []
  if(s.socksPort) args.push('-L', `socks5://${auth}:${s.socksPort}`)
  if(s.httpPort) args.push('-L', `http://${auth}:${s.httpPort}`)
  return args
}

/** Keeps gost running; the kill-switch, not gost, decides where its traffic may go. */
export class Proxy {
  private child: ChildProcess | null = null
  private stopped = false

  constructor(private settings: Settings) {}

  start() {
    const args = gostArgs(this.settings)
    if(!args.length) {
      log.info('Прокси выключены (SOCKS_PORT=0 и HTTP_PORT=0)')
      return
    }
    const spawnOnce = () => {
      if(this.stopped) return
      const child = spawn('gost', args, { stdio: ['ignore', 'ignore', 'pipe'] })
      this.child = child
      child.stderr?.on('data', d => {
        // gost logs every connection at info; keep only problems
        for(const l of String(d).split('\n')) if(/"level":"(error|fatal)"/.test(l)) log.warn(`gost: ${l}`)
      })
      child.on('exit', code => {
        if(this.stopped) return
        log.error(`gost завершился (код ${code}), перезапускаю`)
        setTimeout(spawnOnce, 2000)
      })
    }
    spawnOnce()
    const parts = [
      this.settings.socksPort ? `SOCKS5 :${this.settings.socksPort}` : null,
      this.settings.httpPort ? `HTTP :${this.settings.httpPort}` : null,
    ].filter(Boolean)
    log.info(`Прокси: ${parts.join(', ')}${this.settings.proxyUser ? ' (с паролем)' : ''}`)
  }

  stop() {
    this.stopped = true
    this.child?.kill('SIGTERM')
  }
}
