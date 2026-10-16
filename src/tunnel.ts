import { ChildProcess, spawn } from 'node:child_process'
import { existsSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { CommandError, run, tryRun } from './exec'
import { FWMARK, IFACE } from './firewall'
import { changeKind, ParsedConf, stripConf } from './conf'
import { log } from './log'

/** Rule priorities: API bypass, then main without its default route, then the tunnel table. */
const PRIO_API = 31000
const PRIO_MAIN = 31999
const PRIO_TUNNEL = 32000
const UAPI_DIR = '/var/run/amneziawg'

export interface TunnelInfo {
  up: boolean
  impl: 'kernel' | 'userspace' | null
  latestHandshake: number | null
  rx: number
  tx: number
  endpoint: string | null
}

/**
 * Owns awg0 and the policy routing around it; does what awg-quick does, minus the parts that need
 * a writable /proc/sys or resolvconf, which a container doesn't have.
 */
export class Tunnel {
  private conf: ParsedConf | null = null
  private impl: 'kernel' | 'userspace' | null = null
  private child: ChildProcess | null = null
  private kernelBroken = false
  /** Called when the userspace process exits on its own. */
  onDied: () => void = () => {}

  constructor(private opts: { runDir: string, preferImpl: 'auto' | 'kernel' | 'userspace' }) {}

  get isUp() {
    return this.conf !== null
  }

  /** Static routing that holds whether or not awg0 exists: with no tunnel, traffic hits a blackhole. */
  async setupRouting(apiAddrs: string[]) {
    await run('ip', ['-4', 'route', 'replace', 'blackhole', 'default', 'metric', '4294967295', 'table', String(FWMARK)])
    await this.replaceRule(['not', 'fwmark', String(FWMARK), 'table', String(FWMARK)], PRIO_TUNNEL)
    await this.replaceRule(['table', 'main', 'suppress_prefixlength', '0'], PRIO_MAIN)
    await this.setApiBypass(apiAddrs)
  }

  /** Docker's plain routing, for the bootstrap DNS lookup; the firewall still holds. */
  async clearRouting() {
    for(const prio of [PRIO_TUNNEL, PRIO_MAIN]) {
      while(await tryRun('ip', ['-4', 'rule', 'del', 'priority', String(prio)])) { /* all */ }
    }
  }

  async setApiBypass(apiAddrs: string[]) {
    while(await tryRun('ip', ['-4', 'rule', 'del', 'priority', String(PRIO_API)])) { /* drop all old ones */ }
    for(const a of apiAddrs) await run('ip', ['-4', 'rule', 'add', 'to', `${a}/32`, 'table', 'main', 'priority', String(PRIO_API)])
  }

  private async replaceRule(args: string[], prio: number) {
    while(await tryRun('ip', ['-4', 'rule', 'del', 'priority', String(prio)])) { /* idempotent */ }
    await run('ip', ['-4', 'rule', 'add', ...args, 'priority', String(prio)])
  }

  /** Bring the tunnel to `next`: peers-only changes go through syncconf, the rest recreates awg0. */
  async apply(next: ParsedConf) {
    if(this.conf && existsSync(`/sys/class/net/${IFACE}`)) {
      const kind = changeKind(this.conf, next)
      if(kind === 'none' || kind === 'dns') {
        this.conf = next
        writeResolvConf(next.dns)
        return
      }
      if(kind === 'peers') {
        await run('awg', ['syncconf', IFACE, this.writeStripped(next)])
        this.conf = next
        writeResolvConf(next.dns)
        log.info('Конфиг обновлён без разрыва (поменялись только пиры)')
        return
      }
      log.info('Поменялись параметры интерфейса, пересоздаю туннель')
    }
    await this.down()
    await this.up(next)
  }

  private async up(conf: ParsedConf) {
    const file = this.writeStripped(conf)
    await this.createLink()
    try {
      await run('awg', ['setconf', IFACE, file])
    } catch(e) {
      // An older amneziawg module on the host may not know AWG 3.1 keys; the userspace one does
      if(this.impl !== 'kernel' || this.opts.preferImpl === 'kernel') throw e
      log.warn(`Модуль ядра amneziawg на хосте не принял конфиг (${(e as Error).message.trim()}), перехожу на amneziawg-go`)
      this.kernelBroken = true
      await this.down()
      await this.createLink()
      await run('awg', ['setconf', IFACE, file])
    }
    for(const a of conf.addresses) await run('ip', ['-4', 'address', 'add', a, 'dev', IFACE])
    await run('ip', ['link', 'set', 'dev', IFACE, 'mtu', String(conf.mtu ?? 1280), 'up'])
    await run('ip', ['-4', 'route', 'replace', 'default', 'dev', IFACE, 'table', String(FWMARK)])
    writeResolvConf(conf.dns)
    this.conf = conf
    log.info(`Туннель поднят (${this.impl === 'kernel' ? 'модуль ядра' : 'amneziawg-go'}), адрес ${conf.addresses.join(', ')}, сервер ${conf.endpoints.join(', ')}`)
  }

  private async createLink() {
    const tryKernel = this.opts.preferImpl === 'kernel' || (this.opts.preferImpl === 'auto' && !this.kernelBroken)
    if(tryKernel && await tryRun('ip', ['link', 'add', IFACE, 'type', 'amneziawg'])) {
      this.impl = 'kernel'
      return
    }
    if(this.opts.preferImpl === 'kernel') throw new Error('AWG_IMPL=kernel, но модуля amneziawg на хосте нет')
    this.impl = 'userspace'
    const sock = join(UAPI_DIR, `${IFACE}.sock`)
    // A socket left by a previous run (container restart) would look like a ready interface
    rmSync(sock, { force: true })
    const child = spawn('amneziawg-go', ['-f', IFACE], { stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, LOG_LEVEL: 'error' } })
    this.child = child
    child.on('exit', code => {
      if(this.child !== child) return
      this.child = null
      if(this.conf) {
        log.error(`amneziawg-go завершился (код ${code})`)
        this.conf = null
        this.onDied()
      }
    })
    for(let i = 0; i < 100 && !existsSync(sock); i++) await sleep(50)
    if(!existsSync(sock)) throw new Error('amneziawg-go не создал интерфейс')
  }

  async down() {
    this.conf = null
    const child = this.child
    this.child = null
    if(child && child.exitCode === null) {
      const exited = new Promise(r => child.once('exit', r))
      child.kill('SIGTERM')
      await Promise.race([exited, sleep(3000)])
    }
    await tryRun('ip', ['link', 'del', IFACE])
  }

  async info(): Promise<TunnelInfo> {
    const base: TunnelInfo = { up: false, impl: this.impl, latestHandshake: null, rx: 0, tx: 0, endpoint: null }
    if(!this.conf) return base
    try {
      // dump: interface line, then per peer: pubkey psk endpoint allowed-ips handshake rx tx keepalive
      const lines = (await run('awg', ['show', IFACE, 'dump'])).trim().split('\n').slice(1)
      let hs = 0
      for(const l of lines) {
        const f = l.split('\t')
        hs = Math.max(hs, Number(f[4]) || 0)
        base.rx += Number(f[5]) || 0
        base.tx += Number(f[6]) || 0
        base.endpoint ??= f[2] === '(none)' ? null : f[2]
      }
      return { ...base, up: true, latestHandshake: hs ? hs * 1000 : null }
    } catch(e) {
      if(e instanceof CommandError) return base
      throw e
    }
  }

  private writeStripped(conf: ParsedConf): string {
    const file = join(this.opts.runDir, `${IFACE}.setconf`)
    // The mark goes in with the config: set later, the first handshake leaves unmarked and the
    // kill-switch drops it; and a syncconf without it would reset the mark to 0
    writeFileSync(file, stripConf(conf).replace('[Interface]\n', `[Interface]\nFwMark = ${FWMARK}\n`), { mode: 0o600 })
    return file
  }
}

/** The container's resolver follows the tunnel DNS, so the proxies resolve through the tunnel. */
export function writeResolvConf(dns: string[]) {
  if(!dns.length) return
  try {
    writeFileSync('/etc/resolv.conf', dns.map(d => `nameserver ${d}`).join('\n') + '\noptions timeout:2 attempts:2\n')
  } catch(e) {
    log.warn(`Не удалось записать /etc/resolv.conf: ${(e as Error).message}`)
  }
}

export function sleep(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
