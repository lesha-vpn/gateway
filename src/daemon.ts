import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Api, ApiError, ConfigView, NetworkError, resolveApi } from './api'
import { parseConf, ParsedConf } from './conf'
import { applyFirewall } from './firewall'
import { log } from './log'
import { Proxy } from './proxy'
import { Settings, VERSION } from './settings'
import { PersistentState, Store } from './state'
import { sleep, Tunnel, TunnelInfo } from './tunnel'

export type Phase =
  | 'need_login'      // no token: waiting for `lesha-vpn-gw login <code>`
  | 'starting'        // have a token, getting the config / bringing the tunnel up
  | 'up'              // tunnel up with the current config
  | 'suspended'       // the coordinator suspended the config (user left the chat)
  | 'revoked'         // the config was revoked; a new login issues a new one
  | 'not_member'      // 403 not_member
  | 'error'           // something unexpected; retrying

export interface StatusFile {
  version: string
  phase: Phase
  message: string
  user: PersistentState['user'] | null
  config: { id: string, name: string, revision: string } | null
  tunnel: TunnelInfo & { endpointConfigured: string | null }
  coordinator: { network: string | null, checkedAt: string | null, lastContact: string | null, lastError: string | null }
  updatedAt: string
}

const TOKEN_POLL_MS = 2000
const HEALTH_MS = 10_000
/** After a broken handshake, ask the coordinator at most this often. */
const EARLY_CHECK_MIN_MS = 60_000

export const MESSAGES: Record<Phase, string> = {
  need_login: 'Нужен вход: напиши боту /login и выполни `docker exec lesha-vpn-gw lesha-vpn-gw login <код>`',
  starting: 'Подключаюсь',
  up: 'Туннель работает',
  suspended: 'Конфиг приостановлен координатором: аккаунт не в чате. Трафик закрыт',
  revoked: 'Конфиг отозван. Трафик закрыт. Чтобы выдать новый, войди заново: /login в боте и `lesha-vpn-gw login <код>`',
  not_member: 'Аккаунт не участник чата. Трафик закрыт. После возвращения в чат нужен новый вход',
  error: 'Ошибка, повторяю',
}

export class Daemon {
  private store: Store
  private tunnel: Tunnel
  private proxy: Proxy
  private state: PersistentState
  private token: string | null = null
  private parsed: ParsedConf | null = null
  private phase: Phase = 'starting'
  private message = MESSAGES.starting
  private coordinator: StatusFile['coordinator'] = { network: null, checkedAt: null, lastContact: null, lastError: null }
  private nextCheck = 0
  private lastEarlyCheck = 0
  private failures = 0
  private stopping = false
  private wake: (() => void) | null = null
  /** Docker's resolvers, before writeResolvConf replaces them with the tunnel DNS. */
  private bootstrapDns: string[]

  constructor(private s: Settings) {
    this.store = new Store(s.dataDir)
    mkdirSync(s.runDir, { recursive: true, mode: 0o700 })
    // /run survives `docker restart`; a status from the previous run would lie
    rmSync(join(s.runDir, 'status.json'), { force: true })
    this.tunnel = new Tunnel({ runDir: s.runDir, preferImpl: s.awgImpl })
    this.tunnel.onDied = () => { this.nextCheck = 0; this.kick() }
    this.proxy = new Proxy(s)
    this.state = this.store.read()
    this.bootstrapDns = readNameservers()
  }

  private get apiPort() {
    const u = this.s.coordinatorUrl
    return Number(u.port) || (u.protocol === 'http:' ? 80 : 443)
  }

  private api(token = this.token) {
    return new Api({ baseUrl: this.s.coordinatorUrl, token, fallbackAddrs: this.state.apiAddrs })
  }

  async start() {
    log.info(`lesha-vpn-gw ${VERSION}, координатор ${this.s.coordinatorUrl.origin}, устройство ${this.s.deviceName}`)
    // Kill-switch before anything else runs: nothing leaves the container until the tunnel is up
    await this.loadFirewall()
    await this.tunnel.setupRouting(this.state.apiAddrs ?? [])
    await this.refreshApiAddrs({ bootstrap: true })
    this.proxy.start()
    if(this.s.gateway) {
      const fwd = readFileSync('/proc/sys/net/ipv4/ip_forward', 'utf8').trim()
      if(fwd === '1') log.info(`Режим шлюза: LAN ${this.s.lanCidrs.join(', ')} → туннель${this.s.dnsIntercept ? ', DNS через туннель' : ''}`)
      else log.warn('Режим шлюза выключен: нужен sysctl net.ipv4.ip_forward=1 (см. examples/compose.gateway.yml)')
    }

    this.token = this.store.readToken()
    if(!this.token && this.s.loginCode) await this.loginWithCode(this.s.loginCode)
    // Come up on the last config right away, before (and without) the coordinator answering
    if(this.token && this.state.config && !this.state.configRevoked) await this.bringUp(this.state.config.awg)
    void this.loop()
  }

  async stop() {
    this.stopping = true
    this.kick()
    this.proxy.stop()
    await this.tunnel.down()
  }

  private kick() {
    this.wake?.()
  }

  private async idle(ms: number) {
    await Promise.race([sleep(ms), new Promise<void>(r => { this.wake = r })])
    this.wake = null
  }

  private async loop() {
    while(!this.stopping) {
      try {
        await this.tick()
      } catch(e) {
        this.set('error', `${MESSAGES.error}: ${(e as Error).message}`)
        log.error((e as Error).stack ?? String(e))
        this.nextCheck = Date.now() + this.backoff()
      }
      await this.writeStatus()
      await this.idle(this.token ? HEALTH_MS : TOKEN_POLL_MS)
    }
  }

  private async tick() {
    const token = this.store.readToken()
    if(token !== this.token) {
      // A new login (or logout): forget a revoked config so a fresh one is issued
      this.token = token
      if(token) {
        this.store.update(s => { delete s.configRevoked })
        this.state = this.store.read()
        this.nextCheck = 0
        log.info('Новый токен, проверяю конфиг')
      }
    }
    if(!this.token) {
      if(this.tunnel.isUp) await this.tunnel.down()
      this.set('need_login')
      return
    }
    if(this.state.configRevoked) return

    // Health: a stale handshake or a dead userspace process means: ask the coordinator now
    const info = await this.tunnel.info()
    if(this.tunnel.isUp && !info.up && this.state.config) {
      log.warn('Интерфейс туннеля пропал, поднимаю заново')
      await this.tunnel.down()
      await this.bringUp(this.state.config.awg)
    }
    const now = Date.now()
    const stale = !info.up || !info.latestHandshake || now - info.latestHandshake > this.s.handshakeTimeoutMs
    if(this.phase === 'up' && stale && now - this.lastEarlyCheck > EARLY_CHECK_MIN_MS && this.tunnelAge() > this.s.handshakeTimeoutMs) {
      this.lastEarlyCheck = now
      this.nextCheck = 0
      log.warn('Нет свежего handshake, проверяю конфиг у координатора')
    }
    if(now < this.nextCheck) return
    await this.check()
  }

  private upSince = 0
  private tunnelAge() {
    return this.upSince ? Date.now() - this.upSince : 0
  }

  /** One round of R-A8: make sure we have a config, ask for its status, react. */
  private async check() {
    await this.refreshApiAddrs()
    const api = this.api()
    try {
      if(!this.state.config) {
        await this.obtainConfig(api)
      } else {
        const st = await api.status(this.state.config.id, this.state.config.revision)
        this.coordinator.network = st.network
        this.coordinator.checkedAt = st.checkedAt
        if(st.state === 'ok') {
          if(!this.tunnel.isUp) await this.bringUp(this.state.config.awg)
        } else if(st.state === 'outdated') {
          log.info(`Конфиг устарел (${this.state.config.revision} → ${st.revision}), забираю новый`)
          await this.install(await api.getConfig(this.state.config.id))
        } else if(st.state === 'suspended') {
          await this.closeTraffic('suspended')
        } else {
          await this.revoked()
        }
      }
      this.contact()
      this.nextCheck = Date.now() + this.s.pollIntervalMs
    } catch(e) {
      await this.handleError(e)
    }
  }

  private async obtainConfig(api: Api) {
    const me = await api.me()
    this.store.update(s => { s.user = me.user })
    this.state = this.store.read()
    // Our config may exist already (state lost but token kept, or a restore)
    const base = `gw-${this.s.deviceName}`
    const mine = me.configs.find(c => c.state !== 'revoked' && c.name === base)
    if(mine) {
      log.info(`Нашёл свой конфиг ${mine.name}`)
      await this.install(await api.getConfig(mine.id))
      return
    }
    for(let i = 1; ; i++) {
      const name = i === 1 ? base : `${base.slice(0, 32 - String(i).length - 1)}-${i}`
      try {
        const view = await api.createConfig(name)
        log.info(`Выдан конфиг ${view.name}`)
        await this.install(view)
        return
      } catch(e) {
        if(e instanceof ApiError && e.code === 'name_taken' && i < 20) continue
        throw e
      }
    }
  }

  private async install(view: ConfigView) {
    const parsed = parseConf(view.awg)
    this.store.update(s => { s.config = { id: view.id, name: view.name, revision: view.revision, awg: view.awg } })
    this.state = this.store.read()
    await this.applyParsed(parsed)
  }

  private async bringUp(awg: string) {
    try {
      await this.applyParsed(parseConf(awg))
    } catch(e) {
      log.error(`Не удалось поднять туннель: ${(e as Error).message}`)
      this.set('error', `${MESSAGES.error}: ${(e as Error).message}`)
    }
  }

  private async applyParsed(parsed: ParsedConf) {
    const wasUp = this.tunnel.isUp
    await this.tunnel.apply(parsed)
    if(!wasUp) this.upSince = Date.now()
    this.parsed = parsed
    await this.loadFirewall()
    this.set('up')
  }

  private async closeTraffic(phase: 'suspended' | 'not_member') {
    if(this.phase !== phase) log.warn(MESSAGES[phase])
    await this.tunnel.down()
    this.set(phase)
  }

  private async revoked() {
    log.warn(MESSAGES.revoked)
    await this.tunnel.down()
    this.store.update(s => { delete s.config; s.configRevoked = true })
    this.state = this.store.read()
    this.set('revoked')
  }

  private async handleError(e: unknown) {
    if(e instanceof ApiError) {
      this.contact()
      if(e.status === 401) {
        log.warn('Токен устройства отозван, нужен новый вход')
        this.store.clearToken()
        this.token = null
        await this.tunnel.down()
        this.set('need_login')
        return
      }
      if(e.status === 403 && e.code === 'not_member') {
        await this.closeTraffic('not_member')
        this.nextCheck = Date.now() + this.s.pollIntervalMs
        return
      }
      if(e.status === 404 && this.state.config) {
        await this.revoked()
        return
      }
    }
    // The coordinator is unreachable or broke: keep the tunnel on the last config, retry with backoff
    const msg = (e as Error).message
    this.coordinator.lastError = msg
    this.failures++
    const delay = this.backoff()
    log.warn(`Координатор недоступен (${msg}), повтор через ${Math.round(delay / 1000)} с`)
    this.nextCheck = Date.now() + delay
    if(!this.tunnel.isUp && this.phase !== 'error') this.set('starting', `${MESSAGES.starting}: координатор недоступен`)
  }

  private backoff() {
    return Math.min(this.s.pollIntervalMs, 5000 * 2 ** Math.min(this.failures, 6))
  }

  private contact() {
    this.failures = 0
    this.coordinator.lastContact = new Date().toISOString()
    this.coordinator.lastError = null
  }

  /**
   * Keep the API addresses (bypass rules + firewall set) current. With the tunnel up, DNS goes
   * through it; without it there is only the cache, except at start and before the first tunnel,
   * when Docker's own resolver is opened for this one lookup (bootstrapResolve).
   */
  private async refreshApiAddrs({ bootstrap = false } = {}) {
    const host = this.s.coordinatorUrl.hostname
    const cached = this.state.apiAddrs ?? []
    let addrs: string[] | null
    if(!this.tunnel.isUp && (bootstrap || !cached.length)) {
      addrs = await this.bootstrapResolve(host)
    } else {
      addrs = await resolveApi(host, cached).catch(() => null)
    }
    if(!addrs || (addrs.length === cached.length && addrs.every(a => cached.includes(a)))) return
    this.store.update(s => { s.apiAddrs = addrs })
    this.state = this.store.read()
    await this.tunnel.setApiBypass(addrs)
    await this.loadFirewall()
  }

  private async bootstrapResolve(host: string): Promise<string[] | null> {
    await this.loadFirewall({ bootstrapDns: this.bootstrapDns })
    await this.tunnel.clearRouting()
    try {
      return await resolveApi(host)
    } catch(e) {
      log.warn(`${(e as Error).message}; повторю позже`)
      return null
    } finally {
      await this.tunnel.setupRouting(this.state.apiAddrs ?? [])
      await this.loadFirewall()
    }
  }

  private async loadFirewall({ bootstrapDns = [] as string[] } = {}) {
    await applyFirewall({
      bootstrapDns,
      lanCidrs: this.s.lanCidrs,
      apiAddrs: this.state.apiAddrs ?? [],
      apiPort: this.apiPort,
      proxyPorts: [this.s.socksPort, this.s.httpPort],
      tunnelAddrs: this.parsed?.addresses ?? [],
      gateway: this.s.gateway,
      dnsRedirect: this.s.gateway && this.s.dnsIntercept ? this.parsed?.dns[0] ?? null : null,
    }, join(this.s.runDir, 'firewall.nft'))
  }

  async loginWithCode(code: string) {
    try {
      const res = await this.api(null).login(code, `gateway-${this.s.deviceName}`)
      this.store.writeToken(res.token)
      this.store.update(s => { s.user = res.user })
      this.state = this.store.read()
      log.info(`Вход выполнен: ${res.user.username ? '@' + res.user.username : res.user.tgId}`)
    } catch(e) {
      log.error(`Вход по LESHA_LOGIN_CODE не удался: ${(e as Error).message}`)
    }
  }

  private set(phase: Phase, message = MESSAGES[phase]) {
    if(phase !== this.phase && phase !== 'up') log.info(`Состояние: ${phase}`)
    if(phase === 'up' && this.phase !== 'up') log.info(MESSAGES.up)
    this.phase = phase
    this.message = message
  }

  private async writeStatus() {
    const info = await this.tunnel.info().catch(() => null)
    const cfg = this.state.config
    const status: StatusFile = {
      version: VERSION,
      phase: this.phase,
      message: this.message,
      user: this.state.user ?? null,
      config: cfg ? { id: cfg.id, name: cfg.name, revision: cfg.revision } : null,
      tunnel: {
        ...(info ?? { up: false, impl: null, latestHandshake: null, rx: 0, tx: 0, endpoint: null }),
        endpointConfigured: this.parsed?.endpoints[0] ?? null,
      },
      coordinator: this.coordinator,
      updatedAt: new Date().toISOString(),
    }
    writeFileSync(join(this.s.runDir, 'status.json'), JSON.stringify(status, null, 2))
  }
}

function readNameservers(): string[] {
  try {
    return [...readFileSync('/etc/resolv.conf', 'utf8').matchAll(/^nameserver\s+(\d+\.\d+\.\d+\.\d+)\s*$/gm)]
      .map(m => m[1]).filter(a => !a.startsWith('127.'))
  } catch {
    return []
  }
}
