import { hostname } from 'node:os'

export const VERSION = '0.2.0'

export const DEFAULT_COORDINATOR_URL = 'https://cryptgeon.kiraind.ru'

export interface Settings {
  coordinatorUrl: URL
  dataDir: string
  runDir: string
  /** Device label in the bot's /devices and the base of the config name. */
  deviceName: string
  socksPort: number
  httpPort: number
  proxyUser: string | null
  proxyPassword: string | null
  /** Who may use the proxies (and, with the gateway, route through it). */
  lanCidrs: string[]
  pollIntervalMs: number
  /** Handshake older than this means the tunnel is broken. */
  handshakeTimeoutMs: number
  awgImpl: 'auto' | 'kernel' | 'userspace'
  loginCode: string | null
  /** Route the LAN through the tunnel (devices set this container as their gateway). */
  gateway: boolean
  /** With the gateway: answer every LAN DNS query through the tunnel DNS. */
  dnsIntercept: boolean
}

const PRIVATE_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

export function loadSettings(env: NodeJS.ProcessEnv = process.env): Settings {
  const user = env.PROXY_USER || null
  const password = env.PROXY_PASSWORD || null
  if(Boolean(user) !== Boolean(password)) throw new Error('PROXY_USER и PROXY_PASSWORD задаются вместе')
  const impl = env.AWG_IMPL || 'auto'
  if(impl !== 'auto' && impl !== 'kernel' && impl !== 'userspace') throw new Error(`AWG_IMPL: auto, kernel или userspace, а не ${impl}`)
  return {
    coordinatorUrl: new URL(env.COORDINATOR_URL || DEFAULT_COORDINATOR_URL),
    dataDir: env.DATA_DIR || '/data',
    runDir: env.RUN_DIR || '/run/lesha-vpn-gw',
    deviceName: slug(env.DEVICE_NAME || hostname()) || 'gateway',
    socksPort: port(env.SOCKS_PORT, 1080, 'SOCKS_PORT'),
    httpPort: port(env.HTTP_PORT, 8080, 'HTTP_PORT'),
    proxyUser: user,
    proxyPassword: password,
    lanCidrs: env.LAN_CIDRS ? env.LAN_CIDRS.split(',').map(s => s.trim()).filter(Boolean).map(cidr) : PRIVATE_CIDRS,
    pollIntervalMs: duration(env.POLL_INTERVAL, 5 * 60_000, 'POLL_INTERVAL'),
    handshakeTimeoutMs: duration(env.HANDSHAKE_TIMEOUT, 3 * 60_000, 'HANDSHAKE_TIMEOUT'),
    awgImpl: impl,
    loginCode: env.LESHA_LOGIN_CODE?.trim() || null,
    gateway: flag(env.GATEWAY, true, 'GATEWAY'),
    dnsIntercept: flag(env.DNS_INTERCEPT, true, 'DNS_INTERCEPT'),
  }
}

/** The coordinator's config name pattern is ^[a-z0-9-]{1,32}$ (NAME_RE). */
export function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 24).replace(/-$/, '')
}

function flag(v: string | undefined, def: boolean, name: string): boolean {
  if(v === undefined || v === '') return def
  const s = v.trim().toLowerCase()
  if(['1', 'on', 'true', 'yes'].includes(s)) return true
  if(['0', 'off', 'false', 'no'].includes(s)) return false
  throw new Error(`${name}: on или off, а не ${v}`)
}

function port(v: string | undefined, def: number, name: string): number {
  if(v === undefined || v === '') return def
  const n = Number(v)
  if(!Number.isInteger(n) || n < 0 || n > 65535) throw new Error(`${name}: порт 0–65535 (0 = выключить), а не ${v}`)
  return n
}

export function duration(v: string | undefined, def: number, name: string): number {
  if(v === undefined || v === '') return def
  const m = /^(\d+)(ms|s|m|h)?$/.exec(v.trim())
  if(!m) throw new Error(`${name}: длительность вида 30s, 5m, 1h, а не ${v}`)
  const mult = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 }[(m[2] ?? 's') as 'ms' | 's' | 'm' | 'h']
  return Number(m[1]) * mult
}

function cidr(s: string): string {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/.exec(s)
  if(!m || m.slice(1, 5).some(o => Number(o) > 255) || (m[5] !== undefined && Number(m[5]) > 32)) {
    throw new Error(`LAN_CIDRS: ${s} не похоже на IPv4-подсеть`)
  }
  const bits = m[5] === undefined ? 32 : Number(m[5])
  // nft wants the network address, so 192.168.1.5/24 becomes 192.168.1.0/24
  const ip = m.slice(1, 5).reduce((acc, o) => acc * 256 + Number(o), 0)
  const net = bits === 0 ? 0 : (ip - (ip % 2 ** (32 - bits)))
  return `${[24, 16, 8, 0].map(sh => Math.floor(net / 2 ** sh) % 256).join('.')}/${bits}`
}
