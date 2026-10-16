import { lookup as dnsLookup } from 'node:dns/promises'
import http from 'node:http'
import https from 'node:https'
import type { LookupFunction } from 'node:net'
import { VERSION } from './settings'

/** Coordinator `/v1` client: the same calls the app makes (spec section 9, R-A8). */

export interface ConfigSummary { id: string, name: string, revision: string, state: 'active' | 'suspended' | 'revoked', createdAt: string }
export interface ConfigView { id: string, name: string, revision: string, createdAt: string, awg: string, serverName?: string, endpoint?: string }
export interface ConfigStatus { state: 'ok' | 'outdated' | 'suspended' | 'revoked', revision: string, network: string, checkedAt: string | null }
export interface User { tgId: number, username: string | null }

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message)
  }
}

/** The request never got an HTTP answer: DNS, TCP, TLS or timeout. */
export class NetworkError extends Error {}

export interface ApiOptions {
  baseUrl: URL
  token?: string | null
  /** Addresses to use when DNS fails (the tunnel DNS is unreachable while the tunnel is down). */
  fallbackAddrs?: string[]
  timeoutMs?: number
}

const DNS_TIMEOUT_MS = 4000

/** IPv4 addresses of the API host: DNS first, then the cached ones. */
export async function resolveApi(host: string, fallback: string[] = []): Promise<string[]> {
  if(/^\d+\.\d+\.\d+\.\d+$/.test(host)) return [host]
  try {
    const res = await withTimeout(dnsLookup(host, { family: 4, all: true }), DNS_TIMEOUT_MS)
    const addrs = [...new Set(res.map(r => r.address))]
    if(addrs.length) return addrs
  } catch {
    // fall through to the cache
  }
  if(fallback.length) return fallback
  throw new NetworkError(`не удалось узнать адрес ${host}`)
}

export class Api {
  constructor(private opts: ApiOptions) {}

  login(code: string, deviceLabel: string) {
    return this.request<{ token: string, user: User }>('POST', '/v1/auth/login', { code, deviceLabel })
  }

  logout() {
    return this.request<void>('POST', '/v1/auth/logout')
  }

  me() {
    return this.request<{ user: User, configs: ConfigSummary[] }>('GET', '/v1/me')
  }

  createConfig(name: string) {
    return this.request<ConfigView>('POST', '/v1/configs', { name })
  }

  getConfig(id: string) {
    return this.request<ConfigView>('GET', `/v1/configs/${encodeURIComponent(id)}`)
  }

  status(id: string, revision: string) {
    return this.request<ConfigStatus>('GET', `/v1/configs/${encodeURIComponent(id)}/status?revision=${encodeURIComponent(revision)}`)
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = new URL(path, this.opts.baseUrl)
    const addrs = await resolveApi(url.hostname, this.opts.fallbackAddrs)
    // Connect to the address we resolved (and route around the tunnel), keep the hostname for TLS/SNI
    const lookup: LookupFunction = (_host, options, cb) => {
      if(options.all) cb(null, addrs.map(address => ({ address, family: 4 })))
      else cb(null, addrs[0], 4)
    }
    const payload = body === undefined ? undefined : JSON.stringify(body)
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': `lesha-vpn-gw/${VERSION}`,
      'X-App-Version': `gateway/${VERSION}`,
    }
    if(payload !== undefined) headers['Content-Type'] = 'application/json'
    if(this.opts.token) headers.Authorization = `Bearer ${this.opts.token}`
    const mod = url.protocol === 'http:' ? http : https
    const { status, text } = await new Promise<{ status: number, text: string }>((resolve, reject) => {
      const req = mod.request(url, { method, headers, lookup, timeout: this.opts.timeoutMs ?? 15_000 }, res => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') }))
        res.on('error', e => reject(new NetworkError(e.message)))
      })
      req.on('timeout', () => req.destroy(new Error('timeout')))
      req.on('error', e => reject(new NetworkError(`${url.host}: ${e.message}`)))
      req.end(payload)
    })
    if(status === 204) return undefined as T
    let json: any = null
    try {
      json = text ? JSON.parse(text) : null
    } catch {
      // not JSON: a proxy or load balancer error page
    }
    if(status >= 200 && status < 300 && json !== null) return json as T
    if(json?.error?.code) throw new ApiError(status, json.error.code, json.error.message ?? json.error.code)
    // A 5xx or garbage from something in front of the coordinator is a network problem, not an answer
    throw new NetworkError(`${url.host}: HTTP ${status}`)
  }
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms)
    p.then(v => { clearTimeout(t); resolve(v) }, e => { clearTimeout(t); reject(e) })
  })
}
