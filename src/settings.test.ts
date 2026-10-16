import { describe, expect, it } from 'vitest'
import { duration, loadSettings, slug } from './settings'
import { gostArgs } from './proxy'

describe('settings', () => {
  it('defaults', () => {
    const s = loadSettings({ DEVICE_NAME: 'Home Pi' })
    expect(s.coordinatorUrl.href).toBe('https://cryptgeon.kiraind.ru/')
    expect(s.deviceName).toBe('home-pi')
    expect([s.socksPort, s.httpPort]).toEqual([1080, 8080])
    expect(s.lanCidrs).toEqual(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
    expect(s.pollIntervalMs).toBe(300_000)
  })

  it('normalises LAN_CIDRS to network addresses', () => {
    expect(loadSettings({ LAN_CIDRS: '192.168.1.5/24, 10.1.2.3' }).lanCidrs).toEqual(['192.168.1.0/24', '10.1.2.3/32'])
    expect(() => loadSettings({ LAN_CIDRS: '300.1.1.1/24' })).toThrow(/LAN_CIDRS/)
  })

  it('validates', () => {
    expect(() => loadSettings({ PROXY_USER: 'a' })).toThrow(/PROXY_PASSWORD/)
    expect(() => loadSettings({ SOCKS_PORT: '70000' })).toThrow(/SOCKS_PORT/)
    expect(() => loadSettings({ AWG_IMPL: 'x' })).toThrow(/AWG_IMPL/)
    expect(() => loadSettings({ GATEWAY: 'maybe' })).toThrow(/GATEWAY/)
    expect(loadSettings({ GATEWAY: 'off' }).gateway).toBe(false)
    expect(loadSettings({}).gateway).toBe(true)
    expect(duration('30s', 0, 'X')).toBe(30_000)
    expect(duration('5m', 0, 'X')).toBe(300_000)
    expect(duration('10', 0, 'X')).toBe(10_000)
  })

  it('slugs fit the coordinator name pattern with the gw- prefix', () => {
    expect(slug('Мой роутер')).toBe('')
    expect(slug('raspberrypi.local')).toBe('raspberrypi-local')
    const long = `gw-${slug('a'.repeat(100))}`
    expect(long).toMatch(/^[a-z0-9-]{1,32}$/)
  })
})

describe('gostArgs', () => {
  it('builds listeners with URL-encoded auth', () => {
    expect(gostArgs({ socksPort: 1080, httpPort: 8080, proxyUser: null, proxyPassword: null }))
      .toEqual(['-L', 'socks5://:1080', '-L', 'http://:8080'])
    expect(gostArgs({ socksPort: 0, httpPort: 3128, proxyUser: 'me', proxyPassword: 'p@ss:w/rd' }))
      .toEqual(['-L', 'http://me:p%40ss%3Aw%2Frd@:3128'])
  })
})
