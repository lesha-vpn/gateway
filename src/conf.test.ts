import { describe, expect, it } from 'vitest'
import { changeKind, parseConf, stripConf } from './conf'

// Shaped like the coordinator's renderClientConf output
export const SAMPLE = `[Interface]
Address = 10.66.0.7/32
DNS = 1.1.1.1, 8.8.8.8
PrivateKey = aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tMTI=
MTU = 1280
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
HeaderProtectionKey = c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlYzE=
RekeyAfterTime = 100-120
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = cHVibGljLXB1YmxpYy1wdWJsaWMtcHVibGljLXB1YjE=
PresharedKey = cHNrLXBzay1wc2stcHNrLXBzay1wc2stcHNrLXBzazE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.68.21.109:51820
PersistentKeepalive = 25
`

describe('parseConf', () => {
  it('splits awg-quick keys from setconf keys', () => {
    const c = parseConf(SAMPLE)
    expect(c.addresses).toEqual(['10.66.0.7/32'])
    expect(c.dns).toEqual(['1.1.1.1', '8.8.8.8'])
    expect(c.mtu).toBe(1280)
    expect(c.endpoints).toEqual(['185.68.21.109:51820'])
    expect(c.interfaceLines.some(l => /^(Address|DNS|MTU)/.test(l))).toBe(false)
    expect(c.interfaceLines).toContain('I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>')
  })

  it('dedupes the repeated single DNS the coordinator emits for AmneziaVPN', () => {
    expect(parseConf(SAMPLE.replace('1.1.1.1, 8.8.8.8', '1.1.1.1, 1.1.1.1')).dns).toEqual(['1.1.1.1'])
  })

  it('strips to what awg setconf accepts', () => {
    const text = stripConf(parseConf(SAMPLE))
    expect(text).toMatch(/^\[Interface\]\nPrivateKey = /)
    expect(text).not.toMatch(/Address|DNS|MTU/)
    expect(text).toContain('[Peer]\nPublicKey = ')
    expect(text).toContain('Endpoint = 185.68.21.109:51820')
  })

  it('rejects configs it cannot bring up', () => {
    expect(() => parseConf(SAMPLE.replace(/Address.*\n/, ''))).toThrow(/Address/)
    expect(() => parseConf(SAMPLE.replace(/\[Peer\][\s\S]*/, ''))).toThrow(/Peer/)
    expect(() => parseConf('[Foo]\nA = 1')).toThrow(/section/)
  })
})

describe('changeKind', () => {
  const base = parseConf(SAMPLE)
  it('peer-only changes keep the interface (new LOCAL address)', () => {
    expect(changeKind(base, parseConf(SAMPLE.replace('185.68.21.109', '203.0.113.5')))).toBe('peers')
  })
  it('interface changes recreate it', () => {
    expect(changeKind(base, parseConf(SAMPLE.replace('Jc = 5', 'Jc = 6')))).toBe('interface')
    expect(changeKind(base, parseConf(SAMPLE.replace('10.66.0.7', '10.66.0.8')))).toBe('interface')
    expect(changeKind(base, parseConf(SAMPLE.replace('MTU = 1280', 'MTU = 1380')))).toBe('interface')
  })
  it('DNS alone and no change', () => {
    expect(changeKind(base, parseConf(SAMPLE.replace('1.1.1.1, 8.8.8.8', '9.9.9.9, 9.9.9.9')))).toBe('dns')
    expect(changeKind(base, parseConf(SAMPLE))).toBe('none')
  })
})
