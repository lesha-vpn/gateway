import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { renderFirewall } from './firewall'

const input = {
  lanCidrs: ['192.168.0.0/16', '10.0.0.0/8'],
  apiAddrs: ['170.168.191.74'],
  apiPort: 443,
  proxyPorts: [1080, 8080],
  tunnelAddrs: ['10.66.0.7/32'],
}

function nftAvailable() {
  try {
    execFileSync('nft', ['list', 'tables'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

describe('renderFirewall', () => {
  const text = renderFirewall(input)

  it('drops by default and lets out only the tunnel, awg UDP, the API and the LAN', () => {
    expect(text).toContain('type filter hook output priority filter; policy drop;')
    expect(text).toContain('oifname "awg0" accept')
    expect(text).toContain('meta mark 51820 accept')
    expect(text).toContain('ip daddr @api tcp dport 443 accept')
    expect(text).toMatch(/elements = \{ 170\.168\.191\.74 \}/)
    expect(text).not.toContain('th dport 53')
  })

  it('opens the proxies to the LAN only', () => {
    expect(text).toContain('iifname != "awg0" ip saddr @lan tcp dport { 1080, 8080 } accept')
    expect(renderFirewall({ ...input, proxyPorts: [0, 8080] })).toContain('tcp dport { 8080 } accept')
    expect(renderFirewall({ ...input, proxyPorts: [0, 0] })).not.toContain('tcp dport {')
  })

  it('opens Docker DNS only for the bootstrap lookup', () => {
    expect(renderFirewall({ ...input, bootstrapDns: ['8.8.8.8'] })).toContain('ip daddr { 8.8.8.8 } meta l4proto { tcp, udp } th dport 53 accept')
  })

  it('renders with empty sets', () => {
    expect(renderFirewall({ ...input, apiAddrs: [], tunnelAddrs: [] })).not.toContain('elements = {  }')
  })

  it('forwards nothing without the gateway', () => {
    expect(text).not.toContain('masquerade')
    expect(text).not.toMatch(/chain forward \{[^}]*accept/)
  })

  it('gateway: LAN into the tunnel only, NAT, MSS clamp, DNS redirect', () => {
    const gw = renderFirewall({ ...input, gateway: true, dnsRedirect: '1.1.1.1' })
    expect(gw).toContain('iifname != "awg0" ip saddr @lan oifname "awg0" accept')
    expect(gw).toContain('oifname "awg0" masquerade')
    expect(gw).toContain('tcp option maxseg size set rt mtu')
    expect(gw).toContain('th dport 53 dnat ip to 1.1.1.1')
    expect(renderFirewall({ ...input, gateway: true, dnsRedirect: null })).not.toContain('dnat')
  })

  it.runIf(nftAvailable())('is valid nft syntax', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fw-'))
    for(const v of [input, { ...input, apiAddrs: [], tunnelAddrs: [], bootstrapDns: ['1.1.1.1'] }, { ...input, gateway: true, dnsRedirect: '1.1.1.1' }]) {
      writeFileSync(join(dir, 'fw.nft'), renderFirewall(v))
      execFileSync('nft', ['-c', '-f', join(dir, 'fw.nft')])
    }
  })
})
