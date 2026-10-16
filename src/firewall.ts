import { writeFileSync } from 'node:fs'
import { run } from './exec'

export const IFACE = 'awg0'
/** fwmark on awg's own UDP socket and the routing table for "everything else", as in awg-quick. */
export const FWMARK = 51820
export const TABLE_NAME = 'lesha_vpn_gw'

export interface FirewallInput {
  lanCidrs: string[]
  /** Coordinator API: the only destination allowed outside the tunnel (besides awg's own UDP). */
  apiAddrs: string[]
  apiPort: number
  /** Proxy ports open to the LAN; 0 = off. */
  proxyPorts: number[]
  /** Our tunnel address, guarded against spoofing from other interfaces (awg-quick does the same). */
  tunnelAddrs: string[]
  /** Docker's resolvers, opened only while the API is resolved before the first tunnel. */
  bootstrapDns?: string[]
  /** Gateway mode: forward and masquerade the LAN into the tunnel. */
  gateway?: boolean
  /** With the gateway: send every DNS query from the LAN to this server (the tunnel DNS). */
  dnsRedirect?: string | null
}

/**
 * Kill-switch: the ruleset is loaded before the tunnel comes up and stays loaded, so with the
 * tunnel down nothing but the coordinator API and awg's own handshakes leaves the container.
 * Pure, so the rules are unit-tested; `nft -c` checks them in CI.
 */
export function renderFirewall(input: FirewallInput): string {
  const set = (name: string, elems: string[], interval: boolean) => [
    `  set ${name} {`,
    `    type ipv4_addr`,
    ...(interval ? ['    flags interval'] : []),
    ...(elems.length ? [`    elements = { ${elems.join(', ')} }`] : []),
    '  }',
  ]
  const ports = input.proxyPorts.filter(p => p > 0)
  const tunnelHosts = input.tunnelAddrs.map(a => a.split('/')[0])
  return [
    // Declare-then-delete makes the reload atomic and idempotent
    `table inet ${TABLE_NAME}`,
    `delete table inet ${TABLE_NAME}`,
    `table inet ${TABLE_NAME} {`,
    ...set('lan', input.lanCidrs, true),
    ...set('api', input.apiAddrs, false),
    '',
    '  chain preraw {',
    '    type filter hook prerouting priority raw; policy accept;',
    ...tunnelHosts.map(a => `    iifname != "${IFACE}" ip daddr ${a} fib saddr type != local drop`),
    '  }',
    '',
    // Replies to awg's UDP get its mark back, so the reverse-path check routes them via the main table
    '  chain premangle {',
    '    type filter hook prerouting priority mangle; policy accept;',
    '    meta l4proto udp meta mark set ct mark',
    '  }',
    '  chain postmangle {',
    '    type filter hook postrouting priority mangle; policy accept;',
    `    meta l4proto udp meta mark ${FWMARK} ct mark set meta mark`,
    '  }',
    '',
    '  chain input {',
    '    type filter hook input priority filter; policy drop;',
    '    iifname "lo" accept',
    '    ct state invalid drop',
    '    ct state established,related accept',
    ...(ports.length ? [`    iifname != "${IFACE}" ip saddr @lan tcp dport { ${ports.join(', ')} } accept`] : []),
    `    iifname != "${IFACE}" ip saddr @lan icmp type echo-request accept`,
    '  }',
    '',
    '  chain output {',
    '    type filter hook output priority filter; policy drop;',
    '    oifname "lo" accept',
    `    oifname "${IFACE}" accept`,
    `    meta mark ${FWMARK} accept`,
    '    ct state established,related accept',
    `    ip daddr @api tcp dport ${input.apiPort} accept`,
    ...(input.bootstrapDns?.length ? [`    ip daddr { ${input.bootstrapDns.join(', ')} } meta l4proto { tcp, udp } th dport 53 accept`] : []),
    '    ip daddr @lan accept',
    '  }',
    '',
    // LAN traffic goes into the tunnel or nowhere: with awg0 gone it has no way out (fail-closed)
    '  chain forward {',
    '    type filter hook forward priority filter; policy drop;',
    ...(input.gateway ? [
      '    ct state invalid drop',
      '    ct state established,related accept',
      `    iifname != "${IFACE}" ip saddr @lan oifname "${IFACE}" accept`,
    ] : []),
    '  }',
    ...(input.gateway ? [
      '',
      // The tunnel MTU (1280) is below the LAN's 1500; clamp so TCP never needs fragments
      '  chain mss {',
      '    type filter hook forward priority mangle; policy accept;',
      `    oifname "${IFACE}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu`,
      `    iifname "${IFACE}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu`,
      '  }',
      '  chain postnat {',
      '    type nat hook postrouting priority srcnat; policy accept;',
      `    oifname "${IFACE}" masquerade`,
      '  }',
      ...(input.dnsRedirect ? [
        // Any DNS server a LAN device asks through us (8.8.8.8, the gateway itself...) answers from the tunnel
        '  chain prenat {',
        '    type nat hook prerouting priority dstnat; policy accept;',
        `    iifname != "${IFACE}" ip saddr @lan meta l4proto { tcp, udp } th dport 53 dnat ip to ${input.dnsRedirect}`,
        '  }',
      ] : []),
    ] : []),
    '}',
    '',
  ].join('\n')
}

/** `nft -f -` refuses a pipe on some nft versions ("Not a regular file"), so go through a file. */
export async function applyFirewall(input: FirewallInput, file: string) {
  writeFileSync(file, renderFirewall(input), { mode: 0o600 })
  await run('nft', ['-f', file])
}
