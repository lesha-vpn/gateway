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
    '  chain forward {',
    '    type filter hook forward priority filter; policy drop;',
    '  }',
    '}',
    '',
  ].join('\n')
}

/** `nft -f -` refuses a pipe on some nft versions ("Not a regular file"), so go through a file. */
export async function applyFirewall(input: FirewallInput, file: string) {
  writeFileSync(file, renderFirewall(input), { mode: 0o600 })
  await run('nft', ['-f', file])
}
