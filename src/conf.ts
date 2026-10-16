/**
 * The client `.conf` the coordinator serves (`awg` field of GET /v1/configs/{id}), parsed into the
 * parts this gateway needs: what awg-quick would set itself (Address, DNS, MTU) and the text
 * `awg setconf` accepts.
 */

export interface ParsedConf {
  /** IPv4 addresses with prefix, e.g. 10.66.0.7/32. */
  addresses: string[]
  dns: string[]
  mtu: number | null
  /** [Interface] lines minus awg-quick keys, in file order. */
  interfaceLines: string[]
  /** Every [Peer] section, joined. */
  peerLines: string[]
  /** Peer endpoints as host:port. */
  endpoints: string[]
}

// awg-quick consumes these; `awg setconf` rejects them
const QUICK_KEYS = new Set(['address', 'dns', 'mtu', 'table', 'preup', 'postup', 'predown', 'postdown', 'saveconfig'])

export function parseConf(text: string): ParsedConf {
  const out: ParsedConf = { addresses: [], dns: [], mtu: null, interfaceLines: [], peerLines: [], endpoints: [] }
  let section: 'interface' | 'peer' | null = null
  for(const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim()
    if(!line) continue
    const header = /^\[(\w+)\]$/.exec(line)
    if(header) {
      const name = header[1].toLowerCase()
      if(name === 'interface') {
        section = 'interface'
      } else if(name === 'peer') {
        section = 'peer'
        out.peerLines.push('[Peer]')
      } else {
        throw new Error(`unknown section [${header[1]}]`)
      }
      continue
    }
    const eq = line.indexOf('=')
    if(eq < 0 || !section) throw new Error(`malformed line: ${line}`)
    const key = line.slice(0, eq).trim()
    const value = line.slice(eq + 1).trim()
    const lower = key.toLowerCase()
    if(section === 'peer') {
      if(lower === 'endpoint') out.endpoints.push(value)
      out.peerLines.push(`${key} = ${value}`)
      continue
    }
    if(lower === 'address') {
      // The coordinator issues IPv4 only (R-S2); anything else would need an IPv6 stack we keep off
      out.addresses.push(...list(value).filter(a => !a.includes(':')).map(a => a.includes('/') ? a : `${a}/32`))
    } else if(lower === 'dns') {
      out.dns.push(...list(value).filter(d => /^\d+\.\d+\.\d+\.\d+$/.test(d)))
    } else if(lower === 'mtu') {
      out.mtu = Number(value)
    } else if(!QUICK_KEYS.has(lower)) {
      out.interfaceLines.push(`${key} = ${value}`)
    }
  }
  if(out.addresses.length === 0) throw new Error('config has no IPv4 Address')
  if(!out.interfaceLines.some(l => /^privatekey\s*=/i.test(l))) throw new Error('config has no PrivateKey')
  if(out.peerLines.length === 0) throw new Error('config has no [Peer]')
  // AmneziaVPN repeats a single DNS server (see coordinator renderClientConf); one copy is enough
  out.dns = [...new Set(out.dns)]
  return out
}

function list(value: string): string[] {
  return value.split(',').map(s => s.trim()).filter(Boolean)
}

/** Text for `awg setconf` / `awg syncconf`, like `awg-quick strip`. */
export function stripConf(conf: ParsedConf): string {
  return ['[Interface]', ...conf.interfaceLines, '', ...conf.peerLines, ''].join('\n')
}

/**
 * Whether going from `prev` to `next` can be applied with `awg syncconf` (peers only, sessions kept)
 * or needs the interface recreated, the same split apply.sh makes on the nodes.
 */
export function changeKind(prev: ParsedConf, next: ParsedConf): 'none' | 'peers' | 'interface' | 'dns' {
  const same = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i])
  if(!same(prev.interfaceLines, next.interfaceLines) || !same(prev.addresses, next.addresses) || prev.mtu !== next.mtu) {
    return 'interface'
  }
  if(!same(prev.peerLines, next.peerLines)) return 'peers'
  if(!same(prev.dns, next.dns)) return 'dns'
  return 'none'
}
