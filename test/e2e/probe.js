// probe.js socks|http <proxyHost> <proxyPort> <host> <port>: GET http://host:port/ through the proxy,
// print the body (the echo server answers with the client address it sees) or FAIL.
const net = require('node:net')
const [mode, ph, pp, host, port] = process.argv.slice(2)
const done = out => { console.log(out); process.exit(0) }
const sock = net.connect(Number(pp), ph)
sock.setTimeout(4000, () => done('FAIL timeout'))
sock.on('error', e => done(`FAIL ${e.message}`))
let buf = Buffer.alloc(0)
let stage = 0
const request = () => sock.write(`GET / HTTP/1.0\r\nHost: ${host}\r\n\r\n`)
sock.on('connect', () => {
  if(mode === 'socks') sock.write(Buffer.from([5, 1, 0]))
  else sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`)
})
sock.on('data', d => {
  buf = Buffer.concat([buf, d])
  if(mode === 'socks') {
    if(stage === 0 && buf.length >= 2) {
      buf = buf.subarray(2)
      const ip = host.split('.').map(Number)
      sock.write(Buffer.from([5, 1, 0, 1, ...ip, Number(port) >> 8, Number(port) & 255]))
      stage = 1
    }
    if(stage === 1 && buf.length >= 10) {
      if(buf[1] !== 0) return done(`FAIL socks reply ${buf[1]}`)
      buf = buf.subarray(10)
      stage = 2
      request()
    }
  } else if(stage === 0) {
    const i = buf.indexOf('\r\n\r\n')
    if(i < 0) return
    const head = buf.subarray(0, i).toString()
    if(!/^HTTP\/1\.[01] 200/.test(head)) return done(`FAIL ${head.split('\r\n')[0]}`)
    buf = buf.subarray(i + 4)
    stage = 2
    request()
  }
})
sock.on('end', () => {
  if(stage !== 2) return done('FAIL closed')
  const text = buf.toString()
  const i = text.indexOf('\r\n\r\n')
  done(i < 0 ? 'FAIL no response' : text.slice(i + 4).trim())
})
