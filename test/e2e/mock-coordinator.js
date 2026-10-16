// Minimal stand-in for the coordinator /v1 API (the calls lesha-vpn-gw makes), driven by POST /control.
const http = require('node:http')
const crypto = require('node:crypto')
const fs = require('node:fs')

const TEMPLATE = fs.readFileSync(process.env.CONF_TEMPLATE, 'utf8')
const TOKEN = 'e2e-token'
const ctl = { endpoint: process.env.ENDPOINT, state: 'active', member: true }
let config = null // { id, name }
let lastLogin = null

const awg = () => TEMPLATE.replace('@ENDPOINT@', ctl.endpoint)
const revision = () => crypto.createHash('sha256').update(awg()).digest('hex').slice(0, 8)
const view = () => ({ id: config.id, name: config.name, revision: revision(), createdAt: '2026-10-16T00:00:00Z', awg: awg(), endpoint: ctl.endpoint })

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(body === undefined ? '' : JSON.stringify(body))
}
const err = (res, status, code) => send(res, status, { error: { code, message: code } })

http.createServer((req, res) => {
  let raw = ''
  req.on('data', c => { raw += c })
  req.on('end', () => {
    const body = raw ? JSON.parse(raw) : {}
    const url = new URL(req.url, 'http://x')
    const p = url.pathname
    console.log(req.method, req.url, raw)
    if(p === '/control' && req.method === 'POST') { Object.assign(ctl, body); return send(res, 200, { ...ctl, revision: revision() }) }
    if(p === '/control') return send(res, 200, { ...ctl, config, lastLogin })
    if(p === '/v1/auth/login' && req.method === 'POST') {
      if(body.code !== '123456') return err(res, 400, 'invalid_code')
      lastLogin = { deviceLabel: body.deviceLabel, appVersion: req.headers['x-app-version'] }
      return send(res, 200, { token: TOKEN, user: { tgId: 42, username: 'e2e' } })
    }
    if(req.headers.authorization !== `Bearer ${TOKEN}`) return err(res, 401, 'invalid_token')
    if(p === '/v1/auth/logout' && req.method === 'POST') return send(res, 204)
    if(!ctl.member) return err(res, 403, 'not_member')
    if(p === '/v1/me') return send(res, 200, { user: { tgId: 42, username: 'e2e' }, configs: config ? [{ ...config, revision: revision(), state: ctl.state, createdAt: '' }] : [] })
    if(p === '/v1/configs' && req.method === 'POST') {
      if(!/^[a-z0-9-]{1,32}$/.test(body.name)) return err(res, 400, 'invalid_name')
      config = { id: 'cfg1', name: body.name }
      return send(res, 201, view())
    }
    const m = /^\/v1\/configs\/([^/]+)(\/status)?$/.exec(p)
    if(m && config && m[1] === config.id) {
      if(m[2]) {
        const state = ctl.state !== 'active' ? ctl.state : url.searchParams.get('revision') === revision() ? 'ok' : 'outdated'
        return send(res, 200, { state, revision: revision(), network: 'ok', checkedAt: new Date().toISOString() })
      }
      if(ctl.state === 'revoked') return err(res, 404, 'not_found')
      return send(res, 200, view())
    }
    return err(res, 404, 'not_found')
  })
}).listen(8080, () => console.log('mock coordinator on :8080'))
