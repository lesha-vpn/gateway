import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Api, ApiError } from './api'
import { Daemon, StatusFile } from './daemon'
import { run } from './exec'
import { IFACE } from './firewall'
import { log } from './log'
import { loadSettings, Settings, VERSION } from './settings'
import { Store } from './state'

const USAGE = `lesha-vpn-gw ${VERSION}

  lesha-vpn-gw run            запустить шлюз (по умолчанию в контейнере)
  lesha-vpn-gw login <код>    войти по коду из /login в боте
  lesha-vpn-gw logout         выйти и отозвать токен устройства
  lesha-vpn-gw status         состояние туннеля и конфига
  lesha-vpn-gw health         код выхода 0, если туннель жив (для HEALTHCHECK)
`

async function main(argv: string[]) {
  const [cmd = 'run', ...args] = argv
  if(cmd === '--version' || cmd === 'version') return console.log(VERSION)
  if(cmd === 'help' || cmd === '--help' || cmd === '-h') return console.log(USAGE)
  const s = loadSettings()
  switch(cmd) {
    case 'run': return runDaemon(s)
    case 'login': return login(s, args[0])
    case 'logout': return logout(s)
    case 'status': return status(s)
    case 'health': return health(s)
    default:
      console.error(USAGE)
      process.exitCode = 2
  }
}

async function runDaemon(s: Settings) {
  const d = new Daemon(s)
  let stopping = false
  const stop = async () => {
    if(stopping) return
    stopping = true
    log.info('Останавливаюсь')
    await d.stop()
    process.exit(0)
  }
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
  await d.start()
}

function apiFor(s: Settings, token: string | null) {
  const state = new Store(s.dataDir).read()
  return new Api({ baseUrl: s.coordinatorUrl, token, fallbackAddrs: state.apiAddrs })
}

async function login(s: Settings, code: string | undefined) {
  if(!code) {
    console.error('Использование: lesha-vpn-gw login <код>. Код выдаёт бот по команде /login')
    process.exitCode = 2
    return
  }
  const store = new Store(s.dataDir)
  try {
    const res = await apiFor(s, null).login(code.trim(), `gateway-${s.deviceName}`)
    store.writeToken(res.token)
    console.log(`Вход выполнен: ${res.user.username ? '@' + res.user.username : res.user.tgId}. Шлюз сейчас получит конфиг и поднимет туннель`)
  } catch(e) {
    if(e instanceof ApiError && e.code === 'invalid_code') console.error('Код неверный или устарел. Попроси новый: /login в боте')
    else if(e instanceof ApiError && e.code === 'rate_limited') console.error('Слишком много попыток, подожди минуту')
    else console.error(`Не удалось войти: ${(e as Error).message}`)
    process.exitCode = 1
  }
}

async function logout(s: Settings) {
  const store = new Store(s.dataDir)
  const token = store.readToken()
  if(!token) return console.log('Вход и так не выполнен')
  try {
    await apiFor(s, token).logout()
  } catch(e) {
    // The token is dropped locally either way; /devices in the bot can revoke it later
    if(!(e instanceof ApiError && e.status === 401)) console.error(`Координатор недоступен (${(e as Error).message}), токен удалён только локально; отзови его в боте через /devices`)
  }
  store.clearToken()
  console.log('Выход выполнен, туннель закрыт')
}

function readStatus(s: Settings): StatusFile | null {
  try {
    return JSON.parse(readFileSync(join(s.runDir, 'status.json'), 'utf8')) as StatusFile
  } catch {
    return null
  }
}

function status(s: Settings) {
  const st = readStatus(s)
  if(!st) {
    console.log('Шлюз не запущен')
    process.exitCode = 1
    return
  }
  const ago = (ms: number | null) => ms === null ? 'никогда' : `${Math.round((Date.now() - ms) / 1000)} с назад`
  const mb = (b: number) => `${(b / 1048576).toFixed(1)} МБ`
  const lines = [
    `Состояние:   ${st.message}`,
    `Аккаунт:     ${st.user ? (st.user.username ? '@' + st.user.username : st.user.tgId) : '—'}`,
    `Конфиг:      ${st.config ? `${st.config.name} (ревизия ${st.config.revision})` : '—'}`,
    `Туннель:     ${st.tunnel.up ? `поднят, ${st.tunnel.impl === 'kernel' ? 'модуль ядра' : 'amneziawg-go'}` : 'не поднят'}`,
    `Сервер:      ${st.tunnel.endpoint ?? st.tunnel.endpointConfigured ?? '—'}`,
    `Handshake:   ${ago(st.tunnel.latestHandshake)}`,
    `Трафик:      ↓ ${mb(st.tunnel.rx)}  ↑ ${mb(st.tunnel.tx)}`,
    `Координатор: ${st.coordinator.lastError ? `недоступен (${st.coordinator.lastError})` : st.coordinator.lastContact ? `на связи, сеть ${st.coordinator.network ?? '?'}` : '—'}`,
  ]
  console.log(lines.join('\n'))
}

async function health(s: Settings) {
  const st = readStatus(s)
  // A stale status file means the daemon hung
  const alive = st && Date.now() - Date.parse(st.updatedAt) < 60_000
  let fresh = false
  if(st?.phase === 'up' && alive) {
    try {
      const out = await run('awg', ['show', IFACE, 'latest-handshakes'])
      const hs = Math.max(0, ...out.trim().split('\n').map(l => Number(l.split('\t')[1]) || 0))
      fresh = hs > 0 && Date.now() - hs * 1000 < s.handshakeTimeoutMs
    } catch {
      // no interface
    }
    if(fresh) return
  }
  console.log(!st ? 'Шлюз не запущен' : !alive ? 'Демон не отвечает' : st.phase === 'up' ? 'Нет свежего handshake с сервером' : st.message)
  process.exitCode = 1
}

main(process.argv.slice(2)).catch(e => {
  console.error((e as Error).message)
  process.exit(1)
})
