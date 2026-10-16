/** One line per event on stdout, read with `docker logs`. */
function line(level: string, msg: string) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19)
  process.stdout.write(`${ts} ${level} ${msg}\n`)
}

export const log = {
  info: (msg: string) => line('INFO ', msg),
  warn: (msg: string) => line('WARN ', msg),
  error: (msg: string) => line('ERROR', msg),
}
