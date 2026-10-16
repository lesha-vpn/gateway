import { spawn } from 'node:child_process'

export class CommandError extends Error {
  constructor(public cmd: string, public code: number | null, public stderr: string) {
    super(`${cmd}: ${stderr.trim() || `exit ${code}`}`)
  }
}

/** Run a command to completion; stdin optional. Rejects with CommandError on a non-zero exit. */
export function run(cmd: string, args: string[], input?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    child.stdout.on('data', d => { out += d })
    child.stderr.on('data', d => { err += d })
    child.on('error', e => reject(new CommandError([cmd, ...args].join(' '), null, e.message)))
    child.on('close', code => code === 0 ? resolve(out) : reject(new CommandError([cmd, ...args].join(' '), code, err)))
    child.stdin.end(input)
  })
}

/** Like run, but a failure is fine (deleting something that may not exist). */
export async function tryRun(cmd: string, args: string[]): Promise<boolean> {
  try {
    await run(cmd, args)
    return true
  } catch {
    return false
  }
}
