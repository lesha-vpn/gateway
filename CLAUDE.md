# CLAUDE.md

Docker gateway for Лёша VPN (`lesha-vpn-gw`): an AWG 3.1 tunnel to LOCAL as a regular coordinator client, plus SOCKS5/HTTP proxies (gost) and LAN gateway mode (forward + masquerade into awg0, DNS redirect, MSS clamp; examples/compose.gateway*.yml). User docs (Russian): `README.md`.

- The coordinator is `lesha-vpn/coordinator`; this repo only consumes its `/v1` API (login, me, configs, status), the same contract as the app fork `lesha-vpn/client`. Spec there: `docs/spec/coordinator-spec.md` (R-A8 is the refresh loop this mirrors).
- `src/` — TypeScript manager, no runtime npm deps. `daemon.ts` (state machine: login → config → tunnel → status loop), `api.ts` (`/v1` client, connects to resolved/cached API IPs), `tunnel.ts` (awg0 + policy routing, what awg-quick does without /proc/sys or resolvconf), `firewall.ts` (kill-switch nft ruleset, pure render), `conf.ts` (parse/strip `.conf`, peers-only vs interface change), `proxy.ts` (gost), `main.ts` (CLI).
- Invariants: the kill-switch is loaded before the tunnel and never removed; only awg's marked UDP (fwmark 51820) and TCP to the API addresses leave outside the tunnel; forwarded LAN traffic may only go out awg0. Peers-only config changes go through `awg syncconf`. FwMark is written into the setconf file, never set afterwards.
- Releases: bump `version` in package.json and `VERSION` in src/settings.ts together; a merge to main with an untagged version makes CI publish `:<ver>`/`:latest`, tag `v<ver>` and create the GitHub Release (cloud sessions can't push tags).
- Pinned upstreams in `Dockerfile`: amneziawg-go, amneziawg-tools, gost. Bump them together with an e2e run.
- Tests: `npm test` (vitest, next to code), `npm run e2e` (`test/e2e/run.sh`, Docker + /dev/net/tun). Keep the e2e green for any routing/firewall change.
- User-facing strings (logs, CLI, README) are Russian; code comments English.
