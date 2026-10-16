# Лёша VPN gateway: amneziawg-go + amneziawg-tools + gost + the lesha-vpn-gw manager.
# Platforms: linux/amd64, linux/arm64, linux/arm/v7.

ARG AWG_GO_REF=v3.1.20260828
ARG AWG_TOOLS_REF=v3.1.20260812
ARG GOST_REF=v3.3.0

# Go binaries cross-compile on the build platform, no emulation
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS go
ARG TARGETOS TARGETARCH TARGETVARIANT AWG_GO_REF GOST_REF
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN git clone --depth 1 --branch ${AWG_GO_REF} https://github.com/amnezia-vpn/amneziawg-go /src/amneziawg-go \
 && git clone --depth 1 --branch ${GOST_REF} https://github.com/go-gost/gost /src/gost
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    export GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
 && cd /src/amneziawg-go && printf 'package main\n\nconst Version = "%s"\n' "${AWG_GO_REF}" > version.go \
 && go build -ldflags '-s -w' -o /out/amneziawg-go . \
 && cd /src/gost && go build -ldflags "-s -w -X main.version=${GOST_REF}" -o /out/gost ./cmd/gost

# awg is C; built for the target (emulated on foreign platforms, it is small) against musl,
# like the runtime. node:22-alpine is reused so there is one base to pull
FROM node:22-alpine AS tools
ARG AWG_TOOLS_REF
RUN apk add --no-cache git build-base linux-headers \
 && git clone --depth 1 --branch ${AWG_TOOLS_REF} https://github.com/amnezia-vpn/amneziawg-tools /src \
 && make -C /src/src -j"$(nproc)" wg \
 && install -m 0755 /src/src/wg /out-awg

# TypeScript compiles once, the output is platform-independent
FROM --platform=$BUILDPLATFORM node:22-alpine AS app
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npx tsc

# Alpine: musl, busybox; iproute2 for policy routing (busybox ip lacks rule/fwmark bits)
FROM node:22-alpine
RUN apk add --no-cache iproute2 nftables ca-certificates
COPY --from=go /out/amneziawg-go /out/gost /usr/local/bin/
COPY --from=tools /out-awg /usr/local/bin/awg
COPY --from=app /app/dist /opt/lesha-vpn-gw/dist
COPY package.json /opt/lesha-vpn-gw/
RUN printf '#!/bin/sh\nexec node /opt/lesha-vpn-gw/dist/main.js "$@"\n' > /usr/local/bin/lesha-vpn-gw \
 && chmod +x /usr/local/bin/lesha-vpn-gw
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD ["lesha-vpn-gw", "health"]
ENTRYPOINT ["lesha-vpn-gw"]
CMD ["run"]
