# Stage 1: Build binary warp-go langsung dari source
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
RUN git clone https://gitlab.com/ProjectWARP/warp-go.git . && \
    go build -v -ldflags "-w -s" -o warp-go

# Stage 2: Runtime Node.js
FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache ca-certificates

# Salin binary yang sudah ter-compile dari Stage 1
COPY --from=builder /build/warp-go /usr/local/bin/warp-go
RUN chmod +x /usr/local/bin/warp-go

COPY package.json ./
RUN npm install --production

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "warp-go --register --config=warp.conf 2>/dev/null || true; warp-go --config=warp.conf --socks=127.0.0.1:40000 & sleep 2; node server.js"]