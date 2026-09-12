FROM node:20-slim

WORKDIR /app

# 1. Install curl & ca-certificates
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates tar && \
    rm -rf /var/lib/apt/lists/*

# 2. Download binary warp-go langsung dari mirror fscarmen
RUN curl -fsSL https://raw.githubusercontent.com/fscarmen/warp/main/warp-go/warp-go_linux_amd64 -o /usr/local/bin/warp-go && \
    chmod +x /usr/local/bin/warp-go

COPY package.json ./
RUN npm install --production

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "warp-go --register --config=warp.conf 2>/dev/null || true; warp-go --config=warp.conf --socks=127.0.0.1:40000 & sleep 2; node server.js"]