FROM node:20-alpine

WORKDIR /app

# 1. Pasang dependensi buat download binary
RUN apk add --no-cache wget tar ca-certificates

# 2. Download dan pasang binary warp-go
RUN wget https://gitlab.com/ProjectWARP/warp-go/-/releases/permalink/latest/downloads/warp-go_linux_amd64.tar.gz -O warp-go.tar.gz && \
    tar -xzvf warp-go.tar.gz && \
    chmod +x warp-go && \
    mv warp-go /usr/local/bin/ && \
    rm warp-go.tar.gz

COPY package.json ./
RUN npm install --production

COPY . .

ENV PORT=8080
EXPOSE 8080

# 3. Jalankan WARP socks5 di background (port 40000), baru start node server.js
CMD ["sh", "-c", "warp-go --register --config=warp.conf 2>/dev/null || true; warp-go --config=warp.conf --socks=127.0.0.1:40000 & sleep 2; node server.js"]
