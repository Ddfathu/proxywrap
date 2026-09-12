FROM node:20-alpine

WORKDIR /app

# 1. Install curl & libc compatibility (gcompat) agar binary Go bisa jalan di Alpine
RUN apk add --no-cache curl tar ca-certificates gcompat

# 2. Download binary warp-go langsung dari mirror GitHub release yang valid
RUN curl -fsSL https://github.com/bEpI-gOiNg/warp-go/releases/download/v1.0.8/warp-go_linux_amd64.tar.gz -o warp-go.tar.gz && \
    tar -xzf warp-go.tar.gz && \
    chmod +x warp-go && \
    mv warp-go /usr/local/bin/ && \
    rm warp-go.tar.gz

COPY package.json ./
RUN npm install --production

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "warp-go --register --config=warp.conf 2>/dev/null || true; warp-go --config=warp.conf --socks=127.0.0.1:40000 & sleep 2; node server.js"]