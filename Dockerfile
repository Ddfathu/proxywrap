FROM node:20-bookworm-slim

WORKDIR /app

# 1. Install gpg, curl, ca-certificates
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gpg ca-certificates procps && \
    rm -rf /var/lib/apt/lists/*

# 2. Pasang GPG key & repo resmi Cloudflare WARP
RUN curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" | tee /etc/apt/sources.list.d/cloudflare-client.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends cloudflare-warp && \
    rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --production

COPY . .

ENV PORT=8080
EXPOSE 8080

# 3. Jalankan warp-svc di background, set mode proxy (port 40000), konek, lalu start node
CMD ["sh", "-c", "warp-svc & sleep 3 && warp-cli --accept-tos registration new 2>/dev/null || true && warp-cli --accept-tos mode proxy && warp-cli --accept-tos proxy port 40000 && warp-cli --accept-tos connect && sleep 2 && node server.js"]