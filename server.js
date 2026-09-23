import net from 'net';
import dgram from 'dgram';
import dns from 'dns';
import fs from 'fs';
import path from 'path';

const PORT = process.env.PORT || 8080;
const TCP_DOMAIN = process.env.RAILWAY_TCP_PROXY_DOMAIN || '';
const TCP_PORT = process.env.RAILWAY_TCP_PROXY_PORT || '';
const DB_PATH = path.resolve(process.env.DATA_DIR || './', 'proxy_data.json');

// --- STATE MANAGEMENT ---
const proxyUsers = new Map(); 
let PROXY_AUTH_MODE = 'NONE';

let RAW_TCP_CONFIG = {
  enabled: true,
  defaultTargetHost: 'speed.cloudflare.com',
  defaultTargetPort: 443
};

let DNS_CONFIG = {
  mode: 'DOH',
  activeName: 'Cloudflare DoH (Official)',
  dohUrl: 'https://cloudflare-dns.com/dns-query',
  udpServer: '1.1.1.1',
  udpPort: 53
};

const PRESETS = {
  'cf-doh': { name: 'Cloudflare DoH (Official)', type: 'DOH', url: 'https://cloudflare-dns.com/dns-query' },
  'google-doh': { name: 'Google DoH', type: 'DOH', url: 'https://dns.google/dns-query' },
  'quad9-doh': { name: 'Quad9 DoH (Security)', type: 'DOH', url: 'https://dns.quad9.net/dns-query' },
  'adguard-doh': { name: 'AdGuard DoH (Adblock)', type: 'DOH', url: 'https://dns.adguard-dns.com/dns-query' },
  'cf-udp': { name: 'Cloudflare UDP (1.1.1.1:53)', type: 'UDP', host: '1.1.1.1', port: 53 },
  'google-udp': { name: 'Google UDP (8.8.8.8:53)', type: 'UDP', host: '8.8.8.8', port: 53 },
  'quad9-udp': { name: 'Quad9 UDP (9.9.9.9:53)', type: 'UDP', host: '9.9.9.9', port: 53 }
};

function loadData() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf-8');
      const data = JSON.parse(raw);
      if (data.authMode) PROXY_AUTH_MODE = data.authMode;
      if (data.dnsConfig) DNS_CONFIG = data.dnsConfig;
      if (data.rawTcpConfig) RAW_TCP_CONFIG = { ...RAW_TCP_CONFIG, ...data.rawTcpConfig };
      if (Array.isArray(data.users)) {
        proxyUsers.clear();
        for (const [u, p] of data.users) {
          proxyUsers.set(u, p);
        }
      }
    }
  } catch (err) {
    console.error('[Storage Error] Failed to read database:', err.message);
  }
}

function saveData() {
  try {
    const payload = {
      authMode: PROXY_AUTH_MODE,
      dnsConfig: DNS_CONFIG,
      rawTcpConfig: RAW_TCP_CONFIG,
      users: Array.from(proxyUsers.entries())
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(payload, null, 2), 'utf-8');
  } catch (err) {
    console.error('[Storage Error] Failed to save database:', err.message);
  }
}

loadData();

let PROXY_SERVER_INFO = {
  domain: TCP_DOMAIN,
  port: TCP_PORT,
  ip: '',
  fullProxy: ''
};

function updateRailwayProxyIP() {
  if (TCP_DOMAIN) {
    dns.lookup(TCP_DOMAIN, (err, address) => {
      if (!err && address) {
        PROXY_SERVER_INFO.ip = address;
        PROXY_SERVER_INFO.fullProxy = `${address}:${TCP_PORT}`;
      } else {
        PROXY_SERVER_INFO.ip = TCP_DOMAIN;
        PROXY_SERVER_INFO.fullProxy = `${TCP_DOMAIN}:${TCP_PORT}`;
      }
    });
  } else {
    PROXY_SERVER_INFO.fullProxy = 'TCP Proxy Not Set';
  }
}
updateRailwayProxyIP();
setInterval(updateRailwayProxyIP, 1000 * 60 * 30);

const activeConnections = new Map();
let connectionIdCounter = 0;
let globalTotalBytesIn = 0;
let globalTotalBytesOut = 0;
const dnsCache = new Map();

async function resolveDomain(hostname) {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached && (now - cached.time < 1000 * 60 * 10)) {
    return cached.ip;
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return hostname;
  }

  if (DNS_CONFIG.mode === 'DOH') {
    try {
      const url = new URL(DNS_CONFIG.dohUrl);
      url.searchParams.set('name', hostname);
      url.searchParams.set('type', 'A');

      const res = await fetch(url.toString(), {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(1800)
      });
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        const aRecord = data.Answer.find(ans => ans.type === 1);
        if (aRecord && aRecord.data) {
          dnsCache.set(hostname, { ip: aRecord.data, time: now });
          return aRecord.data;
        }
      }
    } catch (_) {}
  }

  if (DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer) {
    try {
      const resolver = new dns.Resolver();
      resolver.setServers([`${DNS_CONFIG.udpServer}:${DNS_CONFIG.udpPort || 53}`]);
      return await new Promise((resolve, reject) => {
        resolver.resolve4(hostname, (err, addresses) => {
          if (!err && addresses && addresses.length > 0) {
            dnsCache.set(hostname, { ip: addresses[0], time: now });
            resolve(addresses[0]);
          } else {
            reject(err);
          }
        });
      });
    } catch (_) {}
  }

  return new Promise((resolve) => {
    dns.lookup(hostname, (err, address) => {
      const ip = (!err && address) ? address : '104.16.123.96';
      dnsCache.set(hostname, { ip, time: now });
      resolve(ip);
    });
  });
}

function checkHttpAuth(dataStr) {
  if (PROXY_AUTH_MODE === 'NONE') return true;
  if (proxyUsers.size === 0) return true;
  const match = dataStr.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
  if (!match) return false;
  try {
    const creds = Buffer.from(match[1], 'base64').toString('utf-8').split(':');
    const u = creds[0];
    const p = creds.slice(1).join(':');
    return proxyUsers.has(u) && proxyUsers.get(u) === p;
  } catch (_) {
    return false;
  }
}

function parseRequestBody(raw) {
  const delimiterIndex = raw.indexOf('\r\n\r\n');
  if (delimiterIndex === -1) return {};
  const bodyStr = raw.slice(delimiterIndex + 4);
  try {
    return JSON.parse(bodyStr);
  } catch (_) {
    return {};
  }
}

const server = net.createServer({ 
  noDelay: true,
  allowHalfOpen: false,
  pauseOnConnect: false
}, (clientSocket) => {
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 5000);
  clientSocket.setMaxListeners(0);

  const connId = ++connectionIdCounter;
  const rawIp = clientSocket.remoteAddress || 'Unknown';
  const clientIp = rawIp.replace('::ffff:', '');
  const startTime = Date.now();

  const connData = {
    id: connId,
    clientIp,
    type: 'INITIALIZING',
    target: 'pending',
    startTime,
    bytesIn: 0,
    bytesOut: 0
  };

  let isFirstPacket = true;
  let targetSocket = null;
  let udpRelay = null;
  let socksState = 0;
  let httpBuffer = '';

  const bridgeSockets = (sockA, sockB) => {
    sockA.on('data', (d) => { 
      connData.bytesIn += d.length;
      globalTotalBytesIn += d.length;
    });
    sockB.on('data', (d) => { 
      connData.bytesOut += d.length;
      globalTotalBytesOut += d.length;
    });

    sockA.pipe(sockB, { end: true });
    sockB.pipe(sockA, { end: true });

    const cleanup = () => {
      activeConnections.delete(connId);
      sockA.destroy();
      sockB.destroy();
    };

    sockA.on('error', cleanup);
    sockB.on('error', cleanup);
    sockA.on('close', cleanup);
    sockB.on('close', cleanup);
  };

  // --- SOCKS5 HANDLER (TCP CONNECT & UDP ASSOCIATE) ---
  const handleSocks5 = async (chunk) => {
    if (socksState === 0) {
      const nmethods = chunk[1];
      const methods = chunk.slice(2, 2 + nmethods);
      const requiresAuth = (PROXY_AUTH_MODE === 'AUTH' && proxyUsers.size > 0);

      if (requiresAuth) {
        if (!methods.includes(0x02)) {
          clientSocket.write(Buffer.from([0x05, 0xFF]));
          return clientSocket.end();
        }
        socksState = 1;
        clientSocket.write(Buffer.from([0x05, 0x02]));
      } else {
        socksState = 2;
        clientSocket.write(Buffer.from([0x05, 0x00]));
      }
      return;
    }

    if (socksState === 1) {
      if (chunk[0] !== 0x01) return clientSocket.end();
      const uLen = chunk[1];
      const username = chunk.slice(2, 2 + uLen).toString('utf-8');
      const pLen = chunk[2 + uLen];
      const password = chunk.slice(3 + uLen, 3 + uLen + pLen).toString('utf-8');

      if (proxyUsers.has(username) && proxyUsers.get(username) === password) {
        socksState = 2;
        clientSocket.write(Buffer.from([0x01, 0x00]));
      } else {
        clientSocket.write(Buffer.from([0x01, 0x01]));
        return clientSocket.end();
      }
      return;
    }

    if (socksState === 2) {
      const cmd = chunk[1]; // 0x01 = CONNECT (TCP), 0x03 = UDP ASSOCIATE (QUIC/UDP)

      if (cmd === 0x03) {
        // --- FITUR QUIC UDP RELAY ---
        connData.type = 'SOCKS5 UDP (QUIC)';
        connData.target = 'UDP Associate Relay';
        activeConnections.set(connId, connData);

        udpRelay = dgram.createSocket('udp4');
        let clientUdpAddr = null;

        udpRelay.on('message', async (msg, rinfo) => {
          // Tangkap paket dari browser client
          if (!clientUdpAddr) {
            clientUdpAddr = { address: rinfo.address, port: rinfo.port };
          }

          if (rinfo.address === clientUdpAddr.address && rinfo.port === clientUdpAddr.port) {
            // Header SOCKS5 UDP: [RSV(2), FRAG(1), ATYP(1), DST.ADDR, DST.PORT]
            if (msg.length < 10) return;
            const atyp = msg[3];
            let offset = 4;
            let destHost = '';

            if (atyp === 0x01) { // IPv4
              destHost = `${msg[4]}.${msg[5]}.${msg[6]}.${msg[7]}`;
              offset += 4;
            } else if (atyp === 0x03) { // Domain
              const dlen = msg[4];
              destHost = msg.slice(5, 5 + dlen).toString();
              offset += 1 + dlen;
            } else {
              return;
            }

            const destPort = msg.readUInt16BE(offset);
            offset += 2;
            const payload = msg.slice(offset);

            connData.bytesIn += payload.length;
            globalTotalBytesIn += payload.length;

            try {
              const targetIp = await resolveDomain(destHost);
              udpRelay.send(payload, destPort, targetIp);
            } catch (_) {}
          } else {
            // Tangkap respon UDP dari server remote lalu bungkus balik ke format SOCKS5 UDP
            const resHeader = Buffer.from([0x00, 0x00, 0x00, 0x01]);
            const ipParts = Buffer.from(rinfo.address.split('.').map(x => parseInt(x, 10)));
            const portBuf = Buffer.alloc(2);
            portBuf.writeUInt16BE(rinfo.port);

            const outboundPacket = Buffer.concat([resHeader, ipParts, portBuf, msg]);
            connData.bytesOut += msg.length;
            globalTotalBytesOut += msg.length;

            if (clientUdpAddr) {
              udpRelay.send(outboundPacket, clientUdpAddr.port, clientUdpAddr.address);
            }
          }
        });

        udpRelay.bind(0, () => {
          const relayPort = udpRelay.address().port;
          const boundAddr = clientSocket.localAddress || '0.0.0.0';
          const ipParts = boundAddr.includes('.') ? boundAddr.split('.').map(x => parseInt(x, 10)) : [0, 0, 0, 0];

          // Kirim balasan SOCKS5 sukses ke browser: Berikan port UDP yang siap menerima paket QUIC
          const reply = Buffer.alloc(10);
          reply[0] = 0x05; // VER
          reply[1] = 0x00; // SUCCESS
          reply[2] = 0x00; // RSV
          reply[3] = 0x01; // IPv4
          reply[4] = ipParts[0];
          reply[5] = ipParts[1];
          reply[6] = ipParts[2];
          reply[7] = ipParts[3];
          reply.writeUInt16BE(relayPort, 8);
          clientSocket.write(reply);
        });

        // Kontrol TCP tetap terbuka sampai client memutuskan sesi
        clientSocket.on('close', () => {
          if (udpRelay) {
            try { udpRelay.close(); } catch (_) {}
          }
          activeConnections.delete(connId);
        });
        clientSocket.on('error', () => {
          if (udpRelay) {
            try { udpRelay.close(); } catch (_) {}
          }
        });
        return;
      }

      // Standar SOCKS5 TCP CONNECT (0x01)
      if (cmd !== 0x01) {
        clientSocket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return clientSocket.end();
      }

      let targetHost = '';
      let targetPort = 0;
      const atyp = chunk[3];

      if (atyp === 0x01) {
        targetHost = `${chunk[4]}.${chunk[5]}.${chunk[6]}.${chunk[7]}`;
        targetPort = chunk.readUInt16BE(8);
      } else if (atyp === 0x03) {
        const dLen = chunk[4];
        targetHost = chunk.slice(5, 5 + dLen).toString('utf-8');
        targetPort = chunk.readUInt16BE(5 + dLen);
      } else {
        clientSocket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return clientSocket.end();
      }

      connData.type = 'SOCKS5';
      connData.target = `${targetHost}:${targetPort}`;
      activeConnections.set(connId, connData);

      try {
        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 5000);
          clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x10, 0x10]));
          clientSocket.removeAllListeners('data');
          bridgeSockets(clientSocket, targetSocket);
        });

        targetSocket.on('error', () => {
          activeConnections.delete(connId);
          clientSocket.destroy();
        });
      } catch (err) {
        clientSocket.write(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        clientSocket.end();
      }
    }
  };

  clientSocket.on('data', async (chunk) => {
    if (socksState > 0) return handleSocks5(chunk);

    if (isFirstPacket) {
      if (chunk[0] === 0x05) {
        isFirstPacket = false;
        return handleSocks5(chunk);
      }

      const chunkStr = chunk.toString('utf-8');

      // HTTP Web Dashboard & API
      if (/^(GET|POST|PUT|DELETE|OPTIONS|HEAD)\s/i.test(chunkStr)) {
        httpBuffer += chunkStr;

        const contentLenMatch = httpBuffer.match(/Content-Length:\s*(\d+)/i);
        const headerEnd = httpBuffer.indexOf('\r\n\r\n');
        
        if (contentLenMatch && headerEnd !== -1) {
          const expectedLen = parseInt(contentLenMatch[1], 10);
          const bodyLen = Buffer.byteLength(httpBuffer.slice(headerEnd + 4));
          if (bodyLen < expectedLen) return;
        } else if (headerEnd === -1 && httpBuffer.startsWith('POST')) {
          return;
        }

        isFirstPacket = false;
        const dataStr = httpBuffer;
        const firstLine = dataStr.split('\r\n')[0];
        const pathUrl = firstLine.split(' ')[1] || '/';

        // API: Set DNS Langsung
        if (pathUrl.startsWith('/api/set-dns') && dataStr.startsWith('POST')) {
          try {
            const body = parseRequestBody(dataStr);
            if (body.preset && PRESETS[body.preset]) {
              const p = PRESETS[body.preset];
              DNS_CONFIG.mode = p.type;
              DNS_CONFIG.activeName = p.name;
              if (p.type === 'DOH') DNS_CONFIG.dohUrl = p.url;
              else { DNS_CONFIG.udpServer = p.host; DNS_CONFIG.udpPort = p.port; }
            } else if (body.mode === 'DOH') {
              DNS_CONFIG.mode = 'DOH';
              DNS_CONFIG.activeName = 'Custom DoH';
              DNS_CONFIG.dohUrl = body.dohUrl || 'https://cloudflare-dns.com/dns-query';
            } else if (body.mode === 'UDP') {
              DNS_CONFIG.mode = 'UDP';
              DNS_CONFIG.activeName = 'Custom UDP';
              DNS_CONFIG.udpServer = body.udpServer || '1.1.1.1';
              DNS_CONFIG.udpPort = parseInt(body.udpPort, 10) || 53;
            }

            saveData();
            dnsCache.clear();
            const resBody = JSON.stringify({ success: true, config: DNS_CONFIG });
            clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          } catch (e) {
            const errBody = JSON.stringify({ success: false, error: e.message });
            clientSocket.write(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: ${errBody.length}\r\nConnection: close\r\n\r\n${errBody}`);
          }
          clientSocket.end();
          return;
        }

        // API: Set RAW TCP Langsung
        if (pathUrl === '/api/set-raw-tcp' && dataStr.startsWith('POST')) {
          const body = parseRequestBody(dataStr);
          RAW_TCP_CONFIG.enabled = !!body.enabled;
          if (body.defaultTargetHost) RAW_TCP_CONFIG.defaultTargetHost = body.defaultTargetHost.trim();
          if (body.defaultTargetPort) RAW_TCP_CONFIG.defaultTargetPort = parseInt(body.defaultTargetPort, 10) || 443;
          saveData();
          const resBody = JSON.stringify({ success: true, config: RAW_TCP_CONFIG });
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // API: Manage Proxy Users
        if (pathUrl === '/api/manage-users' && dataStr.startsWith('POST')) {
          const body = parseRequestBody(dataStr);
          if (body.action === 'add' && body.username && body.password) {
            proxyUsers.set(body.username.trim(), body.password.trim());
            saveData();
          } else if (body.action === 'delete' && body.username) {
            proxyUsers.delete(body.username);
            saveData();
          } else if (body.action === 'set-mode' && body.mode) {
            PROXY_AUTH_MODE = body.mode;
            saveData();
          }
          const resBody = JSON.stringify({ success: true });
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // API: Stats Realtime
        if (pathUrl === '/api/stats') {
          const activeList = Array.from(activeConnections.values())
            .filter(c => !c.target.includes('railway.com') && !c.target.includes('up.railway.app'))
            .map(c => ({
              id: c.id,
              clientIp: c.clientIp,
              type: c.type,
              target: c.target,
              uptime: Math.floor((Date.now() - c.startTime) / 1000),
              bytesIn: formatBytes(c.bytesIn),
              bytesOut: formatBytes(c.bytesOut)
            }));

          const userObjects = [];
          proxyUsers.forEach((pass, user) => {
            userObjects.push({ username: user, password: pass });
          });

          const resBody = JSON.stringify({
            proxyInfo: PROXY_SERVER_INFO,
            dnsConfig: DNS_CONFIG,
            rawTcpConfig: RAW_TCP_CONFIG,
            authMode: PROXY_AUTH_MODE,
            userList: userObjects,
            totalActive: activeList.length,
            globalTotalIn: formatBytes(globalTotalBytesIn),
            globalTotalOut: formatBytes(globalTotalBytesOut),
            connections: activeList
          });

          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ${Buffer.byteLength(resBody)}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // Dashboard Web UI
        if (pathUrl === '/' || pathUrl === '/index.html') {
          const html = renderDashboardHTML();
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(html)}\r\nConnection: close\r\n\r\n${html}`);
          clientSocket.end();
          return;
        }

        // HTTP Forward Proxy
        if (!checkHttpAuth(dataStr)) {
          const authReq = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          clientSocket.write(authReq);
          return clientSocket.end();
        }

        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
          connData.type = 'HTTP SCAN';
          connData.target = `${targetHost}:${targetPort}`;
          activeConnections.set(connId, connData);
        }

        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 5000);
          targetSocket.write(Buffer.from(httpBuffer));
          bridgeSockets(clientSocket, targetSocket);
        });

        targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
        return;
      }

      isFirstPacket = false;

      // HTTPS CONNECT Proxy
      const dataStr = chunk.toString('utf-8');
      if (dataStr.startsWith('CONNECT ')) {
        if (!checkHttpAuth(dataStr)) {
          const authReq = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          clientSocket.write(authReq);
          return clientSocket.end();
        }

        const match = dataStr.match(/CONNECT\s+([^:\s]+):(\d+)/i);
        if (match) {
          const targetHost = match[1];
          const targetPort = parseInt(match[2], 10) || 443;

          if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
            connData.type = 'HTTPS TUNNEL';
            connData.target = `${targetHost}:${targetPort}`;
            activeConnections.set(connId, connData);
          }

          const resolvedIp = await resolveDomain(targetHost);
          targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
            targetSocket.setNoDelay(true);
            targetSocket.setKeepAlive(true, 5000);
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            bridgeSockets(clientSocket, targetSocket);
          });

          targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
          return;
        }
      }

      // STREAM RAW TCP / VLESS / TROJAN / SNI ROUTER
      const sni = parseTlsSni(chunk);
      let destinationHost = '';
      let destinationPort = 443;

      if (sni) {
        destinationHost = sni;
        connData.type = 'VLESS/TLS (SNI)';
      } else if (RAW_TCP_CONFIG.enabled) {
        destinationHost = RAW_TCP_CONFIG.defaultTargetHost;
        destinationPort = RAW_TCP_CONFIG.defaultTargetPort;
        connData.type = 'RAW TCP MENTAH';
      } else {
        destinationHost = 'speed.cloudflare.com';
        connData.type = 'DIRECT FALLBACK';
      }

      connData.target = `${destinationHost}:${destinationPort}`;
      activeConnections.set(connId, connData);

      const resolvedIp = await resolveDomain(destinationHost);
      targetSocket = net.connect({ host: resolvedIp, port: destinationPort, noDelay: true }, () => {
        targetSocket.setNoDelay(true);
        targetSocket.setKeepAlive(true, 5000);
        targetSocket.write(chunk);
        bridgeSockets(clientSocket, targetSocket);
      });

      targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
    }
  });

  clientSocket.on('error', () => { 
    activeConnections.delete(connId); 
    if (targetSocket) targetSocket.destroy(); 
    if (udpRelay) { try { udpRelay.close(); } catch (_) {} }
  });
  clientSocket.on('close', () => { 
    activeConnections.delete(connId); 
    if (targetSocket) targetSocket.destroy(); 
    if (udpRelay) { try { udpRelay.close(); } catch (_) {} }
  });
});

function parseTlsSni(buffer) {
  try {
    if (buffer[0] !== 0x16) return null;
    let pos = 43;
    if (pos >= buffer.length) return null;
    const sessionIdLen = buffer[pos];
    pos += 1 + sessionIdLen;
    const cipherSuitesLen = buffer.readUInt16BE(pos);
    pos += 2 + cipherSuitesLen;
    const compMethodsLen = buffer[pos];
    pos += 1 + compMethodsLen;
    if (pos >= buffer.length) return null;
    const extensionsLen = buffer.readUInt16BE(pos);
    pos += 2;
    const endExtensions = pos + extensionsLen;
    while (pos + 4 <= endExtensions && pos + 4 <= buffer.length) {
      const extType = buffer.readUInt16BE(pos);
      const extLen = buffer.readUInt16BE(pos + 2);
      pos += 4;
      if (extType === 0) {
        let sniPos = pos + 2;
        if (buffer[sniPos] === 0) {
          const nameLen = buffer.readUInt16BE(sniPos + 1);
          return buffer.toString('utf8', sniPos + 3, sniPos + 3 + nameLen);
        }
      }
      pos += extLen;
    }
  } catch (_) { return null; }
  return null;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function renderDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Proxy Hub & UI Controller</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #06090e; color: #00ffcc; padding: 14px; margin: 0; display: flex; justify-content: center; }
    .card { background: #0c121e; border: 1px solid #00ffcc; box-shadow: 0 0 20px rgba(0,255,204,0.15); border-radius: 14px; max-width: 520px; width: 100%; padding: 18px; }
    h2 { margin: 0 0 16px 0; color: #38bdf8; text-align: center; font-size: 1.2rem; }
    .proxy-box { background: #030712; border: 1px solid #38bdf8; border-radius: 10px; padding: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .proxy-title { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
    .proxy-val { font-family: monospace; font-size: 1.05rem; font-weight: bold; color: #39ff14; word-break: break-all; }
    .btn-copy { background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 8px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; cursor: pointer; }
    .badge-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 18px; }
    .badge { background: #030712; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 10px; text-align: center; }
    .badge h4 { margin: 0; font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; }
    .badge .val { font-size: 1.15rem; font-weight: bold; margin-top: 5px; font-family: monospace; }
    .badge .sub-val { font-size: 0.68rem; color: #94a3b8; margin-top: 3px; font-family: monospace; word-break: break-all; }
    .section-title { font-size: 0.85rem; font-weight: bold; color: #38bdf8; margin-top: 16px; margin-bottom: 10px; }
    .conn-list { display: flex; flex-direction: column; gap: 8px; max-height: 180px; overflow-y: auto; margin-top: 8px; }
    .conn-item { background: #030712; border: 1px solid #1e293b; border-left: 3px solid #39ff14; border-radius: 8px; padding: 8px 10px; font-size: 0.8rem; }
    .tag { background: #032b17; color: #39ff14; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; }
    select, input { width: 100%; padding: 10px; background: #030712; border: 1px solid #1e293b; border-radius: 6px; color: #fff; margin-top: 6px; font-family: monospace; font-size: 0.82rem; }
    button { width: 100%; padding: 10px; background: #00ffcc; color: #000; font-weight: bold; border: none; border-radius: 6px; margin-top: 10px; cursor: pointer; }
    .btn-del { background: #ef4444; color: #fff; padding: 4px 8px; border-radius: 4px; border: none; cursor: pointer; font-size: 0.7rem; width: auto; margin-top: 0; }
    .user-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    .user-table td { padding: 6px 4px; border-bottom: 1px solid #1e293b; font-size: 0.8rem; font-family: monospace; }
    .panel { background: #070d17; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; margin-top: 14px; }
    .hint { font-size: 0.72rem; color: #94a3b8; margin-top: 4px; }
    .toast { display: none; padding: 8px; text-align: center; border-radius: 6px; margin-top: 10px; font-size: 0.8rem; font-weight: bold; background: #052e16; color: #4ade80; border: 1px solid #4ade80; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚡ MULTI-PROTOCOL PROXY HUB</h2>
    
    <div class="proxy-box">
      <div>
        <div class="proxy-title">🚀 Endpoint Proxy (HTTP/S, SOCKS5 + UDP, RAW TCP)</div>
        <div class="proxy-val" id="proxy_full_text">${PROXY_SERVER_INFO.fullProxy || 'Loading...'}</div>
      </div>
      <button class="btn-copy" onclick="navigator.clipboard.writeText(document.getElementById('proxy_full_text').innerText)">📋 SALIN</button>
    </div>

    <div class="badge-grid">
      <div class="badge">
        <h4>Koneksi Aktif</h4>
        <div class="val" style="color:#39ff14;" id="active_count">0</div>
      </div>
      <div class="badge">
        <h4>Status DNS</h4>
        <div class="val" style="color:#38bdf8; font-size:1.0rem;" id="badge_dns_mode">${DNS_CONFIG.mode}</div>
        <div class="sub-val" id="badge_dns_target">${DNS_CONFIG.mode === 'DOH' ? DNS_CONFIG.dohUrl : DNS_CONFIG.udpServer + ':' + DNS_CONFIG.udpPort}</div>
      </div>
      <div class="badge">
        <h4>Total In (RX)</h4>
        <div class="val" style="color:#00ffcc;" id="total_rx">0 B</div>
      </div>
      <div class="badge">
        <h4>Total Out (TX)</h4>
        <div class="val" style="color:#f59e0b;" id="total_tx">0 B</div>
      </div>
    </div>

    <div class="panel" style="border-color:#38bdf8;">
      <div class="section-title" style="margin:0; color:#38bdf8;">🌐 PENGATURAN DNS RESOLVER</div>
      <div class="hint">Pilih preset DoH/UDP atau custom untuk mempercepat pemutaran YouTube:</div>

      <select id="preset_select" onchange="applyPresetUI()">
        <option value="cf-doh" ${DNS_CONFIG.mode === 'DOH' && DNS_CONFIG.dohUrl.includes('cloudflare') ? 'selected' : ''}>⚡ Cloudflare DoH (Official)</option>
        <option value="google-doh" ${DNS_CONFIG.mode === 'DOH' && DNS_CONFIG.dohUrl.includes('google') ? 'selected' : ''}>⚡ Google DoH (Official)</option>
        <option value="cf-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '1.1.1.1' ? 'selected' : ''}>🚀 Cloudflare UDP 1.1.1.1:53 (Paling Cepat)</option>
        <option value="google-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '8.8.8.8' ? 'selected' : ''}>🚀 Google UDP 8.8.8.8:53 (Bagus untuk YouTube)</option>
        <option value="quad9-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '9.9.9.9' ? 'selected' : ''}>🛡️ Quad9 UDP 9.9.9.9:53</option>
        <option value="quad9-doh">🛡️ Quad9 DoH (Security)</option>
        <option value="adguard-doh">🛑 AdGuard DoH (Adblock)</option>
        <option value="custom_doh">✏️ Custom DoH URL (Pribadi)</option>
        <option value="custom_udp">✏️ Custom UDP DNS IP & Port (Pribadi)</option>
      </select>

      <div id="box_custom_doh" style="display:none; margin-top:8px;">
        <label style="font-size:0.75rem; color:#94a3b8;">Masukkan URL DoH Kustom:</label>
        <input type="text" id="custom_doh_url" placeholder="https://dns.nextdns.io/xxxxxx" value="${DNS_CONFIG.dohUrl}">
      </div>

      <div id="box_custom_udp" style="display:none; margin-top:8px;">
        <label style="font-size:0.75rem; color:#94a3b8;">IP Server DNS UDP:</label>
        <input type="text" id="custom_udp_ip" placeholder="Contoh: 1.1.1.1 atau 8.8.8.8" value="${DNS_CONFIG.udpServer}">
        <label style="font-size:0.75rem; color:#94a3b8; margin-top:4px; display:block;">Port DNS UDP:</label>
        <input type="number" id="custom_udp_port" placeholder="Default: 53" value="${DNS_CONFIG.udpPort || 53}">
      </div>

      <button style="background:#38bdf8;" onclick="saveDns()">💾 TERAPKAN DNS BARU</button>
      <div id="dns_toast" class="toast">✅ DNS Berhasil Diperbarui & Cache Direset!</div>
    </div>

    <div class="panel" style="border-color:#a855f7;">
      <div class="section-title" style="margin:0; color:#c084fc;">🛠️ KONTROL PROXY RAW TCP</div>
      <label style="font-size:0.75rem; color:#94a3b8; margin-top:8px; display:block;">Status Raw TCP:</label>
      <select id="raw_tcp_switch">
        <option value="true" ${RAW_TCP_CONFIG.enabled ? 'selected' : ''}>🟢 AKTIF (Terima Paket Mentah)</option>
        <option value="false" ${!RAW_TCP_CONFIG.enabled ? 'selected' : ''}>🔴 NONAKTIF</option>
      </select>

      <label style="font-size:0.75rem; color:#94a3b8; margin-top:8px; display:block;">Default Target Host (Jika Tanpa SNI):</label>
      <input type="text" id="raw_tcp_host" value="${RAW_TCP_CONFIG.defaultTargetHost}">

      <label style="font-size:0.75rem; color:#94a3b8; margin-top:8px; display:block;">Default Target Port:</label>
      <input type="number" id="raw_tcp_port" value="${RAW_TCP_CONFIG.defaultTargetPort}">

      <button style="background:#a855f7; color:#fff;" onclick="saveRawTcp()">💾 SIMPAN PENGATURAN RAW TCP</button>
    </div>

    <div class="panel">
      <div class="section-title" style="margin:0;">👤 USER & PASSWORD PROXY</div>
      <div class="hint">Gunakan mode NONE untuk public/bebas auth:</div>

      <div style="margin-top:10px;">
        <label style="font-size:0.75rem; color:#94a3b8;">Enforce Mode:</label>
        <select id="select_auth_mode" onchange="changeAuthMode()">
          <option value="NONE" ${PROXY_AUTH_MODE === 'NONE' ? 'selected' : ''}>Tanpa Auth (Public Proxy - Rekomendasi)</option>
          <option value="AUTH" ${PROXY_AUTH_MODE === 'AUTH' ? 'selected' : ''}>Wajib User & Password (Private Proxy)</option>
        </select>
      </div>

      <table class="user-table">
        <tbody id="user_list_body"></tbody>
      </table>

      <div style="display:flex; gap:6px; margin-top:10px;">
        <input type="text" id="new_proxy_user" placeholder="User Baru">
        <input type="text" id="new_proxy_pass" placeholder="Pass Baru">
      </div>
      <button onclick="addUser()">+ TAMBAH USER PROXY</button>
    </div>

    <div class="section-title">🟢 LIVE CONNECTIONS (REALTIME)</div>
    <div class="conn-list" id="conn_container"></div>
  </div>

  <script>
    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('active_count').innerText = data.totalActive;
        document.getElementById('total_rx').innerText = data.globalTotalIn;
        document.getElementById('total_tx').innerText = data.globalTotalOut;

        if (data.proxyInfo && data.proxyInfo.fullProxy) {
          document.getElementById('proxy_full_text').innerText = data.proxyInfo.fullProxy;
        }

        if (data.dnsConfig) {
          document.getElementById('badge_dns_mode').innerText = data.dnsConfig.mode + ' (' + (data.dnsConfig.activeName || 'Active') + ')';
          document.getElementById('badge_dns_target').innerText = data.dnsConfig.mode === 'DOH' 
            ? data.dnsConfig.dohUrl 
            : data.dnsConfig.udpServer + ':' + data.dnsConfig.udpPort;
        }

        if (data.authMode) {
          document.getElementById('select_auth_mode').value = data.authMode;
        }

        renderUsers(data.userList);

        const container = document.getElementById('conn_container');
        if (!data.connections || data.connections.length === 0) {
          container.innerHTML = '<div style="text-align:center;color:#64748b;font-size:0.75rem;padding:10px;">Belum ada perangkat terhubung...</div>';
          return;
        }
        container.innerHTML = data.connections.map(c => \`
          <div class="conn-item">
            <div style="display:flex; justify-content:space-between;">
              <b>\${c.clientIp}</b>
              <span class="tag">\${c.type}</span>
            </div>
            <div style="color:#38bdf8; word-break:break-all; font-family:monospace; margin:2px 0;">🎯 \${c.target}</div>
            <div style="color:#94a3b8; font-size:0.7rem;">⏱️ \${c.uptime}s | RX: \${c.bytesIn} | TX: \${c.bytesOut}</div>
          </div>
        \`).join('');
      } catch (e) {}
    }

    function renderUsers(users) {
      const tbody = document.getElementById('user_list_body');
      if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="color:#64748b; text-align:center;">Belum ada user proxy ditambahkan.</td></tr>';
        return;
      }
      tbody.innerHTML = users.map(u => \`
        <tr>
          <td>👤 <b>\${u.username}</b></td>
          <td style="color:#94a3b8;">🔑 \${u.password}</td>
          <td style="text-align:right;"><button class="btn-del" onclick="deleteUser('\${u.username}')">Hapus</button></td>
        </tr>
      \`).join('');
    }

    function applyPresetUI() {
      const val = document.getElementById('preset_select').value;
      document.getElementById('box_custom_doh').style.display = (val === 'custom_doh') ? 'block' : 'none';
      document.getElementById('box_custom_udp').style.display = (val === 'custom_udp') ? 'block' : 'none';
    }

    async function saveDns() {
      const selected = document.getElementById('preset_select').value;
      let payload = {};

      if (selected === 'custom_doh') {
        payload = { mode: 'DOH', dohUrl: document.getElementById('custom_doh_url').value.trim() };
      } else if (selected === 'custom_udp') {
        payload = {
          mode: 'UDP',
          udpServer: document.getElementById('custom_udp_ip').value.trim(),
          udpPort: document.getElementById('custom_udp_port').value.trim()
        };
      } else {
        payload = { preset: selected };
      }

      const res = await fetch('/api/set-dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        const toast = document.getElementById('dns_toast');
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 3000);
        fetchStats();
      }
    }

    async function saveRawTcp() {
      const enabled = document.getElementById('raw_tcp_switch').value === 'true';
      const host = document.getElementById('raw_tcp_host').value.trim();
      const port = document.getElementById('raw_tcp_port').value.trim();

      const res = await fetch('/api/set-raw-tcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, defaultTargetHost: host, defaultTargetPort: port })
      });
      if (res.ok) {
        alert('✅ Pengaturan Raw TCP Berhasil Disimpan!');
        fetchStats();
      }
    }

    async function addUser() {
      const u = document.getElementById('new_proxy_user').value.trim();
      const p = document.getElementById('new_proxy_pass').value.trim();
      if (!u || !p) return alert('Isi user dan password proxy!');
      const res = await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add', username: u, password: p })
      });
      if (res.ok) {
        document.getElementById('new_proxy_user').value = '';
        document.getElementById('new_proxy_pass').value = '';
        fetchStats();
      }
    }

    async function deleteUser(u) {
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete', username: u })
      });
      fetchStats();
    }

    async function changeAuthMode() {
      const mode = document.getElementById('select_auth_mode').value;
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'set-mode', mode })
      });
      fetchStats();
    }

    setInterval(fetchStats, 2000);
    fetchStats();
  </script>
</body>
</html>`;
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[Server] Multi-Protocol Proxy & Dashboard running on port ${PORT}`);
});
