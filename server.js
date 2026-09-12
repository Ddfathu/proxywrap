import net from 'net';
import dns from 'dns';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const PORT = process.env.PORT || 8080;
const TCP_DOMAIN = process.env.RAILWAY_TCP_PROXY_DOMAIN || '';
const TCP_PORT = process.env.RAILWAY_TCP_PROXY_PORT || '';
const DB_PATH = path.resolve(process.env.DATA_DIR || './', 'proxy_data.json');

// Konfigurasi Outbound WARP SOCKS5 Lokal
const WARP_HOST = process.env.WARP_HOST || '127.0.0.1';
const WARP_PORT = parseInt(process.env.WARP_PORT || '40000', 10);
const ENABLE_WARP = process.env.ENABLE_WARP !== 'false';

// Helper: Membuka koneksi outbound via local SOCKS5 (warp-go)
function connectViaWarp(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    if (!ENABLE_WARP) {
      const sock = net.connect({ host: targetHost, port: targetPort, noDelay: true }, () => resolve(sock));
      sock.on('error', reject);
      return;
    }

    const warpSock = net.connect({ host: WARP_HOST, port: WARP_PORT, noDelay: true });

    warpSock.once('connect', () => {
      // SOCKS5 Handshake: Version 5, 1 Method, No Auth (0x00)
      warpSock.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    warpSock.once('data', (data) => {
      if (data[0] !== 0x05 || data[1] !== 0x00) {
        warpSock.destroy();
        return reject(new Error('WARP SOCKS5 handshake gagal'));
      }

      // Request CONNECT (cmd 0x01)
      const hostBuf = Buffer.from(targetHost);
      const req = Buffer.alloc(7 + hostBuf.length);
      req[0] = 0x05; // VER
      req[1] = 0x01; // CMD: CONNECT
      req[2] = 0x00; // RSV
      req[3] = 0x03; // ATYP: DOMAIN
      req[4] = hostBuf.length;
      hostBuf.copy(req, 5);
      req.writeUInt16BE(targetPort, 5 + hostBuf.length);

      warpSock.write(req);

      warpSock.once('data', (res) => {
        if (res[1] === 0x00) {
          warpSock.setNoDelay(true);
          warpSock.setKeepAlive(true, 5000);
          resolve(warpSock);
        } else {
          warpSock.destroy();
          reject(new Error(`WARP SOCKS5 connect ditolak kode: ${res[1]}`));
        }
      });
    });

    warpSock.on('error', reject);
  });
}

// --- STATE MANAGEMENT ---
let ADMIN_CREDENTIALS = null; 
const adminSessions = new Set();
const proxyUsers = new Map(); 
let PROXY_AUTH_MODE = 'AUTH'; 

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
  'cf-udp': { name: 'Cloudflare UDP (1.1.1.1)', type: 'UDP', host: '1.1.1.1', port: 53 },
  'google-udp': { name: 'Google UDP (8.8.8.8)', type: 'UDP', host: '8.8.8.8', port: 53 }
};

// --- FILE PERSISTENCE ---
function loadData() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf-8');
      const data = JSON.parse(raw);
      if (data.admin) ADMIN_CREDENTIALS = data.admin;
      if (data.authMode) PROXY_AUTH_MODE = data.authMode;
      if (data.dnsConfig) DNS_CONFIG = data.dnsConfig;
      if (Array.isArray(data.users)) {
        proxyUsers.clear();
        for (const [u, p] of data.users) {
          proxyUsers.set(u, p);
        }
      }
    }
  } catch (err) {
    console.error('[Storage Error]', err.message);
  }
}

function saveData() {
  try {
    const payload = {
      admin: ADMIN_CREDENTIALS,
      authMode: PROXY_AUTH_MODE,
      dnsConfig: DNS_CONFIG,
      users: Array.from(proxyUsers.entries())
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(payload, null, 2), 'utf-8');
  } catch (err) {
    console.error('[Storage Error]', err.message);
  }
}

loadData();

let PROXY_SERVER_INFO = { domain: TCP_DOMAIN, port: TCP_PORT, ip: '', fullProxy: '' };

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
  if (cached && (now - cached.time < 1000 * 60 * 10)) return cached.ip;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname;

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
  if (PROXY_AUTH_MODE === 'NONE' || proxyUsers.size === 0) return true;
  const match = dataStr.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
  if (!match) return false;
  try {
    const creds = Buffer.from(match[1], 'base64').toString('utf-8').split(':');
    return proxyUsers.has(creds[0]) && proxyUsers.get(creds[0]) === creds.slice(1).join(':');
  } catch (_) { return false; }
}

function parseCookie(dataStr) {
  const match = dataStr.match(/Cookie:\s*([^\r\n]+)/i);
  if (!match) return {};
  const list = {};
  match[1].split(';').forEach(cookie => {
    const parts = cookie.split('=');
    list[parts.shift().trim()] = decodeURI(parts.join('='));
  });
  return list;
}

function isAuthenticatedAdmin(dataStr) {
  const cookies = parseCookie(dataStr);
  return cookies.admin_session && adminSessions.has(cookies.admin_session);
}

function parseRequestBody(raw) {
  const delimiterIndex = raw.indexOf('\r\n\r\n');
  if (delimiterIndex === -1) return {};
  try { return JSON.parse(raw.slice(delimiterIndex + 4)); } catch (_) { return {}; }
}

const server = net.createServer({ 
  noDelay: true,
  allowHalfOpen: false,
  pauseOnConnect: false
}, (clientSocket) => {
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 5000);

  const connId = ++connectionIdCounter;
  const rawIp = clientSocket.remoteAddress || 'Unknown';
  const clientIp = rawIp.replace('::ffff:', '');
  const startTime = Date.now();

  const connData = { id: connId, clientIp, type: 'INITIALIZING', target: 'pending', startTime, bytesIn: 0, bytesOut: 0 };
  let isFirstPacket = true;
  let targetSocket = null;
  let socksState = 0;
  let httpBuffer = '';

  const bridgeSockets = (sockA, sockB) => {
    sockA.on('data', (d) => { connData.bytesIn += d.length; globalTotalBytesIn += d.length; });
    sockB.on('data', (d) => { connData.bytesOut += d.length; globalTotalBytesOut += d.length; });
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

  // --- SOCKS5 HANDLER ---
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
      if (chunk[0] !== 0x05 || chunk[1] !== 0x01) {
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

      connData.type = 'SOCKS5 (WARP)';
      connData.target = `${targetHost}:${targetPort}`;
      activeConnections.set(connId, connData);

      try {
        const dest = ENABLE_WARP ? targetHost : await resolveDomain(targetHost);
        targetSocket = await connectViaWarp(dest, targetPort);
        clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10]));
        clientSocket.removeAllListeners('data');
        bridgeSockets(clientSocket, targetSocket);
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
        const isAuth = isAuthenticatedAdmin(dataStr);

        // API Setup
        if (pathUrl === '/api/setup-admin' && dataStr.startsWith('POST')) {
          const body = parseRequestBody(dataStr);
          if (!ADMIN_CREDENTIALS && body.username && body.password) {
            ADMIN_CREDENTIALS = { username: body.username.trim(), password: body.password.trim() };
            saveData();
            const token = crypto.randomBytes(16).toString('hex');
            adminSessions.add(token);
            const resBody = JSON.stringify({ success: true });
            clientSocket.write(`HTTP/1.1 200 OK\r\nSet-Cookie: admin_session=${token}; Path=/; HttpOnly\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          } else {
            const resBody = JSON.stringify({ success: false, error: 'Setup sudah selesai!' });
            clientSocket.write(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          }
          return clientSocket.end();
        }

        if (pathUrl === '/api/change-admin' && dataStr.startsWith('POST')) {
          if (!isAuth) {
            clientSocket.write(`HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
            return clientSocket.end();
          }
          const body = parseRequestBody(dataStr);
          if (body.username && body.password) {
            ADMIN_CREDENTIALS.username = body.username.trim();
            ADMIN_CREDENTIALS.password = body.password.trim();
            saveData();
            const resBody = JSON.stringify({ success: true });
            clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          }
          return clientSocket.end();
        }

        if (pathUrl === '/api/login' && dataStr.startsWith('POST')) {
          const body = parseRequestBody(dataStr);
          if (ADMIN_CREDENTIALS && body.username === ADMIN_CREDENTIALS.username && body.password === ADMIN_CREDENTIALS.password) {
            const token = crypto.randomBytes(16).toString('hex');
            adminSessions.add(token);
            const resBody = JSON.stringify({ success: true });
            clientSocket.write(`HTTP/1.1 200 OK\r\nSet-Cookie: admin_session=${token}; Path=/; HttpOnly\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          } else {
            const resBody = JSON.stringify({ success: false, error: 'Kredensial salah!' });
            clientSocket.write(`HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          }
          return clientSocket.end();
        }

        if (pathUrl === '/api/logout' && dataStr.startsWith('POST')) {
          const cookies = parseCookie(dataStr);
          if (cookies.admin_session) adminSessions.delete(cookies.admin_session);
          clientSocket.write(`HTTP/1.1 200 OK\r\nSet-Cookie: admin_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
          return clientSocket.end();
        }

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

          const uniqueClients = new Set(activeList.map(c => c.clientIp)).size;
          const userObjects = [];
          if (isAuth) {
            proxyUsers.forEach((pass, user) => {
              userObjects.push({ username: user, password: pass });
            });
          }

          const resBody = JSON.stringify({
            hasAdmin: ADMIN_CREDENTIALS !== null,
            adminUsername: (isAuth && ADMIN_CREDENTIALS) ? ADMIN_CREDENTIALS.username : '',
            isAuth,
            warpEnabled: ENABLE_WARP,
            proxyInfo: PROXY_SERVER_INFO,
            dnsConfig: DNS_CONFIG,
            authMode: PROXY_AUTH_MODE,
            userList: userObjects,
            totalActive: uniqueClients,
            globalTotalIn: formatBytes(globalTotalBytesIn),
            globalTotalOut: formatBytes(globalTotalBytesOut),
            connections: activeList
          });

          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ${Buffer.byteLength(resBody)}\r\nConnection: close\r\n\r\n${resBody}`);
          return clientSocket.end();
        }

        if (pathUrl.startsWith('/api/set-dns') && dataStr.startsWith('POST')) {
          if (!isAuth) {
            clientSocket.write(`HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
            return clientSocket.end();
          }
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
              DNS_CONFIG.activeName = 'Custom DoH Pribadi';
              DNS_CONFIG.dohUrl = body.dohUrl || 'https://cloudflare-dns.com/dns-query';
            } else if (body.mode === 'UDP') {
              DNS_CONFIG.mode = 'UDP';
              DNS_CONFIG.activeName = 'Custom DNS UDP Pribadi';
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
          return clientSocket.end();
        }

        if (pathUrl === '/api/manage-users' && dataStr.startsWith('POST')) {
          if (!isAuth) {
            clientSocket.write(`HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
            return clientSocket.end();
          }
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
          return clientSocket.end();
        }

        if (pathUrl === '/' || pathUrl === '/index.html') {
          const html = renderDashboardHTML();
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(html)}\r\nConnection: close\r\n\r\n${html}`);
          return clientSocket.end();
        }

        // HTTP Forward Proxy (Lewat WARP)
        if (!checkHttpAuth(dataStr)) {
          const authReq = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          clientSocket.write(authReq);
          return clientSocket.end();
        }

        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
          connData.type = 'HTTP (WARP)';
          connData.target = `${targetHost}:${targetPort}`;
          activeConnections.set(connId, connData);
        }

        try {
          const dest = ENABLE_WARP ? targetHost : await resolveDomain(targetHost);
          targetSocket = await connectViaWarp(dest, targetPort);
          targetSocket.write(Buffer.from(httpBuffer));
          bridgeSockets(clientSocket, targetSocket);
        } catch (_) {
          activeConnections.delete(connId);
          clientSocket.destroy();
        }
        return;
      }

      isFirstPacket = false;

      // HTTPS CONNECT Proxy (Lewat WARP)
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
            connData.type = 'HTTPS (WARP)';
            connData.target = `${targetHost}:${targetPort}`;
            activeConnections.set(connId, connData);
          }

          try {
            const dest = ENABLE_WARP ? targetHost : await resolveDomain(targetHost);
            targetSocket = await connectViaWarp(dest, targetPort);
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            bridgeSockets(clientSocket, targetSocket);
          } catch (_) {
            activeConnections.delete(connId);
            clientSocket.destroy();
          }
          return;
        }
      }

      // Stream VLESS / Direct SNI (Lewat WARP)
      const sni = parseTlsSni(chunk);
      const destinationHost = sni || 'speed.cloudflare.com';

      if (!destinationHost.includes('railway.com') && !destinationHost.includes('up.railway.app')) {
        connData.type = sni ? 'VLESS (WARP)' : 'RAW TCP (WARP)';
        connData.target = `${destinationHost}:443`;
        activeConnections.set(connId, connData);
      }

      try {
        const dest = ENABLE_WARP ? destinationHost : await resolveDomain(destinationHost);
        targetSocket = await connectViaWarp(dest, 443);
        targetSocket.write(chunk);
        bridgeSockets(clientSocket, targetSocket);
      } catch (_) {
        activeConnections.delete(connId);
        clientSocket.destroy();
      }
    }
  });

  clientSocket.on('error', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
  clientSocket.on('close', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
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
  <title>Proxy Hub + WARP</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #06090e; color: #00ffcc; padding: 14px; margin: 0; display: flex; justify-content: center; }
    .card { background: #0c121e; border: 1px solid #00ffcc; box-shadow: 0 0 20px rgba(0,255,204,0.15); border-radius: 14px; max-width: 520px; width: 100%; padding: 18px; }
    h2 { margin: 0 0 16px 0; color: #38bdf8; text-align: center; font-size: 1.2rem; }
    .proxy-box { background: #030712; border: 1px solid #38bdf8; border-radius: 10px; padding: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .proxy-title { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
    .proxy-val { font-family: monospace; font-size: 1.05rem; font-weight: bold; color: #39ff14; }
    .btn-copy { background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 8px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; cursor: pointer; }
    .badge-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 18px; }
    .badge { background: #030712; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 10px; text-align: center; }
    .badge h4 { margin: 0; font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; }
    .badge .val { font-size: 1.3rem; font-weight: bold; margin-top: 5px; font-family: monospace; }
    .badge .sub-val { font-size: 0.68rem; color: #94a3b8; margin-top: 3px; font-family: monospace; word-break: break-all; }
    .section-title { font-size: 0.85rem; font-weight: bold; color: #38bdf8; margin-top: 16px; margin-bottom: 10px; }
    .conn-list { display: flex; flex-direction: column; gap: 8px; max-height: 180px; overflow-y: auto; }
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
    <h2>⚡ PROXY HUB + CLOUDFLARE WARP</h2>
    
    <div class="proxy-box">
      <div>
        <div class="proxy-title">🚀 Endpoint Proxy (WARP Outbound)</div>
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
        <h4>WARP Egress</h4>
        <div class="val" style="color:#38bdf8; font-size:1.05rem;">ENABLED</div>
        <div class="sub-val">127.0.0.1:40000</div>
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

    <div class="section-title">🟢 LIVE CONNECTIONS (REALTIME)</div>
    <div class="conn-list" id="conn_container"></div>

    <div id="panel_initial_setup" class="panel" style="display:none; border-color:#f59e0b;">
      <div class="section-title" style="margin-top:0; color:#f59e0b;">⚠️ SETUP ADMIN PERTAMA KALI</div>
      <div class="hint">Buat akun Admin master:</div>
      <input type="text" id="setup_admin_user" placeholder="Username Admin Baru">
      <input type="password" id="setup_admin_pass" placeholder="Password Admin Baru">
      <button style="background:#f59e0b;" onclick="setupAdmin()">SIMPAN & MASUK ADMIN</button>
    </div>

    <div id="panel_login" class="panel" style="display:none;">
      <div class="section-title" style="margin-top:0;">🔒 LOGIN ADMIN CONTROL</div>
      <input type="text" id="login_user" placeholder="Username Admin">
      <input type="password" id="login_pass" placeholder="Password Admin">
      <button onclick="loginAdmin()">MASUK ADMIN</button>
    </div>

    <div id="panel_admin_dashboard" style="display:none;">
      <div class="panel">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span class="section-title" style="margin:0;">👤 USER & PASSWORD PROXY</span>
          <button onclick="logoutAdmin()" style="width:auto; padding:4px 8px; background:#475569; color:#fff; font-size:0.7rem; margin:0;">Logout</button>
        </div>
        <div style="margin-top:10px;">
          <label style="font-size:0.75rem; color:#94a3b8;">Enforce Mode:</label>
          <select id="select_auth_mode" onchange="changeAuthMode()">
            <option value="AUTH">Wajib User & Password (Private Proxy)</option>
            <option value="NONE">Tanpa Auth (Public Proxy)</option>
          </select>
        </div>
        <table class="user-table"><tbody id="user_list_body"></tbody></table>
        <div style="display:flex; gap:6px; margin-top:10px;">
          <input type="text" id="new_proxy_user" placeholder="User Proxy Baru">
          <input type="text" id="new_proxy_pass" placeholder="Pass Proxy Baru">
        </div>
        <button onclick="addUser()">+ TAMBAH USER PROXY</button>
      </div>

      <div class="panel">
        <div class="section-title" style="margin:0;">🔑 GANTI AKUN ADMIN MASTER</div>
        <input type="text" id="edit_admin_user" placeholder="Username Admin Baru">
        <input type="password" id="edit_admin_pass" placeholder="Password Admin Baru">
        <button style="background:#38bdf8;" onclick="changeAdminCreds()">UPDATE KREDENSIAL ADMIN</button>
      </div>

      <div class="panel">
        <div class="section-title" style="margin:0;">⚙️ DNS RESOLVER SETTINGS</div>
        <select id="preset_select" onchange="applyPresetUI()">
          <option value="cf-doh">Cloudflare DoH (Official)</option>
          <option value="google-doh">Google DoH</option>
          <option value="quad9-doh">Quad9 DoH (Security)</option>
          <option value="adguard-doh">AdGuard DoH (Adblock)</option>
          <option value="cf-udp">Cloudflare UDP (1.1.1.1:53)</option>
          <option value="google-udp">Google UDP (8.8.8.8:53)</option>
          <option value="custom_doh">✏️ Custom DoH Pribadi (URL)</option>
          <option value="custom_udp">✏️ Custom DNS UDP Pribadi (IP + Port)</option>
        </select>
        <div id="box_custom_doh" style="display:none; margin-top:8px;">
          <input type="text" id="custom_doh_url" placeholder="https://dns.nextdns.io/xxxxxx" value="${DNS_CONFIG.dohUrl}">
        </div>
        <div id="box_custom_udp" style="display:none; margin-top:8px;">
          <input type="text" id="custom_udp_ip" placeholder="IP: 94.140.14.14" value="${DNS_CONFIG.udpServer}">
          <input type="number" id="custom_udp_port" placeholder="Port: 53" value="${DNS_CONFIG.udpPort || 53}">
        </div>
        <button onclick="saveDns()">💾 SIMPAN DNS</button>
        <div id="dns_toast" class="toast">✅ DNS Berhasil Diperbarui!</div>
      </div>
    </div>
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
        if (!data.hasAdmin) {
          document.getElementById('panel_initial_setup').style.display = 'block';
          document.getElementById('panel_login').style.display = 'none';
          document.getElementById('panel_admin_dashboard').style.display = 'none';
        } else if (!data.isAuth) {
          document.getElementById('panel_initial_setup').style.display = 'none';
          document.getElementById('panel_login').style.display = 'block';
          document.getElementById('panel_admin_dashboard').style.display = 'none';
        } else {
          document.getElementById('panel_initial_setup').style.display = 'none';
          document.getElementById('panel_login').style.display = 'none';
          document.getElementById('panel_admin_dashboard').style.display = 'block';
          document.getElementById('select_auth_mode').value = data.authMode;
          if (!document.getElementById('edit_admin_user').value) {
            document.getElementById('edit_admin_user').value = data.adminUsername;
          }
          renderUsers(data.userList);
        }
        const container = document.getElementById('conn_container');
        if (!data.connections || data.connections.length === 0) {
          container.innerHTML = '<div style="text-align:center;color:#64748b;font-size:0.75rem;padding:10px;">Belum ada koneksi...</div>';
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
        tbody.innerHTML = '<tr><td colspan="3" style="color:#64748b; text-align:center;">Belum ada user.</td></tr>';
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

    async function setupAdmin() {
      const u = document.getElementById('setup_admin_user').value;
      const p = document.getElementById('setup_admin_pass').value;
      if (!u || !p) return alert('Lengkapi data!');
      const res = await fetch('/api/setup-admin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
      if (res.ok) fetchStats();
    }
    async function loginAdmin() {
      const u = document.getElementById('login_user').value;
      const p = document.getElementById('login_pass').value;
      const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
      if (res.ok) fetchStats();
      else alert('Kredensial salah!');
    }
    async function changeAdminCreds() {
      const u = document.getElementById('edit_admin_user').value;
      const p = document.getElementById('edit_admin_pass').value;
      const res = await fetch('/api/change-admin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
      if (res.ok) alert('Admin diperbarui!');
    }
    async function logoutAdmin() {
      await fetch('/api/logout', { method: 'POST' });
      fetchStats();
    }
    async function addUser() {
      const u = document.getElementById('new_proxy_user').value.trim();
      const p = document.getElementById('new_proxy_pass').value.trim();
      if (!u || !p) return alert('Isi lengkap!');
      const res = await fetch('/api/manage-users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'add', username: u, password: p }) });
      if (res.ok) { document.getElementById('new_proxy_user').value = ''; document.getElementById('new_proxy_pass').value = ''; fetchStats(); }
    }
    async function deleteUser(u) {
      await fetch('/api/manage-users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'delete', username: u }) });
      fetchStats();
    }
    async function changeAuthMode() {
      const mode = document.getElementById('select_auth_mode').value;
      await fetch('/api/manage-users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'set-mode', mode }) });
      fetchStats();
    }
    function applyPresetUI() {
      const val = document.getElementById('preset_select').value;
      document.getElementById('box_custom_doh').style.display = (val === 'custom_doh') ? 'block' : 'none';
      document.getElementById('box_custom_udp').style.display = (val === 'custom_udp') ? 'block' : 'none';
    }
    async function saveDns() {
      const selected = document.getElementById('preset_select').value;
      let payload = selected === 'custom_doh' 
        ? { mode: 'DOH', dohUrl: document.getElementById('custom_doh_url').value.trim() }
        : selected === 'custom_udp'
        ? { mode: 'UDP', udpServer: document.getElementById('custom_udp_ip').value.trim(), udpPort: document.getElementById('custom_udp_port').value.trim() }
        : { preset: selected };
      const res = await fetch('/api/set-dns', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await res.json();
      if (data.success) {
        const toast = document.getElementById('dns_toast');
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 3000);
        fetchStats();
      }
    }
    setInterval(fetchStats, 2000);
    fetchStats();
  </script>
</body>
</html>`;
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[Server] Proxy Hub running on port ${PORT} (WARP Outbound: ${ENABLE_WARP ? 'Active' : 'Disabled'})`);
});
