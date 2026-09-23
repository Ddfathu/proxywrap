#!/usr/bin/env node
'use strict';

import net from 'net';
import http from 'http';
import dgram from 'dgram';
import dns from 'dns';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { EventEmitter } from 'events';

const PORT = parseInt(process.env.PORT, 10) || 8080;
const TCP_DOMAIN = process.env.RAILWAY_TCP_PROXY_DOMAIN || '';
const TCP_PORT = process.env.RAILWAY_TCP_PROXY_PORT || '';
const DB_PATH = path.resolve(process.env.DATA_DIR || './', 'proxy_data.json');

// --- KONFIGURASI XUDP RELAY ENGINE ---
const RELAY_CONFIG = Object.freeze({
  WS_PATH: '/',
  MAX_WS_MESSAGE_BYTES: 4 * 1024 * 1024,
  HANDSHAKE_TIMEOUT_MS: 10000,
  IDLE_TIMEOUT_MS: 300000,
  XUDP_GRACE_MS: 60000,
  MAX_CONNECTIONS: 4096,
  REJECT_UDP_443: false, // QUIC port 443 tetap diizinkan
});

const RELAY_MAGIC = Buffer.from('VLRLY004', 'ascii');
const RELAY_MODE_FIXED_UDP = 0x01;
const RELAY_MODE_MUX = 0x02;
const RELAY_MODE_PACKET_UDP = 0x03;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6 = 0x03;
const MUX_STATUS_NEW = 0x01;
const MUX_STATUS_KEEP = 0x02;
const MUX_STATUS_END = 0x03;
const MUX_STATUS_KEEPALIVE = 0x04;
const MUX_OPTION_DATA = 0x01;
const MUX_OPTION_ERROR = 0x02;
const MUX_NETWORK_UDP = 0x02;
const MAX_MUX_META_LEN = 512;
const MAX_PACKET_LEN = 65535;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

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

// STATS XUDP RELAY
const RELAY_STATS = {
  activeClients: 0,
  totalHandshakes: 0,
  udpPacketsOut: 0,
  udpBytesOut: 0,
  udpPacketsIn: 0,
  udpBytesIn: 0,
};

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

// ==========================================
// 1. ENGINE XUDP / MUX RELAY
// ==========================================
function rejectUdpTarget(target) {
  return Boolean(RELAY_CONFIG.REJECT_UDP_443 && Number(target?.port) === 443);
}

class AsyncByteReader {
  constructor(socket) {
    this.socket = socket;
    this.buffers = [];
    this.available = 0;
    this.waiters = [];
    this.ended = false;
    this.error = null;
    socket.on('data', (chunk) => {
      if (!chunk || chunk.length === 0) return;
      this.buffers.push(Buffer.from(chunk));
      this.available += chunk.length;
      this._flush();
    });
    socket.on('end', () => { this.ended = true; this._flush(); });
    socket.on('close', () => { this.ended = true; this._flush(); });
    socket.on('error', (err) => { this.error = err; this._flush(); });
  }

  readExactly(length) {
    if (!Number.isInteger(length) || length < 0) return Promise.reject(new Error('invalid read length'));
    if (length === 0) return Promise.resolve(Buffer.alloc(0));
    if (this.available >= length) return Promise.resolve(this._take(length));
    if (this.error) return Promise.reject(this.error);
    if (this.ended) return Promise.reject(new Error('unexpected EOF'));
    return new Promise((resolve, reject) => {
      this.waiters.push({ length, resolve, reject });
    });
  }

  _flush() {
    while (this.waiters.length > 0) {
      const waiter = this.waiters[0];
      if (this.available >= waiter.length) {
        this.waiters.shift();
        waiter.resolve(this._take(waiter.length));
        continue;
      }
      if (this.error || this.ended) {
        this.waiters.shift();
        waiter.reject(this.error || new Error('unexpected EOF'));
        continue;
      }
      break;
    }
  }

  _take(length) {
    const out = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      const first = this.buffers[0];
      const need = length - offset;
      if (first.length <= need) {
        first.copy(out, offset);
        offset += first.length;
        this.buffers.shift();
      } else {
        first.copy(out, offset, 0, need);
        this.buffers[0] = first.subarray(need);
        offset += need;
      }
    }
    this.available -= length;
    return out;
  }
}

async function readLengthPayload(reader) {
  const lenBuf = await reader.readExactly(2);
  const length = lenBuf.readUInt16BE(0);
  return length === 0 ? Buffer.alloc(0) : reader.readExactly(length);
}

async function readEndpoint(reader) {
  const head = await reader.readExactly(3);
  const port = head.readUInt16BE(0);
  const atyp = head[2];
  if (port === 0) throw new Error('zero port');
  return readEndpointBody(reader, atyp, port);
}

async function readEndpointBody(reader, atyp, port) {
  if (atyp === ATYP_IPV4) {
    const b = await reader.readExactly(4);
    return { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp };
  }
  if (atyp === ATYP_DOMAIN) {
    const len = (await reader.readExactly(1))[0];
    if (len === 0) throw new Error('empty domain');
    const b = await reader.readExactly(len);
    let host;
    try { host = utf8Fatal.decode(b); } catch { throw new Error('invalid UTF-8 domain'); }
    if (!host) throw new Error('empty domain');
    return { host, port, atyp };
  }
  if (atyp === ATYP_IPV6) {
    const b = await reader.readExactly(16);
    return { host: formatIPv6(b), port, atyp };
  }
  throw new Error(`unknown address type ${atyp}`);
}

function parseEndpointBytes(buffer, offset) {
  if (offset < 0 || buffer.length - offset < 3) throw new Error('unexpected EOF in endpoint');
  const port = buffer.readUInt16BE(offset);
  if (port === 0) throw new Error('zero port');
  const atyp = buffer[offset + 2];
  let cursor = offset + 3;
  if (atyp === ATYP_IPV4) {
    if (buffer.length - cursor < 4) throw new Error('unexpected EOF in IPv4');
    const b = buffer.subarray(cursor, cursor + 4);
    cursor += 4;
    return { endpoint: { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp }, next: cursor };
  }
  if (atyp === ATYP_DOMAIN) {
    if (buffer.length - cursor < 1) throw new Error('unexpected EOF in domain length');
    const len = buffer[cursor++];
    if (len === 0 || buffer.length - cursor < len) throw new Error('invalid domain length');
    let host;
    try { host = utf8Fatal.decode(buffer.subarray(cursor, cursor + len)); } catch { throw new Error('invalid UTF-8 domain'); }
    cursor += len;
    return { endpoint: { host, port, atyp }, next: cursor };
  }
  if (atyp === ATYP_IPV6) {
    if (buffer.length - cursor < 16) throw new Error('unexpected EOF in IPv6');
    const host = formatIPv6(buffer.subarray(cursor, cursor + 16));
    cursor += 16;
    return { endpoint: { host, port, atyp }, next: cursor };
  }
  throw new Error(`unknown address type ${atyp}`);
}

function formatIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16));
  return parts.join(':');
}

function ipv6ToBytes(address) {
  let input = address;
  const zone = input.indexOf('%');
  if (zone >= 0) input = input.slice(0, zone);
  let ipv4Tail = null;
  const lastColon = input.lastIndexOf(':');
  if (input.includes('.') && lastColon >= 0) {
    const ipv4 = input.slice(lastColon + 1).split('.').map(Number);
    ipv4Tail = [((ipv4[0] << 8) | ipv4[1]).toString(16), ((ipv4[2] << 8) | ipv4[3]).toString(16)];
    input = input.slice(0, lastColon) + ':' + ipv4Tail.join(':');
  }
  const halves = input.split('::');
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  const out = Buffer.alloc(16);
  words.forEach((word, i) => out.writeUInt16BE(parseInt(word, 16), i * 2));
  return out;
}

function encodeUDPSource(rinfo) {
  const port = Number(rinfo.port);
  const family = net.isIP(rinfo.address);
  const head = Buffer.alloc(3);
  head.writeUInt16BE(port, 0);
  if (family === 4) {
    head[2] = ATYP_IPV4;
    return Buffer.concat([head, Buffer.from(rinfo.address.split('.').map(Number))]);
  }
  if (family === 6) {
    head[2] = ATYP_IPV6;
    return Buffer.concat([head, ipv6ToBytes(rinfo.address)]);
  }
  throw new Error(`invalid UDP source IP: ${rinfo.address}`);
}

function writeSocket(socket, data) {
  if (socket.destroyed || !socket.writable) return Promise.reject(new Error('socket is closed'));
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => err ? reject(err) : resolve());
  });
}

async function writeControlError(socket, message) {
  let body = Buffer.from(String(message || 'relay error'), 'utf8');
  if (body.length > MAX_PACKET_LEN) body = body.subarray(0, MAX_PACKET_LEN);
  const out = Buffer.allocUnsafe(3 + body.length);
  out[0] = 1;
  out.writeUInt16BE(body.length, 1);
  body.copy(out, 3);
  try { await writeSocket(socket, out); } catch {}
}

async function readControl(reader) {
  const magic = await reader.readExactly(RELAY_MAGIC.length);
  if (!magic.equals(RELAY_MAGIC)) throw new Error('bad magic');
  const mode = (await reader.readExactly(1))[0];
  if (![RELAY_MODE_FIXED_UDP, RELAY_MODE_MUX, RELAY_MODE_PACKET_UDP].includes(mode)) throw new Error('bad mode');
  const target = mode === RELAY_MODE_FIXED_UDP ? await readEndpoint(reader) : null;
  return { mode, target };
}

function bindDgram(socket, port, address) {
  return new Promise((resolve, reject) => {
    const onError = (err) => { cleanup(); reject(err); };
    const onListening = () => { cleanup(); resolve(); };
    const cleanup = () => {
      socket.off('error', onError);
      socket.off('listening', onListening);
    };
    socket.once('error', onError);
    socket.once('listening', onListening);
    socket.bind(port, address);
  });
}

class UDPAssociation {
  constructor() {
    this.udp4 = null;
    this.udp6 = null;
    this.port = 0;
    this.sink = null;
    this.closed = false;
  }

  static async create() {
    const assoc = new UDPAssociation();
    assoc.udp4 = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    await bindDgram(assoc.udp4, 0, '0.0.0.0');
    assoc.port = assoc.udp4.address().port;
    assoc.udp4.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
    assoc.udp4.on('error', () => {});

    assoc.udp6 = dgram.createSocket({ type: 'udp6', reuseAddr: true, ipv6Only: true });
    try {
      await bindDgram(assoc.udp6, assoc.port, '::');
      assoc.udp6.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
      assoc.udp6.on('error', () => {});
    } catch {
      try { assoc.udp6.close(); } catch {}
      assoc.udp6 = null;
    }
    return assoc;
  }

  attach(sink) {
    const old = this.sink;
    this.sink = sink;
    return old;
  }

  detach(mux, id) {
    if (this.sink && this.sink.mux === mux && this.sink.id === id) {
      this.sink = null;
      return true;
    }
    return false;
  }

  async send(target, payload) {
    if (this.closed) throw new Error('UDP association is closed');
    if (payload.length > MAX_PACKET_LEN) throw new Error('UDP payload too large');

    let resolvedIp = await resolveDomain(target.host);
    const isV6 = net.isIP(resolvedIp) === 6;
    const socket = isV6 ? this.udp6 : this.udp4;
    if (!socket) throw new Error('UDP socket unavailable');

    await new Promise((resolve, reject) => {
      socket.send(payload, target.port, resolvedIp, (err) => err ? reject(err) : resolve());
    });
    RELAY_STATS.udpPacketsOut++;
    RELAY_STATS.udpBytesOut += payload.length;
    globalTotalBytesOut += payload.length;
  }

  _onMessage(msg, rinfo) {
    RELAY_STATS.udpPacketsIn++;
    RELAY_STATS.udpBytesIn += msg.length;
    globalTotalBytesIn += msg.length;
    const sink = this.sink;
    if (!sink || this.closed) return;
    Promise.resolve(sink.mux.sendUDPData(sink.id, rinfo, Buffer.from(msg))).catch(() => {});
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.sink = null;
    if (this.udp4) { try { this.udp4.close(); } catch {} }
    if (this.udp6) { try { this.udp6.close(); } catch {} }
    this.udp4 = null;
    this.udp6 = null;
  }
}

class XUDPManager {
  constructor(graceMs) {
    this.graceMs = graceMs;
    this.entries = new Map();
  }

  async attach(globalID, mux, sessionID) {
    const key = Buffer.from(globalID).toString('hex');
    let entry = this.entries.get(key);
    if (!entry) {
      entry = { assoc: await UDPAssociation.create(), timer: null };
      this.entries.set(key, entry);
    }
    if (entry.timer) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    const oldSink = entry.assoc.attach({ mux, id: sessionID });
    return { assoc: entry.assoc, oldSink };
  }

  detach(globalID, mux, sessionID) {
    const key = Buffer.from(globalID).toString('hex');
    const entry = this.entries.get(key);
    if (!entry || !entry.assoc.detach(mux, sessionID)) return;
    if (entry.timer) clearTimeout(entry.timer);
    entry.timer = setTimeout(() => {
      const current = this.entries.get(key);
      if (current !== entry) return;
      this.entries.delete(key);
      entry.assoc.close();
    }, this.graceMs);
    entry.timer.unref?.();
  }

  close() {
    for (const entry of this.entries.values()) {
      if (entry.timer) clearTimeout(entry.timer);
      entry.assoc.close();
    }
    this.entries.clear();
  }
}

async function serveDirectUDP(socket, reader, target) {
  if (rejectUdpTarget(target)) {
    await writeControlError(socket, 'UDP/443 rejected');
    return;
  }
  const assoc = await UDPAssociation.create();
  let closed = false;
  assoc.attach({
    mux: {
      sendUDPData: async (_id, _rinfo, data) => {
        if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) return;
        const frame = Buffer.allocUnsafe(2 + data.length);
        frame.writeUInt16BE(data.length, 0);
        data.copy(frame, 2);
        await writeSocket(socket, frame);
      },
    },
    id: 0,
  });
  try {
    await writeSocket(socket, Buffer.from([0]));
    for (;;) {
      const payload = await readLengthPayload(reader);
      if (payload.length === 0 || rejectUdpTarget(target)) continue;
      await assoc.send(target, payload);
    }
  } finally {
    closed = true;
    assoc.close();
  }
}

async function servePacketUDP(socket, reader) {
  const assoc = await UDPAssociation.create();
  let closed = false;
  const writeChain = { value: Promise.resolve() };
  assoc.attach({
    mux: {
      sendUDPData: (_id, rinfo, data) => {
        if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) return Promise.resolve();
        const endpoint = encodeUDPSource(rinfo);
        const len = Buffer.allocUnsafe(2);
        len.writeUInt16BE(data.length, 0);
        const frame = Buffer.concat([endpoint, len, data]);
        const op = writeChain.value.then(() => writeSocket(socket, frame));
        writeChain.value = op.catch(() => {});
        return op;
      },
    },
    id: 0,
  });
  try {
    await writeSocket(socket, Buffer.from([0]));
    for (;;) {
      const target = await readEndpoint(reader);
      const payload = await readLengthPayload(reader);
      if (payload.length === 0 || rejectUdpTarget(target)) continue;
      await assoc.send(target, payload);
    }
  } finally {
    closed = true;
    assoc.close();
  }
}

async function readMuxFrame(reader) {
  const metaLen = (await reader.readExactly(2)).readUInt16BE(0);
  if (metaLen < 4 || metaLen > MAX_MUX_META_LEN) throw new Error(`invalid mux metadata length ${metaLen}`);
  const meta = await reader.readExactly(metaLen);
  const frame = {
    id: meta.readUInt16BE(0),
    status: meta[2],
    option: meta[3],
    network: 0,
    target: null,
    globalID: null,
    data: Buffer.alloc(0),
  };
  let cursor = 4;
  if (frame.status === MUX_STATUS_NEW) {
    frame.network = meta[cursor++];
    const parsed = parseEndpointBytes(meta, cursor);
    frame.target = parsed.endpoint;
    cursor = parsed.next;
    if (frame.network === MUX_NETWORK_UDP && meta.length - cursor >= 8) {
      const gid = meta.subarray(cursor, cursor + 8);
      if (!gid.equals(Buffer.alloc(8))) frame.globalID = Buffer.from(gid);
      cursor += 8;
    }
  } else if (frame.status === MUX_STATUS_KEEP && meta.length > cursor && meta[cursor] === MUX_NETWORK_UDP) {
    frame.network = meta[cursor++];
    frame.target = parseEndpointBytes(meta, cursor).endpoint;
  }
  if ((frame.option & MUX_OPTION_DATA) !== 0) {
    frame.data = await readLengthPayload(reader);
  }
  return frame;
}

class MuxSession {
  constructor(mux, id, network, target) {
    this.mux = mux;
    this.id = id;
    this.network = network;
    this.target = target;
    this.udp = null;
    this.global = false;
    this.gid = null;
    this.closed = false;
  }

  async sendUDP(target, payload) {
    if (!this.udp) throw new Error('UDP session unavailable');
    await this.udp.send(target, payload);
  }

  closeWithoutRemoving() {
    if (this.closed) return;
    this.closed = true;
    if (this.udp) {
      if (this.global) this.mux.xm.detach(this.gid, this.mux, this.id);
      else {
        this.udp.detach(this.mux, this.id);
        this.udp.close();
      }
      this.udp = null;
    }
  }

  async close(sendEnd) {
    if (this.mux.sessions.get(this.id) === this) this.mux.sessions.delete(this.id);
    this.closeWithoutRemoving();
    if (sendEnd) await this.mux.sendEnd(this.id, true).catch(() => {});
  }
}

class MuxConnection {
  constructor(socket, reader, xm) {
    this.socket = socket;
    this.reader = reader;
    this.xm = xm;
    this.sessions = new Map();
    this.closed = false;
    this.writeChain = Promise.resolve();
  }

  async serve() {
    try {
      await writeSocket(this.socket, Buffer.from([0]));
      for (;;) {
        const frame = await readMuxFrame(this.reader);
        await this.handleFrame(frame);
      }
    } finally {
      this.closeAll();
    }
  }

  async handleFrame(frame) {
    if (frame.status === MUX_STATUS_KEEPALIVE) return;
    if (frame.status === MUX_STATUS_NEW) return this.handleNew(frame);
    if (frame.status === MUX_STATUS_KEEP) return this.handleKeep(frame);
    if (frame.status === MUX_STATUS_END) {
      const session = this.sessions.get(frame.id);
      if (session && frame.data.length) await session.sendUDP(session.target, frame.data).catch(() => {});
      this.removeSession(frame.id);
    }
  }

  async handleNew(frame) {
    if (frame.network !== MUX_NETWORK_UDP || !frame.target?.host || !frame.target?.port || rejectUdpTarget(frame.target)) {
      await this.sendEnd(frame.id, true).catch(() => {});
      return;
    }
    this.removeSession(frame.id);
    const session = new MuxSession(this, frame.id, frame.network, frame.target);
    if (frame.globalID) {
      try {
        const { assoc, oldSink } = await this.xm.attach(frame.globalID, this, frame.id);
        session.udp = assoc;
        session.global = true;
        session.gid = Buffer.from(frame.globalID);
        this.sessions.set(session.id, session);
        if (oldSink && (oldSink.mux !== this || oldSink.id !== frame.id)) {
          oldSink.mux.removeSession(oldSink.id);
          await oldSink.mux.sendEnd(oldSink.id, false).catch(() => {});
        }
      } catch {
        await this.sendEnd(frame.id, true).catch(() => {});
        return;
      }
    } else {
      try {
        const assoc = await UDPAssociation.create();
        assoc.attach({ mux: this, id: frame.id });
        session.udp = assoc;
        this.sessions.set(session.id, session);
      } catch {
        await this.sendEnd(frame.id, true).catch(() => {});
        return;
      }
    }
    if (frame.data.length) {
      await session.sendUDP(frame.target, frame.data).catch(() => session.close(true));
    }
  }

  async handleKeep(frame) {
    const session = this.sessions.get(frame.id);
    if (!session) {
      await this.sendEnd(frame.id, false).catch(() => {});
      return;
    }
    if (!frame.data.length) return;
    let target = session.target;
    if (frame.network === MUX_NETWORK_UDP && frame.target?.host && frame.target?.port) {
      target = frame.target;
      session.target = target;
    }
    if (rejectUdpTarget(target)) {
      await session.close(true);
      return;
    }
    await session.sendUDP(target, frame.data).catch(() => session.close(true));
  }

  removeSession(id) {
    const session = this.sessions.get(id);
    if (!session) return;
    this.sessions.delete(id);
    session.closeWithoutRemoving();
  }

  closeAll() {
    if (this.closed) return;
    this.closed = true;
    const sessions = [...this.sessions.values()];
    this.sessions.clear();
    for (const session of sessions) session.closeWithoutRemoving();
  }

  _queueWrite(data) {
    const op = this.writeChain.then(() => writeSocket(this.socket, data));
    this.writeChain = op.catch(() => {});
    return op;
  }

  sendUDPData(id, source, data) {
    const addr = encodeUDPSource(source);
    const meta = Buffer.allocUnsafe(5 + addr.length);
    meta.writeUInt16BE(id, 0);
    meta[2] = MUX_STATUS_KEEP;
    meta[3] = MUX_OPTION_DATA;
    meta[4] = MUX_NETWORK_UDP;
    addr.copy(meta, 5);
    return this.writeMuxPacket(meta, data);
  }

  sendEnd(id, hasError) {
    const meta = Buffer.alloc(4);
    meta.writeUInt16BE(id, 0);
    meta[2] = MUX_STATUS_END;
    meta[3] = hasError ? MUX_OPTION_ERROR : 0;
    return this.writeMuxMeta(meta);
  }

  writeMuxPacket(meta, data) {
    if (data.length > MAX_PACKET_LEN) return Promise.reject(new Error('mux payload too large'));
    const out = Buffer.allocUnsafe(2 + meta.length + 2 + data.length);
    out.writeUInt16BE(meta.length, 0);
    meta.copy(out, 2);
    const off = 2 + meta.length;
    out.writeUInt16BE(data.length, off);
    data.copy(out, off + 2);
    return this._queueWrite(out);
  }

  writeMuxMeta(meta) {
    const out = Buffer.allocUnsafe(2 + meta.length);
    out.writeUInt16BE(meta.length, 0);
    meta.copy(out, 2);
    return this._queueWrite(out);
  }
}

// ==========================================
// 2. WEBSOCKET PROTOCOL ENCAPSULATION
// ==========================================
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function websocketAccept(key) {
  return crypto.createHash('sha1').update(String(key) + WS_GUID, 'ascii').digest('base64');
}

function websocketFrame(opcode, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let header;
  if (body.length < 126) {
    header = Buffer.allocUnsafe(2);
    header[1] = body.length;
  } else if (body.length <= 0xffff) {
    header = Buffer.allocUnsafe(4);
    header[1] = 126;
    header.writeUInt16BE(body.length, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(body.length), 2);
  }
  header[0] = 0x80 | (opcode & 0x0f);
  return body.length ? Buffer.concat([header, body]) : header;
}

class WebSocketRelaySocket extends EventEmitter {
  constructor(raw, maxMessageBytes) {
    super();
    this.raw = raw;
    this.remoteAddress = raw.remoteAddress;
    this.remotePort = raw.remotePort;
    this.destroyed = false;
    this.writable = true;
    this.buffer = Buffer.alloc(0);
    this.maxMessageBytes = maxMessageBytes;
    this.timeoutMs = 0;
    this.timeoutTimer = null;
    this.timeoutCallback = null;

    raw.on('data', (chunk) => {
      if (this.destroyed || !chunk?.length) return;
      this._touch();
      this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : Buffer.from(chunk);
      this._parse();
    });
    raw.on('end', () => this.emit('end'));
    raw.on('close', () => {
      if (this.destroyed) return;
      this.destroyed = true;
      this.writable = false;
      this._clearTimeout();
      this.emit('close');
    });
    raw.on('error', (err) => { if (this.listenerCount('error')) this.emit('error', err); });
  }

  feedHead(head) {
    if (!head?.length || this.destroyed) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, head]) : Buffer.from(head);
    this._parse();
  }

  setNoDelay(val) { this.raw.setNoDelay(val); return this; }
  setTimeout(ms, callback) {
    this.timeoutMs = Number(ms) || 0;
    this.timeoutCallback = typeof callback === 'function' ? callback : null;
    this._touch();
    return this;
  }
  _clearTimeout() { if (this.timeoutTimer) clearTimeout(this.timeoutTimer); this.timeoutTimer = null; }
  _touch() {
    this._clearTimeout();
    if (this.timeoutMs > 0 && !this.destroyed) {
      this.timeoutTimer = setTimeout(() => {
        this.timeoutTimer = null;
        if (this.timeoutCallback && !this.destroyed) this.timeoutCallback();
      }, this.timeoutMs);
      this.timeoutTimer.unref?.();
    }
  }

  write(data, cb) {
    if (this.destroyed || !this.writable) return false;
    const frame = websocketFrame(0x2, Buffer.from(data));
    this._touch();
    return this.raw.write(frame, cb);
  }

  _parse() {
    while (!this.destroyed) {
      if (this.buffer.length < 2) return;
      const b0 = this.buffer[0];
      const b1 = this.buffer[1];
      const fin = Boolean(b0 & 0x80);
      const opcode = b0 & 0x0f;
      const masked = Boolean(b1 & 0x80);
      let length = b1 & 0x7f;
      let offset = 2;

      if (!masked) { this.destroy(new Error('client frames must be masked')); return; }
      if (length === 126) {
        if (this.buffer.length < 4) return;
        length = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.length < 10) return;
        length = Number(this.buffer.readBigUInt64BE(2));
        offset = 10;
      }

      if (this.buffer.length < offset + 4 + length) return;
      const mask = this.buffer.subarray(offset, offset + 4);
      offset += 4;
      const payload = Buffer.from(this.buffer.subarray(offset, offset + length));
      this.buffer = this.buffer.subarray(offset + length);
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];

      if (opcode === 0x8) { this.raw.end(); return; }
      if (opcode === 0x9) { this.raw.write(websocketFrame(0xA, payload)); continue; }
      if (opcode === 0x2 && payload.length) this.emit('data', payload);
    }
  }

  destroy(error) {
    if (this.destroyed) return;
    this.destroyed = true;
    this.writable = false;
    this._clearTimeout();
    this.raw.destroy();
    this.emit('close');
  }
}

const xm = new XUDPManager(RELAY_CONFIG.XUDP_GRACE_MS);

async function handleRelayWsConnection(socket) {
  const reader = new AsyncByteReader(socket);
  socket.setNoDelay(true);
  socket.setTimeout(RELAY_CONFIG.HANDSHAKE_TIMEOUT_MS, () => socket.destroy(new Error('handshake timeout')));
  try {
    const control = await readControl(reader);
    RELAY_STATS.totalHandshakes++;
    socket.setTimeout(RELAY_CONFIG.IDLE_TIMEOUT_MS, () => socket.destroy(new Error('idle timeout')));
    if (control.mode === RELAY_MODE_FIXED_UDP) {
      await serveDirectUDP(socket, reader, control.target);
    } else if (control.mode === RELAY_MODE_PACKET_UDP) {
      await servePacketUDP(socket, reader);
    } else {
      const mux = new MuxConnection(socket, reader, xm);
      await mux.serve();
    }
  } catch (err) {
    socket.destroy();
  }
}

// ==========================================
// 3. HTTP / SOCKS5 / TCP PROXY HANDLER
// ==========================================
const server = http.createServer(async (req, res) => {
  const pathUrl = req.url || '/';

  // REST API: Set DNS
  if (pathUrl.startsWith('/api/set-dns') && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        if (parsed.preset && PRESETS[parsed.preset]) {
          const p = PRESETS[parsed.preset];
          DNS_CONFIG.mode = p.type;
          DNS_CONFIG.activeName = p.name;
          if (p.type === 'DOH') DNS_CONFIG.dohUrl = p.url;
          else { DNS_CONFIG.udpServer = p.host; DNS_CONFIG.udpPort = p.port; }
        } else if (parsed.mode === 'DOH') {
          DNS_CONFIG.mode = 'DOH';
          DNS_CONFIG.activeName = 'Custom DoH';
          DNS_CONFIG.dohUrl = parsed.dohUrl || 'https://cloudflare-dns.com/dns-query';
        } else if (parsed.mode === 'UDP') {
          DNS_CONFIG.mode = 'UDP';
          DNS_CONFIG.activeName = 'Custom UDP';
          DNS_CONFIG.udpServer = parsed.udpServer || '1.1.1.1';
          DNS_CONFIG.udpPort = parseInt(parsed.udpPort, 10) || 53;
        }
        saveData();
        dnsCache.clear();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, config: DNS_CONFIG }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // REST API: Set Raw TCP
  if (pathUrl === '/api/set-raw-tcp' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        RAW_TCP_CONFIG.enabled = !!parsed.enabled;
        if (parsed.defaultTargetHost) RAW_TCP_CONFIG.defaultTargetHost = parsed.defaultTargetHost.trim();
        if (parsed.defaultTargetPort) RAW_TCP_CONFIG.defaultTargetPort = parseInt(parsed.defaultTargetPort, 10) || 443;
        saveData();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, config: RAW_TCP_CONFIG }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // REST API: Manage Users
  if (pathUrl === '/api/manage-users' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        if (parsed.action === 'add' && parsed.username && parsed.password) {
          proxyUsers.set(parsed.username.trim(), parsed.password.trim());
          saveData();
        } else if (parsed.action === 'delete' && parsed.username) {
          proxyUsers.delete(parsed.username);
          saveData();
        } else if (parsed.action === 'set-mode' && parsed.mode) {
          PROXY_AUTH_MODE = parsed.mode;
          saveData();
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // REST API: Stats
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
    proxyUsers.forEach((pass, user) => userObjects.push({ username: user, password: pass }));

    const resBody = JSON.stringify({
      proxyInfo: PROXY_SERVER_INFO,
      dnsConfig: DNS_CONFIG,
      rawTcpConfig: RAW_TCP_CONFIG,
      authMode: PROXY_AUTH_MODE,
      userList: userObjects,
      totalActive: activeList.length + RELAY_STATS.activeClients,
      globalTotalIn: formatBytes(globalTotalBytesIn),
      globalTotalOut: formatBytes(globalTotalBytesOut),
      relayStats: RELAY_STATS,
      connections: activeList
    });

    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(resBody);
    return;
  }

  // Dashboard Web UI
  if (pathUrl === '/' || pathUrl === '/index.html') {
    const html = renderDashboardHTML();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  // HTTP Forward Proxy
  const authHeader = req.headers['proxy-authorization'] || '';
  if (!checkHttpAuth(`Proxy-Authorization: ${authHeader}`)) {
    res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Proxy Auth"', 'Content-Length': 0 });
    res.end();
    return;
  }

  const parsedHost = req.headers.host || 'speed.cloudflare.com';
  const parts = parsedHost.split(':');
  const targetHost = parts[0];
  const targetPort = parseInt(parts[1], 10) || 80;

  try {
    const resolvedIp = await resolveDomain(targetHost);
    const targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
      targetSocket.setNoDelay(true);
      res.writeHead(200);
      req.pipe(targetSocket);
      targetSocket.pipe(res);
    });
    targetSocket.on('error', () => { res.writeHead(502); res.end(); });
  } catch (_) {
    res.writeHead(500); res.end();
  }
});

// UPGRADE LISTENER: WEBSOCKET XUDP RELAY
server.on('upgrade', (req, rawSocket, head) => {
  const upgrade = String(req.headers.upgrade || '').toLowerCase();
  const key = String(req.headers['sec-websocket-key'] || '');
  if (upgrade !== 'websocket' || !key) {
    rawSocket.destroy();
    return;
  }

  const accept = websocketAccept(key);
  rawSocket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );

  RELAY_STATS.activeClients++;
  rawSocket.once('close', () => {
    RELAY_STATS.activeClients = Math.max(0, RELAY_STATS.activeClients - 1);
  });

  const wsSocket = new WebSocketRelaySocket(rawSocket, RELAY_CONFIG.MAX_WS_MESSAGE_BYTES);
  handleRelayWsConnection(wsSocket).catch(() => wsSocket.destroy());
  wsSocket.feedHead(head);
});

// HTTPS CONNECT TUNNEL (DIPAKAI WORKER DI PATH /vless/IP:PORT)
server.on('connect', async (req, clientSocket, head) => {
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 5000);

  const authHeader = req.headers['proxy-authorization'] || '';
  if (!checkHttpAuth(`Proxy-Authorization: ${authHeader}`)) {
    clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\n\r\n');
    return clientSocket.end();
  }

  const connId = ++connectionIdCounter;
  const rawIp = clientSocket.remoteAddress || 'Unknown';
  const clientIp = rawIp.replace('::ffff:', '');
  const [targetHost, targetPortStr] = (req.url || '').split(':');
  const targetPort = parseInt(targetPortStr, 10) || 443;

  const connData = {
    id: connId,
    clientIp,
    type: 'HTTPS TUNNEL (WORKER TCP)',
    target: `${targetHost}:${targetPort}`,
    startTime: Date.now(),
    bytesIn: 0,
    bytesOut: 0
  };

  activeConnections.set(connId, connData);

  try {
    const resolvedIp = await resolveDomain(targetHost);
    const targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
      targetSocket.setNoDelay(true);
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) targetSocket.write(head);

      clientSocket.on('data', d => {
        connData.bytesIn += d.length;
        globalTotalBytesIn += d.length;
      });
      targetSocket.on('data', d => {
        connData.bytesOut += d.length;
        globalTotalBytesOut += d.length;
      });

      clientSocket.pipe(targetSocket);
      targetSocket.pipe(clientSocket);
    });

    const cleanup = () => {
      activeConnections.delete(connId);
      clientSocket.destroy();
      targetSocket.destroy();
    };

    clientSocket.on('error', cleanup);
    targetSocket.on('error', cleanup);
    clientSocket.on('close', cleanup);
    targetSocket.on('close', cleanup);
  } catch (err) {
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.end();
  }
});

// RAW TCP / SOCKS5 FALLBACK LISTENER
server.on('connection', (clientSocket) => {
  clientSocket.once('data', async (chunk) => {
    // 1. SOCKS5 Protocol Handshake
    if (chunk[0] === 0x05) {
      handleSocks5Connection(clientSocket, chunk);
      return;
    }

    // 2. HTTP Methods (dilepas ke listener HTTP default)
    const firstString = chunk.slice(0, 8).toString('ascii');
    if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT)\s/i.test(firstString)) {
      clientSocket.unshift(chunk);
      return;
    }

    // 3. RAW TCP / SNI Router / VLESS TLS Mentah
    const sni = parseTlsSni(chunk);
    let destHost = '';
    let destPort = 443;

    if (sni) {
      destHost = sni;
    } else if (RAW_TCP_CONFIG.enabled) {
      destHost = RAW_TCP_CONFIG.defaultTargetHost;
      destPort = RAW_TCP_CONFIG.defaultTargetPort;
    } else {
      destHost = 'speed.cloudflare.com';
    }

    const connId = ++connectionIdCounter;
    const connData = {
      id: connId,
      clientIp: (clientSocket.remoteAddress || '').replace('::ffff:', ''),
      type: sni ? 'VLESS/TLS (SNI)' : 'RAW TCP MENTAH',
      target: `${destHost}:${destPort}`,
      startTime: Date.now(),
      bytesIn: chunk.length,
      bytesOut: 0
    };
    activeConnections.set(connId, connData);

    try {
      const resolvedIp = await resolveDomain(destHost);
      const targetSocket = net.connect({ host: resolvedIp, port: destPort, noDelay: true }, () => {
        targetSocket.write(chunk);
        clientSocket.pipe(targetSocket);
        targetSocket.pipe(clientSocket);
      });

      clientSocket.on('data', d => { connData.bytesIn += d.length; globalTotalBytesIn += d.length; });
      targetSocket.on('data', d => { connData.bytesOut += d.length; globalTotalBytesOut += d.length; });

      const cleanup = () => {
        activeConnections.delete(connId);
        clientSocket.destroy();
        targetSocket.destroy();
      };
      clientSocket.on('error', cleanup);
      targetSocket.on('error', cleanup);
      clientSocket.on('close', cleanup);
      targetSocket.on('close', cleanup);
    } catch (_) {
      clientSocket.destroy();
    }
  });
});

async function handleSocks5Connection(clientSocket, chunk) {
  let socksState = 0;
  const connId = ++connectionIdCounter;
  const connData = {
    id: connId,
    clientIp: (clientSocket.remoteAddress || '').replace('::ffff:', ''),
    type: 'SOCKS5 TCP',
    target: 'pending',
    startTime: Date.now(),
    bytesIn: 0,
    bytesOut: 0
  };

  const processChunk = async (data) => {
    if (socksState === 0) {
      const nmethods = data[1];
      const methods = data.slice(2, 2 + nmethods);
      const reqAuth = (PROXY_AUTH_MODE === 'AUTH' && proxyUsers.size > 0);
      if (reqAuth) {
        if (!methods.includes(0x02)) return clientSocket.end(Buffer.from([0x05, 0xFF]));
        socksState = 1;
        return clientSocket.write(Buffer.from([0x05, 0x02]));
      }
      socksState = 2;
      return clientSocket.write(Buffer.from([0x05, 0x00]));
    }

    if (socksState === 1) {
      if (data[0] !== 0x01) return clientSocket.end();
      const uLen = data[1];
      const user = data.slice(2, 2 + uLen).toString();
      const pLen = data[2 + uLen];
      const pass = data.slice(3 + uLen, 3 + uLen + pLen).toString();
      if (proxyUsers.has(user) && proxyUsers.get(user) === pass) {
        socksState = 2;
        return clientSocket.write(Buffer.from([0x01, 0x00]));
      }
      return clientSocket.end(Buffer.from([0x01, 0x01]));
    }

    if (socksState === 2) {
      const cmd = data[1];
      if (cmd !== 0x01) return clientSocket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

      let targetHost = '';
      let targetPort = 0;
      const atyp = data[3];

      if (atyp === 0x01) {
        targetHost = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
        targetPort = data.readUInt16BE(8);
      } else if (atyp === 0x03) {
        const dLen = data[4];
        targetHost = data.slice(5, 5 + dLen).toString();
        targetPort = data.readUInt16BE(5 + dLen);
      } else {
        return clientSocket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      }

      connData.target = `${targetHost}:${targetPort}`;
      activeConnections.set(connId, connData);

      try {
        const resolvedIp = await resolveDomain(targetHost);
        const targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x10, 0x10]));
          clientSocket.removeListener('data', processChunk);
          clientSocket.pipe(targetSocket);
          targetSocket.pipe(clientSocket);
        });

        const cleanup = () => {
          activeConnections.delete(connId);
          clientSocket.destroy();
          targetSocket.destroy();
        };
        clientSocket.on('error', cleanup);
        targetSocket.on('error', cleanup);
        clientSocket.on('close', cleanup);
        targetSocket.on('close', cleanup);
      } catch (_) {
        clientSocket.end(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      }
    }
  };

  clientSocket.on('data', processChunk);
  processChunk(chunk);
}

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
  <title>Unified Proxy & XUDP Relay Hub</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #06090e; color: #00ffcc; padding: 14px; margin: 0; display: flex; justify-content: center; }
    .card { background: #0c121e; border: 1px solid #00ffcc; box-shadow: 0 0 20px rgba(0,255,204,0.15); border-radius: 14px; max-width: 540px; width: 100%; padding: 18px; }
    h2 { margin: 0 0 16px 0; color: #38bdf8; text-align: center; font-size: 1.15rem; }
    .proxy-box { background: #030712; border: 1px solid #38bdf8; border-radius: 10px; padding: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .proxy-title { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
    .proxy-val { font-family: monospace; font-size: 1.05rem; font-weight: bold; color: #39ff14; word-break: break-all; }
    .btn-copy { background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 8px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; cursor: pointer; }
    .badge-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 18px; }
    .badge { background: #030712; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 10px; text-align: center; }
    .badge h4 { margin: 0; font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; }
    .badge .val { font-size: 1.15rem; font-weight: bold; margin-top: 5px; font-family: monospace; }
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
    <h2>⚡ ALL-IN-ONE PROXY & XUDP HUB</h2>
    
    <div class="proxy-box">
      <div>
        <div class="proxy-title">🚀 Endpoint Proxy (Untuk Target /vless/IP:PORT)</div>
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
        <h4>XUDP Handshakes</h4>
        <div class="val" style="color:#fde047;" id="xudp_shakes">0</div>
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

    <!-- PANEL PENGATURAN DNS RESOLVER -->
    <div class="panel" style="border-color:#38bdf8;">
      <div class="section-title" style="margin:0; color:#38bdf8;">🌐 PENGATURAN DNS RESOLVER</div>
      <div class="hint">Resolusi domain untuk koneksi TCP & UDP Relay:</div>

      <select id="preset_select" onchange="applyPresetUI()">
        <option value="cf-doh" ${DNS_CONFIG.mode === 'DOH' && DNS_CONFIG.dohUrl.includes('cloudflare') ? 'selected' : ''}>⚡ Cloudflare DoH</option>
        <option value="google-doh" ${DNS_CONFIG.mode === 'DOH' && DNS_CONFIG.dohUrl.includes('google') ? 'selected' : ''}>⚡ Google DoH</option>
        <option value="cf-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '1.1.1.1' ? 'selected' : ''}>🚀 Cloudflare UDP 1.1.1.1:53</option>
        <option value="google-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '8.8.8.8' ? 'selected' : ''}>🚀 Google UDP 8.8.8.8:53</option>
        <option value="custom_doh">✏️ Custom DoH URL</option>
        <option value="custom_udp">✏️ Custom UDP DNS IP & Port</option>
      </select>

      <div id="box_custom_doh" style="display:none; margin-top:8px;">
        <input type="text" id="custom_doh_url" placeholder="https://..." value="${DNS_CONFIG.dohUrl}">
      </div>

      <div id="box_custom_udp" style="display:none; margin-top:8px;">
        <input type="text" id="custom_udp_ip" placeholder="1.1.1.1" value="${DNS_CONFIG.udpServer}">
        <input type="number" id="custom_udp_port" placeholder="53" value="${DNS_CONFIG.udpPort || 53}">
      </div>

      <button style="background:#38bdf8;" onclick="saveDns()">💾 TERAPKAN DNS</button>
      <div id="dns_toast" class="toast">✅ DNS Berhasil Disimpan!</div>
    </div>

    <!-- PANEL RAW TCP -->
    <div class="panel" style="border-color:#a855f7;">
      <div class="section-title" style="margin:0; color:#c084fc;">🛠️ KONTROL PROXY RAW TCP</div>
      <select id="raw_tcp_switch">
        <option value="true" ${RAW_TCP_CONFIG.enabled ? 'selected' : ''}>🟢 AKTIF (Terima Paket Mentah)</option>
        <option value="false" ${!RAW_TCP_CONFIG.enabled ? 'selected' : ''}>🔴 NONAKTIF</option>
      </select>
      <input type="text" id="raw_tcp_host" value="${RAW_TCP_CONFIG.defaultTargetHost}">
      <input type="number" id="raw_tcp_port" value="${RAW_TCP_CONFIG.defaultTargetPort}">
      <button style="background:#a855f7; color:#fff;" onclick="saveRawTcp()">💾 SIMPAN RAW TCP</button>
    </div>

    <!-- PANEL AUTHENTICATION -->
    <div class="panel">
      <div class="section-title" style="margin:0;">👤 AUTHENTICATION</div>
      <select id="select_auth_mode" onchange="changeAuthMode()">
        <option value="NONE" ${PROXY_AUTH_MODE === 'NONE' ? 'selected' : ''}>Tanpa Auth (Public Proxy)</option>
        <option value="AUTH" ${PROXY_AUTH_MODE === 'AUTH' ? 'selected' : ''}>Wajib User & Password</option>
      </select>
      <table class="user-table"><tbody id="user_list_body"></tbody></table>
      <div style="display:flex; gap:6px; margin-top:10px;">
        <input type="text" id="new_proxy_user" placeholder="User Baru">
        <input type="text" id="new_proxy_pass" placeholder="Pass Baru">
      </div>
      <button onclick="addUser()">+ TAMBAH USER</button>
    </div>

    <!-- LIVE CONNECTIONS -->
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
        if (data.relayStats) {
          document.getElementById('xudp_shakes').innerText = data.relayStats.totalHandshakes;
        }
        if (data.proxyInfo && data.proxyInfo.fullProxy) {
          document.getElementById('proxy_full_text').innerText = data.proxyInfo.fullProxy;
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
        payload = { mode: 'UDP', udpServer: document.getElementById('custom_udp_ip').value.trim(), udpPort: document.getElementById('custom_udp_port').value.trim() };
      } else {
        payload = { preset: selected };
      }

      const res = await fetch('/api/set-dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const toast = document.getElementById('dns_toast');
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 3000);
        fetchStats();
      }
    }

    async function saveRawTcp() {
      const res = await fetch('/api/set-raw-tcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: document.getElementById('raw_tcp_switch').value === 'true',
          defaultTargetHost: document.getElementById('raw_tcp_host').value.trim(),
          defaultTargetPort: document.getElementById('raw_tcp_port').value.trim()
        })
      });
      if (res.ok) alert('Pengaturan Raw TCP Disimpan!');
    }

    async function addUser() {
      const u = document.getElementById('new_proxy_user').value.trim();
      const p = document.getElementById('new_proxy_pass').value.trim();
      if (!u || !p) return alert('Isi user & pass!');
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add', username: u, password: p })
      });
      document.getElementById('new_proxy_user').value = '';
      document.getElementById('new_proxy_pass').value = '';
      fetchStats();
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
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'set-mode', mode: document.getElementById('select_auth_mode').value })
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
  console.log(`[Unified Server] Proxy (TCP/HTTP/RAW) & XUDP Relay (WS) listening on port ${PORT}`);
});
