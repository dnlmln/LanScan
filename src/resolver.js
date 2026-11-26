import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import tls from 'node:tls';
import { parseIpv4Octets } from './subnet.js';

const MDNS_PORT = 5353;
const MDNS_MULTICAST_ADDR = '224.0.0.251';
const NBNS_PORT = 137;
const LLMNR_PORT = 5355;
const SSDP_PORT = 1900;
const SNMP_PORT = 161;
const CAST_PORT = 8008;

const SNMP_SYSNAME_OID = Buffer.from([
  0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00,
]);

const GENERIC_NAMES = new Set([
  '400',
  '401',
  '403',
  '404',
  '500',
  '502',
  '503',
  '401 unauthorized',
  '403 forbidden',
  '404 not found',
  '500 internal server error',
  'not found',
  'forbidden',
  'unauthorized',
  'bad request',
  'error',
  'redirect',
  'redirecting',
  'moved permanently',
  '301 moved permanently',
  '302 found',
  'document moved',
  'object moved',
  'index',
  'home',
  'login',
  'log in',
  'sign in',
  'welcome',
  'untitled',
  'document',
  'loading',
  'loading...',
  'nginx',
  'apache',
  'apache2',
  'iis',
  'default',
  'self-signed',
  'example.com',
  'localhost',
  'localhost.localdomain',
  'test page',
]);

/**
 * Decode common HTML/XML character entities into plain text.
 */
export function decodeHtmlEntities(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#(\d+);/g, (_m, dec) => {
      const code = Number.parseInt(dec, 10);
      return code >= 32 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex) => {
      const code = Number.parseInt(hex, 16);
      return code >= 32 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    });
}

/**
 * Normalize and filter a candidate device name or title, rejecting raw IPs and generic boilerplate.
 */
export function cleanDeviceName(raw, ip = null, maxLen = 48) {
  if (typeof raw !== 'string') return null;
  let cleaned = raw
    .replace(/[\x00-\x1f\x7f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleaned) return null;

  if (cleaned.length > maxLen) {
    cleaned = cleaned.slice(0, maxLen).trim();
  }
  if (!cleaned) return null;

  if (ip && cleaned === ip) return null;
  if (parseIpv4Octets(cleaned) !== null) return null;

  const lower = cleaned.toLowerCase();
  if (GENERIC_NAMES.has(lower)) return null;

  return cleaned;
}

/**
 * Format an IPv4 address into its reverse DNS PTR name (<d>.<c>.<b>.<a>.in-addr.arpa).
 */
export function formatReversePtrName(ip) {
  const octets = parseIpv4Octets(ip);
  if (!octets) return null;
  return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
}

/**
 * Encode a dotted domain name into DNS wire-format length-prefixed labels.
 */
function encodeDomainName(domain) {
  const labels = domain.replace(/\.$/, '').split('.');
  const chunks = [];
  for (const label of labels) {
    const labelBuf = Buffer.from(label, 'ascii');
    chunks.push(Buffer.from([labelBuf.length]), labelBuf);
  }
  chunks.push(Buffer.from([0x00]));
  return Buffer.concat(chunks);
}

/**
 * Build a standard DNS PTR query packet for an IPv4 address.
 */
export function buildPtrQuery(ip) {
  const reverseName = formatReversePtrName(ip);
  if (!reverseName) {
    throw new Error(`Invalid IPv4 address for PTR query: ${ip}`);
  }

  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1337, 0); // Transaction ID
  header.writeUInt16BE(0x0100, 2); // Standard query with recursion desired
  header.writeUInt16BE(1, 4); // QDCOUNT = 1

  const qname = encodeDomainName(reverseName);
  const trailer = Buffer.alloc(4);
  trailer.writeUInt16BE(12, 0); // QTYPE = PTR
  trailer.writeUInt16BE(1, 2); // QCLASS = IN

  return Buffer.concat([header, qname, trailer]);
}

/**
 * Decode a DNS domain name starting at `startOffset`, following compression pointers safely.
 */
export function readDomainName(buf, startOffset) {
  const labels = [];
  let offset = startOffset;
  let nextOffset = null;
  let jumps = 0;
  const visited = new Set();

  while (offset < buf.length) {
    if (visited.has(offset) || jumps > 16) {
      return null;
    }
    visited.add(offset);

    const len = buf[offset];
    if (len === 0) {
      if (nextOffset === null) {
        nextOffset = offset + 1;
      }
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= buf.length) return null;
      const pointer = ((len & 0x3f) << 8) | buf[offset + 1];
      if (nextOffset === null) {
        nextOffset = offset + 2;
      }
      offset = pointer;
      jumps += 1;
      continue;
    }

    if (len > 63 || offset + 1 + len > buf.length) {
      return null;
    }
    labels.push(buf.subarray(offset + 1, offset + 1 + len).toString('utf8'));
    offset += 1 + len;
  }

  if (nextOffset === null) return null;
  return { name: labels.join('.'), nextOffset };
}

/**
 * Parse a DNS or mDNS PTR response buffer and return `{ hostname, owner }` or null.
 */
export function parseDnsPtrResponse(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;

  const qdCount = buf.readUInt16BE(4);
  const anCount = buf.readUInt16BE(6);
  if (anCount === 0) return null;

  let offset = 12;

  for (let i = 0; i < qdCount; i += 1) {
    const qName = readDomainName(buf, offset);
    if (!qName || qName.nextOffset + 4 > buf.length) return null;
    offset = qName.nextOffset + 4;
  }

  for (let i = 0; i < anCount; i += 1) {
    const rrName = readDomainName(buf, offset);
    if (!rrName || rrName.nextOffset + 10 > buf.length) return null;

    const rrHeader = rrName.nextOffset;
    const type = buf.readUInt16BE(rrHeader);
    const rdLength = buf.readUInt16BE(rrHeader + 8);
    const rdataOffset = rrHeader + 10;
    if (rdataOffset + rdLength > buf.length) return null;

    if (type === 12) {
      const target = readDomainName(buf, rdataOffset);
      if (target && target.name) {
        const hostname = target.name.replace(/\.$/, '').trim();
        if (hostname) {
          return {
            hostname,
            owner: rrName.name.replace(/\.$/, '').trim(),
          };
        }
      }
    }

    offset = rdataOffset + rdLength;
  }

  return null;
}

/**
 * Build the 50-byte NetBIOS Name Service (NBSTAT) wildcard query packet.
 */
export function buildNetbiosQuery() {
  const header = Buffer.from([
    0x13, 0x38, // Transaction ID
    0x00, 0x00, // Flags
    0x00, 0x01, // Questions = 1
    0x00, 0x00, // Answer RRs
    0x00, 0x00, // Authority RRs
    0x00, 0x00, // Additional RRs
  ]);
  const encodedWildcard = Buffer.concat([
    Buffer.from([0x20]),
    Buffer.from('CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'ascii'),
    Buffer.from([0x00]),
  ]);
  const trailer = Buffer.from([
    0x00, 0x21, // QTYPE = NBSTAT
    0x00, 0x01, // QCLASS = IN
  ]);
  return Buffer.concat([header, encodedWildcard, trailer]);
}

/**
 * Parse a NetBIOS NBSTAT response packet and return the best machine hostname or null.
 */
export function parseNetbiosResponse(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 57) return null;
  const numNames = buf[56];
  if (numNames === 0) return null;

  let fallbackName = null;
  let serverName = null;

  for (let i = 0; i < numNames; i += 1) {
    const pos = 57 + i * 18;
    if (pos + 18 > buf.length) break;

    const rawName = buf.subarray(pos, pos + 15).toString('ascii');
    const name = rawName.replace(/\0/g, '').trim();
    const suffix = buf[pos + 15];
    const flags = buf.readUInt16BE(pos + 16);

    // Ignore group names (bit 15) and non-printable/browse entries.
    if ((flags & 0x8000) !== 0) continue;
    if (!name || !/^[A-Za-z0-9._-]+$/.test(name)) continue;

    if (suffix === 0x00) {
      return name;
    }
    if (suffix === 0x20 && !serverName) {
      serverName = name;
    }
    if (!fallbackName) {
      fallbackName = name;
    }
  }

  return serverName || fallbackName;
}

/**
 * Query a host's hostname over mDNS (unicast + multicast fallback on UDP 5353).
 */
export function queryMdns(ip, timeoutMs = 750) {
  const expectedOwner = formatReversePtrName(ip);
  if (!expectedOwner) return Promise.resolve(null);

  let packet;
  try {
    packet = buildPtrQuery(ip);
  } catch {
    return Promise.resolve(null);
  }

  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors.
      }
      resolve(result);
    };

    timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('error', () => finish(null));
    socket.on('message', (msg, rinfo) => {
      const parsed = parseDnsPtrResponse(msg);
      if (!parsed) return;

      // Guard against cross-talk from multicast responses belonging to another host.
      const ownerMatches =
        parsed.owner.toLowerCase() === expectedOwner.toLowerCase();
      if (rinfo.address === ip || ownerMatches) {
        finish({ hostname: parsed.hostname, source: 'mDNS' });
      }
    });

    socket.send(packet, MDNS_PORT, ip, () => {
      try {
        socket.send(packet, MDNS_PORT, MDNS_MULTICAST_ADDR, () => {});
      } catch {
        // Ignore multicast send errors.
      }
    });
  });
}

/**
 * Query a host's hostname over unicast LLMNR (UDP port 5355).
 */
export function queryLlmnr(ip, timeoutMs = 750, port = LLMNR_PORT) {
  const expectedOwner = formatReversePtrName(ip);
  if (!expectedOwner) return Promise.resolve(null);

  let packet;
  try {
    packet = buildPtrQuery(ip);
    packet.writeUInt16BE(0x0000, 2); // RFC 4795 LLMNR flags = 0
  } catch {
    return Promise.resolve(null);
  }

  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors.
      }
      resolve(result);
    };

    timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('error', () => finish(null));
    socket.on('message', (msg, rinfo) => {
      const parsed = parseDnsPtrResponse(msg);
      if (!parsed) return;
      const ownerMatches =
        parsed.owner.toLowerCase() === expectedOwner.toLowerCase();
      if (rinfo.address === ip || ownerMatches) {
        const cleaned = cleanDeviceName(parsed.hostname, ip);
        if (cleaned) {
          finish({ hostname: cleaned, source: 'LLMNR' });
        }
      }
    });

    socket.send(packet, port, ip, (err) => {
      if (err) finish(null);
    });
  });
}

/**
 * Query a host's NetBIOS name via UDP port 137.
 */
export function queryNetbios(ip, timeoutMs = 750) {
  const packet = buildNetbiosQuery();

  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors.
      }
      resolve(result);
    };

    timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('error', () => finish(null));
    socket.on('message', (msg, rinfo) => {
      if (rinfo.address !== ip) return;
      const hostname = parseNetbiosResponse(msg);
      if (hostname) {
        finish({ hostname, source: 'NetBIOS' });
      }
    });

    socket.send(packet, NBNS_PORT, ip, (err) => {
      if (err) finish(null);
    });
  });
}

function withTimeout(promise, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    promise
      .then((val) => {
        clearTimeout(timer);
        resolve(val);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(null);
      });
  });
}

/**
 * Perform standard reverse DNS PTR lookup (system resolver and router gateway DNS).
 */
export async function queryReverseDns(ip, gatewayIp, timeoutMs = 750) {
  const queries = [withTimeout(dns.promises.reverse(ip), timeoutMs)];

  if (gatewayIp && parseIpv4Octets(gatewayIp)) {
    const gatewayResolver = new dns.promises.Resolver();
    gatewayResolver.setServers([gatewayIp]);
    queries.push(withTimeout(gatewayResolver.reverse(ip), timeoutMs));
  }

  const results = await Promise.all(queries);
  for (const hostnames of results) {
    if (Array.isArray(hostnames) && hostnames.length > 0) {
      const cleaned = String(hostnames[0]).replace(/\.$/, '').trim();
      if (cleaned && cleaned !== ip) {
        return { hostname: cleaned, source: 'DNS' };
      }
    }
  }
  return null;
}

/**
 * Fetch an HTTP resource with strict timeout, byte limit, and same-host redirect protection.
 */
function fetchHttpText(
  urlString,
  { expectedIp = null, timeoutMs = 900, maxBytes = 32 * 1024, maxRedirects = 1 } = {}
) {
  let targetUrl;
  try {
    targetUrl = new URL(urlString);
  } catch {
    return Promise.resolve(null);
  }

  if (targetUrl.protocol !== 'http:') return Promise.resolve(null);
  if (expectedIp && targetUrl.hostname !== expectedIp) {
    return Promise.resolve(null);
  }

  const startedAt = Date.now();

  return new Promise((resolve) => {
    let settled = false;
    let req = null;

    const finish = (val) => {
      if (settled) return;
      settled = true;
      resolve(val);
    };

    req = http.request(
      targetUrl,
      {
        method: 'GET',
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'LanScan/1.0',
          Accept: '*/*',
          Connection: 'close',
        },
      },
      (res) => {
        const statusCode = res.statusCode || 0;
        const location = res.headers?.location;

        if (
          [301, 302, 303, 307, 308].includes(statusCode) &&
          location &&
          maxRedirects > 0
        ) {
          res.resume();
          const remaining = timeoutMs - (Date.now() - startedAt);
          if (remaining <= 50) {
            finish(null);
            return;
          }
          let nextUrl;
          try {
            nextUrl = new URL(location, targetUrl);
          } catch {
            finish(null);
            return;
          }
          if (
            nextUrl.protocol !== 'http:' ||
            (expectedIp && nextUrl.hostname !== expectedIp)
          ) {
            finish(null);
            return;
          }
          fetchHttpText(nextUrl.toString(), {
            expectedIp,
            timeoutMs: remaining,
            maxBytes,
            maxRedirects: maxRedirects - 1,
          }).then(finish);
          return;
        }

        const chunks = [];
        let totalBytes = 0;

        res.on('data', (chunk) => {
          totalBytes += chunk.length;
          if (totalBytes <= maxBytes) {
            chunks.push(chunk);
          } else {
            const sliceLen = chunk.length - (totalBytes - maxBytes);
            if (sliceLen > 0) chunks.push(chunk.subarray(0, sliceLen));
            res.destroy();
            finish({
              statusCode,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          }
        });

        res.on('end', () => {
          finish({
            statusCode,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });

        res.on('error', () => {
          if (chunks.length > 0) {
            finish({
              statusCode,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          } else {
            finish(null);
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      finish(null);
    });
    req.on('error', () => finish(null));
    req.end();
  });
}

/**
 * Query Google Cast / Chromecast device info endpoint on HTTP port 8008.
 */
export async function queryGoogleCast(
  ip,
  timeoutMs = 900,
  port = CAST_PORT
) {
  const res = await fetchHttpText(`http://${ip}:${port}/setup/eureka_info`, {
    expectedIp: ip,
    timeoutMs,
    maxBytes: 32 * 1024,
    maxRedirects: 0,
  });
  if (!res || res.statusCode !== 200 || !res.body) return null;

  try {
    const data = JSON.parse(res.body);
    const rawName = data?.name || data?.device_info?.name;
    const cleaned = cleanDeviceName(rawName, ip);
    if (cleaned) {
      return { hostname: cleaned, source: 'Cast' };
    }
  } catch {
    // Ignore non-JSON payloads.
  }
  return null;
}

/**
 * Extract the LOCATION URL header from a UPnP/SSDP response string.
 */
export function parseSsdpLocation(raw) {
  if (typeof raw !== 'string') return null;
  const match = raw.match(/^LOCATION:\s*(.+)$/im);
  if (!match) return null;
  const loc = match[1].trim();
  return loc || null;
}

/**
 * Extract a device's friendlyName (or fallback modelName) from UPnP description XML.
 */
export function parseUpnpXmlDeviceName(xml, ip = null) {
  if (typeof xml !== 'string' || !xml) return null;
  const friendlyMatch = xml.match(/<friendlyName>([\s\S]*?)<\/friendlyName>/i);
  if (friendlyMatch) {
    const decoded = decodeHtmlEntities(friendlyMatch[1]);
    const cleaned = cleanDeviceName(decoded, ip);
    if (cleaned) return cleaned;
  }

  const modelMatch = xml.match(/<modelName>([\s\S]*?)<\/modelName>/i);
  if (modelMatch) {
    const decoded = decodeHtmlEntities(modelMatch[1]);
    const cleaned = cleanDeviceName(decoded, ip);
    if (cleaned) return cleaned;
  }

  return null;
}

/**
 * Probe a host via unicast SSDP (UDP 1900) and fetch its UPnP XML friendlyName.
 */
export function querySsdp(ip, timeoutMs = 1000, port = SSDP_PORT) {
  const probe = Buffer.from(
    'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n',
    'ascii'
  );
  const startedAt = Date.now();

  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors.
      }
      resolve(result);
    };

    timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('error', () => finish(null));
    socket.on('message', async (msg, rinfo) => {
      if (rinfo.address !== ip) return;
      const location = parseSsdpLocation(msg.toString('utf8'));
      if (!location) return;

      let locUrl;
      try {
        locUrl = new URL(location);
      } catch {
        return;
      }
      if (locUrl.protocol !== 'http:' || locUrl.hostname !== ip) {
        return;
      }

      if (timer) clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors.
      }

      const remaining = Math.max(200, timeoutMs - (Date.now() - startedAt));
      const xmlRes = await fetchHttpText(locUrl.toString(), {
        expectedIp: ip,
        timeoutMs: remaining,
        maxBytes: 64 * 1024,
        maxRedirects: 1,
      });
      if (xmlRes && xmlRes.statusCode >= 200 && xmlRes.statusCode < 400) {
        const name = parseUpnpXmlDeviceName(xmlRes.body, ip);
        if (name) {
          finish({ hostname: name, source: 'UPnP' });
          return;
        }
      }
      finish(null);
    });

    socket.send(probe, port, ip, (err) => {
      if (err) finish(null);
    });
  });
}

/**
 * Build the 43-byte SNMPv2c 'public' GetRequest packet for OID 1.3.6.1.2.1.1.5.0 (sysName.0).
 */
export function buildSnmpSysNameQuery() {
  return Buffer.from([
    0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0xa0, 0x1c, 0x02, 0x04, 0x13, 0x37, 0x00, 0x02, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00,
  ]);
}

/**
 * Parse an SNMP GetResponse packet containing OID 1.3.6.1.2.1.1.5.0 and extract its OCTET STRING value.
 */
export function parseSnmpStringResponse(buf, ip = null) {
  if (!Buffer.isBuffer(buf) || buf.length < 20) return null;
  if (!buf.includes(0xa2)) return null;

  const oidIndex = buf.indexOf(SNMP_SYSNAME_OID);
  if (oidIndex === -1) return null;

  let pos = oidIndex + SNMP_SYSNAME_OID.length;
  if (pos + 2 > buf.length) return null;
  if (buf[pos] !== 0x04) return null; // OCTET STRING

  const lenByte = buf[pos + 1];
  let strLen = 0;
  let valueStart = pos + 2;

  if ((lenByte & 0x80) === 0) {
    strLen = lenByte;
  } else {
    const numLenBytes = lenByte & 0x7f;
    if (numLenBytes === 0 || numLenBytes > 2 || pos + 2 + numLenBytes > buf.length) {
      return null;
    }
    for (let i = 0; i < numLenBytes; i += 1) {
      strLen = (strLen << 8) | buf[pos + 2 + i];
    }
    valueStart = pos + 2 + numLenBytes;
  }

  if (strLen <= 0 || valueStart + strLen > buf.length) return null;
  const raw = buf.subarray(valueStart, valueStart + strLen).toString('utf8');
  return cleanDeviceName(raw, ip);
}

/**
 * Query SNMP sysName.0 over UDP port 161.
 */
export function querySnmpSysName(ip, timeoutMs = 900, port = SNMP_PORT) {
  const packet = buildSnmpSysNameQuery();

  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors.
      }
      resolve(result);
    };

    timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('error', () => finish(null));
    socket.on('message', (msg, rinfo) => {
      if (rinfo.address !== ip) return;
      const sysName = parseSnmpStringResponse(msg, ip);
      if (sysName) {
        finish({ hostname: sysName, source: 'SNMP' });
      }
    });

    socket.send(packet, port, ip, (err) => {
      if (err) finish(null);
    });
  });
}

/**
 * Extract a clean hostname from a TLS peer certificate's CN or DNS Subject Alternative Names.
 */
export function extractCertHostname(cert, ip = null) {
  if (!cert || typeof cert !== 'object') return null;

  const candidates = [];
  const cn = cert.subject?.CN;
  if (typeof cn === 'string') {
    candidates.push(cn);
  } else if (Array.isArray(cn)) {
    candidates.push(...cn);
  }

  if (typeof cert.subjectaltname === 'string') {
    for (const part of cert.subjectaltname.split(',')) {
      const match = part.trim().match(/^DNS:(.+)$/i);
      if (match) candidates.push(match[1].trim());
    }
  }

  for (const candidate of candidates) {
    if (typeof candidate !== 'string' || candidate.includes('*')) continue;
    const cleaned = cleanDeviceName(candidate, ip);
    if (cleaned) return cleaned;
  }
  return null;
}

function probeSingleTlsCert(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({
      host: ip,
      port,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });

    const finish = (val) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve(val);
    };

    socket.on('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate(false);
        const hostname = extractCertHostname(cert, ip);
        finish(hostname ? { hostname, source: 'TLS' } : null);
      } catch {
        finish(null);
      }
    });

    socket.on('timeout', () => finish(null));
    socket.on('error', () => finish(null));
  });
}

/**
 * Inspect TLS certificates on HTTPS ports (443, 8443) for a host's CN or DNS SAN.
 */
export async function queryTlsCertName(
  ip,
  timeoutMs = 900,
  ports = [443, 8443]
) {
  const results = await Promise.all(
    ports.map((port) => probeSingleTlsCert(ip, port, timeoutMs))
  );
  return results.find((r) => r?.hostname) || null;
}

/**
 * Extract a clean page title from HTML, filtering out generic error/login boilerplate.
 */
export function extractHtmlTitle(html, ip = null) {
  if (typeof html !== 'string' || !html) return null;
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return null;
  const decoded = decodeHtmlEntities(match[1]);
  return cleanDeviceName(decoded, ip);
}

/**
 * Probe HTTP ports (80, 8080) and extract a meaningful HTML <title>.
 */
export async function queryHttpTitle(
  ip,
  timeoutMs = 900,
  ports = [80, 8080]
) {
  const results = await Promise.all(
    ports.map(async (port) => {
      const res = await fetchHttpText(`http://${ip}:${port}/`, {
        expectedIp: ip,
        timeoutMs,
        maxBytes: 16 * 1024,
        maxRedirects: 1,
      });
      if (!res || !res.body) return null;
      const title = extractHtmlTitle(res.body, ip);
      return title ? { hostname: title, source: 'HTTP' } : null;
    })
  );
  return results.find((r) => r?.hostname) || null;
}

/**
 * Multi-protocol hostname resolver using a two-tier lookup pipeline:
 * Tier 1: mDNS -> DNS -> NetBIOS -> LLMNR
 * Tier 2 (if Tier 1 misses): Cast -> UPnP -> SNMP -> TLS -> HTTP -> Gateway
 */
export class HostnameResolver {
  constructor(options = {}) {
    this.queryTimeoutMs = options.queryTimeoutMs ?? 750;
    this.extendedTimeoutMs = options.extendedTimeoutMs ?? 950;
    this.enableExtended = options.enableExtended ?? true;
    this.inFlight = new Map();
  }

  clear() {
    this.inFlight.clear();
  }

  async resolve(ip, gatewayIp = null) {
    const existingTask = this.inFlight.get(ip);
    if (existingTask) {
      return existingTask;
    }

    const task = (async () => {
      try {
        const [mdnsRes, dnsRes, netbiosRes, llmnrRes] = await Promise.allSettled([
          queryMdns(ip, this.queryTimeoutMs),
          queryReverseDns(ip, gatewayIp, this.queryTimeoutMs),
          queryNetbios(ip, this.queryTimeoutMs),
          queryLlmnr(ip, this.queryTimeoutMs),
        ]);

        let resolved = null;
        if (mdnsRes.status === 'fulfilled' && mdnsRes.value?.hostname) {
          resolved = mdnsRes.value;
        } else if (dnsRes.status === 'fulfilled' && dnsRes.value?.hostname) {
          resolved = dnsRes.value;
        } else if (
          netbiosRes.status === 'fulfilled' &&
          netbiosRes.value?.hostname
        ) {
          resolved = netbiosRes.value;
        } else if (
          llmnrRes.status === 'fulfilled' &&
          llmnrRes.value?.hostname
        ) {
          resolved = llmnrRes.value;
        }

        if (!resolved && this.enableExtended) {
          const [castRes, ssdpRes, snmpRes, tlsRes, httpRes] =
            await Promise.allSettled([
              queryGoogleCast(ip, this.extendedTimeoutMs),
              querySsdp(ip, this.extendedTimeoutMs),
              querySnmpSysName(ip, this.extendedTimeoutMs),
              queryTlsCertName(ip, this.extendedTimeoutMs),
              queryHttpTitle(ip, this.extendedTimeoutMs),
            ]);

          if (castRes.status === 'fulfilled' && castRes.value?.hostname) {
            resolved = castRes.value;
          } else if (
            ssdpRes.status === 'fulfilled' &&
            ssdpRes.value?.hostname
          ) {
            resolved = ssdpRes.value;
          } else if (
            snmpRes.status === 'fulfilled' &&
            snmpRes.value?.hostname
          ) {
            resolved = snmpRes.value;
          } else if (tlsRes.status === 'fulfilled' && tlsRes.value?.hostname) {
            resolved = tlsRes.value;
          } else if (
            httpRes.status === 'fulfilled' &&
            httpRes.value?.hostname
          ) {
            resolved = httpRes.value;
          }
        }

        if (!resolved && gatewayIp && ip === gatewayIp) {
          resolved = { hostname: 'gateway.local', source: 'Gateway' };
        }

        return {
          hostname: resolved?.hostname ?? null,
          source: resolved?.source ?? null,
        };
      } finally {
        this.inFlight.delete(ip);
      }
    })();

    this.inFlight.set(ip, task);
    return task;
  }
}
