import dgram from 'node:dgram';
import dns from 'node:dns';
import { parseIpv4Octets } from './subnet.js';

const MDNS_PORT = 5353;
const MDNS_MULTICAST_ADDR = '224.0.0.251';
const NBNS_PORT = 137;

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

    socket.send(packet, MDNS_PORT, ip, (err) => {
      if (err) {
        // Still try multicast below in case unicast send failed.
      }
      try {
        socket.send(packet, MDNS_PORT, MDNS_MULTICAST_ADDR, () => {});
      } catch {
        // Ignore multicast send errors.
      }
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
 * Multi-protocol hostname resolver prioritizing mDNS -> DNS -> NetBIOS -> Gateway
 * with in-flight request deduplication (caching and retry scheduling are managed by LanScanner).
 */
export class HostnameResolver {
  constructor(options = {}) {
    this.queryTimeoutMs = options.queryTimeoutMs ?? 750;
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
        const [mdnsRes, dnsRes, netbiosRes] = await Promise.allSettled([
          queryMdns(ip, this.queryTimeoutMs),
          queryReverseDns(ip, gatewayIp, this.queryTimeoutMs),
          queryNetbios(ip, this.queryTimeoutMs),
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
        } else if (gatewayIp && ip === gatewayIp) {
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
