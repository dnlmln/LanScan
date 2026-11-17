import { execFile } from 'node:child_process';
import os from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const VIRTUAL_CONTAINER_PREFIXES = [
  '127.',
  '0.',
  '169.254.',
  '192.168.215.',
  '192.168.139.',
  '192.168.65.',
  '172.17.',
  '172.18.',
  '172.19.',
  '172.20.',
  '172.21.',
];

/**
 * Validate a dotted-quad IPv4 string and return its 4 numeric octets, or null.
 */
export function parseIpv4Octets(ip) {
  if (typeof ip !== 'string') return null;
  const trimmed = ip.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const num = Number(part);
    if (num < 0 || num > 255) return null;
    octets.push(num);
  }
  return octets;
}

/**
 * Convert an IPv4 string into an unsigned 32-bit integer for numeric sorting.
 */
export function ipToNumber(ip) {
  const octets = parseIpv4Octets(ip);
  if (!octets) return 0;
  return (
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
  );
}

/**
 * Normalize a subnet or IP input ('192.168.1.0/24', '192.168.1.1', or '192.168.1')
 * into a canonical /24 descriptor.
 */
export function normalizeSubnet(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!trimmed) return null;

  let baseIp = trimmed;
  if (trimmed.includes('/')) {
    const [addr, mask, ...rest] = trimmed.split('/');
    if (rest.length > 0 || mask !== '24') return null;
    baseIp = addr;
  }

  const parts = baseIp.split('.');
  if (parts.length === 3) {
    const octets = parseIpv4Octets(`${baseIp}.1`);
    if (!octets) return null;
    const prefix = `${octets[0]}.${octets[1]}.${octets[2]}`;
    return {
      subnet: `${prefix}.0/24`,
      prefix,
      gateway: `${prefix}.1`,
    };
  }

  const octets = parseIpv4Octets(baseIp);
  if (!octets) return null;
  const prefix = `${octets[0]}.${octets[1]}.${octets[2]}`;
  return {
    subnet: `${prefix}.0/24`,
    prefix,
    gateway: `${prefix}.1`,
  };
}

/**
 * Return true if the IP belongs to loopback, link-local, or container virtual bridges.
 */
export function isVirtualContainerIp(ip) {
  if (typeof ip !== 'string') return false;
  return VIRTUAL_CONTAINER_PREFIXES.some((prefix) => ip.startsWith(prefix));
}

/**
 * Return true if the IP is an RFC1918 private IPv4 address.
 */
export function isPrivateIpv4(ip) {
  const octets = parseIpv4Octets(ip);
  if (!octets) return false;
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

/**
 * Extract hop IP addresses from traceroute -n output.
 */
export function parseTracerouteHops(stdout) {
  if (typeof stdout !== 'string') return [];
  const hops = [];
  for (const line of stdout.split(/\r?\n/)) {
    const match = line.match(/^\s*\d+\s+(\d{1,3}(?:\.\d{1,3}){3})/);
    if (match && parseIpv4Octets(match[1])) {
      hops.push(match[1]);
    }
  }
  return hops;
}

/**
 * Extract the /24 prefix ('a.b.c') from a valid IPv4 address.
 */
function getPrefix24(ip) {
  const octets = parseIpv4Octets(ip);
  if (!octets) return null;
  return `${octets[0]}.${octets[1]}.${octets[2]}`;
}

/**
 * Collect /24 prefixes assigned to local non-loopback IPv4 interfaces.
 */
export function getLocalInterfacePrefixes() {
  const prefixes = new Set();
  const interfaces = os.networkInterfaces();
  for (const entries of Object.values(interfaces)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (entry && entry.family === 'IPv4' && !entry.internal) {
        const prefix = getPrefix24(entry.address);
        if (prefix) prefixes.add(prefix);
      }
    }
  }
  return prefixes;
}

/**
 * Select the physical LAN gateway IP from traceroute hops by inspecting private
 * hops prior to the first public Internet IP and skipping container virtual bridges.
 */
export function selectLanGatewayFromHops(hops, localPrefixes = new Set()) {
  if (!Array.isArray(hops) || hops.length === 0) return null;

  const prePublicPrivateHops = [];
  for (const ip of hops) {
    if (!isPrivateIpv4(ip)) break;
    prePublicPrivateHops.push(ip);
  }

  const externalLanHop = prePublicPrivateHops.find((ip) => {
    const prefix = getPrefix24(ip);
    return !isVirtualContainerIp(ip) && !(prefix && localPrefixes.has(prefix));
  });
  if (externalLanHop) return externalLanHop;

  return (
    prePublicPrivateHops.find((ip) => !isVirtualContainerIp(ip)) || null
  );
}

/**
 * Detect the physical LAN /24 subnet from configured override, traceroute hops,
 * host network interfaces, or fallback default.
 */
export async function detectSubnet(configuredSubnet = 'auto') {
  if (
    typeof configuredSubnet === 'string' &&
    configuredSubnet.trim().toLowerCase() !== 'auto'
  ) {
    const normalized = normalizeSubnet(configuredSubnet);
    if (normalized) {
      return { ...normalized, source: 'configured' };
    }
  }

  const localPrefixes = getLocalInterfacePrefixes();

  try {
    const { stdout } = await execFileAsync(
      'traceroute',
      ['-n', '-m', '5', '-q', '1', '-w', '1', '1.1.1.1'],
      { timeout: 4000 }
    );
    const hops = parseTracerouteHops(stdout);
    const lanHop = selectLanGatewayFromHops(hops, localPrefixes);
    if (lanHop) {
      const normalized = normalizeSubnet(lanHop);
      if (normalized) {
        return {
          subnet: normalized.subnet,
          prefix: normalized.prefix,
          gateway: lanHop,
          source: 'traceroute',
        };
      }
    }
  } catch {
    // Traceroute may fail when offline; fall back to interface inspection.
  }

  const interfaces = os.networkInterfaces();
  for (const entries of Object.values(interfaces)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (
        entry &&
        entry.family === 'IPv4' &&
        !entry.internal &&
        isPrivateIpv4(entry.address) &&
        !isVirtualContainerIp(entry.address)
      ) {
        const normalized = normalizeSubnet(entry.address);
        if (normalized) {
          return { ...normalized, source: 'interface' };
        }
      }
    }
  }

  return {
    subnet: '192.168.1.0/24',
    prefix: '192.168.1',
    gateway: '192.168.1.1',
    source: 'fallback',
  };
}

/**
 * Parse output lines from `fping -a -e -g <subnet>` into a Map of IP -> RTT (ms).
 */
export function parseFpingOutput(stdout) {
  const results = new Map();
  if (typeof stdout !== 'string' || !stdout.trim()) return results;

  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(
      /^(\d{1,3}(?:\.\d{1,3}){3})(?:\s+\(([\d.]+)\s*ms\))?/i
    );
    if (!match) continue;
    const ip = match[1];
    if (!parseIpv4Octets(ip)) continue;
    const rtt = match[2] !== undefined ? Number.parseFloat(match[2]) : 0;
    results.set(ip, Number.isFinite(rtt) ? Math.round(rtt * 100) / 100 : 0);
  }
  return results;
}
