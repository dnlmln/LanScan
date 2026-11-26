import { execFile } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { scanHostPorts } from './portScanner.js';
import { HostnameResolver } from './resolver.js';
import {
  detectSubnet,
  ipToNumber,
  isPrivateIpv4,
  normalizeSubnet,
  parseFpingOutput,
  parseIpv4Octets,
} from './subnet.js';

const MIN_INTERVAL_MS = 250;
const MAX_INTERVAL_MS = 60000;
const HISTORY_LIMIT = 20;
export const HOSTNAME_CACHE_TTL_MS = 30 * 60 * 1000;
export const UNRESOLVED_RETRY_DELAY_MS = 30 * 1000;

/**
 * Clamp and validate a scan interval in milliseconds.
 */
export function clampIntervalMs(value, fallback = 1000) {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(MIN_INTERVAL_MS, Math.min(MAX_INTERVAL_MS, Math.round(num)));
}

/**
 * Default fping runner. fping exits with code 1 when some hosts in a subnet
 * do not reply, which is expected; stdout still lists all alive hosts.
 */
export function defaultRunFping(subnet, pingTimeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(
      'fping',
      ['-a', '-e', '-g', subnet, '-r', '0', '-t', String(pingTimeoutMs), '-i', '1'],
      { timeout: Math.max(5000, pingTimeoutMs + 3000), maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        if (!err || err.code === 1) {
          resolve(stdout || '');
          return;
        }
        if (stdout && stdout.trim()) {
          resolve(stdout);
          return;
        }
        const message = stderr?.trim() || err.message || 'fping execution failed';
        reject(new Error(message));
      }
    );
  });
}

/**
 * Live LAN scanner that sweeps a /24 subnet on a configurable interval,
 * tracks latency statistics, and resolves hostnames asynchronously.
 */
export class LanScanner extends EventEmitter {
  constructor(options = {}) {
    super();
    this.version = options.version || null;
    this.configuredSubnet = options.subnet || 'auto';
    this.subnet = null;
    this.gateway = null;
    this.subnetSource = 'auto';
    this.intervalMs = clampIntervalMs(options.intervalMs, 1000);
    this.pingTimeoutMs = Math.max(100, Number(options.pingTimeoutMs) || 350);
    this.graceMs = Math.max(500, Number(options.graceMs) || 3500);
    this.hostnameCacheTtlMs = Math.max(
      1000,
      Number(options.hostnameCacheTtlMs) || HOSTNAME_CACHE_TTL_MS
    );
    this.unresolvedRetryDelayMs = Math.max(
      0,
      options.unresolvedRetryDelayMs !== undefined
        ? Number(options.unresolvedRetryDelayMs)
        : UNRESOLVED_RETRY_DELAY_MS
    );
    this.paused = false;
    this.scanning = false;
    this.stopped = false;
    this.scanCount = 0;
    this.lastScanAt = null;
    this.lastScanDurationMs = 0;
    this.lastError = null;
    this.timer = null;

    this.hosts = new Map();
    this.resolvingIps = new Set();
    this.portScans = new Map();
    this.portScanningIps = new Map();
    this.resolver = options.resolver || new HostnameResolver();
    this.runFping = options.runFping || defaultRunFping;
    this.runPortScan = options.runPortScan || scanHostPorts;
  }

  async init() {
    const detected = await detectSubnet(this.configuredSubnet);
    this.subnet = detected.subnet;
    this.gateway = detected.gateway;
    this.subnetSource = detected.source;
    this.emitUpdate();
    return detected;
  }

  async start() {
    this.stopped = false;
    if (!this.subnet) {
      await this.init();
    }
    await this.runScanCycle();
  }

  stop() {
    this.stopped = true;
    this.clearTimer();
  }

  clearTimer() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  scheduleNext(elapsedMs = 0) {
    this.clearTimer();
    if (this.stopped || this.paused) return;
    const delay = Math.max(50, this.intervalMs - elapsedMs);
    this.timer = setTimeout(() => {
      this.runScanCycle().catch((err) => {
        this.lastError = err.message;
        this.emitUpdate();
      });
    }, delay);
  }

  async scanNow() {
    this.clearTimer();
    await this.runScanCycle();
  }

  async setConfig({ intervalMs, subnet, paused } = {}) {
    let subnetChanged = false;

    if (intervalMs !== undefined) {
      this.intervalMs = clampIntervalMs(intervalMs, this.intervalMs);
    }

    if (typeof subnet === 'string' && subnet.trim()) {
      const trimmed = subnet.trim();
      if (trimmed.toLowerCase() === 'auto') {
        this.configuredSubnet = 'auto';
        const detected = await detectSubnet('auto');
        if (detected.subnet !== this.subnet) {
          subnetChanged = true;
        }
        this.subnet = detected.subnet;
        this.gateway = detected.gateway;
        this.subnetSource = detected.source;
      } else {
        const normalized = normalizeSubnet(trimmed);
        if (!normalized) {
          throw new Error('Invalid subnet format. Expected e.g. 192.168.1.0/24');
        }
        if (!isPrivateIpv4(normalized.gateway)) {
          throw new Error(
            'Subnet must be a private RFC1918 IPv4 range (10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16)'
          );
        }
        this.configuredSubnet = normalized.subnet;
        if (normalized.subnet !== this.subnet) {
          subnetChanged = true;
        }
        this.subnet = normalized.subnet;
        this.gateway = normalized.gateway;
        this.subnetSource = 'manual';
      }
    }

    if (subnetChanged) {
      this.hosts.clear();
      this.resolvingIps.clear();
      this.portScans.clear();
      this.portScanningIps.clear();
      this.resolver.clear();
      this.scanCount = 0;
    }

    const wasPaused = this.paused;
    if (typeof paused === 'boolean') {
      this.paused = paused;
    }

    this.emitUpdate();

    if (this.paused) {
      this.clearTimer();
      return this.getState();
    }

    if (subnetChanged || (wasPaused && !this.paused)) {
      this.clearTimer();
      await this.runScanCycle();
    } else if (!this.scanning) {
      this.scheduleNext(0);
    }

    return this.getState();
  }

  async runScanCycle() {
    if (this.stopped || this.scanning) return;
    if (!this.subnet) {
      await this.init();
    }

    this.scanning = true;
    const startedAt = Date.now();
    this.emitUpdate();

    let elapsedMs = 0;

    try {
      const stdout = await this.runFping(this.subnet, this.pingTimeoutMs);
      const now = Date.now();
      elapsedMs = now - startedAt;
      const aliveMap = parseFpingOutput(stdout);

      this.applySweepResults(aliveMap, now);
      this.lastError = null;
      this.scanCount += 1;
      this.lastScanAt = now;
      this.lastScanDurationMs = elapsedMs;

      for (const ip of aliveMap.keys()) {
        this.ensureHostnameResolution(ip);
      }
    } catch (err) {
      elapsedMs = Date.now() - startedAt;
      this.lastError = err.message || 'Scan failed';
      this.lastScanDurationMs = elapsedMs;
    } finally {
      this.scanning = false;
      this.emitUpdate();
      this.scheduleNext(elapsedMs);
    }
  }

  applySweepResults(aliveMap, now = Date.now()) {
    const effectiveGraceMs = Math.max(this.graceMs, this.intervalMs * 2);

    for (const [ip, rttMs] of aliveMap.entries()) {
      let host = this.hosts.get(ip);
      if (!host) {
        host = {
          ip,
          hostname: null,
          hostnameSource: null,
          resolveAttempts: 0,
          lastResolveAttemptAt: 0,
          consecutiveResolveMisses: 0,
          rttMs,
          lastRttMs: rttMs,
          minRttMs: rttMs,
          maxRttMs: rttMs,
          avgRttMs: rttMs,
          rttSum: rttMs,
          hits: 1,
          totalChecks: 1,
          history: [rttMs],
          respondingNow: true,
          online: true,
          isGateway: ip === this.gateway,
          firstSeen: now,
          lastSeen: now,
        };
        this.hosts.set(ip, host);
      } else {
        host.hits += 1;
        host.totalChecks += 1;
        host.rttMs = rttMs;
        host.lastRttMs = rttMs;
        host.minRttMs =
          host.minRttMs === null ? rttMs : Math.min(host.minRttMs, rttMs);
        host.maxRttMs =
          host.maxRttMs === null ? rttMs : Math.max(host.maxRttMs, rttMs);
        host.rttSum += rttMs;
        host.avgRttMs = Math.round((host.rttSum / host.hits) * 100) / 100;
        host.history.push(rttMs);
        if (host.history.length > HISTORY_LIMIT) {
          host.history.shift();
        }
        host.respondingNow = true;
        host.online = true;
        host.isGateway = ip === this.gateway;
        host.lastSeen = now;
      }
    }

    for (const [ip, host] of this.hosts.entries()) {
      if (aliveMap.has(ip)) continue;
      host.totalChecks += 1;
      host.rttMs = null;
      host.respondingNow = false;
      host.online = now - host.lastSeen <= effectiveGraceMs;
      host.history.push(null);
      if (host.history.length > HISTORY_LIMIT) {
        host.history.shift();
      }
    }
  }

  shouldAutoResolveHost(host, now = Date.now()) {
    if (!host || this.resolvingIps.has(host.ip)) return false;
    if (host.resolveAttempts === 0) return true;

    const elapsed = now - host.lastResolveAttemptAt;
    if (host.hostname) {
      if (host.consecutiveResolveMisses === 1) {
        return elapsed >= this.unresolvedRetryDelayMs;
      }
      return elapsed >= this.hostnameCacheTtlMs;
    }
    if (host.resolveAttempts === 1) {
      return elapsed >= this.unresolvedRetryDelayMs;
    }
    return elapsed >= this.hostnameCacheTtlMs;
  }

  ensureHostnameResolution(ip, force = false) {
    if (this.resolvingIps.has(ip)) return Promise.resolve(null);
    const host = this.hosts.get(ip);
    const now = Date.now();

    if (!force && !this.shouldAutoResolveHost(host, now)) {
      return Promise.resolve(
        host
          ? {
              hostname: host.hostname,
              source: host.hostnameSource,
            }
          : null
      );
    }

    if (host) {
      if (force || now - host.lastResolveAttemptAt >= this.hostnameCacheTtlMs) {
        host.resolveAttempts = 1;
      } else {
        host.resolveAttempts += 1;
      }
      host.lastResolveAttemptAt = now;
    }

    this.resolvingIps.add(ip);
    return this.resolver
      .resolve(ip, this.gateway)
      .then((res) => {
        const currentHost = this.hosts.get(ip);
        if (currentHost) {
          if (res?.hostname) {
            currentHost.hostname = res.hostname;
            currentHost.hostnameSource = res.source;
            currentHost.consecutiveResolveMisses = 0;
          } else if (currentHost.hostname) {
            if (force || currentHost.consecutiveResolveMisses >= 1) {
              currentHost.hostname = null;
              currentHost.hostnameSource = null;
              currentHost.consecutiveResolveMisses = 0;
              currentHost.resolveAttempts = 2;
            } else {
              currentHost.consecutiveResolveMisses = 1;
            }
          }
        }
        return res;
      })
      .catch(() => null)
      .finally(() => {
        this.resolvingIps.delete(ip);
        this.emitUpdate();
      });
  }

  async resolveHost(ip, force = true) {
    const trimmedIp = typeof ip === 'string' ? ip.trim() : '';
    if (!parseIpv4Octets(trimmedIp)) {
      throw new Error('Invalid IPv4 address');
    }
    if (!isPrivateIpv4(trimmedIp)) {
      throw new Error(
        'Hostname resolution is restricted to private LAN IPv4 addresses'
      );
    }
    const res = await this.ensureHostnameResolution(trimmedIp, force);
    this.emitUpdate();
    return res;
  }

  async resolveAllHosts() {
    const ips = Array.from(this.hosts.keys());
    await Promise.allSettled(
      ips.map((ip) => this.ensureHostnameResolution(ip, true))
    );
    this.emitUpdate();
    return this.getState();
  }

  async scanPorts(ip, options = {}) {
    const trimmedIp = typeof ip === 'string' ? ip.trim() : '';
    if (!parseIpv4Octets(trimmedIp)) {
      throw new Error('Invalid IPv4 address');
    }
    if (!isPrivateIpv4(trimmedIp)) {
      throw new Error(
        'Port scanning is restricted to private LAN IPv4 addresses'
      );
    }

    const existingTask = this.portScanningIps.get(trimmedIp);
    if (existingTask) {
      return existingTask;
    }

    const task = (async () => {
      try {
        const result = await this.runPortScan(trimmedIp, options);
        this.portScans.set(trimmedIp, result);
        return result;
      } finally {
        this.portScanningIps.delete(trimmedIp);
        this.emitUpdate();
      }
    })();

    this.portScanningIps.set(trimmedIp, task);
    this.emitUpdate();
    return task;
  }

  getState() {
    const hosts = Array.from(this.hosts.values())
      .sort((a, b) => ipToNumber(a.ip) - ipToNumber(b.ip))
      .map((host) => ({
        ip: host.ip,
        hostname: host.hostname,
        hostnameSource: host.hostnameSource,
        resolving: this.resolvingIps.has(host.ip),
        portScanning: this.portScanningIps.has(host.ip),
        portScan: this.portScans.get(host.ip) || null,
        respondingNow: host.respondingNow,
        online: host.online,
        isGateway: host.isGateway,
        rttMs: host.rttMs,
        lastRttMs: host.lastRttMs,
        minRttMs: host.minRttMs,
        maxRttMs: host.maxRttMs,
        avgRttMs: host.avgRttMs,
        history: host.history.slice(),
        hits: host.hits,
        totalChecks: host.totalChecks,
        responseRate:
          host.totalChecks > 0
            ? Math.round((host.hits / host.totalChecks) * 100)
            : 0,
        firstSeen: host.firstSeen,
        lastSeen: host.lastSeen,
      }));

    const respondingCount = hosts.filter((h) => h.respondingNow).length;
    const onlineCount = hosts.filter((h) => h.online).length;
    const resolvedCount = hosts.filter((h) => Boolean(h.hostname)).length;

    return {
      version: this.version,
      subnet: this.subnet,
      configuredSubnet: this.configuredSubnet,
      subnetSource: this.subnetSource,
      gateway: this.gateway,
      intervalMs: this.intervalMs,
      pingTimeoutMs: this.pingTimeoutMs,
      paused: this.paused,
      scanning: this.scanning,
      scanCount: this.scanCount,
      lastScanAt: this.lastScanAt,
      lastScanDurationMs: this.lastScanDurationMs,
      lastError: this.lastError,
      portScanningIps: Array.from(this.portScanningIps.keys()),
      portScans: Object.fromEntries(this.portScans),
      summary: {
        respondingCount,
        onlineCount,
        totalSeenCount: hosts.length,
        resolvedCount,
      },
      hosts,
    };
  }

  emitUpdate() {
    this.emit('update', this.getState());
  }
}
