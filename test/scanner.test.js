import assert from 'node:assert/strict';
import test from 'node:test';
import { clampIntervalMs, LanScanner } from '../src/scanner.js';

test('clampIntervalMs enforces min and max bounds', () => {
  assert.equal(clampIntervalMs(100), 250);
  assert.equal(clampIntervalMs(1000), 1000);
  assert.equal(clampIntervalMs(90000), 60000);
  assert.equal(clampIntervalMs('invalid', 1000), 1000);
});

test('LanScanner tracks RTT stats, grace periods, and resolves hostnames', async () => {
  let sweepIndex = 0;
  const sweeps = [
    '192.168.1.1 (2.50 ms)\n192.168.1.10 (0.75 ms)\n',
    '192.168.1.1 (4.50 ms)\n',
  ];

  const fakeResolver = {
    clear() {},
    async resolve(ip) {
      if (ip === '192.168.1.10') {
        return { hostname: 'workstation.local', source: 'mDNS' };
      }
      if (ip === '192.168.1.1') {
        return { hostname: 'gateway.local', source: 'Gateway' };
      }
      return { hostname: null, source: null };
    },
  };

  const scanner = new LanScanner({
    subnet: '192.168.1.0/24',
    intervalMs: 1000,
    graceMs: 5000,
    resolver: fakeResolver,
    runFping: async () => sweeps[sweepIndex++] || '',
  });

  await scanner.init();
  // Prevent background timer from running during assertions
  scanner.paused = true;

  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));

  let state = scanner.getState();
  assert.equal(state.subnet, '192.168.1.0/24');
  assert.equal(state.scanCount, 1);
  assert.equal(state.summary.respondingCount, 2);
  assert.equal(state.summary.resolvedCount, 2);

  const host = state.hosts.find((h) => h.ip === '192.168.1.10');
  assert.equal(host.hostname, 'workstation.local');
  assert.equal(host.hostnameSource, 'mDNS');
  assert.equal(host.rttMs, 0.75);

  await scanner.runScanCycle();
  state = scanner.getState();
  const gw = state.hosts.find((h) => h.ip === '192.168.1.1');
  const hostAfter = state.hosts.find((h) => h.ip === '192.168.1.10');

  assert.equal(gw.avgRttMs, 3.5);
  assert.equal(gw.minRttMs, 2.5);
  assert.equal(gw.maxRttMs, 4.5);
  assert.equal(hostAfter.respondingNow, false);
  assert.equal(hostAfter.online, true); // still within grace period
  assert.equal(hostAfter.responseRate, 50);

  await assert.rejects(
    () => scanner.setConfig({ subnet: 'not-valid' }),
    /Invalid subnet format/
  );
  await assert.rejects(
    () => scanner.setConfig({ subnet: '8.8.8.0/24' }),
    /private RFC1918 IPv4 range/
  );
  await assert.rejects(() => scanner.resolveHost('not-valid'), /Invalid IPv4/);
  await assert.rejects(
    () => scanner.resolveHost('8.8.8.8'),
    /restricted to private LAN IPv4/
  );
  scanner.stop();
});

test('LanScanner resolves on discovery, retries once after 30s, then caches for 30 min', async () => {
  const resolveCounts = new Map();
  let returnNameForUnresolved = false;

  const countingResolver = {
    clear() {},
    async resolve(ip) {
      resolveCounts.set(ip, (resolveCounts.get(ip) || 0) + 1);
      if (ip === '192.168.1.1') {
        return { hostname: 'gateway.local', source: 'Gateway' };
      }
      if (ip === '192.168.1.50' && returnNameForUnresolved) {
        return { hostname: 'late-device.local', source: 'mDNS' };
      }
      return { hostname: null, source: null };
    },
  };

  const scanner = new LanScanner({
    subnet: '192.168.1.0/24',
    intervalMs: 1000,
    hostnameCacheTtlMs: 30 * 60 * 1000,
    unresolvedRetryDelayMs: 30 * 1000,
    resolver: countingResolver,
    runFping: async () => '192.168.1.1 (2.0 ms)\n192.168.1.50 (5.0 ms)\n',
  });

  await scanner.init();
  scanner.paused = true;

  // Sweep 1: initial discovery triggers attempt 1 for both IPs
  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(resolveCounts.get('192.168.1.1'), 1);
  assert.equal(resolveCounts.get('192.168.1.50'), 1);

  // Sweep 2 (immediately after): neither IP should be re-probed
  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(resolveCounts.get('192.168.1.1'), 1);
  assert.equal(resolveCounts.get('192.168.1.50'), 1);

  // Simulate 31 seconds elapsed since attempt 1 -> unresolved host gets 1 retry, resolved stays cached
  const unresolvedHost = scanner.hosts.get('192.168.1.50');
  const resolvedHost = scanner.hosts.get('192.168.1.1');
  unresolvedHost.lastResolveAttemptAt = Date.now() - 31_000;
  resolvedHost.lastResolveAttemptAt = Date.now() - 31_000;

  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(resolveCounts.get('192.168.1.1'), 1);
  assert.equal(resolveCounts.get('192.168.1.50'), 2);
  assert.equal(unresolvedHost.resolveAttempts, 2);

  // Simulate another 60 seconds elapsed after attempt 2 -> still cached negative for 30 min
  unresolvedHost.lastResolveAttemptAt = Date.now() - 60_000;
  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(resolveCounts.get('192.168.1.50'), 2);

  // Manual Resolve All forces immediate re-probe regardless of cache
  returnNameForUnresolved = true;
  await scanner.resolveAllHosts();
  assert.equal(resolveCounts.get('192.168.1.1'), 2);
  assert.equal(resolveCounts.get('192.168.1.50'), 3);
  assert.equal(unresolvedHost.hostname, 'late-device.local');

  scanner.stop();
});

test('LanScanner clears stale hostname after DHCP reassignment confirmation or forced resolve', async () => {
  let currentName = 'old-mac.local';
  let calls = 0;

  const dhcpResolver = {
    clear() {},
    async resolve() {
      calls += 1;
      return currentName
        ? { hostname: currentName, source: 'mDNS' }
        : { hostname: null, source: null };
    },
  };

  const scanner = new LanScanner({
    subnet: '192.168.1.0/24',
    intervalMs: 1000,
    hostnameCacheTtlMs: 30 * 60 * 1000,
    unresolvedRetryDelayMs: 30 * 1000,
    resolver: dhcpResolver,
    runFping: async () => '192.168.1.166 (3.0 ms)\n',
  });

  await scanner.init();
  scanner.paused = true;

  // Initial discovery resolves old-mac.local
  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  const host = scanner.hosts.get('192.168.1.166');
  assert.equal(host.hostname, 'old-mac.local');
  assert.equal(calls, 1);

  // Simulate DHCP reassignment (resolver now returns null) and 30+ min elapsed
  currentName = null;
  host.lastResolveAttemptAt = Date.now() - 31 * 60 * 1000;

  // First re-check records miss 1 and keeps old-mac.local pending 30s confirmation
  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(calls, 2);
  assert.equal(host.hostname, 'old-mac.local');
  assert.equal(host.consecutiveResolveMisses, 1);

  // Simulate 31s elapsed -> confirmation retry runs and clears stale hostname
  host.lastResolveAttemptAt = Date.now() - 31_000;
  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(calls, 3);
  assert.equal(host.hostname, null);
  assert.equal(host.hostnameSource, null);

  // Subsequent sweeps stay cached negative (no immediate re-probes)
  await scanner.runScanCycle();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(calls, 3);

  // Re-resolve a name, then verify forced resolveAllHosts clears stale name immediately
  currentName = 'new-mac.local';
  await scanner.resolveAllHosts();
  assert.equal(host.hostname, 'new-mac.local');
  currentName = null;
  await scanner.resolveAllHosts();
  assert.equal(host.hostname, null);
  assert.equal(host.hostnameSource, null);

  scanner.stop();
});
