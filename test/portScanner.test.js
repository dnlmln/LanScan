import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import test from 'node:test';
import {
  buildUdpProbePayload,
  getServiceInfo,
  scanHostPorts,
} from '../src/portScanner.js';
import { LanScanner } from '../src/scanner.js';

function startTcpServer() {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => {
      socket.write('HELLO-LANSCAN\r\n');
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: addr.port });
    });
  });
}

function getUnusedTcpPort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function startUdpServer() {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    socket.on('message', (msg, rinfo) => {
      socket.send(Buffer.from('UDP-PONG'), rinfo.port, rinfo.address);
    });
    socket.bind(0, '127.0.0.1', () => {
      const addr = socket.address();
      resolve({ socket, port: addr.port });
    });
  });
}

function getUnusedUdpPort() {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    socket.bind(0, '127.0.0.1', () => {
      const { port } = socket.address();
      socket.close(() => resolve(port));
    });
  });
}

test('getServiceInfo and buildUdpProbePayload return expected metadata and probes', () => {
  assert.deepEqual(getServiceInfo(22, 'tcp'), {
    service: 'ssh',
    description: 'Secure Shell',
  });
  assert.deepEqual(getServiceInfo(5353, 'udp'), {
    service: 'mdns',
    description: 'Multicast DNS (Bonjour)',
  });
  assert.equal(getServiceInfo(65123, 'tcp').service, 'unknown');

  assert.equal(buildUdpProbePayload(123, '127.0.0.1').length, 48);
  assert.equal(buildUdpProbePayload(161, '127.0.0.1')[0], 0x30);
  assert.ok(
    buildUdpProbePayload(1900, '127.0.0.1').toString('ascii').includes('M-SEARCH')
  );
});

test('scanHostPorts detects open TCP and UDP ports and skips closed ports', async () => {
  const tcp = await startTcpServer();
  const udp = await startUdpServer();
  const closedTcpPort = await getUnusedTcpPort();
  const closedUdpPort = await getUnusedUdpPort();

  try {
    const result = await scanHostPorts('127.0.0.1', {
      tcpPorts: [tcp.port, closedTcpPort],
      udpPorts: [udp.port, closedUdpPort],
      tcpTimeoutMs: 300,
      udpTimeoutMs: 300,
    });

    assert.equal(result.ip, '127.0.0.1');
    assert.equal(result.tcpScannedCount, 2);
    assert.equal(result.udpScannedCount, 2);

    const openTcp = result.openPorts.filter((p) => p.protocol === 'tcp');
    const openUdp = result.openPorts.filter((p) => p.protocol === 'udp');

    assert.equal(openTcp.length, 1);
    assert.equal(openTcp[0].port, tcp.port);
    assert.equal(openTcp[0].banner, 'HELLO-LANSCAN');
    assert.ok(openTcp[0].rttMs >= 0);

    assert.equal(openUdp.length, 1);
    assert.equal(openUdp[0].port, udp.port);
    assert.equal(openUdp[0].banner, 'UDP-PONG');
    assert.ok(openUdp[0].rttMs >= 0);
  } finally {
    await new Promise((r) => tcp.server.close(r));
    await new Promise((r) => udp.socket.close(r));
  }
});

test('LanScanner.scanPorts validates IPs and stores port scan results in state', async () => {
  const scanner = new LanScanner({
    subnet: '192.168.1.0/24',
    runFping: async () => '192.168.1.1 (2.0 ms)\n',
    runPortScan: async (ip) => ({
      ip,
      scannedAt: 1234567890,
      durationMs: 42,
      tcpScannedCount: 95,
      udpScannedCount: 25,
      openPorts: [
        {
          port: 80,
          protocol: 'tcp',
          state: 'open',
          rttMs: 1.5,
          service: 'http',
          description: 'Web Server (HTTP)',
          banner: null,
        },
      ],
    }),
  });

  await scanner.init();
  scanner.paused = true;
  await scanner.runScanCycle();

  await assert.rejects(() => scanner.scanPorts('invalid-ip'), /Invalid IPv4/);

  const scanRes = await scanner.scanPorts('192.168.1.1');
  assert.equal(scanRes.openPorts.length, 1);

  const state = scanner.getState();
  const gw = state.hosts.find((h) => h.ip === '192.168.1.1');
  assert.equal(gw.portScanning, false);
  assert.equal(gw.portScan.openPorts[0].port, 80);
  assert.equal(state.portScans['192.168.1.1'].durationMs, 42);

  scanner.stop();
});
