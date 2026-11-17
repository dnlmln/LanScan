import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ipToNumber,
  isPrivateIpv4,
  isVirtualContainerIp,
  normalizeSubnet,
  parseFpingOutput,
  parseTracerouteHops,
  selectLanGatewayFromHops,
} from '../src/subnet.js';

test('normalizeSubnet handles CIDR, IP, and 3-octet prefixes', () => {
  assert.deepEqual(normalizeSubnet('192.168.1.0/24'), {
    subnet: '192.168.1.0/24',
    prefix: '192.168.1',
    gateway: '192.168.1.1',
  });
  assert.deepEqual(normalizeSubnet('192.168.1.42'), {
    subnet: '192.168.1.0/24',
    prefix: '192.168.1',
    gateway: '192.168.1.1',
  });
  assert.deepEqual(normalizeSubnet('10.0.5'), {
    subnet: '10.0.5.0/24',
    prefix: '10.0.5',
    gateway: '10.0.5.1',
  });
  assert.equal(normalizeSubnet('192.168.1.999'), null);
  assert.equal(normalizeSubnet('192.168.1.0/16'), null);
  assert.equal(normalizeSubnet('not-an-ip'), null);
});

test('isPrivateIpv4 and isVirtualContainerIp distinguish LAN vs container IPs', () => {
  assert.equal(isPrivateIpv4('192.168.1.1'), true);
  assert.equal(isPrivateIpv4('10.10.0.5'), true);
  assert.equal(isPrivateIpv4('172.16.4.2'), true);
  assert.equal(isPrivateIpv4('8.8.8.8'), false);

  assert.equal(isVirtualContainerIp('192.168.215.1'), true);
  assert.equal(isVirtualContainerIp('192.168.139.1'), true);
  assert.equal(isVirtualContainerIp('172.17.0.1'), true);
  assert.equal(isVirtualContainerIp('192.168.1.1'), false);
});

test('parseTracerouteHops extracts hop IPs cleanly', () => {
  const sample = `
traceroute to 1.1.1.1 (1.1.1.1), 5 hops max, 46 byte packets
 1  192.168.215.1  0.003 ms
 2  192.168.139.1  0.001 ms
 3  192.168.1.1  8.563 ms
 4  203.0.113.1  17.503 ms
`;
  assert.deepEqual(parseTracerouteHops(sample), [
    '192.168.215.1',
    '192.168.139.1',
    '192.168.1.1',
    '203.0.113.1',
  ]);
});

test('parseFpingOutput parses IP and RTT milliseconds', () => {
  const output = `
192.168.1.1 (3.66 ms)
192.168.1.10 (0.81 ms)
192.168.1.20 (12.4 ms)
`;
  const parsed = parseFpingOutput(output);
  assert.equal(parsed.size, 3);
  assert.equal(parsed.get('192.168.1.1'), 3.66);
  assert.equal(parsed.get('192.168.1.10'), 0.81);
  assert.equal(parsed.get('192.168.1.20'), 12.4);
});

test('ipToNumber sorts IP addresses numerically', () => {
  const ips = ['192.168.1.100', '192.168.1.2', '192.168.1.10', '192.168.1.1'];
  ips.sort((a, b) => ipToNumber(a) - ipToNumber(b));
  assert.deepEqual(ips, [
    '192.168.1.1',
    '192.168.1.2',
    '192.168.1.10',
    '192.168.1.100',
  ]);
});

test('selectLanGatewayFromHops skips compose bridge and OrbStack VM hops', () => {
  const hops = [
    '192.168.97.1',
    '192.168.139.1',
    '192.168.1.1',
    '203.0.113.1',
    '10.254.0.1',
  ];
  assert.equal(
    selectLanGatewayFromHops(hops, new Set(['192.168.97'])),
    '192.168.1.1'
  );
  assert.equal(
    selectLanGatewayFromHops(['192.168.1.1', '203.0.113.1'], new Set(['192.168.1'])),
    '192.168.1.1'
  );
});
