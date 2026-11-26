import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import http from 'node:http';
import test from 'node:test';
import {
  buildNetbiosQuery,
  buildPtrQuery,
  buildSnmpSysNameQuery,
  cleanDeviceName,
  extractCertHostname,
  extractHtmlTitle,
  formatReversePtrName,
  parseDnsPtrResponse,
  parseNetbiosResponse,
  parseSnmpStringResponse,
  parseSsdpLocation,
  parseUpnpXmlDeviceName,
  queryGoogleCast,
  queryHttpTitle,
  querySnmpSysName,
} from '../src/resolver.js';

function encodeLabels(domain) {
  const parts = domain.split('.');
  const bufs = [];
  for (const part of parts) {
    const b = Buffer.from(part, 'ascii');
    bufs.push(Buffer.from([b.length]), b);
  }
  bufs.push(Buffer.from([0x00]));
  return Buffer.concat(bufs);
}

test('formatReversePtrName and buildPtrQuery construct valid DNS PTR query', () => {
  assert.equal(
    formatReversePtrName('192.168.1.10'),
    '10.1.168.192.in-addr.arpa'
  );
  const query = buildPtrQuery('192.168.1.10');
  assert.equal(query.readUInt16BE(4), 1); // QDCOUNT
  assert.equal(query.readUInt16BE(query.length - 4), 12); // QTYPE PTR
  assert.equal(query.readUInt16BE(query.length - 2), 1); // QCLASS IN
});

test('parseDnsPtrResponse parses mDNS PTR response with compression pointer', () => {
  const header = Buffer.from([
    0x00, 0x00, // ID
    0x84, 0x00, // Standard query response, authoritative
    0x00, 0x00, // QDCOUNT = 0
    0x00, 0x01, // ANCOUNT = 1
    0x00, 0x00,
    0x00, 0x00,
  ]);

  const owner = encodeLabels('10.1.168.192.in-addr.arpa');
  const rdataPrefix = encodeLabels('workstation');
  // Compression pointer to '.local' or full name: test full label + compression pointer to .in-addr.arpa
  // Here let's encode full hostname 'workstation.local.' directly in one RR and also test compression in another.
  const fullTarget = encodeLabels('workstation.local');
  const rrMeta = Buffer.alloc(10);
  rrMeta.writeUInt16BE(12, 0); // PTR
  rrMeta.writeUInt16BE(1, 2); // IN
  rrMeta.writeUInt32BE(120, 4); // TTL
  rrMeta.writeUInt16BE(fullTarget.length, 8);

  const packet = Buffer.concat([header, owner, rrMeta, fullTarget]);
  const parsed = parseDnsPtrResponse(packet);
  assert.deepEqual(parsed, {
    hostname: 'workstation.local',
    owner: '10.1.168.192.in-addr.arpa',
  });

  // Also verify compression pointer in owner name (pointing back to question at offset 12)
  const qHeader = Buffer.from([
    0x13, 0x37,
    0x84, 0x00,
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x01, // ANCOUNT = 1
    0x00, 0x00,
    0x00, 0x00,
  ]);
  const qSection = Buffer.concat([
    encodeLabels('20.1.168.192.in-addr.arpa'),
    Buffer.from([0x00, 0x0c, 0x00, 0x01]),
  ]);
  const compressedOwner = Buffer.from([0xc0, 0x0c]); // Pointer to offset 12
  const rdata2 = encodeLabels('media-tv.local');
  const rrMeta2 = Buffer.alloc(10);
  rrMeta2.writeUInt16BE(12, 0);
  rrMeta2.writeUInt16BE(1, 2);
  rrMeta2.writeUInt32BE(120, 4);
  rrMeta2.writeUInt16BE(rdata2.length, 8);

  const compressedPacket = Buffer.concat([
    qHeader,
    qSection,
    compressedOwner,
    rrMeta2,
    rdata2,
  ]);
  assert.deepEqual(parseDnsPtrResponse(compressedPacket), {
    hostname: 'media-tv.local',
    owner: '20.1.168.192.in-addr.arpa',
  });
  assert.ok(rdataPrefix.length > 0);
});

test('buildNetbiosQuery and parseNetbiosResponse handle NBSTAT packets', () => {
  const query = buildNetbiosQuery();
  assert.equal(query.length, 50);

  const headerAndPrefix = Buffer.alloc(57, 0);
  headerAndPrefix[56] = 2; // 2 entries

  // Entry 1: WORKGROUP (group flag 0x8000) -> should be skipped
  const entry1 = Buffer.alloc(18, 0x20);
  Buffer.from('WORKGROUP').copy(entry1, 0);
  entry1[15] = 0x00;
  entry1.writeUInt16BE(0x8000, 16);

  // Entry 2: NAS-BOX (unique workstation 0x00) -> should be returned
  const entry2 = Buffer.alloc(18, 0x20);
  Buffer.from('NAS-BOX').copy(entry2, 0);
  entry2[15] = 0x00;
  entry2.writeUInt16BE(0x0400, 16);

  const resp = Buffer.concat([headerAndPrefix, entry1, entry2]);
  assert.equal(parseNetbiosResponse(resp), 'NAS-BOX');
});

test('parseSsdpLocation and parseUpnpXmlDeviceName extract device name and decode entities', () => {
  const ssdp =
    'HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.50:1400/xml/device_description.xml\r\n\r\n';
  assert.equal(
    parseSsdpLocation(ssdp),
    'http://192.168.1.50:1400/xml/device_description.xml'
  );
  assert.equal(parseSsdpLocation('HTTP/1.1 200 OK\r\n\r\n'), null);

  const xmlFriendly =
    '<root><device><friendlyName>Living Room &amp; TV</friendlyName><modelName>Sonos Arc</modelName></device></root>';
  assert.equal(
    parseUpnpXmlDeviceName(xmlFriendly, '192.168.1.50'),
    'Living Room & TV'
  );

  const xmlModelFallback =
    '<root><device><friendlyName>192.168.1.50</friendlyName><modelName>Canon GX2020 series</modelName></device></root>';
  assert.equal(
    parseUpnpXmlDeviceName(xmlModelFallback, '192.168.1.50'),
    'Canon GX2020 series'
  );
});

test('buildSnmpSysNameQuery and parseSnmpStringResponse handle SNMP sysName packets', () => {
  const query = buildSnmpSysNameQuery();
  assert.equal(query.length, 43);

  const oid = Buffer.from([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]);
  const sysName = Buffer.from('core-switch-01', 'ascii');
  const resp = Buffer.concat([
    Buffer.from([0x30, 0x20, 0x02, 0x01, 0x01, 0x04, 0x06]),
    Buffer.from('public', 'ascii'),
    Buffer.from([0xa2, 0x16, 0x06, 0x08]),
    oid,
    Buffer.from([0x04, sysName.length]),
    sysName,
  ]);
  assert.equal(parseSnmpStringResponse(resp, '192.168.1.2'), 'core-switch-01');
});

test('extractCertHostname and extractHtmlTitle filter boilerplate and invalid names', () => {
  assert.equal(
    extractCertHostname(
      { subject: { CN: 'proxmox.local' }, subjectaltname: 'DNS:pve.local' },
      '192.168.1.10'
    ),
    'proxmox.local'
  );
  assert.equal(
    extractCertHostname(
      { subject: { CN: '*.example.com' }, subjectaltname: 'DNS:192.168.1.10, DNS:nas-box.lan' },
      '192.168.1.10'
    ),
    'nas-box.lan'
  );
  assert.equal(
    extractCertHostname({ subject: { CN: 'localhost' } }, '192.168.1.10'),
    null
  );

  assert.equal(
    extractHtmlTitle('<html><head><title>Synology&nbsp;NAS &amp; DSM</title></head></html>', '192.168.1.10'),
    'Synology NAS & DSM'
  );
  assert.equal(extractHtmlTitle('<title>404 Not Found</title>', '192.168.1.10'), null);
  assert.equal(extractHtmlTitle('<title>Login</title>', '192.168.1.10'), null);
  assert.equal(cleanDeviceName('192.168.1.10', '192.168.1.10'), null);
});

test('queryGoogleCast, queryHttpTitle, and querySnmpSysName resolve against local servers', async () => {
  const castServer = http.createServer((req, res) => {
    if (req.url === '/setup/eureka_info') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ name: 'Kitchen Speaker' }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const httpServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><head><title>Archer AX55 Router</title></head></html>');
  });

  const snmpSocket = dgram.createSocket('udp4');
  snmpSocket.on('message', (_msg, rinfo) => {
    const oid = Buffer.from([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]);
    const val = Buffer.from('office-printer', 'ascii');
    const reply = Buffer.concat([
      Buffer.from([0x30, 0x1e, 0xa2, 0x1a, 0x06, 0x08]),
      oid,
      Buffer.from([0x04, val.length]),
      val,
    ]);
    snmpSocket.send(reply, rinfo.port, rinfo.address);
  });

  await Promise.all([
    new Promise((r) => castServer.listen(0, '127.0.0.1', r)),
    new Promise((r) => httpServer.listen(0, '127.0.0.1', r)),
    new Promise((r) => snmpSocket.bind(0, '127.0.0.1', r)),
  ]);

  try {
    const castRes = await queryGoogleCast(
      '127.0.0.1',
      500,
      castServer.address().port
    );
    assert.deepEqual(castRes, { hostname: 'Kitchen Speaker', source: 'Cast' });

    const httpRes = await queryHttpTitle(
      '127.0.0.1',
      500,
      [httpServer.address().port]
    );
    assert.deepEqual(httpRes, { hostname: 'Archer AX55 Router', source: 'HTTP' });

    const snmpRes = await querySnmpSysName(
      '127.0.0.1',
      500,
      snmpSocket.address().port
    );
    assert.deepEqual(snmpRes, { hostname: 'office-printer', source: 'SNMP' });
  } finally {
    await Promise.all([
      new Promise((r) => castServer.close(r)),
      new Promise((r) => httpServer.close(r)),
      new Promise((r) => snmpSocket.close(r)),
    ]);
  }
});
