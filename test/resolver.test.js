import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildNetbiosQuery,
  buildPtrQuery,
  formatReversePtrName,
  parseDnsPtrResponse,
  parseNetbiosResponse,
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
