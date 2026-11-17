import dgram from 'node:dgram';
import net from 'node:net';
import { buildNetbiosQuery, buildPtrQuery } from './resolver.js';
import { parseIpv4Octets } from './subnet.js';

export const COMMON_TCP_PORTS = [
  21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465,
  515, 548, 554, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1883, 2049,
  2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 3478, 3689, 4000, 4443, 5000,
  5001, 5060, 5353, 5357, 5432, 5672, 5900, 5901, 5984, 6000, 6379, 6443, 6667,
  7000, 7001, 7100, 7443, 8000, 8006, 8008, 8009, 8080, 8081, 8086, 8088, 8096,
  8123, 8200, 8384, 8443, 8500, 8880, 8883, 8888, 9000, 9001, 9090, 9091, 9100,
  9200, 9418, 9443, 10000, 11211, 27017, 32400, 49152, 49153, 49154, 51413,
  62078,
];

export const COMMON_UDP_PORTS = [
  53, 67, 68, 69, 111, 123, 137, 138, 161, 427, 500, 514, 520, 631, 1701, 1900,
  3478, 3702, 4500, 5351, 5353, 5355, 5683, 10001, 32414,
];

const TCP_SERVICES = new Map([
  [21, ['ftp', 'File Transfer Protocol']],
  [22, ['ssh', 'Secure Shell']],
  [23, ['telnet', 'Telnet Remote Terminal']],
  [25, ['smtp', 'Simple Mail Transfer Protocol']],
  [53, ['dns', 'Domain Name System']],
  [80, ['http', 'Web Server (HTTP)']],
  [81, ['http-alt', 'Alternate HTTP / Proxy UI']],
  [88, ['kerberos', 'Kerberos Authentication']],
  [110, ['pop3', 'POP3 Mail']],
  [111, ['rpcbind', 'ONC RPC Portmapper']],
  [135, ['msrpc', 'Microsoft RPC Endpoint Mapper']],
  [139, ['netbios-ssn', 'NetBIOS Session Service']],
  [143, ['imap', 'IMAP Mail']],
  [389, ['ldap', 'Directory Service (LDAP)']],
  [443, ['https', 'Secure Web Server (HTTPS)']],
  [445, ['microsoft-ds', 'SMB / Windows File Sharing']],
  [465, ['smtps', 'Secure SMTP']],
  [515, ['printer', 'LPD Line Printer Spooler']],
  [548, ['afp', 'Apple Filing Protocol']],
  [554, ['rtsp', 'Real Time Streaming Protocol']],
  [587, ['submission', 'SMTP Mail Submission']],
  [631, ['ipp', 'Internet Printing Protocol / CUPS']],
  [636, ['ldaps', 'Secure LDAP']],
  [873, ['rsync', 'Rsync File Synchronization']],
  [993, ['imaps', 'Secure IMAP']],
  [995, ['pop3s', 'Secure POP3']],
  [1080, ['socks', 'SOCKS Proxy']],
  [1433, ['mssql', 'Microsoft SQL Server']],
  [1521, ['oracle', 'Oracle Database']],
  [1883, ['mqtt', 'MQTT IoT Messaging Broker']],
  [2049, ['nfs', 'Network File System']],
  [2181, ['zookeeper', 'Apache ZooKeeper']],
  [2375, ['docker', 'Docker REST API (Unencrypted)']],
  [2376, ['docker-tls', 'Docker REST API (TLS)']],
  [3000, ['http-dev', 'Web App / Node.js / Grafana']],
  [3128, ['squid-http', 'HTTP Proxy']],
  [3268, ['globalcat', 'Active Directory Global Catalog']],
  [3306, ['mysql', 'MySQL / MariaDB Database']],
  [3389, ['rdp', 'Remote Desktop Protocol']],
  [3478, ['stun', 'STUN / TURN NAT Traversal']],
  [3689, ['daap', 'Digital Audio Access / AirPlay']],
  [4000, ['remote-ui', 'Web Admin / App Server']],
  [4443, ['https-alt', 'Alternate HTTPS Admin UI']],
  [5000, ['upnp-synology', 'Synology DSM / AirPlay / Flask']],
  [5001, ['synology-ssl', 'Synology DSM HTTPS / iPerf']],
  [5060, ['sip', 'SIP VoIP Signaling']],
  [5353, ['mdns', 'Multicast DNS']],
  [5357, ['wsdapi', 'Web Services for Devices']],
  [5432, ['postgresql', 'PostgreSQL Database']],
  [5672, ['amqp', 'RabbitMQ / AMQP Broker']],
  [5900, ['vnc', 'VNC / Apple Screen Sharing']],
  [5901, ['vnc-1', 'VNC Display :1']],
  [5984, ['couchdb', 'Apache CouchDB']],
  [6000, ['x11', 'X11 Display Server']],
  [6379, ['redis', 'Redis Key-Value Store']],
  [6443, ['kubernetes', 'Kubernetes API Server']],
  [6667, ['irc', 'Internet Relay Chat']],
  [7000, ['airplay', 'AirPlay Control / Media Service']],
  [7001, ['afs', 'WebLogic / Media Control']],
  [7100, ['font-service', 'XFS / AirPlay Audio']],
  [7443, ['https-alt', 'UniFi / Alternate HTTPS']],
  [8000, ['http-alt', 'Web Service / Development Server']],
  [8006, ['proxmox', 'Proxmox VE Web Console']],
  [8008, ['cast-http', 'Google Cast / HTTP Alt']],
  [8009, ['cast', 'Google Cast / AJP13']],
  [8080, ['http-proxy', 'HTTP Alt / Router / Web UI']],
  [8081, ['http-alt', 'Web Admin / App Interface']],
  [8086, ['influxdb', 'InfluxDB HTTP API']],
  [8088, ['http-alt', 'Web Admin / Radarr / Splunk']],
  [8096, ['jellyfin', 'Jellyfin / Emby Media Server']],
  [8123, ['home-assistant', 'Home Assistant Web UI']],
  [8200, ['dlna', 'MiniDLNA / Vault API']],
  [8384, ['syncthing', 'Syncthing Web GUI']],
  [8443, ['https-alt', 'UniFi / HTTPS Alt Admin UI']],
  [8500, ['consul', 'HashiCorp Consul / Web UI']],
  [8880, ['http-alt', 'UniFi Portal / Alternate HTTP']],
  [8883, ['mqtts', 'Secure MQTT over TLS']],
  [8888, ['http-alt', 'Jupyter / Alternate Web UI']],
  [9000, ['portainer', 'Portainer / PHP-FPM / SonarQube']],
  [9001, ['tor-orport', 'Supervisor / MinIO Console']],
  [9090, ['prometheus', 'Prometheus / Cockpit Web UI']],
  [9091, ['transmission', 'Transmission Web RPC']],
  [9100, ['jetdirect', 'RAW Network Printer (JetDirect)']],
  [9200, ['elasticsearch', 'Elasticsearch REST API']],
  [9418, ['git', 'Git Daemon']],
  [9443, ['https-alt', 'Portainer HTTPS / Web UI']],
  [10000, ['webmin', 'Webmin / Network Backup']],
  [11211, ['memcached', 'Memcached In-Memory Cache']],
  [27017, ['mongodb', 'MongoDB Database']],
  [32400, ['plex', 'Plex Media Server']],
  [49152, ['upnp', 'UPnP / Apple HomeKit / Dynamic']],
  [49153, ['upnp', 'UPnP / Sonos / Dynamic']],
  [49154, ['upnp', 'UPnP / Media / Dynamic']],
  [51413, ['bittorrent', 'Transmission BitTorrent Peer']],
  [62078, ['iphone-sync', 'Apple iOS Lockdown / Wi-Fi Sync']],
]);

const UDP_SERVICES = new Map([
  [53, ['dns', 'Domain Name System']],
  [67, ['dhcps', 'DHCP Server']],
  [68, ['dhcpc', 'DHCP Client']],
  [69, ['tftp', 'Trivial File Transfer Protocol']],
  [111, ['rpcbind', 'ONC RPC Portmapper']],
  [123, ['ntp', 'Network Time Protocol']],
  [137, ['netbios-ns', 'NetBIOS Name Service']],
  [138, ['netbios-dgm', 'NetBIOS Datagram Service']],
  [161, ['snmp', 'Simple Network Management Protocol']],
  [427, ['svrloc', 'Service Location Protocol']],
  [500, ['isakmp', 'IPsec IKE VPN']],
  [514, ['syslog', 'Syslog Event Logging']],
  [520, ['rip', 'RIP Routing Protocol']],
  [631, ['ipp', 'CUPS / Printer Discovery']],
  [1701, ['l2tp', 'L2TP VPN']],
  [1900, ['ssdp', 'UPnP / SSDP Device Discovery']],
  [3478, ['stun', 'STUN / WebRTC NAT Traversal']],
  [3702, ['ws-discovery', 'WS-Discovery (Cameras / Windows)']],
  [4500, ['ipsec-nat-t', 'IPsec NAT Traversal']],
  [5351, ['nat-pmp', 'NAT-PMP / PCP Gateway Mapping']],
  [5353, ['mdns', 'Multicast DNS (Bonjour)']],
  [5355, ['llmnr', 'Link-Local Multicast Name Resolution']],
  [5683, ['coap', 'Constrained Application Protocol (IoT)']],
  [10001, ['ubnt-discovery', 'Ubiquiti Device Discovery']],
  [32414, ['plex-gdm', 'Plex Good Day Mate Discovery']],
]);

/**
 * Look up a human-readable service name and description for a port + protocol.
 */
export function getServiceInfo(port, protocol) {
  const table = protocol === 'udp' ? UDP_SERVICES : TCP_SERVICES;
  const entry = table.get(port);
  if (entry) {
    return { service: entry[0], description: entry[1] };
  }
  return { service: 'unknown', description: 'Custom / Unassigned Port' };
}

function sanitizeBanner(raw) {
  if (!raw) return null;
  const text = raw
    .toString('utf8')
    .replace(/[^\x20-\x7e\r\n\t]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) return null;
  return text.length > 60 ? `${text.slice(0, 57)}...` : text;
}

/**
 * Probe a single TCP port using a non-blocking socket connect + brief banner read.
 */
export function probeTcpPort(ip, port, timeoutMs = 450) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const startedAt = performance.now();
    let settled = false;
    let bannerTimer = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (bannerTimer) clearTimeout(bannerTimer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);

    socket.once('connect', () => {
      const rttMs = Math.round((performance.now() - startedAt) * 100) / 100;
      const { service, description } = getServiceInfo(port, 'tcp');

      const complete = (banner = null) => {
        finish({
          port,
          protocol: 'tcp',
          state: 'open',
          rttMs,
          service,
          description,
          banner,
        });
      };

      socket.once('data', (chunk) => {
        complete(sanitizeBanner(chunk));
      });

      socket.once('close', () => complete(null));
      socket.once('error', () => complete(null));

      bannerTimer = setTimeout(() => complete(null), 80);
    });

    socket.once('timeout', () => finish(null));
    socket.once('error', () => finish(null));

    try {
      socket.connect(port, ip);
    } catch {
      finish(null);
    }
  });
}

/**
 * Build a protocol-appropriate UDP probe packet so responsive LAN UDP services reply.
 */
export function buildUdpProbePayload(port, ip) {
  switch (port) {
    case 53:
      // DNS standard query for root NS record
      return Buffer.from([
        0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x01,
      ]);
    case 111: {
      // SunRPC Portmapper NULL call (Prog=100000, Vers=2, Proc=0)
      const buf = Buffer.alloc(40, 0);
      buf.writeUInt32BE(0x12345678, 0); // XID
      buf.writeUInt32BE(0, 4); // Call
      buf.writeUInt32BE(2, 8); // RPC v2
      buf.writeUInt32BE(100000, 12); // Portmapper
      buf.writeUInt32BE(2, 16); // Version 2
      buf.writeUInt32BE(0, 20); // Proc NULL
      return buf;
    }
    case 123: {
      // NTP v3 client request
      const buf = Buffer.alloc(48, 0);
      buf[0] = 0x1b;
      return buf;
    }
    case 137:
      return buildNetbiosQuery();
    case 161:
      // SNMPv2c 'public' GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr.0)
      return Buffer.from([
        0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
        0x63, 0xa0, 0x1c, 0x02, 0x04, 0x13, 0x37, 0x00, 0x01, 0x02, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
        0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
      ]);
    case 1900:
      return Buffer.from(
        'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
        'ascii'
      );
    case 3478: {
      // STUN Binding Request
      const buf = Buffer.alloc(20, 0);
      buf.writeUInt16BE(0x0001, 0);
      buf.writeUInt16BE(0x0000, 2);
      buf.writeUInt32BE(0x2112a442, 4);
      buf.writeUInt32BE(0x13370001, 8);
      return buf;
    }
    case 5351:
      return Buffer.from([0x00, 0x00]); // NAT-PMP external address request
    case 5353:
      return buildPtrQuery(ip);
    case 5355: {
      const q = buildPtrQuery(ip);
      q.writeUInt16BE(0x0000, 2); // LLMNR uses flags = 0
      return q;
    }
    case 5683:
      return Buffer.from([0x40, 0x01, 0x13, 0x37]); // CoAP Confirmable GET
    case 10001:
      return Buffer.from([0x01, 0x00, 0x00, 0x00]); // Ubiquiti discovery
    case 32414:
      return Buffer.from('M-SEARCH * HTTP/1.1\r\n\r\n', 'ascii');
    default:
      return Buffer.from([0x00, 0x00, 0x00, 0x00]);
  }
}

function extractUdpBanner(port, msg) {
  if (!Buffer.isBuffer(msg) || msg.length === 0) return null;
  if (port === 1900 || port === 32414) {
    const raw = msg.toString('utf8');
    const serverMatch = raw.match(/SERVER:\s*([^\r\n]+)/i);
    if (serverMatch) {
      return sanitizeBanner(serverMatch[1]);
    }
    return sanitizeBanner(msg);
  }
  if (port === 123 && msg.length >= 48) {
    const stratum = msg[1];
    return `NTP stratum ${stratum}`;
  }
  if (port === 53 || port === 5353 || port === 5355) {
    return `DNS reply (${msg.length}B)`;
  }

  let printable = 0;
  for (let i = 0; i < msg.length; i += 1) {
    const b = msg[i];
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) {
      printable += 1;
    }
  }
  if (printable / msg.length >= 0.75) {
    return sanitizeBanner(msg);
  }
  return `UDP reply (${msg.length}B)`;
}

/**
 * Probe a single UDP port using a connected UDP socket so ICMP Port Unreachable
 * returns quickly and responsive services yield an open result.
 */
export function probeUdpPort(ip, port, timeoutMs = 550) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer = null;
    let startedAt = performance.now();

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.removeAllListeners();
      try {
        socket.close();
      } catch {
        // Ignore close errors.
      }
      resolve(result);
    };

    timer = setTimeout(() => finish(null), timeoutMs);

    socket.on('error', () => finish(null));

    socket.on('message', (msg) => {
      const rttMs = Math.round((performance.now() - startedAt) * 100) / 100;
      const { service, description } = getServiceInfo(port, 'udp');
      finish({
        port,
        protocol: 'udp',
        state: 'open',
        rttMs,
        service,
        description,
        banner: extractUdpBanner(port, msg),
      });
    });

    socket.on('connect', () => {
      startedAt = performance.now();
      const payload = buildUdpProbePayload(port, ip);
      socket.send(payload, (err) => {
        if (err) finish(null);
      });
    });

    try {
      socket.connect(port, ip);
    } catch {
      finish(null);
    }
  });
}

async function runWithConcurrency(tasks, concurrency) {
  const results = new Array(tasks.length);
  let nextIndex = 0;

  const workers = Array.from(
    { length: Math.min(concurrency, tasks.length) },
    async () => {
      while (true) {
        const current = nextIndex;
        nextIndex += 1;
        if (current >= tasks.length) break;
        results[current] = await tasks[current]();
      }
    }
  );

  await Promise.all(workers);
  return results;
}

function normalizePortList(ports, fallback) {
  if (!Array.isArray(ports)) return fallback;
  const cleaned = [];
  const seen = new Set();
  for (const p of ports) {
    const num = Number(p);
    if (Number.isInteger(num) && num >= 1 && num <= 65535 && !seen.has(num)) {
      seen.add(num);
      cleaned.push(num);
    }
  }
  return cleaned;
}

/**
 * Run a fast concurrent scan of common TCP and UDP ports on a target IPv4 host.
 */
export async function scanHostPorts(ip, options = {}) {
  if (!parseIpv4Octets(ip)) {
    throw new Error('Invalid IPv4 address');
  }

  const tcpPorts = normalizePortList(options.tcpPorts, COMMON_TCP_PORTS);
  const udpPorts = normalizePortList(options.udpPorts, COMMON_UDP_PORTS);
  const tcpTimeoutMs = Math.max(100, Number(options.tcpTimeoutMs) || 450);
  const udpTimeoutMs = Math.max(100, Number(options.udpTimeoutMs) || 550);
  const concurrency = Math.max(1, Math.min(128, Number(options.concurrency) || 48));

  const startedAt = Date.now();
  const tasks = [
    ...tcpPorts.map((port) => () => probeTcpPort(ip, port, tcpTimeoutMs)),
    ...udpPorts.map((port) => () => probeUdpPort(ip, port, udpTimeoutMs)),
  ];

  const rawResults = await runWithConcurrency(tasks, concurrency);
  const openPorts = rawResults
    .filter(Boolean)
    .sort((a, b) => {
      if (a.port !== b.port) return a.port - b.port;
      if (a.protocol === b.protocol) return 0;
      return a.protocol === 'tcp' ? -1 : 1;
    });

  return {
    ip,
    scannedAt: Date.now(),
    durationMs: Date.now() - startedAt,
    tcpScannedCount: tcpPorts.length,
    udpScannedCount: udpPorts.length,
    openPorts,
  };
}
