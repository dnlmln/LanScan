import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { WebSocket, WebSocketServer } from 'ws';
import { LanScanner } from './scanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, '../public');

const PORT = Number(process.env.PORT || 3000);

const scanner = new LanScanner({
  subnet: process.env.SCAN_SUBNET || 'auto',
  intervalMs: Number(process.env.SCAN_INTERVAL_MS || 1000),
  pingTimeoutMs: Number(process.env.PING_TIMEOUT_MS || 350),
  graceMs: Number(process.env.HOST_GRACE_MS || 3500),
});

const app = express();
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

app.get('/api/state', (_req, res) => {
  res.json(scanner.getState());
});

app.post('/api/config', async (req, res) => {
  try {
    const state = await scanner.setConfig(req.body || {});
    res.json({ ok: true, state });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/scan', async (_req, res) => {
  await scanner.scanNow();
  res.json({ ok: true, state: scanner.getState() });
});

app.post('/api/resolve', async (req, res) => {
  try {
    const ip = req.body?.ip;
    if (typeof ip === 'string' && ip.trim()) {
      await scanner.resolveHost(ip.trim(), true);
    } else {
      await scanner.resolveAllHosts();
    }
    res.json({ ok: true, state: scanner.getState() });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/ports', async (req, res) => {
  try {
    const { ip, tcpPorts, udpPorts } = req.body || {};
    const targetIp = typeof ip === 'string' ? ip.trim() : '';
    const result = await scanner.scanPorts(targetIp, { tcpPorts, udpPorts });
    res.json({ ok: true, result, state: scanner.getState() });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

function sendWs(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function broadcastState(state) {
  const message = JSON.stringify({ type: 'state', data: state });
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  }
}

scanner.on('update', broadcastState);

wss.on('connection', (ws) => {
  sendWs(ws, { type: 'state', data: scanner.getState() });

  ws.on('message', async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      sendWs(ws, { type: 'error', message: 'Invalid JSON payload' });
      return;
    }

    try {
      if (msg?.type === 'set_config') {
        await scanner.setConfig(msg);
      } else if (msg?.type === 'scan_now') {
        await scanner.scanNow();
      } else if (msg?.type === 'resolve_host' && typeof msg.ip === 'string') {
        await scanner.resolveHost(msg.ip.trim(), true);
      } else if (msg?.type === 'resolve_all') {
        await scanner.resolveAllHosts();
      } else if (msg?.type === 'scan_ports' && typeof msg.ip === 'string') {
        const result = await scanner.scanPorts(msg.ip.trim(), msg);
        sendWs(ws, { type: 'port_scan_result', data: result });
      }
    } catch (err) {
      sendWs(ws, { type: 'error', message: err.message });
    }
  });
});

async function main() {
  await scanner.init();
  server.listen(PORT, '0.0.0.0', () => {
    console.log(
      `LanScan listening on http://0.0.0.0:${PORT} (subnet ${scanner.subnet}, interval ${scanner.intervalMs}ms)`
    );
  });
  await scanner.start();
}

function shutdown() {
  scanner.stop();
  wss.close(() => {
    server.close(() => process.exit(0));
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

main().catch((err) => {
  console.error('Failed to start LanScan:', err);
  process.exit(1);
});
