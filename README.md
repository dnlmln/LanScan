# LanScan

**LanScan** is a containerized real-time LAN IP and hostname monitor built with Node.js, Express, WebSockets, and `fping`, styled in authentic **Solarized Dark** and **Solarized Light** themes.

## Features

- **Live ICMP Sweeps**: Sweeps your `/24` LAN subnet every second by default using `fping` and streams updates over WebSockets.
- **Configurable Update Interval**: Choose presets (`0.5s`, `1s`, `2s`, `5s`, `10s`) or dial in any custom interval (`250 ms` – `60,000 ms`).
- **Solarized Dark & Solarized Light**: Full theme switcher built strictly with Ethan Schoonover's Solarized palette, persisted in `localStorage`.
- **Multi-Protocol Hostname Resolution**: Probes mDNS (`UDP 5353`), Reverse DNS (`UDP 53`), NetBIOS Name Service (`UDP 137`), and Gateway detection.
- **Quick TCP & UDP Port Scanner**: Select any discovered host row (or enter an IP) to concurrently probe common LAN TCP and UDP ports with service metadata, RTT, and banners.
- **Per-Host Telemetry**: Live status (`LIVE` / `GRACE` / `OFFLINE`), current/min/avg/max RTT, 20-tick SVG latency sparkline, response rate, and search/sorting.
- **Fully Containerized**: Runs inside Docker/OrbStack with `NET_RAW` capability—zero host runtime dependencies.

## Quick Start

1. Optional configuration overrides (defaults are loaded from `.env.example`):

   ```bash
   cp .env.example .env
   ```

2. Build and start with Docker Compose:

   ```bash
   docker compose up -d --build
   ```

3. Open **http://localhost:3000** in your browser.

## Running Tests

Run the unit test suite inside the container:

```bash
docker compose run --rm lanscan npm test
```
