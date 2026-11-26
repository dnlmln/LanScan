# LanScan

**LanScan** is a containerized real-time LAN IP, hostname, and port monitor built with Node.js, Express, WebSockets, and `fping`, styled in **Solarized Dark** and **Solarized Light**.

---

## Features

- **Live ICMP Sweeps:** Sweeps your `/24` LAN subnet every second by default using `fping` and streams updates over WebSockets.
- **Configurable Cadence:** Switch between presets (`0.5s`, `1s`, `2s`, `5s`, `10s`) or set any custom interval (`250 ms` – `60,000 ms`) from the UI.
- **Multi-Protocol Hostname Resolution (v1.1.0):** Uses a two-tier lookup so far fewer devices stay `Unresolved`:
  - **Tier 1:** mDNS (`UDP 5353`), Reverse DNS (`UDP 53`), NetBIOS Name Service (`UDP 137`), and LLMNR (`UDP 5355`).
  - **Tier 2 (only if Tier 1 finds nothing):** Google Cast (`HTTP :8008/setup/eureka_info`), UPnP/SSDP (`UDP 1900` → device XML `friendlyName`/`modelName`), SNMP `sysName` (`UDP 161`), TLS certificate CN/SAN (`TCP 443`/`8443`), and HTTP page `<title>` (`TCP 80`/`8080`), followed by `gateway.local` for the router.
  - The protocol that produced each name is shown as a badge next to the hostname.
- **Smart Hostname Caching (v1.1.0):** Each IP is resolved once on discovery, retried once after 30 seconds if unresolved, then cached for 30 minutes (instead of re-probing on every ping). **Resolve All** forces an immediate refresh.
- **Stale Hostname Clearing (v1.1.0):** If a named IP stops resolving (for example, DHCP reassigned it to another device), the old name is cleared after a 30-second confirmation re-check, or immediately via **Resolve All**.
- **Quick TCP & UDP Port Scanner:** Click any host row (or enter an IP) to probe common LAN TCP and UDP ports with service info, RTT, and banners.
- **Per-Host Telemetry:** Shows live status (`LIVE` = replied to the latest sweep, `GRACE` = missed the latest sweep but seen within the grace window, `OFFLINE` = silent longer than the grace window), current/min/avg/max RTT, a 20-tick latency sparkline, response rate, and search/sorting.
- **Solarized Dark & Light UI:** Theme toggle persisted in browser `localStorage`.

---

## Prerequisites

You only need **Git** and **Docker** (with Docker Compose):

- **macOS:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) or [OrbStack](https://orbstack.dev/)
- **Windows:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- **Linux:** Docker Engine + Docker Compose plugin (`docker compose`)

*(No local Node.js installation is required—everything runs inside the container.)*

---

## Deploy with Docker (Recommended)

### 1. Clone the repository

```bash
git clone https://github.com/dnlmln/LanScan.git
cd LanScan
```

### 2. Build and start the container

```bash
docker compose up -d --build
```

No extra `.env` setup is needed—`compose.yaml` automatically loads defaults from `.env.example` and grants the container `NET_RAW` capability for `fping`.

### 3. Open the dashboard

- On the same machine: **http://localhost:3000**
- From another device on your LAN (if deployed on a home server/VM): **`http://<server-ip>:3000`**

If LanScan auto-detects the wrong subnet (for example, a Docker bridge instead of your physical LAN), enter your LAN subnet (such as `192.168.1.0/24` or `10.0.0.0/24`) in the **Target Subnet** box in the UI and click **Apply**.

---

## Configuration (Optional)

Default environment variables live in `.env.example`:

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | Port the web server listens on inside the container |
| `SCAN_SUBNET` | `auto` | `/24` subnet to sweep (e.g. `192.168.1.0/24`), or `auto` to detect automatically |
| `SCAN_INTERVAL_MS` | `1000` | Time between ICMP sweeps in milliseconds (`250`–`60000`) |
| `PING_TIMEOUT_MS` | `350` | Per-host `fping` timeout in milliseconds |
| `HOST_GRACE_MS` | `3500` | How long a host remains `GRACE` before turning `OFFLINE` |

To customize defaults permanently:
- Edit `.env.example`, **or** copy `.env.example` to `.env` and update `env_file` in `compose.yaml` to `- .env`.
- If port `3000` is already in use on your machine, set `HOST_PORT` (for example, `HOST_PORT=8080 docker compose up -d --build`) and open `http://localhost:8080`. You can also set `CONTAINER_NAME` and use `-p <project>` to run a second instance side by side (for example, `CONTAINER_NAME=lanscan-test HOST_PORT=3001 docker compose -p lanscan-test up -d --build`).

### Linux Tip (Optional): Better mDNS Discovery

By default, `compose.yaml` maps port `3000:3000` on Docker's bridge network so it works identically on macOS, Windows, and Linux. On a **Linux** host, if you want multicast mDNS (`.local` hostnames) to reach the container directly from your physical LAN, you can replace `ports:` in `compose.yaml` with `network_mode: host`.

---

## Useful Commands

Check container status and logs:

```bash
docker compose ps
docker compose logs -f lanscan
```

Stop LanScan:

```bash
docker compose down
```

Pull updates and rebuild:

```bash
git pull
docker compose up -d --build
```

---

## Running Tests

Run the unit test suite inside the container:

```bash
docker compose run --rm lanscan npm test
```

Or locally if you have Node.js 20+ installed:

```bash
npm test
```
