(() => {
  const THEME_STORAGE_KEY = 'lanscan-theme';

  const state = {
    server: null,
    sortBy: 'ip',
    sortDir: 'asc',
    filterMode: 'online',
    searchQuery: '',
    wsConnected: false,
    selectedIp: null,
    portFilter: 'all',
    pendingPortScans: new Set(),
    localPortScans: new Map(),
  };

  let ws = null;
  let reconnectTimer = null;
  let intervalDebounceTimer = null;

  const els = {
    radarDot: document.getElementById('radarDot'),
    subnetBadge: document.getElementById('subnetBadge'),
    connBadge: document.getElementById('connBadge'),
    themeDarkBtn: document.getElementById('themeDarkBtn'),
    themeLightBtn: document.getElementById('themeLightBtn'),
    alertBanner: document.getElementById('alertBanner'),
    alertText: document.getElementById('alertText'),
    alertCloseBtn: document.getElementById('alertCloseBtn'),
    intervalDisplay: document.getElementById('intervalDisplay'),
    intervalSlider: document.getElementById('intervalSlider'),
    intervalInput: document.getElementById('intervalInput'),
    presetPills: Array.from(document.querySelectorAll('.pill-btn')),
    subnetSourceLabel: document.getElementById('subnetSourceLabel'),
    subnetForm: document.getElementById('subnetForm'),
    subnetInput: document.getElementById('subnetInput'),
    autoSubnetBtn: document.getElementById('autoSubnetBtn'),
    scannerStateLabel: document.getElementById('scannerStateLabel'),
    pauseBtn: document.getElementById('pauseBtn'),
    scanNowBtn: document.getElementById('scanNowBtn'),
    resolveAllBtn: document.getElementById('resolveAllBtn'),
    metricResponding: document.getElementById('metricResponding'),
    metricSeenSub: document.getElementById('metricSeenSub'),
    metricResolved: document.getElementById('metricResolved'),
    metricAvgRtt: document.getElementById('metricAvgRtt'),
    metricGatewaySub: document.getElementById('metricGatewaySub'),
    metricScanCount: document.getElementById('metricScanCount'),
    metricDurationSub: document.getElementById('metricDurationSub'),
    searchInput: document.getElementById('searchInput'),
    filterOnlineBtn: document.getElementById('filterOnlineBtn'),
    filterAllBtn: document.getElementById('filterAllBtn'),
    filterOnlineCount: document.getElementById('filterOnlineCount'),
    filterAllCount: document.getElementById('filterAllCount'),
    sortButtons: Array.from(document.querySelectorAll('.sort-btn')),
    hostsBody: document.getElementById('hostsBody'),
    selectedTargetBadge: document.getElementById('selectedTargetBadge'),
    portScanForm: document.getElementById('portScanForm'),
    portScanIpSelect: document.getElementById('portScanIpSelect'),
    portScanIpInput: document.getElementById('portScanIpInput'),
    runPortScanBtn: document.getElementById('runPortScanBtn'),
    portFilterButtons: Array.from(document.querySelectorAll('[data-port-filter]')),
    portScanSummary: document.getElementById('portScanSummary'),
    portScanResults: document.getElementById('portScanResults'),
  };

  function ipToNumber(ip) {
    const parts = String(ip).split('.').map(Number);
    if (parts.length !== 4 || parts.some(Number.isNaN)) return 0;
    return (
      ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
    );
  }

  function formatInterval(ms) {
    const sec = (ms / 1000).toFixed(ms % 1000 === 0 ? 1 : 2);
    return `${sec}s (${ms} ms)`;
  }

  function formatRelativeTime(ts) {
    if (!ts) return '—';
    const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (diffSec === 0) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const mins = Math.floor(diffSec / 60);
    return `${mins}m ${diffSec % 60}s ago`;
  }

  function showAlert(message) {
    if (!message) return;
    els.alertText.textContent = message;
    els.alertBanner.classList.remove('hidden');
  }

  function clearAlert() {
    els.alertBanner.classList.add('hidden');
    els.alertText.textContent = '';
  }

  function applyTheme(theme) {
    const normalized = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = normalized;
    els.themeDarkBtn.classList.toggle('active', normalized === 'dark');
    els.themeDarkBtn.setAttribute('aria-pressed', String(normalized === 'dark'));
    els.themeLightBtn.classList.toggle('active', normalized === 'light');
    els.themeLightBtn.setAttribute(
      'aria-pressed',
      String(normalized === 'light')
    );
    try {
      localStorage.setItem(THEME_STORAGE_KEY, normalized);
    } catch {
      // Ignore storage failures.
    }
  }

  async function sendConfig(payload) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'set_config', ...payload }));
      return;
    }
    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const json = await res.json();
      if (!res.ok) {
        showAlert(json.error || 'Failed to update configuration');
      } else if (json.state) {
        updateState(json.state);
      }
    } catch (err) {
      showAlert(err.message || 'Network request failed');
    }
  }

  function sendAction(type, extra = {}) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, ...extra }));
      return;
    }
    const endpoint =
      type === 'scan_now'
        ? '/api/scan'
        : type === 'resolve_host' || type === 'resolve_all'
        ? '/api/resolve'
        : null;
    if (!endpoint) return;
    fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(extra),
    })
      .then((res) => res.json())
      .then((json) => {
        if (json.state) updateState(json.state);
      })
      .catch((err) => showAlert(err.message));
  }

  function syncIntervalUI(intervalMs) {
    els.intervalDisplay.textContent = formatInterval(intervalMs);
    const sliderVal = Math.min(15000, Math.max(250, intervalMs));
    if (document.activeElement !== els.intervalSlider) {
      els.intervalSlider.value = String(sliderVal);
    }
    if (document.activeElement !== els.intervalInput) {
      els.intervalInput.value = String(intervalMs);
    }
    for (const pill of els.presetPills) {
      pill.classList.toggle(
        'active',
        Number(pill.dataset.interval) === intervalMs
      );
    }
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function renderSparkline(history) {
    const slots = 20;
    const width = 120;
    const height = 24;
    const step = width / slots;
    const padded = Array(Math.max(0, slots - history.length))
      .fill(undefined)
      .concat(history.slice(-slots));

    const validRtts = padded.filter((v) => typeof v === 'number' && v >= 0);
    const maxRtt = Math.max(10, ...validRtts);

    const bars = padded
      .map((val, idx) => {
        const x = idx * step + 1;
        const barWidth = Math.max(2, step - 2);
        if (val === undefined) {
          return `<rect x="${x.toFixed(1)}" y="20" width="${barWidth.toFixed(
            1
          )}" height="2" rx="1" fill="var(--border-color)" opacity="0.45" />`;
        }
        if (val === null) {
          return `<rect x="${x.toFixed(1)}" y="19" width="${barWidth.toFixed(
            1
          )}" height="4" rx="1" fill="var(--sol-red)" opacity="0.65" />`;
        }
        const ratio = Math.min(1, Math.max(0.15, val / maxRtt));
        const barH = Math.max(4, Math.round(ratio * (height - 4)));
        const y = height - barH;
        const color =
          val < 10
            ? 'var(--sol-green)'
            : val < 40
            ? 'var(--sol-cyan)'
            : val < 100
            ? 'var(--sol-yellow)'
            : 'var(--sol-orange)';
        return `<rect x="${x.toFixed(1)}" y="${y}" width="${barWidth.toFixed(
          1
        )}" height="${barH}" rx="1.2" fill="${color}" />`;
      })
      .join('');

    return `<svg class="sparkline" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" aria-hidden="true">${bars}</svg>`;
  }

  function sortHosts(hosts) {
    const dir = state.sortDir === 'desc' ? -1 : 1;
    const statusWeight = (h) => (h.respondingNow ? 2 : h.online ? 1 : 0);

    return hosts.slice().sort((a, b) => {
      let cmp = 0;
      switch (state.sortBy) {
        case 'status':
          cmp = statusWeight(a) - statusWeight(b);
          break;
        case 'hostname': {
          const ha = (a.hostname || '\uffff').toLowerCase();
          const hb = (b.hostname || '\uffff').toLowerCase();
          cmp = ha.localeCompare(hb);
          break;
        }
        case 'rtt':
          cmp =
            (a.rttMs ?? Number.POSITIVE_INFINITY) -
            (b.rttMs ?? Number.POSITIVE_INFINITY);
          break;
        case 'avg':
          cmp =
            (a.avgRttMs ?? Number.POSITIVE_INFINITY) -
            (b.avgRttMs ?? Number.POSITIVE_INFINITY);
          break;
        case 'rate':
          cmp = a.responseRate - b.responseRate;
          break;
        case 'lastSeen':
          cmp = (a.lastSeen || 0) - (b.lastSeen || 0);
          break;
        case 'ip':
        default:
          cmp = ipToNumber(a.ip) - ipToNumber(b.ip);
          break;
      }
      if (cmp === 0) {
        cmp = ipToNumber(a.ip) - ipToNumber(b.ip);
      }
      return cmp * dir;
    });
  }

  const HTTP_WEB_PORTS = new Set([
    80, 81, 3000, 4000, 5000, 8000, 8008, 8080, 8081, 8088, 8096, 8123, 8200,
    8384, 8500, 8880, 8888, 9000, 9090, 9091, 10000, 32400,
  ]);
  const HTTPS_WEB_PORTS = new Set([443, 4443, 5001, 6443, 7443, 8006, 8443, 9443]);

  function getHostByIp(ip) {
    return state.server?.hosts?.find((h) => h.ip === ip) || null;
  }

  function getPortScanForIp(ip) {
    if (!ip) return null;
    return (
      state.server?.portScans?.[ip] ||
      state.localPortScans.get(ip) ||
      null
    );
  }

  function isPortScanning(ip) {
    if (!ip) return false;
    return (
      state.pendingPortScans.has(ip) ||
      Boolean(state.server?.portScanningIps?.includes(ip))
    );
  }

  function selectIp(ip, syncInput = true) {
    const cleaned = typeof ip === 'string' ? ip.trim() : '';
    state.selectedIp = cleaned || null;
    if (syncInput && document.activeElement !== els.portScanIpInput) {
      els.portScanIpInput.value = cleaned;
    }
    if (els.portScanIpSelect) {
      const hasOption = Array.from(els.portScanIpSelect.options).some(
        (opt) => opt.value === cleaned
      );
      els.portScanIpSelect.value = hasOption ? cleaned : '';
    }
    renderPortScanner();
    renderTable();
  }

  async function triggerPortScan(rawIp) {
    const ip = typeof rawIp === 'string' ? rawIp.trim() : '';
    if (!ip) {
      showAlert('Select or enter a valid IPv4 address to scan ports.');
      return;
    }

    clearAlert();
    selectIp(ip);
    state.pendingPortScans.add(ip);
    renderPortScanner();
    renderTable();

    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'scan_ports', ip }));
      return;
    }

    try {
      const res = await fetch('/api/ports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      const json = await res.json();
      state.pendingPortScans.delete(ip);
      if (!res.ok) {
        showAlert(json.error || 'Port scan failed');
      } else {
        if (json.result) {
          state.localPortScans.set(ip, json.result);
        }
        if (json.state) {
          updateState(json.state);
        } else {
          renderPortScanner();
          renderTable();
        }
      }
    } catch (err) {
      state.pendingPortScans.delete(ip);
      showAlert(err.message || 'Port scan request failed');
      renderPortScanner();
      renderTable();
    }
  }

  function renderPortScanSelect() {
    if (!els.portScanIpSelect || !state.server) return;
    const hosts = state.server.hosts || [];
    const current = state.selectedIp || '';

    const optionsHtml = [
      '<option value="">Choose discovered host...</option>',
      ...hosts.map((h) => {
        const label = h.hostname ? `${h.ip} — ${h.hostname}` : h.ip;
        const selected = h.ip === current ? ' selected' : '';
        return `<option value="${escapeHtml(h.ip)}"${selected}>${escapeHtml(
          label
        )}</option>`;
      }),
    ].join('');

    if (document.activeElement !== els.portScanIpSelect) {
      els.portScanIpSelect.innerHTML = optionsHtml;
    }
  }

  function renderPortScanner() {
    const ip = state.selectedIp;
    const host = ip ? getHostByIp(ip) : null;
    const scanning = isPortScanning(ip);
    const scan = getPortScanForIp(ip);

    if (!ip) {
      els.selectedTargetBadge.textContent = 'Select an IP';
      els.runPortScanBtn.disabled = false;
      els.runPortScanBtn.textContent = 'Quick Scan TCP & UDP';
      els.portScanSummary.innerHTML =
        'Click any host row below—or select/enter an IP above—and click <strong>Quick Scan TCP &amp; UDP</strong> to probe common TCP &amp; UDP ports.';
      els.portScanResults.innerHTML = '';
      return;
    }

    els.selectedTargetBadge.textContent = host?.hostname
      ? `${ip} • ${host.hostname}`
      : ip;
    els.runPortScanBtn.disabled = scanning;
    els.runPortScanBtn.textContent = scanning
      ? 'Scanning...'
      : 'Quick Scan TCP & UDP';

    if (scanning) {
      els.portScanSummary.innerHTML = `<span class="port-scanning-pill"><span class="mini-spinner"></span>Probing common TCP &amp; UDP ports on <strong>${escapeHtml(
        ip
      )}</strong>...</span>`;
    } else if (!scan) {
      els.portScanSummary.innerHTML = `Target <strong>${escapeHtml(
        ip
      )}</strong> selected. Click <strong>Quick Scan TCP &amp; UDP</strong> to probe open ports.`;
      els.portScanResults.innerHTML = '';
      return;
    } else {
      const openTcp = scan.openPorts.filter((p) => p.protocol === 'tcp').length;
      const openUdp = scan.openPorts.filter((p) => p.protocol === 'udp').length;
      els.portScanSummary.innerHTML = `
        <span class="port-stat-chip port-stat-tcp">${openTcp} Open TCP</span>
        <span class="port-stat-chip port-stat-udp">${openUdp} Open UDP</span>
        <span class="port-stat-meta">Scanned ${scan.tcpScannedCount} TCP + ${scan.udpScannedCount} UDP ports in ${scan.durationMs} ms (${formatRelativeTime(
          scan.scannedAt
        )})</span>
      `;
    }

    if (!scan) {
      els.portScanResults.innerHTML = '';
      return;
    }

    const filteredPorts = scan.openPorts.filter((p) =>
      state.portFilter === 'all' ? true : p.protocol === state.portFilter
    );

    if (filteredPorts.length === 0) {
      const label =
        state.portFilter === 'all'
          ? 'No common TCP or UDP ports responded on this host.'
          : `No open ${state.portFilter.toUpperCase()} ports found on this host.`;
      els.portScanResults.innerHTML = `<div class="port-scan-summary">${escapeHtml(
        label
      )}</div>`;
      return;
    }

    const rowsHtml = filteredPorts
      .map((entry) => {
        const isHttps = entry.protocol === 'tcp' && HTTPS_WEB_PORTS.has(entry.port);
        const isHttp = entry.protocol === 'tcp' && HTTP_WEB_PORTS.has(entry.port);
        const portCell =
          isHttps || isHttp
            ? `<a class="port-link mono" href="${
                isHttps ? 'https' : 'http'
              }://${escapeHtml(ip)}:${
                entry.port
              }" target="_blank" rel="noopener noreferrer">${entry.port}</a>`
            : `<span class="mono">${entry.port}</span>`;

        return `<tr>
          <td><span class="proto-pill proto-${entry.protocol}">${entry.protocol}</span></td>
          <td>${portCell}</td>
          <td class="mono">${escapeHtml(entry.service)}</td>
          <td>${escapeHtml(entry.description)}</td>
          <td class="mono rtt-fast">${entry.rttMs.toFixed(1)} ms</td>
          <td class="mono rtt-muted">${
            entry.banner ? escapeHtml(entry.banner) : '—'
          }</td>
        </tr>`;
      })
      .join('');

    els.portScanResults.innerHTML = `
      <div class="port-table-wrap">
        <table class="port-results-table">
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Port</th>
              <th>Service</th>
              <th>Description</th>
              <th>RTT</th>
              <th>Details / Banner</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;
  }

  function buildHostRowCells(host) {
    const statusClass = host.respondingNow
      ? 'status-live'
      : host.online
      ? 'status-grace'
      : 'status-offline';
    const statusLabel = host.respondingNow
      ? 'LIVE'
      : host.online
      ? 'GRACE'
      : 'OFFLINE';

    const rttClass =
      host.rttMs === null
        ? 'rtt-muted'
        : host.rttMs < 10
        ? 'rtt-fast'
        : host.rttMs < 40
        ? 'rtt-mid'
        : 'rtt-slow';

    const rttLabel =
      host.rttMs !== null ? `${host.rttMs.toFixed(2)} ms` : '—';

    const statsLabel = `${host.minRttMs?.toFixed(1) ?? '—'} / ${
      host.avgRttMs?.toFixed(1) ?? '—'
    } / ${host.maxRttMs?.toFixed(1) ?? '—'}`;

    const hostnameHtml = host.hostname
      ? `<div class="hostname-wrap">
          <span class="hostname-text">${escapeHtml(host.hostname)}</span>
          ${
            host.hostnameSource
              ? `<span class="proto-badge">${escapeHtml(
                  host.hostnameSource
                )}</span>`
              : ''
          }
        </div>`
      : `<span class="hostname-unresolved">${
          host.resolving ? 'Resolving...' : 'Unresolved'
        }</span>`;

    const gwTag = host.isGateway ? '<span class="gw-tag">GW</span>' : '';

    return `<td>
        <span class="status-pill ${statusClass}">
          <span class="dot"></span>${statusLabel}
        </span>
      </td>
      <td class="ip-cell">${escapeHtml(host.ip)}${gwTag}</td>
      <td>${hostnameHtml}</td>
      <td class="num-col mono ${rttClass}">${rttLabel}</td>
      <td class="num-col mono rtt-muted">${statsLabel}</td>
      <td>${renderSparkline(host.history)}</td>
      <td class="num-col mono">${host.responseRate}% <span class="rtt-muted">(${host.hits}/${host.totalChecks})</span></td>
      <td class="num-col mono rtt-muted">${formatRelativeTime(host.lastSeen)}</td>`;
  }

  function renderTable() {
    const data = state.server;
    if (!data) return;

    const query = state.searchQuery.trim().toLowerCase();
    const onlineHosts = data.hosts.filter((h) => h.online);

    els.filterOnlineCount.textContent = String(onlineHosts.length);
    els.filterAllCount.textContent = String(data.hosts.length);

    let filtered = state.filterMode === 'online' ? onlineHosts : data.hosts;
    if (query) {
      filtered = filtered.filter((h) => {
        return (
          h.ip.toLowerCase().includes(query) ||
          (h.hostname && h.hostname.toLowerCase().includes(query)) ||
          (h.hostnameSource && h.hostnameSource.toLowerCase().includes(query))
        );
      });
    }

    const sorted = sortHosts(filtered);

    if (sorted.length === 0) {
      const msg = data.scanCount === 0
        ? 'Running initial ping sweep across your LAN...'
        : query
        ? 'No hosts match your current filter.'
        : 'No hosts currently responding to pings.';
      els.hostsBody.innerHTML = `<tr class="empty-row"><td colspan="8">${escapeHtml(
        msg
      )}</td></tr>`;
      return;
    }

    const existingRows = new Map();
    for (const child of Array.from(els.hostsBody.children)) {
      const ip = child.getAttribute('data-host-ip');
      if (ip) {
        existingRows.set(ip, child);
      } else {
        child.remove();
      }
    }

    const activeIps = new Set();
    let cursor = els.hostsBody.firstElementChild;

    for (const host of sorted) {
      activeIps.add(host.ip);
      let tr = existingRows.get(host.ip);
      if (!tr) {
        tr = document.createElement('tr');
        tr.setAttribute('data-host-ip', host.ip);
      }

      const selectedClass = state.selectedIp === host.ip ? 'selected-row' : '';
      if (tr.className !== selectedClass) {
        tr.className = selectedClass;
      }

      const cellsHtml = buildHostRowCells(host);
      if (tr.dataset.lastHtml !== cellsHtml) {
        tr.innerHTML = cellsHtml;
        tr.dataset.lastHtml = cellsHtml;
      }

      if (tr !== cursor) {
        els.hostsBody.insertBefore(tr, cursor);
      } else {
        cursor = cursor.nextElementSibling;
      }
    }

    for (const [ip, tr] of existingRows.entries()) {
      if (!activeIps.has(ip)) {
        tr.remove();
      }
    }
  }

  function updateConnectionIndicators() {
    const paused = state.server?.paused;
    els.radarDot.classList.toggle('offline', !state.wsConnected);
    els.radarDot.classList.toggle('paused', state.wsConnected && Boolean(paused));

    els.connBadge.classList.remove('paused', 'offline');
    if (!state.wsConnected) {
      els.connBadge.textContent = 'Reconnecting';
      els.connBadge.classList.add('offline');
    } else if (paused) {
      els.connBadge.textContent = 'Paused';
      els.connBadge.classList.add('paused');
    } else {
      els.connBadge.textContent = 'Live';
    }
  }

  function updateState(data) {
    state.server = data;
    if (data.lastError) {
      showAlert(data.lastError);
    }

    els.subnetBadge.textContent = data.subnet || 'Detecting...';
    els.subnetSourceLabel.textContent = data.subnetSource || 'auto';
    if (
      data.subnet &&
      document.activeElement !== els.subnetInput &&
      !els.subnetInput.dataset.dirty
    ) {
      els.subnetInput.value = data.subnet;
    }

    syncIntervalUI(data.intervalMs);

    els.scannerStateLabel.textContent = data.paused
      ? 'Paused'
      : data.scanning
      ? 'Sweeping...'
      : 'Running';
    els.pauseBtn.textContent = data.paused ? 'Resume' : 'Pause';
    els.pauseBtn.classList.toggle('is-paused', Boolean(data.paused));

    const respondingHosts = data.hosts.filter((h) => h.respondingNow);
    const avgRtt =
      respondingHosts.length > 0
        ? respondingHosts.reduce((acc, h) => acc + (h.rttMs || 0), 0) /
          respondingHosts.length
        : null;

    els.metricResponding.textContent = String(data.summary.respondingCount);
    els.metricSeenSub.textContent = `${data.summary.onlineCount} active / ${data.summary.totalSeenCount} seen`;
    els.metricResolved.textContent = String(data.summary.resolvedCount);
    els.metricAvgRtt.textContent =
      avgRtt !== null ? `${avgRtt.toFixed(1)} ms` : '—';
    els.metricGatewaySub.textContent = `Gateway ${data.gateway || '—'}`;
    els.metricScanCount.textContent = `#${data.scanCount}`;
    els.metricDurationSub.textContent = `${(data.intervalMs / 1000).toFixed(
      data.intervalMs % 1000 === 0 ? 1 : 2
    )}s interval • ${data.lastScanDurationMs}ms sweep`;

    if (data.portScans) {
      for (const ip of Object.keys(data.portScans)) {
        if (!data.portScanningIps?.includes(ip)) {
          state.pendingPortScans.delete(ip);
        }
      }
    }

    updateConnectionIndicators();
    renderPortScanSelect();
    renderPortScanner();
    renderTable();
  }

  function connectWebSocket() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.addEventListener('open', () => {
      state.wsConnected = true;
      updateConnectionIndicators();
    });

    ws.addEventListener('message', (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'state' && msg.data) {
          updateState(msg.data);
        } else if (msg.type === 'port_scan_result' && msg.data) {
          state.pendingPortScans.delete(msg.data.ip);
          state.localPortScans.set(msg.data.ip, msg.data);
          renderPortScanner();
          renderTable();
        } else if (msg.type === 'error' && msg.message) {
          state.pendingPortScans.clear();
          showAlert(msg.message);
          renderPortScanner();
          renderTable();
        }
      } catch {
        // Ignore malformed server frames.
      }
    });

    ws.addEventListener('close', () => {
      state.wsConnected = false;
      updateConnectionIndicators();
      reconnectTimer = setTimeout(connectWebSocket, 1500);
    });

    ws.addEventListener('error', () => {
      state.wsConnected = false;
      updateConnectionIndicators();
    });
  }

  function commitInterval(rawMs) {
    const clamped = Math.max(250, Math.min(60000, Math.round(Number(rawMs) || 1000)));
    syncIntervalUI(clamped);
    clearTimeout(intervalDebounceTimer);
    intervalDebounceTimer = setTimeout(() => {
      sendConfig({ intervalMs: clamped });
    }, 120);
  }

  // Event listeners
  applyTheme(document.documentElement.dataset.theme || 'dark');

  els.themeDarkBtn.addEventListener('click', () => applyTheme('dark'));
  els.themeLightBtn.addEventListener('click', () => applyTheme('light'));
  els.alertCloseBtn.addEventListener('click', clearAlert);

  for (const pill of els.presetPills) {
    pill.addEventListener('click', () => {
      commitInterval(Number(pill.dataset.interval));
    });
  }

  els.intervalSlider.addEventListener('input', (e) => {
    commitInterval(e.target.value);
  });

  els.intervalInput.addEventListener('change', (e) => {
    commitInterval(e.target.value);
  });

  els.subnetInput.addEventListener('input', () => {
    els.subnetInput.dataset.dirty = '1';
  });

  els.subnetForm.addEventListener('submit', (e) => {
    e.preventDefault();
    delete els.subnetInput.dataset.dirty;
    clearAlert();
    sendConfig({ subnet: els.subnetInput.value.trim() });
  });

  els.autoSubnetBtn.addEventListener('click', () => {
    delete els.subnetInput.dataset.dirty;
    clearAlert();
    sendConfig({ subnet: 'auto' });
  });

  els.pauseBtn.addEventListener('click', () => {
    const currentlyPaused = Boolean(state.server?.paused);
    sendConfig({ paused: !currentlyPaused });
  });

  els.scanNowBtn.addEventListener('click', () => sendAction('scan_now'));
  els.resolveAllBtn.addEventListener('click', () => sendAction('resolve_all'));

  els.searchInput.addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderTable();
  });

  for (const btn of [els.filterOnlineBtn, els.filterAllBtn]) {
    btn.addEventListener('click', () => {
      state.filterMode = btn.dataset.filter;
      els.filterOnlineBtn.classList.toggle('active', state.filterMode === 'online');
      els.filterAllBtn.classList.toggle('active', state.filterMode === 'all');
      renderTable();
    });
  }

  for (const btn of els.sortButtons) {
    btn.addEventListener('click', () => {
      const col = btn.dataset.sort;
      if (state.sortBy === col) {
        state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        state.sortBy = col;
        state.sortDir = col === 'rate' || col === 'lastSeen' ? 'desc' : 'asc';
      }
      for (const b of els.sortButtons) {
        b.classList.toggle('active', b.dataset.sort === state.sortBy);
        const ind = b.querySelector('.sort-indicator');
        if (ind) {
          ind.textContent =
            b.dataset.sort === state.sortBy
              ? state.sortDir === 'asc'
                ? '▲'
                : '▼'
              : '';
        }
      }
      renderTable();
    });
  }

  els.portScanIpSelect.addEventListener('change', (e) => {
    const ip = e.target.value;
    if (ip) {
      selectIp(ip, true);
    } else {
      selectIp('', true);
    }
  });

  els.portScanForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const ip = els.portScanIpInput.value.trim() || els.portScanIpSelect.value;
    triggerPortScan(ip);
  });

  for (const btn of els.portFilterButtons) {
    btn.addEventListener('click', () => {
      state.portFilter = btn.dataset.portFilter;
      for (const b of els.portFilterButtons) {
        b.classList.toggle('active', b.dataset.portFilter === state.portFilter);
      }
      renderPortScanner();
    });
  }

  els.hostsBody.addEventListener('click', (e) => {
    const row = e.target.closest('tr[data-host-ip]');
    if (row) {
      const ip = row.getAttribute('data-host-ip');
      if (ip) selectIp(ip, true);
    }
  });

  // Initial state fetch + live WebSocket updates
  fetch('/api/state')
    .then((res) => res.json())
    .then((data) => updateState(data))
    .catch(() => {});

  connectWebSocket();
})();
