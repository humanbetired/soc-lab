from flask import Flask, jsonify, render_template_string
import subprocess
import json
import requests
import warnings
from datetime import datetime
from collections import defaultdict

warnings.filterwarnings('ignore')

app = Flask(__name__)

# ── KONFIGURASI ──────────────────────────────────────
WAZUH_HOST = "https://localhost:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "Wazuh1313*"
ALERT_LOG  = "/var/ossec/logs/alerts/alerts.json"
# ─────────────────────────────────────────────────────

def get_token():
    r = requests.post(
        f"{WAZUH_HOST}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS), verify=False
    )
    return r.json()["data"]["token"]

def get_alerts():
    result = subprocess.run(
        ['sudo', 'grep', '-E', '"id":"60122"|"id":"60115"', ALERT_LOG],
        capture_output=True, text=True
    )
    alerts = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try:
                alerts.append(json.loads(line))
            except:
                pass
    return alerts

def get_all_windows_alerts():
    result = subprocess.run(
        ['sudo', 'grep', 'Windows-Target', ALERT_LOG],
        capture_output=True, text=True
    )
    alerts = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try:
                alerts.append(json.loads(line))
            except:
                pass
    return alerts

def parse_stats(alerts):
    ip_data = {}
    timeline = defaultdict(int)

    for alert in alerts:
        eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
        rule_id   = alert.get("rule", {}).get("id", "")
        timestamp = alert.get("timestamp", "")
        username  = eventdata.get("targetUserName") or "Unknown"

        src_ip = (
            eventdata.get("ipAddress") or
            eventdata.get("sourceNetworkAddress") or
            "192.168.1.12"
        )

        # Timeline per jam
        if timestamp:
            hour = timestamp[:13]  # "2026-03-16T05"
            timeline[hour] += 1

        if src_ip not in ip_data:
            ip_data[src_ip] = {
                "count": 0,
                "locked": False,
                "usernames": set(),
                "first_seen": timestamp,
                "last_seen": timestamp,
            }

        ip_data[src_ip]["count"] += 1
        ip_data[src_ip]["usernames"].add(username)
        ip_data[src_ip]["last_seen"] = timestamp
        if rule_id == "60115":
            ip_data[src_ip]["locked"] = True

    # Convert set to list untuk JSON
    for ip in ip_data:
        ip_data[ip]["usernames"] = list(ip_data[ip]["usernames"])

    return ip_data, dict(sorted(timeline.items()))

def get_severity(count, locked):
    if locked or count >= 10:
        return "CRITICAL"
    elif count >= 5:
        return "HIGH"
    else:
        return "MEDIUM"

@app.route('/api/stats')
def api_stats():
    try:
        alerts      = get_alerts()
        all_alerts  = get_all_windows_alerts()
        ip_data, timeline = parse_stats(alerts)

        # Summary cards
        total_attempts = len(alerts)
        unique_ips     = len(ip_data)
        locked_count   = sum(1 for i in ip_data.values() if i["locked"])
        critical_count = sum(1 for i in ip_data.values() if get_severity(i["count"], i["locked"]) == "CRITICAL")

        # IP table
        ip_table = []
        for ip, info in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True):
            ip_table.append({
                "ip":         ip,
                "attempts":   info["count"],
                "severity":   get_severity(info["count"], info["locked"]),
                "locked":     info["locked"],
                "users":      ", ".join(info["usernames"]),
                "first_seen": info["first_seen"][:19].replace("T", " ") if info["first_seen"] else "-",
                "last_seen":  info["last_seen"][:19].replace("T", " ") if info["last_seen"] else "-",
            })

        # Recent alerts (last 10)
        recent = []
        for a in all_alerts[-10:]:
            recent.append({
                "time":  a.get("timestamp", "")[:19].replace("T", " "),
                "rule":  a.get("rule", {}).get("id", ""),
                "desc":  a.get("rule", {}).get("description", ""),
                "agent": a.get("agent", {}).get("name", ""),
                "level": a.get("rule", {}).get("level", 0),
            })
        recent.reverse()

        return jsonify({
            "status": "ok",
            "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_attempts": total_attempts,
                "unique_ips":     unique_ips,
                "locked_count":   locked_count,
                "critical_count": critical_count,
                "total_windows":  len(all_alerts),
            },
            "ip_table":  ip_table,
            "timeline":  timeline,
            "recent":    recent,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def dashboard():
    return render_template_string(HTML)

HTML = '''
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Dashboard — Wazuh</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', sans-serif; }

  header {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 16px 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  header h1 { font-size: 18px; font-weight: 600; color: #58a6ff; }
  header h1 span { color: #e6edf3; }
  #status-bar { font-size: 12px; color: #8b949e; }
  #status-dot { display: inline-block; width: 8px; height: 8px;
    background: #3fb950; border-radius: 50%; margin-right: 6px;
    animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }

  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
  }
  .card .label { font-size: 12px; color: #8b949e; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 32px; font-weight: 700; }
  .card.red   .value { color: #f85149; }
  .card.orange .value { color: #ff7b72; }
  .card.blue  .value { color: #58a6ff; }
  .card.green .value { color: #3fb950; }

  .grid2 { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; margin-bottom: 24px; }
  .panel {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
  }
  .panel h2 { font-size: 14px; font-weight: 600; color: #8b949e;
    text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 16px; }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; color: #8b949e;
    border-bottom: 1px solid #30363d; font-weight: 500; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 10px 12px; border-bottom: 1px solid #21262d; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1c2128; }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge.CRITICAL { background: #3d1a1a; color: #f85149; border: 1px solid #f8514940; }
  .badge.HIGH     { background: #2d1f0e; color: #ff7b72; border: 1px solid #ff7b7240; }
  .badge.MEDIUM   { background: #2d2a0e; color: #e3b341; border: 1px solid #e3b34140; }
  .badge.locked   { background: #3d1a1a; color: #f85149; }
  .badge.ok       { background: #0d2a12; color: #3fb950; }

  .level-bar {
    display: inline-block;
    width: 6px; height: 6px;
    border-radius: 50%;
    margin-right: 6px;
  }
  .level-high   { background: #f85149; }
  .level-medium { background: #e3b341; }
  .level-low    { background: #3fb950; }

  .recent-item { display: flex; align-items: flex-start; gap: 10px;
    padding: 8px 0; border-bottom: 1px solid #21262d; font-size: 12px; }
  .recent-item:last-child { border-bottom: none; }
  .recent-time { color: #8b949e; white-space: nowrap; min-width: 130px; }
  .recent-desc { color: #e6edf3; }
  .recent-agent { color: #58a6ff; font-size: 11px; margin-top: 2px; }

  canvas { width: 100% !important; }

  #refresh-bar {
    height: 2px;
    background: #58a6ff;
    width: 100%;
    animation: shrink 30s linear infinite;
  }
  @keyframes shrink { from{width:100%} to{width:0%} }
</style>
</head>
<body>

<div id="refresh-bar"></div>

<header>
  <h1>🛡️ SOC Dashboard </span></h1>
  <div id="status-bar">
    <span id="status-dot"></span>
    <span id="last-update">Memuat...</span>
    &nbsp;|&nbsp; Auto-refresh: 30s
  </div>
</header>

<div class="container">

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card red">
      <div class="label">Total Attempts</div>
      <div class="value" id="c-attempts">—</div>
    </div>
    <div class="card orange">
      <div class="label">Unique Attacker IPs</div>
      <div class="value" id="c-ips">—</div>
    </div>
    <div class="card red">
      <div class="label">Accounts Locked</div>
      <div class="value" id="c-locked">—</div>
    </div>
    <div class="card blue">
      <div class="label">Total Windows Alerts</div>
      <div class="value" id="c-windows">—</div>
    </div>
  </div>

  <!-- Chart + Recent -->
  <div class="grid2">
    <div class="panel">
      <h2> Attack Timeline</h2>
      <canvas id="timelineChart" height="120"></canvas>
    </div>
    <div class="panel">
      <h2>Recent Alerts</h2>
      <div id="recent-list">Memuat...</div>
    </div>
  </div>

  <!-- IP Table -->
  <div class="panel">
    <h2>Attacker IP Analysis</h2>
    <table>
      <thead>
        <tr>
          <th>Source IP</th>
          <th>Attempts</th>
          <th>Severity</th>
          <th>Locked Out</th>
          <th>Target User</th>
          <th>First Seen</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody id="ip-table">
        <tr><td colspan="7" style="color:#8b949e;text-align:center">Memuat data...</td></tr>
      </tbody>
    </table>
  </div>

</div>

<script>
let chart = null;

async function fetchData() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    if (d.status !== 'ok') return;

    // Update cards
    document.getElementById('c-attempts').textContent = d.summary.total_attempts;
    document.getElementById('c-ips').textContent      = d.summary.unique_ips;
    document.getElementById('c-locked').textContent   = d.summary.locked_count;
    document.getElementById('c-windows').textContent  = d.summary.total_windows;
    document.getElementById('last-update').textContent = 'Updated: ' + d.updated;

    // Timeline chart
    const labels = Object.keys(d.timeline).map(h => h.replace('T', ' ') + ':00');
    const values = Object.values(d.timeline);

    if (chart) {
      chart.data.labels = labels;
      chart.data.datasets[0].data = values;
      chart.update();
    } else {
      const ctx = document.getElementById('timelineChart').getContext('2d');
      chart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Failed Attempts',
            data: values,
            backgroundColor: '#f8514960',
            borderColor: '#f85149',
            borderWidth: 1,
            borderRadius: 4,
          }]
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e', font: {size:11} }, grid: { color: '#21262d' } },
            y: { ticks: { color: '#8b949e', font: {size:11} }, grid: { color: '#21262d' }, beginAtZero: true }
          }
        }
      });
    }

    // IP Table
    const tbody = document.getElementById('ip-table');
    if (d.ip_table.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="color:#8b949e;text-align:center">Tidak ada data</td></tr>';
    } else {
      tbody.innerHTML = d.ip_table.map(row => `
        <tr>
          <td style="font-family:monospace;color:#58a6ff">${row.ip}</td>
          <td style="font-weight:600">${row.attempts}</td>
          <td><span class="badge ${row.severity}">${row.severity}</span></td>
          <td><span class="badge ${row.locked ? 'locked' : 'ok'}">${row.locked ? 'YES ⚠' : 'No'}</span></td>
          <td style="font-family:monospace">${row.users}</td>
          <td style="color:#8b949e">${row.first_seen}</td>
          <td style="color:#8b949e">${row.last_seen}</td>
        </tr>
      `).join('');
    }

    // Recent alerts
    const recentEl = document.getElementById('recent-list');
    if (d.recent.length === 0) {
      recentEl.innerHTML = '<p style="color:#8b949e;font-size:13px">Tidak ada alert</p>';
    } else {
      recentEl.innerHTML = d.recent.map(a => {
        const lvlClass = a.level >= 10 ? 'level-high' : a.level >= 7 ? 'level-medium' : 'level-low';
        return `
        <div class="recent-item">
          <div>
            <span class="level-bar ${lvlClass}"></span>
            <span class="recent-time">${a.time}</span>
          </div>
          <div>
            <div class="recent-desc">${a.desc}</div>
            <div class="recent-agent">${a.agent} — Rule ${a.rule}</div>
          </div>
        </div>`;
      }).join('');
    }

  } catch(e) {
    console.error('Fetch error:', e);
  }
}

// Initial load + auto refresh
fetchData();
setInterval(() => {
  fetchData();
  // Reset refresh bar animation
  const bar = document.getElementById('refresh-bar');
  bar.style.animation = 'none';
  bar.offsetHeight;
  bar.style.animation = 'shrink 30s linear infinite';
}, 30000);
</script>
</body>
</html>
'''

if __name__ == '__main__':
    print("\n🛡️  SOC Dashboard starting...")
    print("   URL: http://192.168.1.10:5000")
    print("   Auto-refresh: 30 detik")
    print("   Tekan Ctrl+C untuk stop\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
