from flask import Flask, jsonify, render_template_string
import subprocess, json, warnings
from datetime import datetime
from collections import defaultdict

warnings.filterwarnings('ignore')
import requests

app = Flask(__name__)

WAZUH_HOST = "https://localhost:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "Wazuh1313*"
ALERT_LOG  = "/var/ossec/logs/alerts/alerts.json"

def get_token():
    r = requests.post(f"{WAZUH_HOST}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS), verify=False)
    return r.json()["data"]["token"]

def grep_alerts(pattern):
    result = subprocess.run(
        ['sudo', 'grep', '-E', pattern, ALERT_LOG],
        capture_output=True, text=True)
    alerts = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try: alerts.append(json.loads(line))
            except: pass
    return alerts

def get_privesc_alerts():
    return grep_alerts('"id":"61618"|"id":"61634"|"id":"61638"|"id":"61138"|"id":"100001"|"id":"100002"|"id":"100003"')

def get_smb_alerts():
    return grep_alerts('"id":"92652"|"id":"60104"|"id":"60205"')

def get_rdp_alerts():
    result = subprocess.run(
        ['sudo', 'grep', '-E', '"id":"60122"|"id":"60115"', ALERT_LOG],
        capture_output=True, text=True)
    alerts = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try:
                a = json.loads(line)
                logon_type = a.get('data',{}).get('win',{}).get('eventdata',{}).get('logonType','')
                if logon_type == '3':
                    alerts.append(a)
            except: pass
    return alerts

@app.route('/api/stats')
def api_stats():
    try:
        ssh_alerts = grep_alerts('"id":"60122"|"id":"60115"')
        web_alerts = grep_alerts('"id":"31103"|"id":"31104"|"id":"31105"|"id":"31152"|"id":"31170"|"id":"31171"')
        privesc_alerts = get_privesc_alerts()
        smb_alerts = get_smb_alerts()
        rdp_alerts = get_rdp_alerts()
        all_alerts = grep_alerts('"Windows-Target"')

        def parse_ip(alerts, key_fn):
            ip_data = {}
            timeline = defaultdict(int)
            for a in alerts:
                ip = key_fn(a)
                ts = a.get('timestamp','')
                if ts: timeline[ts[:13]] += 1
                if ip not in ip_data:
                    ip_data[ip] = {'count':0,'first':ts,'last':ts,'extra':set()}
                ip_data[ip]['count'] += 1
                ip_data[ip]['last'] = ts
            return ip_data, dict(sorted(timeline.items()))

        def ssh_key(a):
            return a.get('data',{}).get('win',{}).get('eventdata',{}).get('ipAddress') or '192.168.1.12'
        def web_key(a):
            return a.get('data',{}).get('srcip','Unknown')

        ssh_ip, ssh_tl = parse_ip(ssh_alerts, ssh_key)
        web_ip, web_tl = parse_ip(web_alerts, web_key)

        def make_table(ip_data, thresholds=(50,10)):
            rows = []
            for ip, info in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True):
                sev = 'CRITICAL' if info['count']>=thresholds[0] else 'HIGH' if info['count']>=thresholds[1] else 'MEDIUM'
                rows.append({'ip':ip,'count':info['count'],'severity':sev,
                    'first':info['first'][:19].replace('T',' '),
                    'last':info['last'][:19].replace('T',' ')})
            return rows

        recent = []
        for a in all_alerts[-10:]:
            recent.append({
                'time': a.get('timestamp','')[:19].replace('T',' '),
                'rule': a.get('rule',{}).get('id',''),
                'desc': a.get('rule',{}).get('description',''),
                'level': a.get('rule',{}).get('level',0),
            })
        recent.reverse()

        # Parse privesc
        privesc_ip = {}
        privesc_tl = defaultdict(int)
        for a in privesc_alerts:
            agent = a.get('agent',{}).get('name','Unknown')
            ts    = a.get('timestamp','')
            proc  = a.get('data',{}).get('win',{}).get('eventdata',{}).get('image','')
            proc  = proc.split('\\\\')[-1] if proc else 'Unknown'
            if ts: privesc_tl[ts[:13]] += 1
            if agent not in privesc_ip:
                privesc_ip[agent] = {'count':0,'first':ts,'last':ts,'proc':set()}
            privesc_ip[agent]['count'] += 1
            privesc_ip[agent]['last'] = ts
            if proc: privesc_ip[agent]['proc'].add(proc)

        privesc_table = []
        for agent, info in sorted(privesc_ip.items(), key=lambda x: x[1]['count'], reverse=True):
            sev = 'CRITICAL' if info['count']>=10 else 'HIGH' if info['count']>=5 else 'MEDIUM'
            privesc_table.append({
                'agent': agent,
                'count': info['count'],
                'severity': sev,
                'processes': ', '.join(list(info['proc'])[:3]),
                'first': info['first'][:19].replace('T',' '),
                'last': info['last'][:19].replace('T',' '),
            })

        # Parse SMB
        smb_ip = {}
        smb_tl = defaultdict(int)
        for a in smb_alerts:
            eventdata = a.get('data',{}).get('win',{}).get('eventdata',{})
            src = eventdata.get('ipAddress') or eventdata.get('sourceNetworkAddress') or 'Unknown'
            user = eventdata.get('subjectUserName') or eventdata.get('targetUserName') or 'Unknown'
            share = eventdata.get('shareName','')
            ts = a.get('timestamp','')
            if ts: smb_tl[ts[:13]] += 1
            if src not in smb_ip:
                smb_ip[src] = {'count':0,'first':ts,'last':ts,'users':set(),'shares':set(),'anon':False}
            smb_ip[src]['count'] += 1
            smb_ip[src]['last'] = ts
            smb_ip[src]['users'].add(user)
            if share: smb_ip[src]['shares'].add(share)
            if 'ANON' in user.upper(): smb_ip[src]['anon'] = True

        smb_table = []
        for ip, info in sorted(smb_ip.items(), key=lambda x: x[1]['count'], reverse=True):
            sev = 'CRITICAL' if info['anon'] or info['count']>=10 else 'HIGH' if info['count']>=5 else 'MEDIUM'
            smb_table.append({
                'ip': ip, 'count': info['count'], 'severity': sev,
                'users': ', '.join(list(info['users'])[:3]),
                'shares': ', '.join(list(info['shares'])[:2]) if info['shares'] else 'None',
                'anonymous': info['anon'],
                'first': info['first'][:19].replace('T',' '),
                'last': info['last'][:19].replace('T',' '),
            })

        # Parse RDP
        rdp_ip = {}
        rdp_tl = defaultdict(int)
        for a in rdp_alerts:
            eventdata = a.get('data',{}).get('win',{}).get('eventdata',{})
            src = eventdata.get('ipAddress') or eventdata.get('sourceNetworkAddress') or '192.168.1.12'
            user = eventdata.get('targetUserName') or 'Unknown'
            ts = a.get('timestamp','')
            rid = a.get('rule',{}).get('id','')
            if ts: rdp_tl[ts[:13]] += 1
            if src not in rdp_ip:
                rdp_ip[src] = {'count':0,'first':ts,'last':ts,'users':set(),'locked':False}
            rdp_ip[src]['count'] += 1
            rdp_ip[src]['last'] = ts
            rdp_ip[src]['users'].add(user)
            if rid == '60115': rdp_ip[src]['locked'] = True

        rdp_table = []
        for ip, info in sorted(rdp_ip.items(), key=lambda x: x[1]['count'], reverse=True):
            sev = 'CRITICAL' if info['locked'] or info['count']>=10 else 'HIGH' if info['count']>=5 else 'MEDIUM'
            rdp_table.append({
                'ip': ip, 'count': info['count'], 'severity': sev,
                'users': ', '.join(list(info['users'])[:3]),
                'locked': info['locked'],
                'first': info['first'][:19].replace('T',' '),
                'last': info['last'][:19].replace('T',' '),
            })

        return jsonify({
            'status':'ok',
            'updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ssh': {'total':len(ssh_alerts),'unique':len(ssh_ip),
                    'timeline':ssh_tl,'table':make_table(ssh_ip,(10,5))},
            'web': {'total':len(web_alerts),'unique':len(web_ip),
                    'timeline':web_tl,'table':make_table(web_ip,(50,10))},
            'privesc': {'total':len(privesc_alerts),'unique':len(privesc_ip),
                        'timeline':dict(sorted(privesc_tl.items())),
                        'table':privesc_table},
            'smb': {'total':len(smb_alerts),'unique':len(smb_ip),
                    'timeline':dict(sorted(smb_tl.items())),
                    'table':smb_table},
            'rdp': {'total':len(rdp_alerts),'unique':len(rdp_ip),
                    'timeline':dict(sorted(rdp_tl.items())),
                    'table':rdp_table},
            'recent': recent,
        })
    except Exception as e:
        return jsonify({'status':'error','message':str(e)}), 500

@app.route('/')
def index():
    return render_template_string(HTML)

HTML = '''<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>SOC Dashboard — Wazuh</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',sans-serif}
header{background:#161b22;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;justify-content:space-between;align-items:center}
header h1{font-size:18px;font-weight:600;color:#58a6ff}
header h1 span{color:#e6edf3}
#status-bar{font-size:12px;color:#8b949e}
#dot{display:inline-block;width:8px;height:8px;background:#3fb950;border-radius:50%;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.container{max-width:1200px;margin:0 auto;padding:24px}
.tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #30363d;padding-bottom:0}
.tab{padding:10px 20px;cursor:pointer;font-size:13px;color:#8b949e;border-bottom:2px solid transparent;transition:.2s}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
.tab-content{display:none}.tab-content.active{display:block}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px}
.card .lbl{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.card .val{font-size:32px;font-weight:700}
.card.red .val{color:#f85149}.card.orange .val{color:#ff7b72}
.card.blue .val{color:#58a6ff}.card.green .val{color:#3fb950}
.grid2{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:20px}
.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px}
.panel h2{font-size:12px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 12px;color:#8b949e;border-bottom:1px solid #30363d;font-size:11px;text-transform:uppercase}
td{padding:10px 12px;border-bottom:1px solid #21262d}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2128}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge.CRITICAL{background:#3d1a1a;color:#f85149;border:1px solid #f8514940}
.badge.HIGH{background:#2d1f0e;color:#ff7b72;border:1px solid #ff7b7240}
.badge.MEDIUM{background:#2d2a0e;color:#e3b341;border:1px solid #e3b34140}
.recent-item{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #21262d;font-size:12px}
.recent-item:last-child{border-bottom:none}
.rdot{width:6px;height:6px;border-radius:50%;margin-top:4px;flex-shrink:0}
.r-h{background:#f85149}.r-m{background:#e3b341}.r-l{background:#3fb950}
#rbar{height:2px;background:#58a6ff;animation:shrink 30s linear infinite}
@keyframes shrink{from{width:100%}to{width:0%}}
</style>
</head>
<body>
<div id="rbar"></div>
<header>
  <h1>🛡️ SOC Dashboard <span>— Wazuh SIEM</span></h1>
  <div id="status-bar"><span id="dot"></span><span id="upd">Memuat...</span> | Auto-refresh: 30s</div>
</header>
<div class="container">
  <div class="tabs">
    <div class="tab active" onclick="switchTab('ssh',this)">🔐 SSH Brute Force</div>
    <div class="tab" onclick="switchTab('web',this)">🌐 Web Attacks</div>
    <div class="tab" onclick="switchTab('privesc',this)">⚡ Privilege Escalation</div>
    <div class="tab" onclick="switchTab('smb',this)">🗂 SMB Attack</div>
    <div class="tab" onclick="switchTab('rdp',this)">🖥 RDP Brute Force</div>
    <div class="tab" onclick="switchTab('recent',this)">🕐 Recent Alerts</div>
  </div>

  <!-- SSH TAB -->
  <div id="tab-ssh" class="tab-content active">
    <div class="cards">
      <div class="card red"><div class="lbl">Total Attempts</div><div class="val" id="ssh-total">—</div></div>
      <div class="card orange"><div class="lbl">Unique IPs</div><div class="val" id="ssh-ips">—</div></div>
      <div class="card red"><div class="lbl">Accounts Locked</div><div class="val" id="ssh-locked">—</div></div>
      <div class="card blue"><div class="lbl">Status</div><div class="val" style="font-size:16px;padding-top:8px" id="ssh-status">—</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h2>Attack timeline</h2><canvas id="sshChart" height="120"></canvas></div>
      <div class="panel"><h2>IP table</h2>
        <table><thead><tr><th>IP</th><th>Attempts</th><th>Severity</th><th>Last seen</th></tr></thead>
        <tbody id="ssh-table"><tr><td colspan="4" style="color:#8b949e;text-align:center">Memuat...</td></tr></tbody></table>
      </div>
    </div>
  </div>

  <!-- WEB TAB -->
  <div id="tab-web" class="tab-content">
    <div class="cards">
      <div class="card red"><div class="lbl">Total Requests</div><div class="val" id="web-total">—</div></div>
      <div class="card orange"><div class="lbl">Unique IPs</div><div class="val" id="web-ips">—</div></div>
      <div class="card red"><div class="lbl">Attack Type</div><div class="val" style="font-size:16px;padding-top:8px">SQL Injection</div></div>
      <div class="card blue"><div class="lbl">Target</div><div class="val" style="font-size:14px;padding-top:8px">DVWA</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h2>Attack timeline</h2><canvas id="webChart" height="120"></canvas></div>
      <div class="panel"><h2>IP table</h2>
        <table><thead><tr><th>IP</th><th>Requests</th><th>Severity</th><th>Last seen</th></tr></thead>
        <tbody id="web-table"><tr><td colspan="4" style="color:#8b949e;text-align:center">Memuat...</td></tr></tbody></table>
      </div>
    </div>
  </div>

  <!-- PRIVESC TAB -->
  <div id="tab-privesc" class="tab-content">
    <div class="cards">
      <div class="card red"><div class="lbl">Total Events</div><div class="val" id="pe-total">—</div></div>
      <div class="card orange"><div class="lbl">Unique Agents</div><div class="val" id="pe-agents">—</div></div>
      <div class="card red"><div class="lbl">Detection</div><div class="val" style="font-size:14px;padding-top:8px">Sysmon</div></div>
      <div class="card blue"><div class="lbl">Tool</div><div class="val" style="font-size:14px;padding-top:8px">Wazuh Rules</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h2>Event timeline</h2><canvas id="peChart" height="120"></canvas></div>
      <div class="panel"><h2>Agent table</h2>
        <table><thead><tr><th>Agent</th><th>Events</th><th>Severity</th><th>Processes</th></tr></thead>
        <tbody id="pe-table"><tr><td colspan="4" style="color:#8b949e;text-align:center">Memuat...</td></tr></tbody></table>
      </div>
    </div>
  </div>

  <!-- SMB TAB -->
  <div id="tab-smb" class="tab-content">
    <div class="cards">
      <div class="card red"><div class="lbl">Total Events</div><div class="val" id="smb-total">—</div></div>
      <div class="card orange"><div class="lbl">Unique IPs</div><div class="val" id="smb-ips">—</div></div>
      <div class="card red"><div class="lbl">Anonymous Access</div><div class="val" id="smb-anon" style="font-size:16px;padding-top:8px">—</div></div>
      <div class="card blue"><div class="lbl">Protocol</div><div class="val" style="font-size:14px;padding-top:8px">SMB/CIFS</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h2>Event timeline</h2><canvas id="smbChart" height="120"></canvas></div>
      <div class="panel"><h2>IP table</h2>
        <table><thead><tr><th>IP</th><th>Events</th><th>Severity</th><th>Shares</th></tr></thead>
        <tbody id="smb-table"><tr><td colspan="4" style="color:#8b949e;text-align:center">Memuat...</td></tr></tbody></table>
      </div>
    </div>
  </div>

  <!-- RDP TAB -->
  <div id="tab-rdp" class="tab-content">
    <div class="cards">
      <div class="card red"><div class="lbl">Total Attempts</div><div class="val" id="rdp-total">—</div></div>
      <div class="card orange"><div class="lbl">Unique IPs</div><div class="val" id="rdp-ips">—</div></div>
      <div class="card red"><div class="lbl">Accounts Locked</div><div class="val" id="rdp-locked">—</div></div>
      <div class="card blue"><div class="lbl">Protocol</div><div class="val" style="font-size:14px;padding-top:8px">RDP/3389</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h2>Attack timeline</h2><canvas id="rdpChart" height="120"></canvas></div>
      <div class="panel"><h2>IP table</h2>
        <table><thead><tr><th>IP</th><th>Attempts</th><th>Severity</th><th>Target</th></tr></thead>
        <tbody id="rdp-table"><tr><td colspan="4" style="color:#8b949e;text-align:center">Memuat...</td></tr></tbody></table>
      </div>
    </div>
  </div>

  <!-- RECENT TAB -->
  <div id="tab-recent" class="tab-content">
    <div class="panel"><h2>Recent alerts (all types)</h2>
      <div id="recent-list">Memuat...</div>
    </div>
  </div>
</div>

<script>
let charts={};
function switchTab(name,el){
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  el.classList.add('active');
}
function makeChart(id,labels,values,color){
  const ctx=document.getElementById(id).getContext('2d');
  if(charts[id]){charts[id].data.labels=labels;charts[id].data.datasets[0].data=values;charts[id].update();return;}
  charts[id]=new Chart(ctx,{type:'bar',data:{labels,datasets:[{label:'Alerts',data:values,
    backgroundColor:color+'40',borderColor:color,borderWidth:1,borderRadius:4}]},
    options:{responsive:true,plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'}},
            y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'},beginAtZero:true}}}});
}
function makeTable(tbodyId,rows){
  const tb=document.getElementById(tbodyId);
  if(!rows.length){tb.innerHTML='<tr><td colspan="4" style="color:#8b949e;text-align:center">Tidak ada data</td></tr>';return;}
  tb.innerHTML=rows.map(r=>`<tr>
    <td style="font-family:monospace;color:#58a6ff">${r.ip}</td>
    <td style="font-weight:600">${r.count}</td>
    <td><span class="badge ${r.severity}">${r.severity}</span></td>
    <td style="color:#8b949e">${r.last}</td></tr>`).join('');
}
async function fetchData(){
  try{
    const d=await fetch('/api/stats').then(r=>r.json());
    if(d.status!=='ok')return;
    document.getElementById('upd').textContent='Updated: '+d.updated;
    document.getElementById('ssh-total').textContent=d.ssh.total;
    document.getElementById('ssh-ips').textContent=d.ssh.unique;
    document.getElementById('ssh-locked').textContent=d.ssh.table.filter(r=>r.severity==='CRITICAL').length;
    document.getElementById('ssh-status').textContent=d.ssh.total>0?'ALERT':'Normal';
    document.getElementById('web-total').textContent=d.web.total;
    document.getElementById('web-ips').textContent=d.web.unique;
    const ssl=Object.keys(d.ssh.timeline).map(h=>h.replace('T',' ')+':00');
    const ssv=Object.values(d.ssh.timeline);
    makeChart('sshChart',ssl,ssv,'#f85149');
    const wsl=Object.keys(d.web.timeline).map(h=>h.replace('T',' ')+':00');
    const wsv=Object.values(d.web.timeline);
    makeChart('webChart',wsl,wsv,'#ff7b72');
    makeTable('ssh-table',d.ssh.table);
    makeTable('web-table',d.web.table);
    document.getElementById('pe-total').textContent=d.privesc.total;
    document.getElementById('pe-agents').textContent=d.privesc.unique;
    const pel=Object.keys(d.privesc.timeline).map(h=>h.replace('T',' ')+':00');
    const pev=Object.values(d.privesc.timeline);
    makeChart('peChart',pel,pev,'#a371f7');
    const petb=document.getElementById('pe-table');
    if(!d.privesc.table.length){petb.innerHTML='<tr><td colspan="4" style="color:#8b949e;text-align:center">Tidak ada data</td></tr>';}
    else{petb.innerHTML=d.privesc.table.map(r=>`<tr>
      <td style="color:#58a6ff">${r.agent}</td>
      <td style="font-weight:600">${r.count}</td>
      <td><span class="badge ${r.severity}">${r.severity}</span></td>
      <td style="color:#8b949e;font-size:11px">${r.processes||'—'}</td></tr>`).join('');}
    document.getElementById('smb-total').textContent=d.smb.total;
    document.getElementById('smb-ips').textContent=d.smb.unique;
    const hasAnon=d.smb.table.some(r=>r.anonymous);
    document.getElementById('smb-anon').textContent=hasAnon?'YES ⚠':'No';
    document.getElementById('smb-anon').style.color=hasAnon?'#f85149':'#3fb950';
    const sml=Object.keys(d.smb.timeline).map(h=>h.replace('T',' ')+':00');
    const smv=Object.values(d.smb.timeline);
    makeChart('smbChart',sml,smv,'#e3b341');
    const smtb=document.getElementById('smb-table');
    if(!d.smb.table.length){smtb.innerHTML='<tr><td colspan="4" style="color:#8b949e;text-align:center">Tidak ada data</td></tr>';}
    else{smtb.innerHTML=d.smb.table.map(r=>`<tr>
      <td style="font-family:monospace;color:#58a6ff">${r.ip}</td>
      <td style="font-weight:600">${r.count}</td>
      <td><span class="badge ${r.severity}">${r.severity}</span></td>
      <td style="color:#8b949e;font-size:11px">${r.shares||'—'}</td></tr>`).join('');}
    document.getElementById('rdp-total').textContent=d.rdp.total;
    document.getElementById('rdp-ips').textContent=d.rdp.unique;
    document.getElementById('rdp-locked').textContent=d.rdp.table.filter(r=>r.locked).length;
    const rdpl=Object.keys(d.rdp.timeline).map(h=>h.replace('T',' ')+':00');
    const rdpv=Object.values(d.rdp.timeline);
    makeChart('rdpChart',rdpl,rdpv,'#a371f7');
    const rdptb=document.getElementById('rdp-table');
    if(!d.rdp.table.length){rdptb.innerHTML='<tr><td colspan="4" style="color:#8b949e;text-align:center">Tidak ada data</td></tr>';}
    else{rdptb.innerHTML=d.rdp.table.map(r=>`<tr>
      <td style="font-family:monospace;color:#58a6ff">${r.ip}</td>
      <td style="font-weight:600">${r.count}</td>
      <td><span class="badge ${r.severity}">${r.severity}</span></td>
      <td style="color:#8b949e;font-size:11px">${r.users||'—'}</td></tr>`).join('');}
    const rel=document.getElementById('recent-list');
    rel.innerHTML=d.recent.map(a=>{
      const cls=a.level>=10?'r-h':a.level>=7?'r-m':'r-l';
      return`<div class="recent-item"><div class="rdot ${cls}"></div>
        <div><div style="color:#e6edf3">${a.desc}</div>
        <div style="color:#8b949e;margin-top:2px">${a.time} — Rule ${a.rule}</div></div></div>`;
    }).join('');
  }catch(e){console.error(e);}
}
fetchData();
setInterval(()=>{fetchData();
  const b=document.getElementById('rbar');
  b.style.animation='none';b.offsetHeight;b.style.animation='shrink 30s linear infinite';
},30000);
</script>
</body></html>'''

if __name__=='__main__':
    print("\n🛡️  SOC Dashboard starting...")
    print("   URL: http://192.168.1.10:5000")
    print("   Tabs: SSH Brute Force | Web Attacks | Recent Alerts")
    print("   Auto-refresh: 30 detik\n")
    app.run(host='0.0.0.0',port=5000,debug=False)
