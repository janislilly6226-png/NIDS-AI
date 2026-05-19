"""
=============================================================
 NIDS - GeoIP Attack Map Dashboard
 Real-time world map showing attack origins
 Uses Leaflet.js for interactive map rendering
=============================================================
 Setup:
   python nids_geoip.py --setup     (download DB first)
   pip install flask flask-socketio geoip2
   python nids_map_dashboard.py
   Open: http://localhost:5001
=============================================================
"""

import time
import random
import threading
from datetime import datetime
from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO

try:
    from nids_geoip import AttackMapStore, download_geodb
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

app    = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-geoip-map-2024'
socketio = SocketIO(app, cors_allowed_origins='*')

# ─── Global store ───
store = AttackMapStore() if GEOIP_AVAILABLE else None

# ─── Sample data for demo mode (when no live traffic) ───
DEMO_ATTACKS = [
    ('41.75.32.10',   'DDoS',       'Kenya'),
    ('196.202.45.67', 'PortScan',   'Kenya'),
    ('154.73.41.9',   'BruteForce', 'Nigeria'),
    ('41.90.65.201',  'DoS Hulk',   'Tanzania'),
    ('197.248.10.3',  'Bot',        'Ethiopia'),
    ('185.220.101.1', 'DDoS',       'Germany'),
    ('103.21.244.0',  'PortScan',   'China'),
    ('45.33.32.156',  'BruteForce', 'USA'),
    ('91.108.4.1',    'Bot',        'Russia'),
    ('202.43.120.1',  'Infiltration','India'),
    ('102.89.23.44',  'DDoS',       'Ghana'),
    ('196.13.55.12',  'BruteForce', 'South Africa'),
]

ATTACK_TYPES = ['DDoS', 'PortScan', 'BruteForce', 'DoS Hulk', 'Bot', 'Infiltration']

# Pre-seeded demo geo data (for when GeoIP DB not available)
DEMO_GEO = {
    '41.75.32.10'  : {'country':'Kenya',       'city':'Nairobi',      'lat':-1.286389, 'lon':36.817223,  'country_code':'KE'},
    '196.202.45.67': {'country':'Kenya',       'city':'Mombasa',      'lat':-4.043477, 'lon':39.668206,  'country_code':'KE'},
    '154.73.41.9'  : {'country':'Nigeria',     'city':'Lagos',        'lat':6.524379,  'lon':3.379206,   'country_code':'NG'},
    '41.90.65.201' : {'country':'Tanzania',    'city':'Dar es Salaam','lat':-6.792354, 'lon':39.208328,  'country_code':'TZ'},
    '197.248.10.3' : {'country':'Ethiopia',    'city':'Addis Ababa',  'lat':9.024249,  'lon':38.746826,  'country_code':'ET'},
    '185.220.101.1': {'country':'Germany',     'city':'Frankfurt',    'lat':50.110924, 'lon':8.682127,   'country_code':'DE'},
    '103.21.244.0' : {'country':'China',       'city':'Beijing',      'lat':39.904202, 'lon':116.407394, 'country_code':'CN'},
    '45.33.32.156' : {'country':'USA',         'city':'Dallas',       'lat':32.783058, 'lon':-96.806671, 'country_code':'US'},
    '91.108.4.1'   : {'country':'Russia',      'city':'Moscow',       'lat':55.755826, 'lon':37.617300,  'country_code':'RU'},
    '202.43.120.1' : {'country':'India',       'city':'Mumbai',       'lat':19.075984, 'lon':72.877656,  'country_code':'IN'},
    '102.89.23.44' : {'country':'Ghana',       'city':'Accra',        'lat':5.603717,  'lon':-0.186964,  'country_code':'GH'},
    '196.13.55.12' : {'country':'South Africa','city':'Johannesburg',  'lat':-26.204103,'lon':28.047305,  'country_code':'ZA'},
}

# In-memory attack log for demo
demo_events    = []
demo_origins   = {}
demo_countries = {}
attack_counter = 0


def add_demo_attack(ip, attack_type):
    global attack_counter
    attack_counter += 1
    geo = DEMO_GEO.get(ip, {'country':'Unknown','city':'Unknown','lat':0,'lon':0,'country_code':'XX'})
    confidence = round(random.uniform(70, 99), 1)
    action     = 'BLOCKED' if confidence > 85 else 'MONITORED'

    event = {
        'id'          : attack_counter,
        'timestamp'   : datetime.now().strftime('%H:%M:%S'),
        'src_ip'      : ip,
        'attack_type' : attack_type,
        'confidence'  : confidence,
        'action'      : action,
        **geo,
    }

    demo_events.append(event)
    if len(demo_events) > 200:
        demo_events.pop(0)

    if ip not in demo_origins:
        demo_origins[ip] = {**geo, 'ip': ip, 'count': 0}
    demo_origins[ip]['count'] += 1

    country = geo['country']
    if country not in ('Unknown', 'Local Network'):
        demo_countries[country] = demo_countries.get(country, 0) + 1

    return event


def get_map_data():
    markers = [
        {
            'ip'          : ip,
            'lat'         : info['lat'],
            'lon'         : info['lon'],
            'country'     : info['country'],
            'city'        : info['city'],
            'count'       : info['count'],
            'country_code': info['country_code'],
        }
        for ip, info in demo_origins.items()
        if info['lat'] != 0
    ]

    top_countries = sorted(
        demo_countries.items(), key=lambda x: x[1], reverse=True
    )[:8]

    return {
        'markers'          : markers,
        'top_countries'    : top_countries,
        'recent_events'    : list(reversed(demo_events[-15:])),
        'total_attacks'    : len(demo_events),
        'unique_ips'       : len(demo_origins),
        'unique_countries' : len(demo_countries),
    }


def simulate_attacks():
    """Simulate incoming attacks for demo."""
    # Pre-seed with some data
    for ip, attack_type, _ in DEMO_ATTACKS[:6]:
        add_demo_attack(ip, attack_type)
        time.sleep(0.1)

    while True:
        time.sleep(random.uniform(1.5, 4.0))
        ip, attack_type, _ = random.choice(DEMO_ATTACKS)
        event = add_demo_attack(ip, attack_type)
        socketio.emit('new_attack', event)
        socketio.emit('map_update', get_map_data())


@app.route('/api/map')
def api_map():
    return jsonify(get_map_data())


@app.route('/')
def index():
    return render_template_string(MAP_DASHBOARD_HTML)


# ─────────────────────────────────────────────
# MAP DASHBOARD HTML
# ─────────────────────────────────────────────

MAP_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NIDS | GeoIP Attack Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@400;600;700&family=Orbitron:wght@700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #060d14;
    --panel:   #0b1929;
    --border:  #112840;
    --accent:  #00c8ff;
    --danger:  #ff3f5e;
    --warn:    #ffb800;
    --safe:    #00e887;
    --text:    #b8d8f0;
    --muted:   #2d5a7a;
    --mono:    'Share Tech Mono', monospace;
    --ui:      'Barlow Condensed', sans-serif;
    --head:    'Orbitron', sans-serif;
  }

  * { margin:0; padding:0; box-sizing:border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--ui);
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* scanlines */
  body::after {
    content:'';
    position:fixed; inset:0;
    background: repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.06) 3px,rgba(0,0,0,0.06) 4px);
    pointer-events:none; z-index:9999;
  }

  /* ── HEADER ── */
  header {
    display:flex; align-items:center; justify-content:space-between;
    padding: 10px 24px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    z-index: 1000;
  }

  .logo {
    font-family: var(--head);
    font-size: 1rem;
    color: var(--accent);
    letter-spacing: 3px;
    text-shadow: 0 0 15px rgba(0,200,255,0.5);
  }

  .header-stats {
    display:flex; gap:32px;
  }

  .hstat {
    text-align:center;
  }

  .hstat-val {
    font-family: var(--head);
    font-size: 1.3rem;
    line-height:1;
  }

  .hstat-val.danger { color: var(--danger); }
  .hstat-val.accent { color: var(--accent); }
  .hstat-val.warn   { color: var(--warn);   }
  .hstat-val.safe   { color: var(--safe);   }

  .hstat-label {
    font-family: var(--mono);
    font-size: 0.62rem;
    color: var(--muted);
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-top: 2px;
  }

  .live-pill {
    display:flex; align-items:center; gap:6px;
    font-family: var(--mono); font-size:0.72rem;
    color: var(--safe);
    border: 1px solid rgba(0,232,135,0.3);
    padding: 4px 12px; border-radius: 20px;
    background: rgba(0,232,135,0.05);
  }

  .pulse {
    width:6px; height:6px; border-radius:50%;
    background: var(--safe);
    animation: pulse 1.5s infinite;
  }

  @keyframes pulse {
    0%,100% { opacity:1; transform:scale(1); }
    50%      { opacity:0.5; transform:scale(1.4); }
  }

  /* ── MAIN LAYOUT ── */
  .main {
    display:grid;
    grid-template-columns: 260px 1fr 260px;
    flex:1;
    overflow:hidden;
  }

  /* ── SIDE PANELS ── */
  .side-panel {
    background: var(--panel);
    border-right: 1px solid var(--border);
    display:flex; flex-direction:column;
    overflow:hidden;
  }

  .side-panel.right {
    border-right:none;
    border-left: 1px solid var(--border);
  }

  .panel-hdr {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    font-family: var(--head);
    font-size: 0.65rem;
    letter-spacing: 2px;
    color: var(--accent);
    text-transform: uppercase;
    flex-shrink:0;
  }

  /* ── MAP ── */
  #map {
    flex:1;
    z-index: 1;
  }

  .leaflet-container { background: #060d14 !important; }

  /* ── COUNTRY LIST ── */
  .country-list {
    flex:1; overflow-y:auto; padding: 8px 0;
  }

  .country-list::-webkit-scrollbar { width:3px; }
  .country-list::-webkit-scrollbar-thumb { background: var(--border); }

  .country-row {
    display:flex; align-items:center; gap:10px;
    padding: 8px 16px;
    border-bottom: 1px solid rgba(17,40,64,0.5);
    transition: background 0.15s;
  }

  .country-row:hover { background: rgba(0,200,255,0.04); }

  .country-rank {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted);
    width: 16px;
    flex-shrink:0;
  }

  .country-flag {
    font-size:1.1rem; flex-shrink:0;
    width:22px; text-align:center;
  }

  .country-name {
    flex:1; font-size:0.85rem; font-weight:600;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  }

  .country-count {
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--danger);
    font-weight:bold;
  }

  .country-bar-wrap {
    height:2px; background: rgba(255,63,94,0.1);
    border-radius:1px; margin: 0 16px 4px;
  }

  .country-bar {
    height:100%;
    background: linear-gradient(90deg, var(--danger), rgba(255,63,94,0.3));
    border-radius:1px;
    transition: width 0.6s ease;
  }

  /* ── ALERT FEED ── */
  .alert-feed {
    flex:1; overflow-y:auto; padding:0;
  }

  .alert-feed::-webkit-scrollbar { width:3px; }
  .alert-feed::-webkit-scrollbar-thumb { background: var(--border); }

  .alert-row {
    padding: 9px 14px;
    border-bottom: 1px solid rgba(17,40,64,0.5);
    animation: fadeIn 0.4s ease;
    cursor:default;
    transition: background 0.15s;
  }

  .alert-row:hover { background: rgba(0,200,255,0.03); }

  @keyframes fadeIn {
    from { opacity:0; transform:translateX(8px); }
    to   { opacity:1; transform:translateX(0); }
  }

  .alert-row-top {
    display:flex; align-items:center; justify-content:space-between;
    margin-bottom:3px;
  }

  .alert-type {
    font-size:0.82rem; font-weight:700;
    color: var(--text);
  }

  .alert-badge {
    font-family:var(--mono); font-size:0.6rem;
    padding:1px 6px; border-radius:2px;
  }

  .alert-badge.blocked  { background:rgba(255,63,94,0.15); color:var(--danger); border:1px solid rgba(255,63,94,0.3); }
  .alert-badge.monitored{ background:rgba(255,184,0,0.12); color:var(--warn);   border:1px solid rgba(255,184,0,0.25);}

  .alert-meta {
    font-family:var(--mono); font-size:0.65rem;
    color: var(--muted); line-height:1.5;
  }

  .alert-meta span { color: var(--text); }

  /* ── MAP CUSTOM STYLES ── */
  .attack-marker {
    display:flex; align-items:center; justify-content:center;
    border-radius:50%;
    border: 2px solid var(--danger);
    background: rgba(255,63,94,0.25);
    animation: markerPulse 2s infinite;
    cursor:pointer;
  }

  @keyframes markerPulse {
    0%,100% { box-shadow: 0 0 0 0 rgba(255,63,94,0.4); }
    50%      { box-shadow: 0 0 0 8px rgba(255,63,94,0); }
  }

  .leaflet-popup-content-wrapper {
    background: var(--panel) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
    color: var(--text) !important;
    font-family: var(--ui) !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5) !important;
  }

  .leaflet-popup-tip { background: var(--panel) !important; }
  .leaflet-popup-close-button { color: var(--muted) !important; }

  .popup-ip {
    font-family:var(--mono); font-size:0.85rem;
    color: var(--danger); margin-bottom:6px;
  }

  .popup-row {
    font-size:0.8rem; margin-bottom:3px;
  }

  .popup-row span { color: var(--muted); }

  /* ── BOTTOM BAR ── */
  .bottom-bar {
    background: var(--panel);
    border-top: 1px solid var(--border);
    padding: 6px 24px;
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted);
    letter-spacing:1px;
    flex-shrink:0;
    display:flex; justify-content:space-between;
  }

  .empty-feed {
    padding:24px 16px;
    text-align:center;
    font-family:var(--mono);
    font-size:0.72rem;
    color:var(--muted);
  }
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <div class="logo">NIDS · GEOIP ATTACK MAP</div>

  <div class="header-stats">
    <div class="hstat">
      <div class="hstat-val danger" id="h-total">0</div>
      <div class="hstat-label">Total Attacks</div>
    </div>
    <div class="hstat">
      <div class="hstat-val accent" id="h-ips">0</div>
      <div class="hstat-label">Unique IPs</div>
    </div>
    <div class="hstat">
      <div class="hstat-val warn" id="h-countries">0</div>
      <div class="hstat-label">Countries</div>
    </div>
  </div>

  <div class="live-pill"><div class="pulse"></div>LIVE</div>
</header>

<!-- MAIN -->
<div class="main">

  <!-- LEFT: Top Countries -->
  <div class="side-panel">
    <div class="panel-hdr">Top Attacking Countries</div>
    <div class="country-list" id="country-list">
      <div class="empty-feed">Waiting for attacks...</div>
    </div>
  </div>

  <!-- CENTER: Map -->
  <div id="map"></div>

  <!-- RIGHT: Live Alert Feed -->
  <div class="side-panel right">
    <div class="panel-hdr">Live Attack Feed</div>
    <div class="alert-feed" id="alert-feed">
      <div class="empty-feed">Monitoring...<br>No attacks yet.</div>
    </div>
  </div>

</div>

<!-- BOTTOM BAR -->
<div class="bottom-bar">
  <span>NIDS v1.0 · East Africa Network Defense System</span>
  <span id="clock">--:--:--</span>
</div>

<script>
// ── CLOCK ──
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

// ── MAP INIT ──
const map = L.map('map', {
  center: [5, 20],
  zoom: 3,
  zoomControl: true,
  attributionControl: false,
});

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  maxZoom: 18,
  subdomains: 'abcd',
}).addTo(map);

// Target marker (Arusha, Tanzania — your location)
const homeIcon = L.divIcon({
  html: `<div style="width:14px;height:14px;border-radius:50%;background:#00e887;border:2px solid #fff;box-shadow:0 0 12px #00e887;"></div>`,
  iconSize:[14,14], iconAnchor:[7,7], className:''
});
L.marker([-3.386925, 36.682995], {icon: homeIcon})
  .addTo(map)
  .bindPopup('<div style="color:#00e887;font-weight:bold;">Protected Network<br><small style="color:#2d5a7a">Arusha, Tanzania</small></div>');

// ── MARKERS MAP ──
const markers = {};

function getMarkerSize(count) {
  if (count >= 10) return 22;
  if (count >= 5)  return 16;
  return 11;
}

function addOrUpdateMarker(m) {
  if (m.lat === 0 && m.lon === 0) return;

  const size = getMarkerSize(m.count);
  const icon = L.divIcon({
    html: `<div class="attack-marker" style="width:${size}px;height:${size}px;font-family:'Share Tech Mono';font-size:${size > 14 ? 9 : 0}px;color:#ff3f5e;">${m.count > 1 ? m.count : ''}</div>`,
    iconSize:[size,size], iconAnchor:[size/2,size/2], className:''
  });

  const popup = `
    <div class="popup-ip">${m.ip}</div>
    <div class="popup-row"><span>Country: </span>${m.country} ${getFlagEmoji(m.country_code)}</div>
    <div class="popup-row"><span>City: </span>${m.city}</div>
    <div class="popup-row"><span>Attacks: </span><b style="color:#ff3f5e">${m.count}</b></div>
  `;

  if (markers[m.ip]) {
    markers[m.ip].setIcon(icon);
    markers[m.ip].setPopupContent(popup);
  } else {
    markers[m.ip] = L.marker([m.lat, m.lon], {icon})
      .addTo(map)
      .bindPopup(popup);
  }
}

// Draw attack line from attacker to Arusha
function drawAttackLine(lat, lon) {
  const line = L.polyline(
    [[lat, lon], [-3.386925, 36.682995]],
    { color:'#ff3f5e', weight:1, opacity:0.5, dashArray:'4,6' }
  ).addTo(map);
  setTimeout(() => map.removeLayer(line), 4000);
}

function getFlagEmoji(code) {
  if (!code || code === 'XX') return '';
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
  );
}

// ── UPDATE UI ──
function updateStats(data) {
  document.getElementById('h-total').textContent     = data.total_attacks;
  document.getElementById('h-ips').textContent       = data.unique_ips;
  document.getElementById('h-countries').textContent = data.unique_countries;
}

function updateCountryList(countries) {
  const list = document.getElementById('country-list');
  if (!countries.length) return;

  const max = countries[0][1];
  list.innerHTML = countries.map(([country, count], i) => `
    <div>
      <div class="country-row">
        <div class="country-rank">${i+1}</div>
        <div class="country-flag">${getFlagEmoji(getCode(country))}</div>
        <div class="country-name">${country}</div>
        <div class="country-count">${count}</div>
      </div>
      <div class="country-bar-wrap">
        <div class="country-bar" style="width:${Math.round(count/max*100)}%"></div>
      </div>
    </div>
  `).join('');
}

// Country → code lookup (basic)
const CODES = {
  'Kenya':'KE','Tanzania':'TZ','Nigeria':'NG','Ethiopia':'ET',
  'Ghana':'GH','South Africa':'ZA','Uganda':'UG','Rwanda':'RW',
  'Germany':'DE','Russia':'RU','China':'CN','USA':'US',
  'India':'IN','France':'FR','UK':'GB','Brazil':'BR',
  'Japan':'JP','Australia':'AU','Canada':'CA','Netherlands':'NL',
};
function getCode(country) { return CODES[country] || 'XX'; }

function addAlertRow(event) {
  const feed = document.getElementById('alert-feed');
  if (feed.querySelector('.empty-feed')) feed.innerHTML = '';

  const isBlocked = event.action === 'BLOCKED';
  const div = document.createElement('div');
  div.className = 'alert-row';
  div.innerHTML = `
    <div class="alert-row-top">
      <div class="alert-type">${event.attack_type}</div>
      <div class="alert-badge ${isBlocked ? 'blocked' : 'monitored'}">${event.action}</div>
    </div>
    <div class="alert-meta">
      <span>${event.src_ip}</span> · ${event.city}, ${event.country}<br>
      ${getFlagEmoji(event.country_code)} ${event.confidence}% confidence · ${event.timestamp}
    </div>
  `;
  feed.insertBefore(div, feed.firstChild);
  while (feed.children.length > 40) feed.removeChild(feed.lastChild);
}

// ── INITIAL LOAD ──
fetch('/api/map').then(r => r.json()).then(data => {
  updateStats(data);
  updateCountryList(data.top_countries);
  data.markers.forEach(addOrUpdateMarker);
  data.recent_events.forEach(addAlertRow);
});

// ── SOCKET UPDATES ──
const socket = io();

socket.on('new_attack', event => {
  addAlertRow(event);

  // Draw attack line on map
  if (event.lat && event.lon && event.lat !== 0) {
    drawAttackLine(event.lat, event.lon);
  }
});

socket.on('map_update', data => {
  updateStats(data);
  updateCountryList(data.top_countries);
  data.markers.forEach(addOrUpdateMarker);
});
</script>
</body>
</html>"""


if __name__ == '__main__':
    print('=' * 55)
    print(' 🗺️  NIDS GeoIP Attack Map Starting...')
    print(' Open: http://localhost:5001')
    print('=' * 55)

    t = threading.Thread(target=simulate_attacks, daemon=True)
    t.start()

    socketio.run(app, host='0.0.0.0', port=5001, debug=False)
