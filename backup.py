"""
=============================================================
 NIDS - Unified Real-Time Dashboard
 REAL packet capture + REAL-TIME analysis
 Every packet is captured AND shown live on the dashboard
 Flows are analysed every 3 seconds — not just on expiry

 Tabs:
   1. Dashboard  — live stats, traffic chart, alert feed
   2. Packet Log — every single packet captured in real time
   3. Attack Map — world map of attacking IPs

 Run:  sudo python nids_dashboard.py eth0
 Open: http://localhost:5000
=============================================================
"""

import os, sys, time, threading, warnings, numpy as np, joblib
warnings.filterwarnings('ignore')

from collections import defaultdict, deque
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS

# ── GeoIP ──
try:
    import geoip2.database
    _gdb = 'geoip_db/GeoLite2-City.mmdb'
    GEOIP_READER = geoip2.database.Reader(_gdb) if os.path.exists(_gdb) else None
except Exception:
    GEOIP_READER = None

# ── ML Model ──
try:
    ML_MODEL   = joblib.load('models/xgboost.pkl')
    ML_SCALER  = joblib.load('models/scaler.pkl')
    ML_ENCODER = joblib.load('models/label_encoder.pkl')
    ML_READY   = True
    print('[+] ML model loaded')
except Exception:
    ML_READY = False
    print('[!] ML model not found — heuristic mode')

INTERFACE            = sys.argv[1] if len(sys.argv) > 1 else 'eth0'
CONFIDENCE_THRESHOLD = 40.0   # low threshold — catch more attacks
FLOW_TIMEOUT         = 10
ANALYSIS_INTERVAL    = 2

# Empty whitelist — detect all traffic including from simulator
WHITELIST = set()

# ─────────────────────────────────────────────
# FLASK
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-realtime-2024'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# ─────────────────────────────────────────────
# SHARED STATE
# ─────────────────────────────────────────────
state = {
    'packets_captured' : 0,
    'attacks_detected' : 0,
    'ips_blocked'      : 0,
    'active_flows'     : 0,
    'bytes_per_sec'    : 0,
    'pkts_per_sec'     : 0,
    '_byte_acc'        : 0,
    '_pkt_acc'         : 0,
    'alerts'           : deque(maxlen=500),
    'blocked_ips'      : {},
    'traffic_history'  : deque(maxlen=120),  # 2 minutes of history
    'attack_types'     : defaultdict(int),
    'protocol_counts'  : defaultdict(int),
}

# Live packet log — every packet captured
packet_log = deque(maxlen=1000)

geo_state = {
    'events'   : [],
    'origins'  : {},
    'countries': defaultdict(int),
    'counter'  : 0,
}

lock = threading.Lock()

# ─────────────────────────────────────────────
# GEO LOOKUP
# ─────────────────────────────────────────────
_geo_cache = {}

def geo_lookup(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    r = {'country':'Unknown','country_code':'XX','city':'Unknown','lat':0.0,'lon':0.0}
    if any(ip.startswith(p) for p in ('10.','192.168.','172.','127.','0.','169.254.')):
        r['country'] = 'Local Network'
        _geo_cache[ip] = r; return r
    if GEOIP_READER:
        try:
            g = GEOIP_READER.city(ip)
            r.update({'country':g.country.name or 'Unknown','country_code':g.country.iso_code or 'XX',
                      'city':g.city.name or 'Unknown','lat':float(g.location.latitude or 0),
                      'lon':float(g.location.longitude or 0)})
        except: pass
    _geo_cache[ip] = r; return r

# ─────────────────────────────────────────────
# PROTOCOL HELPER
# ─────────────────────────────────────────────
def get_proto(pkt):
    if pkt.haslayer(TCP):  return 'TCP'
    if pkt.haslayer(UDP):  return 'UDP'
    if pkt.haslayer(ICMP): return 'ICMP'
    if pkt.haslayer(ARP):  return 'ARP'
    if pkt.haslayer(DNS):  return 'DNS'
    return 'OTHER'

def get_flags(pkt):
    if not pkt.haslayer(TCP): return ''
    f = pkt[TCP].flags
    out = []
    if f & 0x01: out.append('FIN')
    if f & 0x02: out.append('SYN')
    if f & 0x04: out.append('RST')
    if f & 0x08: out.append('PSH')
    if f & 0x10: out.append('ACK')
    if f & 0x20: out.append('URG')
    return ' '.join(out)

# ─────────────────────────────────────────────
# NETWORK FLOW
# ─────────────────────────────────────────────
class NetworkFlow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip; self.dst_ip = dst_ip
        self.src_port = src_port; self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time(); self.last_seen = time.time()
        self.fwd_pkts = []; self.bwd_pkts = []; self.fwd_flags = []
        self.pkt_count = 0

    def add_packet(self, pkt, direction='fwd'):
        self.pkt_count += 1
        sz = len(pkt)
        if direction == 'fwd':
            self.fwd_pkts.append(sz)
            if pkt.haslayer(TCP): self.fwd_flags.append(pkt[TCP].flags)
        else:
            self.bwd_pkts.append(sz)
        self.last_seen = time.time()

    def duration(self): return max(self.last_seen - self.start_time, 1e-6)

    def extract_features(self):
        fwd, bwd = self.fwd_pkts, self.bwd_pkts
        all_p    = fwd + bwd
        dur      = self.duration()
        def st(l):
            if not l: return 0,0,0,0
            return float(np.mean(l)),float(np.std(l)),float(np.max(l)),float(np.min(l))
        fm,fs,fx,fn = st(fwd); bm,bs,bx,bn = st(bwd); am,_,ax,_ = st(all_p)
        syn = sum(1 for f in self.fwd_flags if f and f & 0x02)
        ack = sum(1 for f in self.fwd_flags if f and f & 0x10)
        fin = sum(1 for f in self.fwd_flags if f and f & 0x01)
        rst = sum(1 for f in self.fwd_flags if f and f & 0x04)
        psh = sum(1 for f in self.fwd_flags if f and f & 0x08)
        urg = sum(1 for f in self.fwd_flags if f and f & 0x20)
        tf = len(fwd); tb = len(bwd); tot = sum(all_p)
        return {
            "Total Fwd Packets":tf,"Total Backward Packets":tb,
            "Total Length of Fwd Packets":sum(fwd),"Total Length of Bwd Packets":sum(bwd),
            "Fwd Packet Length Max":fx,"Fwd Packet Length Min":fn,
            "Fwd Packet Length Mean":fm,"Fwd Packet Length Std":fs,
            "Bwd Packet Length Max":bx,"Bwd Packet Length Min":bn,
            "Bwd Packet Length Mean":bm,"Bwd Packet Length Std":bs,
            "Flow Duration":dur*1e6,"Flow Bytes/s":tot/dur,"Flow Packets/s":len(all_p)/dur,
            "Flow IAT Mean":dur/max(len(all_p),1)*1e6,"Flow IAT Std":0,
            "Flow IAT Max":dur*1e6,"Flow IAT Min":0,
            "Fwd IAT Total":dur*1e6,"Fwd IAT Mean":dur/max(tf,1)*1e6,
            "Fwd IAT Std":0,"Fwd IAT Max":dur*1e6,"Fwd IAT Min":0,
            "Bwd IAT Total":dur*1e6,"Bwd IAT Mean":dur/max(tb,1)*1e6,
            "Bwd IAT Std":0,"Bwd IAT Max":dur*1e6,"Bwd IAT Min":0,
            "Fwd PSH Flags":psh,"Bwd PSH Flags":0,"Fwd URG Flags":urg,"Bwd URG Flags":0,
            "FIN Flag Count":fin,"SYN Flag Count":syn,"RST Flag Count":rst,
            "PSH Flag Count":psh,"ACK Flag Count":ack,"URG Flag Count":urg,
            "CWE Flag Count":0,"ECE Flag Count":0,
            "Down/Up Ratio":tb/max(tf,1),"Average Packet Size":am,
            "Avg Fwd Segment Size":fm,"Avg Bwd Segment Size":bm,
            "Fwd Header Length":tf*20,"Bwd Header Length":tb*20,"Fwd Header Length.1":tf*20,
            "Subflow Fwd Packets":tf,"Subflow Fwd Bytes":sum(fwd),
            "Subflow Bwd Packets":tb,"Subflow Bwd Bytes":sum(bwd),
            "Init_Win_bytes_forward":65535,"Init_Win_bytes_backward":65535,
            "act_data_pkt_fwd":tf,"min_seg_size_forward":fn,
            "Active Mean":0,"Active Std":0,"Active Max":0,"Active Min":0,
            "Idle Mean":0,"Idle Std":0,"Idle Max":0,"Idle Min":0,
            "Fwd Avg Bytes/Bulk":0,"Fwd Avg Packets/Bulk":0,"Fwd Avg Bulk Rate":0,
            "Bwd Avg Bytes/Bulk":0,"Bwd Avg Packets/Bulk":0,"Bwd Avg Bulk Rate":0,
        }

# ─────────────────────────────────────────────
# FLOW MANAGER
# ─────────────────────────────────────────────
class FlowManager:
    def __init__(self, timeout=FLOW_TIMEOUT):
        self.flows = {}; self.timeout = timeout; self.lock = threading.Lock()

    def _key(self, si, di, sp, dp, proto):
        return (si,di,sp,dp,proto) if (si,sp)<(di,dp) else (di,si,dp,sp,proto)

    def add_packet(self, pkt):
        if not pkt.haslayer(IP): return None
        si=pkt[IP].src; di=pkt[IP].dst; proto=pkt[IP].proto
        sp=dp=0
        if pkt.haslayer(TCP): sp=pkt[TCP].sport; dp=pkt[TCP].dport
        elif pkt.haslayer(UDP): sp=pkt[UDP].sport; dp=pkt[UDP].dport
        key=self._key(si,di,sp,dp,proto)
        dirn='fwd' if (key[0]==si and key[2]==sp) else 'bwd'
        with self.lock:
            if key not in self.flows:
                self.flows[key]=NetworkFlow(si,di,sp,dp,proto)
            self.flows[key].add_packet(pkt,dirn)
        return key

    def get_all_active(self):
        with self.lock: return list(self.flows.items())

    def get_expired(self):
        now=time.time(); expired=[]
        with self.lock:
            for k,f in list(self.flows.items()):
                if now-f.last_seen>self.timeout:
                    expired.append((k,f)); del self.flows[k]
        return expired

    def count(self):
        with self.lock: return len(self.flows)

flow_mgr = FlowManager()
alerted_flows = set()   # track which flows already raised an alert

# ─────────────────────────────────────────────
# DETECTION
# ─────────────────────────────────────────────
def heuristic_detect(flow):
    tf   = len(flow.fwd_pkts)
    tb   = len(flow.bwd_pkts)
    dur  = flow.duration()
    pps  = (tf + tb) / max(dur, 0.001)
    syn  = sum(1 for f in flow.fwd_flags if f and f & 0x02)
    rst  = sum(1 for f in flow.fwd_flags if f and f & 0x04)
    avg  = float(np.mean(flow.fwd_pkts)) if flow.fwd_pkts else 0
    fwd_bytes = sum(flow.fwd_pkts)
    bwd_bytes = sum(flow.bwd_pkts)

    # ── UDP Flood / DDoS: high pps, one direction ──
    if pps > 50 and tb == 0 and tf > 20:
        return 'DDoS', 93.0

    # ── SYN Flood: SYN with no ACK response ──
    if syn >= 3 and tb == 0:
        return 'DDoS', 90.0

    # ── DDoS: high rate, mostly forward ──
    if pps > 30 and tb < tf * 0.05:
        return 'DDoS', 88.0

    # ── Port Scan: RST replies = closed ports ──
    if rst >= 2:
        return 'PortScan', 85.0

    # ── Port Scan: tiny packets, no reply ──
    if tf >= 2 and avg < 200 and tb == 0 and pps > 2:
        return 'PortScan', 78.0

    # ── Brute Force: lots of small bidirectional packets ──
    if tf >= 8 and tb >= 3 and 20 < avg < 250:
        return 'BruteForce', 76.0

    # ── DoS Hulk: moderate-high rate ──
    if pps > 20:
        return 'DoS Hulk', 80.0

    # ── Infiltration: long session, high outbound ──
    if dur > 8 and bwd_bytes > 50_000:
        return 'Infiltration', 73.0

    # ── Any one-sided high volume traffic ──
    if fwd_bytes > 100_000 and tb == 0:
        return 'DDoS', 71.0

    return 'BENIGN', 96.0

def ml_predict(features):
    try:
        import pandas as pd
        df=pd.DataFrame([features])
        fn=ML_MODEL.get_booster().feature_names
        for c in fn:
            if c not in df.columns: df[c]=0
        df=df[fn]
        X=ML_SCALER.transform(df)
        pred=ML_MODEL.predict(X)[0]; prob=ML_MODEL.predict_proba(X)[0]
        return ML_ENCODER.inverse_transform([pred])[0], float(prob[pred])*100
    except:
        return 'BENIGN', 50.0

def analyse_flow(key, flow, final=False):
    src_ip = key[0]
    if src_ip in WHITELIST: return
    if len(flow.fwd_pkts) < 1: return

    # Don't re-alert on same flow unless it's the final analysis
    flow_id = (key, flow.start_time)
    if not final and flow_id in alerted_flows: return

    # Always use heuristic for real-time detection
    # ML model needs real CICIDS dataset to be accurate
    # Heuristic works on actual traffic patterns
    label, conf = heuristic_detect(flow)

    # Optionally also run ML and take higher confidence
    if ML_READY:
        try:
            ml_label, ml_conf = ml_predict(flow.extract_features())
            if ml_label != 'BENIGN' and ml_conf > conf:
                label, conf = ml_label, ml_conf
        except:
            pass

    if label == 'BENIGN' or conf < CONFIDENCE_THRESHOLD: return

    # Mark as alerted
    alerted_flows.add(flow_id)
    # Keep set small
    if len(alerted_flows) > 5000:
        alerted_flows.clear()

    action = 'BLOCKED' if conf > 70 else 'MONITORED'
    geo    = geo_lookup(src_ip)

    with lock:
        state['attacks_detected']+=1
        state['attack_types'][label]+=1

    alert={
        'id'          : state['attacks_detected'],
        'timestamp'   : datetime.now().strftime('%H:%M:%S'),
        'src_ip'      : src_ip,
        'dst_ip'      : key[1],
        'src_port'    : key[2],
        'dst_port'    : key[3],
        'attack_type' : label,
        'confidence'  : round(conf,1),
        'action'      : action,
        'fwd_pkts'    : len(flow.fwd_pkts),
        'bwd_pkts'    : len(flow.bwd_pkts),
        'duration_sec': round(flow.duration(),2),
        'pps'         : round((len(flow.fwd_pkts)+len(flow.bwd_pkts))/flow.duration(),1),
        **geo,
    }

    with lock:
        state['alerts'].appendleft(alert)
        if action=='BLOCKED':
            state['ips_blocked']+=1
            state['blocked_ips'][src_ip]={
                'attack_type':label,
                'blocked_at':datetime.now().strftime('%H:%M:%S'),
                'unblock_at':(datetime.now()+timedelta(hours=1)).strftime('%H:%M:%S'),
                'confidence':round(conf,1),
            }

    # Update geo map
    geo_state['counter']+=1
    ev={**alert,'id':geo_state['counter']}
    geo_state['events'].append(ev)
    if len(geo_state['events'])>300: geo_state['events'].pop(0)
    if src_ip not in geo_state['origins']:
        geo_state['origins'][src_ip]={
            'ip':src_ip,'count':0,
            'country':geo['country'],'city':geo['city'],
            'lat':geo['lat'],'lon':geo['lon'],
            'country_code':geo['country_code'],
        }
    geo_state['origins'][src_ip]['count']+=1
    c=geo['country']
    if c not in ('Unknown','Local Network'):
        geo_state['countries'][c]+=1

    # Block via iptables
    if action=='BLOCKED':
        os.system(f'iptables -A INPUT -s {src_ip} -j DROP 2>/dev/null')

    socketio.emit('new_alert',  alert)
    socketio.emit('new_attack', alert)
    print(f'[🚨] {label} | {src_ip}:{key[2]} → {key[1]}:{key[3]} | {conf:.1f}% | {action}')

# ─────────────────────────────────────────────
# BACKGROUND THREADS
# ─────────────────────────────────────────────

def analyse_thread():
    """
    Analyses flows every ANALYSIS_INTERVAL seconds — both
    active flows (early warning) and expired flows (final verdict).
    """
    while True:
        time.sleep(ANALYSIS_INTERVAL)

        with lock:
            state['active_flows'] = flow_mgr.count()

        # Analyse ALL active flows for early detection
        for key, flow in flow_mgr.get_all_active():
            if flow.pkt_count >= 2:
                analyse_flow(key, flow, final=False)

        # Also analyse expired flows (final verdict)
        for key, flow in flow_mgr.get_expired():
            if flow.pkt_count >= 1:
                analyse_flow(key, flow, final=True)


def ticker_thread():
    """
    Updates every 200ms for smooth chart rendering.
    Uses exponential moving average to smooth out spikes.
    Emits stats to dashboard continuously.
    """
    INTERVAL    = 0.2    # 200ms — smooth updates
    HISTORY_SEC = 1.0    # accumulate over 1s windows for the history line
    SMOOTH      = 0.25   # EMA smoothing factor (lower = smoother)

    _bps_smooth = 0.0
    _pps_smooth = 0.0
    _acc_timer  = time.time()

    while True:
        time.sleep(INTERVAL)

        with lock:
            raw_bps = state['_byte_acc']
            raw_pps = state['_pkt_acc']
            state['_byte_acc'] = 0
            state['_pkt_acc']  = 0

        # Scale to per-second rates
        bps_rate = raw_bps / INTERVAL
        pps_rate = raw_pps / INTERVAL

        # Exponential moving average for smooth wave
        _bps_smooth = SMOOTH * bps_rate + (1 - SMOOTH) * _bps_smooth
        _pps_smooth = SMOOTH * pps_rate + (1 - SMOOTH) * _pps_smooth

        with lock:
            state['bytes_per_sec'] = int(_bps_smooth)
            state['pkts_per_sec']  = int(_pps_smooth)

        # Add to history every 1 second for the chart line
        if time.time() - _acc_timer >= HISTORY_SEC:
            _acc_timer = time.time()
            with lock:
                state['traffic_history'].append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'bps' : int(_bps_smooth),
                    'pps' : int(_pps_smooth),
                })

        # Push smooth stats every 200ms
        socketio.emit('stats_update', _main_stats())
        socketio.emit('map_update',   _map_data())


# Ports to ignore — dashboard's own communication
IGNORED_PORTS = {5000, 5001}

def process_packet(pkt):
    """
    Called for EVERY captured packet.
    1. Logs it to the live packet table immediately
    2. Adds it to the flow tracker
    """
    now = datetime.now()

    # Skip dashboard's own Flask/SocketIO traffic
    if pkt.haslayer(TCP):
        sp = pkt[TCP].sport; dp = pkt[TCP].dport
        if sp in IGNORED_PORTS or dp in IGNORED_PORTS:
            return
    if pkt.haslayer(UDP):
        sp = pkt[UDP].sport; dp = pkt[UDP].dport
        if sp in IGNORED_PORTS or dp in IGNORED_PORTS:
            return

    # Skip purely internal loopback-to-loopback traffic
    if pkt.haslayer(IP):
        si = pkt[IP].src; di = pkt[IP].dst
        if si == '127.0.0.1' and di == '127.0.0.1':
            return

    with lock:
        state['packets_captured']+=1
        sz=len(pkt)
        state['_byte_acc']+=sz
        state['_pkt_acc']+=1

    # ── Build packet log entry ──
    proto=get_proto(pkt)
    src_ip=dst_ip=src_port=dst_port=''
    flags=info=''

    if pkt.haslayer(IP):
        src_ip=pkt[IP].src; dst_ip=pkt[IP].dst

    if pkt.haslayer(TCP):
        src_port=pkt[TCP].sport; dst_port=pkt[TCP].dport
        flags=get_flags(pkt)
        info=f'TCP {flags}' if flags else 'TCP'
    elif pkt.haslayer(UDP):
        src_port=pkt[UDP].sport; dst_port=pkt[UDP].dport
        info='DNS Query' if dst_port==53 else f'UDP :{dst_port}'
    elif pkt.haslayer(ICMP):
        info=f'ICMP type={pkt[ICMP].type}'
    elif pkt.haslayer(ARP):
        src_ip=pkt[ARP].psrc; dst_ip=pkt[ARP].pdst
        info='ARP Request' if pkt[ARP].op==1 else 'ARP Reply'
        proto='ARP'

    # Determine if suspicious (quick heuristic on single packet)
    suspicion=''
    if flags:
        if 'SYN' in flags and 'ACK' not in flags: suspicion='warn'  # SYN only
        if 'RST' in flags:                         suspicion='warn'  # RST
    if src_port in (22,23,3389,445,1433,3306) or dst_port in (22,23,3389,445,1433,3306):
        suspicion='warn'  # sensitive ports

    # Check if src_ip is already known attacker
    if src_ip and src_ip in state.get('blocked_ips',{}):
        suspicion='danger'

    # Never flag dashboard's own traffic
    try:
        sp2 = int(str(src_port).split(':')[-1]) if src_port else 0
        dp2 = int(str(dst_port).split(':')[-1]) if dst_port else 0
        if sp2 in IGNORED_PORTS or dp2 in IGNORED_PORTS:
            return  # skip logging dashboard traffic entirely
    except:
        pass

    entry={
        'no'      : state['packets_captured'],
        'time'    : now.strftime('%H:%M:%S.') + f'{now.microsecond//1000:03d}',
        'src'     : f'{src_ip}:{src_port}' if src_port else src_ip,
        'dst'     : f'{dst_ip}:{dst_port}' if dst_port else dst_ip,
        'proto'   : proto,
        'len'     : sz,
        'flags'   : flags,
        'info'    : info,
        'suspicion': suspicion,
    }

    packet_log.appendleft(entry)
    # Emit this single packet immediately to all connected browsers
    socketio.emit('new_packet', entry)

    # Update protocol counter
    with lock:
        state['protocol_counts'][proto]+=1

    # Add to flow tracker
    flow_mgr.add_packet(pkt)


def capture_on_iface(iface):
    try:
        print(f'[*] Capturing on {iface}...')
        # Exclude dashboard's own Flask/SocketIO traffic on port 5000
        # Exclude loopback internal traffic (127.0.0.1 <-> 127.0.0.1)
        bpf = (
            'ip and '
            'not (port 5000) and '
            'not (src host 127.0.0.1 and dst host 127.0.0.1)'
        )
        sniff(iface=iface, prn=process_packet, store=False, filter=bpf)
    except Exception as e:
        print(f'[!] {iface}: {e}')


def capture_thread():
    """Capture on BOTH main interface AND loopback so simulator traffic is caught."""
    interfaces = list(dict.fromkeys([INTERFACE, 'lo']))
    print(f'[*] Starting capture on: {", ".join(interfaces)}')

    if os.geteuid() != 0:
        print('[!] Not root -- run: sudo venv/bin/python nids_dashboard.py')
        sys.exit(1)

    threads = []
    for iface in interfaces:
        t = threading.Thread(target=capture_on_iface, args=(iface,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# ─────────────────────────────────────────────
# DATA HELPERS
# ─────────────────────────────────────────────
def _main_stats():
    with lock:
        return {
            'packets_captured' : state['packets_captured'],
            'attacks_detected' : state['attacks_detected'],
            'ips_blocked'      : state['ips_blocked'],
            'active_flows'     : state['active_flows'],
            'bytes_per_sec'    : state['bytes_per_sec'],
            'pkts_per_sec'     : state['pkts_per_sec'],
            'traffic'          : list(state['traffic_history'])[-60:],
            'attack_types'     : dict(state['attack_types']),
            'protocol_counts'  : dict(state['protocol_counts']),
            'blocked_ips'      : dict(state['blocked_ips']),
        }

def _map_data():
    markers=[
        {'ip':ip,'lat':v['lat'],'lon':v['lon'],
         'country':v['country'],'city':v['city'],
         'count':v['count'],'country_code':v['country_code']}
        for ip,v in geo_state['origins'].items() if v['lat']!=0
    ]
    top=sorted(geo_state['countries'].items(),key=lambda x:x[1],reverse=True)[:8]
    return {
        'markers':markers,'top_countries':top,
        'recent_events':list(reversed(geo_state['events'][-15:])),
        'total_attacks':len(geo_state['events']),
        'unique_ips':len(geo_state['origins']),
        'unique_countries':len(geo_state['countries']),
    }

# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────
@app.route('/api/stats')
def api_stats():
    d=_main_stats()
    with lock: d['alerts']=list(state['alerts'])[:30]
    return jsonify(d)

@app.route('/api/packets')
def api_packets():
    return jsonify({'packets':list(packet_log)[:100]})

@app.route('/api/map')
def api_map():
    return jsonify(_map_data())

@app.route('/api/unblock/<ip>',methods=['POST'])
def api_unblock(ip):
    with lock:
        if ip in state['blocked_ips']:
            del state['blocked_ips'][ip]
            state['ips_blocked']=max(0,state['ips_blocked']-1)
    os.system(f'iptables -D INPUT -s {ip} -j DROP 2>/dev/null')
    return jsonify({'success':True})

@app.route('/api/system')
def api_system():
    return jsonify({'interface':INTERFACE,'ml_ready':ML_READY,'geoip_ready':GEOIP_READER is not None})

@app.route('/')
def index():
    return render_template_string(HTML)

# ─────────────────────────────────────────────
# HTML — 3 TABS: Dashboard | Packet Log | Map
# ─────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NIDS | East Africa</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@400;600;700&family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#060d14;--panel:#0b1929;--border:#112840;--accent:#00c8ff;--danger:#ff3f5e;--warn:#ffb800;--safe:#00e887;--text:#b8d8f0;--muted:#2d5a7a;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'Barlow Condensed',sans-serif;height:100vh;display:flex;flex-direction:column;overflow:hidden;}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.05) 3px,rgba(0,0,0,0.05) 4px);pointer-events:none;z-index:9999;}

/* HEADER */
header{display:flex;align-items:center;justify-content:space-between;padding:9px 24px;background:var(--panel);border-bottom:1px solid var(--border);flex-shrink:0;z-index:500;}
.logo{font-family:'Orbitron',sans-serif;font-size:.95rem;color:var(--accent);letter-spacing:3px;text-shadow:0 0 15px rgba(0,200,255,.4);}
.logo em{color:var(--danger);font-style:normal;}
.hright{display:flex;align-items:center;gap:10px;}
.sbadge{font-family:'Share Tech Mono',monospace;font-size:.62rem;padding:3px 9px;border-radius:2px;border:1px solid var(--border);color:var(--muted);}
.sbadge.ok{border-color:rgba(0,232,135,.3);color:var(--safe);}
.sbadge.warn{border-color:rgba(255,184,0,.3);color:var(--warn);}
.live-pill{display:flex;align-items:center;gap:5px;font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--safe);border:1px solid rgba(0,232,135,.3);padding:3px 10px;border-radius:20px;}
.dot{width:6px;height:6px;border-radius:50%;background:var(--safe);animation:dotpulse 1.5s infinite;}
@keyframes dotpulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.4;transform:scale(1.5);}}
#clock{font-family:'Share Tech Mono',monospace;font-size:.72rem;color:var(--muted);}

/* NAV */
nav{display:flex;background:var(--panel);border-bottom:1px solid var(--border);flex-shrink:0;padding:0 24px;gap:2px;}
.tab{font-family:'Orbitron',sans-serif;font-size:.6rem;letter-spacing:2px;padding:9px 18px;cursor:pointer;border-bottom:2px solid transparent;color:var(--muted);transition:all .2s;text-transform:uppercase;background:none;border-top:none;border-left:none;border-right:none;}
.tab:hover{color:var(--text);}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}

/* VIEWS */
.view{display:none;flex:1;overflow:hidden;flex-direction:column;}
.view.active{display:flex;}

/* ══ DASHBOARD ══ */
.dbody{flex:1;overflow-y:auto;padding:16px 24px;}
.dbody::-webkit-scrollbar{width:4px;}
.dbody::-webkit-scrollbar-thumb{background:var(--border);}
.sgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;}
.sc{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:15px 18px;position:relative;overflow:hidden;}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
.sc.p::before{background:var(--accent);box-shadow:0 0 8px var(--accent);}
.sc.a::before{background:var(--danger);box-shadow:0 0 8px var(--danger);}
.sc.b::before{background:var(--warn);box-shadow:0 0 8px var(--warn);}
.sc.f::before{background:var(--safe);box-shadow:0 0 8px var(--safe);}
.slabel{font-size:.65rem;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:5px;}
.sval{font-family:'Orbitron',sans-serif;font-size:1.7rem;font-weight:900;line-height:1;}
.sc.p .sval{color:var(--accent);}
.sc.a .sval{color:var(--danger);}
.sc.b .sval{color:var(--warn);}
.sc.f .sval{color:var(--safe);}
.ssub{font-size:.65rem;color:var(--muted);margin-top:3px;font-family:'Share Tech Mono',monospace;}
.mgrid{display:grid;grid-template-columns:1fr 300px;gap:12px;margin-bottom:12px;}
.bgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:4px;overflow:hidden;}
.phdr{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border);}
.ptitle{font-family:'Orbitron',sans-serif;font-size:.6rem;letter-spacing:2px;color:var(--accent);text-transform:uppercase;}
.pbadge{font-family:'Share Tech Mono',monospace;font-size:.65rem;padding:2px 7px;border-radius:2px;background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.2);color:var(--accent);}
.pbody{padding:12px 16px;}
.cwrap{position:relative;height:175px;}
.afeed{max-height:320px;overflow-y:auto;}
.afeed::-webkit-scrollbar{width:3px;}
.afeed::-webkit-scrollbar-thumb{background:var(--border);}
.ai{display:grid;grid-template-columns:26px 1fr auto;align-items:center;gap:9px;padding:8px 16px;border-bottom:1px solid rgba(17,40,64,.5);animation:sIn .3s ease;}
@keyframes sIn{from{opacity:0;transform:translateX(-6px);}to{opacity:1;transform:translateX(0);}}
.aico{width:26px;height:26px;border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0;}
.aico.blocked{background:rgba(255,63,94,.1);border:1px solid rgba(255,63,94,.25);}
.aico.monitored{background:rgba(255,184,0,.1);border:1px solid rgba(255,184,0,.25);}
.atype{font-weight:700;font-size:.82rem;}
.ameta{font-family:'Share Tech Mono',monospace;font-size:.62rem;color:var(--muted);margin-top:1px;}
.abadge{font-size:.6rem;font-family:'Share Tech Mono',monospace;padding:2px 6px;border-radius:2px;}
.abadge.blocked{background:rgba(255,63,94,.1);color:var(--danger);border:1px solid rgba(255,63,94,.25);}
.abadge.monitored{background:rgba(255,184,0,.08);color:var(--warn);border:1px solid rgba(255,184,0,.2);}
.ipt{width:100%;border-collapse:collapse;font-size:.75rem;}
.ipt th{text-align:left;padding:6px 9px;font-family:'Share Tech Mono',monospace;font-size:.58rem;letter-spacing:1px;color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--border);}
.ipt td{padding:7px 9px;border-bottom:1px solid rgba(17,40,64,.4);font-family:'Share Tech Mono',monospace;font-size:.68rem;}
.iptag{display:inline-block;padding:1px 6px;border-radius:2px;font-size:.6rem;background:rgba(255,63,94,.1);color:var(--danger);border:1px solid rgba(255,63,94,.2);}
.ubtn{background:none;border:1px solid var(--border);color:var(--muted);padding:2px 7px;border-radius:2px;cursor:pointer;font-family:'Share Tech Mono',monospace;font-size:.6rem;transition:all .2s;}
.ubtn:hover{border-color:var(--safe);color:var(--safe);}
.empty{text-align:center;padding:28px 14px;color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:.72rem;line-height:2;}

/* ══ PACKET LOG TAB ══ */
.plog-body{flex:1;display:flex;flex-direction:column;overflow:hidden;padding:12px 24px;gap:10px;}
.plog-toolbar{display:flex;align-items:center;gap:12px;flex-shrink:0;}
.plog-toolbar input{flex:1;background:var(--panel);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:.75rem;outline:none;}
.plog-toolbar input:focus{border-color:var(--accent);}
.pfilter{background:none;border:1px solid var(--border);color:var(--muted);padding:5px 12px;border-radius:3px;cursor:pointer;font-family:'Share Tech Mono',monospace;font-size:.65rem;transition:all .2s;}
.pfilter:hover,.pfilter.active{border-color:var(--accent);color:var(--accent);}
.pfilter.danger.active{border-color:var(--danger);color:var(--danger);}
.pfilter.warn.active{border-color:var(--warn);color:var(--warn);}
.pclear{background:rgba(255,63,94,.1);border:1px solid rgba(255,63,94,.3);color:var(--danger);padding:5px 12px;border-radius:3px;cursor:pointer;font-family:'Share Tech Mono',monospace;font-size:.65rem;}
.plog-stats{display:flex;gap:20px;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--muted);flex-shrink:0;}
.plog-stats span{color:var(--text);}
.plog-wrap{flex:1;overflow-y:auto;border:1px solid var(--border);border-radius:4px;background:var(--panel);}
.plog-wrap::-webkit-scrollbar{width:4px;}
.plog-wrap::-webkit-scrollbar-thumb{background:var(--border);}
.ptable{width:100%;border-collapse:collapse;font-family:'Share Tech Mono',monospace;font-size:.68rem;}
.ptable th{position:sticky;top:0;background:#0d1f35;text-align:left;padding:7px 10px;font-size:.58rem;letter-spacing:1px;color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--border);z-index:10;}
.ptable td{padding:5px 10px;border-bottom:1px solid rgba(17,40,64,.3);white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis;}
.ptable tr{transition:background .1s;}
.ptable tr:hover td{background:rgba(0,200,255,.03);}
.ptable tr.new-row{animation:rowIn .25s ease;}
@keyframes rowIn{from{opacity:0;background:rgba(0,200,255,.08);}to{opacity:1;background:transparent;}}
.ptable tr.danger td:first-child{border-left:2px solid var(--danger);}
.ptable tr.warn   td:first-child{border-left:2px solid var(--warn);}
.proto-badge{display:inline-block;padding:1px 5px;border-radius:2px;font-size:.58rem;font-weight:bold;}
.proto-TCP  {background:rgba(0,200,255,.1);color:var(--accent);border:1px solid rgba(0,200,255,.25);}
.proto-UDP  {background:rgba(0,232,135,.1);color:var(--safe);border:1px solid rgba(0,232,135,.25);}
.proto-ICMP {background:rgba(255,184,0,.1);color:var(--warn);border:1px solid rgba(255,184,0,.25);}
.proto-ARP  {background:rgba(168,85,247,.1);color:#a855f7;border:1px solid rgba(168,85,247,.25);}
.proto-DNS  {background:rgba(249,115,22,.1);color:#f97316;border:1px solid rgba(249,115,22,.25);}
.proto-OTHER{background:rgba(45,90,122,.1);color:var(--muted);border:1px solid rgba(45,90,122,.3);}
.flag-SYN{color:#00c8ff;}.flag-ACK{color:var(--safe);}.flag-FIN{color:var(--warn);}
.flag-RST{color:var(--danger);}.flag-PSH{color:#a855f7;}.flag-URG{color:#f97316;}
.pause-badge{background:rgba(255,184,0,.1);border:1px solid rgba(255,184,0,.3);color:var(--warn);padding:2px 8px;border-radius:2px;font-size:.6rem;margin-left:8px;display:none;}
.pause-badge.visible{display:inline-block;}

/* ══ MAP ══ */
.map-body{flex:1;display:grid;grid-template-columns:230px 1fr 230px;overflow:hidden;}
.mside{background:var(--panel);display:flex;flex-direction:column;overflow:hidden;}
.mside.right{border-left:1px solid var(--border);}
.mside.left{border-right:1px solid var(--border);}
.mshdr{padding:10px 13px;border-bottom:1px solid var(--border);font-family:'Orbitron',sans-serif;font-size:.58rem;letter-spacing:2px;color:var(--accent);text-transform:uppercase;flex-shrink:0;}
#map{flex:1;z-index:1;}
.leaflet-container{background:#060d14!important;}
.clist{flex:1;overflow-y:auto;}
.clist::-webkit-scrollbar{width:3px;}
.clist::-webkit-scrollbar-thumb{background:var(--border);}
.crow{display:flex;align-items:center;gap:7px;padding:6px 13px;border-bottom:1px solid rgba(17,40,64,.4);}
.crank{font-family:'Share Tech Mono',monospace;font-size:.58rem;color:var(--muted);width:13px;flex-shrink:0;}
.cflag{font-size:.95rem;width:18px;text-align:center;flex-shrink:0;}
.cname{flex:1;font-size:.78rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.ccnt{font-family:'Share Tech Mono',monospace;font-size:.7rem;color:var(--danger);font-weight:bold;}
.cbar-w{height:2px;background:rgba(255,63,94,.1);margin:0 13px 3px;}
.cbar{height:100%;background:var(--danger);border-radius:1px;transition:width .5s;}
.mfeed{flex:1;overflow-y:auto;}
.mfeed::-webkit-scrollbar{width:3px;}
.mfeed::-webkit-scrollbar-thumb{background:var(--border);}
.malert{padding:7px 11px;border-bottom:1px solid rgba(17,40,64,.4);animation:fR .35s ease;}
@keyframes fR{from{opacity:0;transform:translateX(5px);}to{opacity:1;transform:translateX(0);}}
.matop{display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;}
.matype{font-size:.78rem;font-weight:700;}
.mab{font-family:'Share Tech Mono',monospace;font-size:.56rem;padding:1px 5px;border-radius:2px;}
.mab.blocked{background:rgba(255,63,94,.1);color:var(--danger);border:1px solid rgba(255,63,94,.25);}
.mab.monitored{background:rgba(255,184,0,.08);color:var(--warn);border:1px solid rgba(255,184,0,.2);}
.mameta{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--muted);line-height:1.5;}
.mameta span{color:var(--text);}
.map-sbar{display:flex;gap:24px;padding:7px 18px;background:var(--panel);border-top:1px solid var(--border);flex-shrink:0;}
.ms{text-align:center;}
.msv{font-family:'Orbitron',sans-serif;font-size:1.05rem;}
.msv.d{color:var(--danger)}.msv.a{color:var(--accent)}.msv.w{color:var(--warn)}
.msl{font-family:'Share Tech Mono',monospace;font-size:.56rem;color:var(--muted);letter-spacing:1px;}
.leaflet-popup-content-wrapper{background:var(--panel)!important;border:1px solid var(--border)!important;border-radius:4px!important;color:var(--text)!important;font-family:'Barlow Condensed',sans-serif!important;box-shadow:0 4px 20px rgba(0,0,0,.5)!important;}
.leaflet-popup-tip{background:var(--panel)!important;}
.popi{font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--danger);margin-bottom:4px;}
.popr{font-size:.76rem;margin-bottom:2px;}
.popr span{color:var(--muted);}

footer{background:var(--panel);border-top:1px solid var(--border);padding:4px 24px;font-family:'Share Tech Mono',monospace;font-size:.58rem;color:var(--muted);letter-spacing:1px;display:flex;justify-content:space-between;flex-shrink:0;}
</style>
</head>
<body>

<header>
  <div class="logo">N<em>I</em>DS <span style="font-size:.5rem;color:var(--muted);letter-spacing:1px">EAST AFRICA</span></div>
  <div class="hright">
    <div class="sbadge" id="b-iface">⬛ loading</div>
    <div class="sbadge" id="b-ml">⬛ ML</div>
    <div class="sbadge" id="b-geo">⬛ GeoIP</div>
    <div class="live-pill"><div class="dot"></div>LIVE</div>
    <div id="clock">--:--:--</div>
  </div>
</header>

<nav>
  <button class="tab active" onclick="switchTab('dashboard',this)">⬛ DASHBOARD</button>
  <button class="tab" onclick="switchTab('packets',this)">📡 PACKET LOG</button>
  <button class="tab" onclick="switchTab('map',this)">🌍 ATTACK MAP</button>
</nav>

<!-- ══════ DASHBOARD ══════ -->
<div class="view active" id="view-dashboard">
 <div class="dbody">
  <div class="sgrid">
   <div class="sc p"><div class="slabel">Packets Captured</div><div class="sval" id="s-pkt">0</div><div class="ssub" id="s-pps">0 pps</div></div>
   <div class="sc a"><div class="slabel">Attacks Detected</div><div class="sval" id="s-atk">0</div><div class="ssub">ML / heuristic</div></div>
   <div class="sc b"><div class="slabel">IPs Blocked</div><div class="sval" id="s-blk">0</div><div class="ssub">via iptables</div></div>
   <div class="sc f"><div class="slabel">Active Flows</div><div class="sval" id="s-flw">0</div><div class="ssub">tracked</div></div>
  </div>
  <div class="mgrid">
   <div class="panel">
    <div class="phdr"><div class="ptitle">Live Traffic</div><div class="pbadge" id="bps-badge">0 B/s</div></div>
    <div class="pbody"><div class="cwrap"><canvas id="trafficChart"></canvas></div></div>
   </div>
   <div class="panel">
    <div class="phdr"><div class="ptitle">Alert Feed</div><div class="pbadge" id="alert-cnt">0</div></div>
    <div class="afeed" id="alert-feed"><div class="empty">🛡️<br>Monitoring live traffic<br>No threats yet</div></div>
   </div>
  </div>
  <div class="bgrid">
   <div class="panel">
    <div class="phdr"><div class="ptitle">Attack Breakdown</div></div>
    <div class="pbody"><div class="cwrap"><canvas id="attackChart"></canvas></div></div>
   </div>
   <div class="panel">
    <div class="phdr"><div class="ptitle">Blocked IPs</div><div class="pbadge" id="blk-cnt">0</div></div>
    <div class="pbody" id="blk-panel"><div class="empty">✅<br>No IPs blocked</div></div>
   </div>
  </div>
 </div>
</div>

<!-- ══════ PACKET LOG ══════ -->
<div class="view" id="view-packets">
 <div class="plog-body">
  <div class="plog-toolbar">
   <input id="pkt-search" placeholder="🔍  Filter by IP, protocol, port, flag..." oninput="filterPackets()">
   <button class="pfilter active" id="f-all"    onclick="setFilter('all',this)">ALL</button>
   <button class="pfilter" id="f-tcp"   onclick="setFilter('TCP',this)">TCP</button>
   <button class="pfilter" id="f-udp"   onclick="setFilter('UDP',this)">UDP</button>
   <button class="pfilter" id="f-icmp"  onclick="setFilter('ICMP',this)">ICMP</button>
   <button class="pfilter danger" id="f-sus" onclick="setFilter('suspicious',this)">⚠ SUSPICIOUS</button>
   <span class="pause-badge" id="pause-badge">⏸ PAUSED</span>
   <button class="pclear" onclick="clearPackets()">CLEAR</button>
  </div>
  <div class="plog-stats">
    Total: <span id="ps-total">0</span> &nbsp;|&nbsp;
    TCP: <span id="ps-tcp">0</span> &nbsp;|&nbsp;
    UDP: <span id="ps-udp">0</span> &nbsp;|&nbsp;
    ICMP: <span id="ps-icmp">0</span> &nbsp;|&nbsp;
    Suspicious: <span id="ps-sus" style="color:var(--warn)">0</span> &nbsp;|&nbsp;
    <span style="color:var(--muted)">Pauses when you scroll up ↑</span>
  </div>
  <div class="plog-wrap" id="plog-wrap">
   <table class="ptable" id="ptable">
    <thead><tr>
     <th>#</th><th>Time</th><th>Source</th><th>Destination</th>
     <th>Proto</th><th>Len</th><th>Flags</th><th>Info</th>
    </tr></thead>
    <tbody id="ptbody"></tbody>
   </table>
  </div>
 </div>
</div>

<!-- ══════ ATTACK MAP ══════ -->
<div class="view" id="view-map">
 <div class="map-body">
  <div class="mside left">
   <div class="mshdr">Top Countries</div>
   <div class="clist" id="clist"><div class="empty">Waiting...</div></div>
  </div>
  <div id="map"></div>
  <div class="mside right">
   <div class="mshdr">Live Attack Feed</div>
   <div class="mfeed" id="mfeed"><div class="empty">Monitoring...</div></div>
  </div>
 </div>
 <div class="map-sbar">
  <div class="ms"><div class="msv d" id="m-tot">0</div><div class="msl">Attacks</div></div>
  <div class="ms"><div class="msv a" id="m-ips">0</div><div class="msl">Unique IPs</div></div>
  <div class="ms"><div class="msv w" id="m-ctr">0</div><div class="msl">Countries</div></div>
 </div>
</div>

<footer>
  <span id="f-iface">Interface: loading...</span>
  <span>NIDS v1.0 · East Africa Network Defense · Final Year Project</span>
  <span id="f-clock">--:--:--</span>
</footer>

<script>
// ── TABS ──
function switchTab(name,btn){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('view-'+name).classList.add('active');
  btn.classList.add('active');
  if(name==='map') setTimeout(()=>map.invalidateSize(),60);
}

// ── CLOCK ──
setInterval(()=>{const t=new Date().toLocaleTimeString();document.getElementById('clock').textContent=t;document.getElementById('f-clock').textContent=t;},1000);

// ── SYSTEM STATUS ──
fetch('/api/system').then(r=>r.json()).then(d=>{
  const ib=document.getElementById('b-iface');
  ib.textContent='📡 '+d.interface; ib.className='sbadge ok';
  document.getElementById('f-iface').textContent='Interface: '+d.interface;
  const mb=document.getElementById('b-ml');
  mb.textContent=d.ml_ready?'🤖 ML: ON':'⚠ ML: HEURISTIC';
  mb.className='sbadge '+(d.ml_ready?'ok':'warn');
  const gb=document.getElementById('b-geo');
  gb.textContent=d.geoip_ready?'🌍 GeoIP: ON':'⚠ GeoIP: OFF';
  gb.className='sbadge '+(d.geoip_ready?'ok':'warn');
});

// ══════════════════════════════════════
// DASHBOARD CHARTS
// ══════════════════════════════════════
const tCtx=document.getElementById('trafficChart').getContext('2d');
const trafficChart=new Chart(tCtx,{
  type:'line',
  data:{
    labels:[],
    datasets:[
      {
        label:'Bytes/s',
        data:[],
        borderColor:'#00c8ff',
        backgroundColor:(ctx)=>{
          const g=ctx.chart.ctx.createLinearGradient(0,0,0,180);
          g.addColorStop(0,'rgba(0,200,255,0.25)');
          g.addColorStop(1,'rgba(0,200,255,0.0)');
          return g;
        },
        borderWidth:2.5,
        fill:true,
        tension:0.5,
        pointRadius:0,
        pointHoverRadius:0,
        cubicInterpolationMode:'monotone',
      },
      {
        label:'Pkts/s',
        data:[],
        borderColor:'#00e887',
        backgroundColor:'rgba(0,232,135,0.04)',
        borderWidth:1.5,
        fill:true,
        tension:0.5,
        pointRadius:0,
        pointHoverRadius:0,
        cubicInterpolationMode:'monotone',
      },
    ]
  },
  options:{
    responsive:true,
    maintainAspectRatio:false,
    animation:{
      duration:800,
      easing:'easeInOutQuart',
    },
    transitions:{
      active:{animation:{duration:400}},
    },
    interaction:{mode:'nearest',intersect:false},
    plugins:{
      legend:{labels:{color:'#2d5a7a',font:{family:'Share Tech Mono',size:9}}},
      tooltip:{enabled:false},
    },
    scales:{
      x:{
        ticks:{color:'#2d5a7a',font:{family:'Share Tech Mono',size:8},maxTicksLimit:8},
        grid:{color:'rgba(17,40,64,0.5)'},
      },
      y:{
        ticks:{color:'#2d5a7a',font:{family:'Share Tech Mono',size:8},maxTicksLimit:6},
        grid:{color:'rgba(17,40,64,0.5)'},
        beginAtZero:true,
      }
    }
  }
});

const aCtx=document.getElementById('attackChart').getContext('2d');
const attackChart=new Chart(aCtx,{type:'doughnut',data:{labels:[],datasets:[{data:[],
  backgroundColor:['#ff3f5e','#00c8ff','#ffb800','#00e887','#a855f7','#f97316'],borderColor:'#0b1929',borderWidth:3}]},
  options:{responsive:true,maintainAspectRatio:false,
    plugins:{legend:{position:'right',labels:{color:'#b8d8f0',font:{family:'Barlow Condensed',size:11},padding:8}}}}});

let alertCount=0;

function updateDash(d){
  document.getElementById('s-pkt').textContent=d.packets_captured.toLocaleString();
  document.getElementById('s-atk').textContent=d.attacks_detected.toLocaleString();
  document.getElementById('s-blk').textContent=d.ips_blocked.toLocaleString();
  document.getElementById('s-flw').textContent=d.active_flows.toLocaleString();
  document.getElementById('s-pps').textContent=(d.pkts_per_sec||0)+' pps';

  // Smooth live BPS/PPS display using client-side smoothing
  const liveBps = d.bytes_per_sec || 0;
  const livePps = d.pkts_per_sec  || 0;
  document.getElementById('bps-badge').textContent = formatBytes(liveBps)+'/s';

  // Push new data point smoothly into chart
  if(d.traffic && d.traffic.length){
    const latest = d.traffic[d.traffic.length-1];

    // Add new point if label changed (new second)
    const labels = trafficChart.data.labels;
    if(!labels.length || labels[labels.length-1] !== latest.time){
      trafficChart.data.labels.push(latest.time);
      trafficChart.data.datasets[0].data.push(latest.bps);
      trafficChart.data.datasets[1].data.push(latest.pps);

      // Keep max 60 points (60 seconds of history)
      if(trafficChart.data.labels.length > 60){
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
        trafficChart.data.datasets[1].data.shift();
      }
    } else {
      // Update last point with smoothed live value
      const len = trafficChart.data.datasets[0].data.length;
      if(len > 0){
        const prev0 = trafficChart.data.datasets[0].data[len-1] || 0;
        const prev1 = trafficChart.data.datasets[1].data[len-1] || 0;
        trafficChart.data.datasets[0].data[len-1] = prev0 * 0.6 + liveBps * 0.4;
        trafficChart.data.datasets[1].data[len-1] = prev1 * 0.6 + livePps * 0.4;
      }
    }

    trafficChart.update();
  }
  if(d.attack_types&&Object.keys(d.attack_types).length){
    attackChart.data.labels=Object.keys(d.attack_types);
    attackChart.data.datasets[0].data=Object.values(d.attack_types);
    attackChart.update('none');
  }
  if(d.blocked_ips) updateBlockedPanel(d.blocked_ips);
  // update packet log protocol stats
  if(d.protocol_counts){
    document.getElementById('ps-tcp').textContent=d.protocol_counts['TCP']||0;
    document.getElementById('ps-udp').textContent=d.protocol_counts['UDP']||0;
    document.getElementById('ps-icmp').textContent=d.protocol_counts['ICMP']||0;
  }
}

function formatBytes(b){
  if(b>1048576) return (b/1048576).toFixed(1)+' MB';
  if(b>1024)    return (b/1024).toFixed(1)+' KB';
  return b+' B';
}

function updateBlockedPanel(blocked){
  const p=document.getElementById('blk-panel');
  const e=Object.entries(blocked);
  document.getElementById('blk-cnt').textContent=e.length+' active';
  if(!e.length){p.innerHTML='<div class="empty">✅<br>No IPs blocked</div>';return;}
  p.innerHTML=`<table class="ipt"><thead><tr><th>IP</th><th>Type</th><th>Conf</th><th>Unblocks</th><th></th></tr></thead><tbody>
    ${e.map(([ip,i])=>`<tr>
      <td style="color:var(--danger)">${ip}</td>
      <td><span class="iptag">${i.attack_type}</span></td>
      <td style="color:var(--warn)">${i.confidence}%</td>
      <td style="color:var(--muted)">${i.unblock_at}</td>
      <td><button class="ubtn" onclick="unblock('${ip}')">UNBLOCK</button></td>
    </tr>`).join('')}</tbody></table>`;
}

function addAlert(a){
  alertCount++;
  document.getElementById('alert-cnt').textContent=alertCount;
  const feed=document.getElementById('alert-feed');
  if(feed.querySelector('.empty')) feed.innerHTML='';
  const isB=a.action==='BLOCKED';
  const d=document.createElement('div');
  d.className='ai';
  d.innerHTML=`
    <div class="aico ${isB?'blocked':'monitored'}">${isB?'🔴':'🟡'}</div>
    <div>
      <div class="atype">${a.attack_type}</div>
      <div class="ameta">${a.src_ip}:${a.src_port} → ${a.dst_ip}:${a.dst_port}<br>${a.confidence}% · ${a.fwd_pkts}↑ ${a.bwd_pkts}↓ pkts · ${a.duration_sec}s</div>
    </div>
    <div class="abadge ${isB?'blocked':'monitored'}">${a.action}</div>`;
  feed.insertBefore(d,feed.firstChild);
  while(feed.children.length>60) feed.removeChild(feed.lastChild);
}

async function unblock(ip){await fetch('/api/unblock/'+ip,{method:'POST'});}

// ══════════════════════════════════════
// PACKET LOG
// ══════════════════════════════════════
let allPackets=[];
let currentFilter='all';
let searchTerm='';
let paused=false;
let suspiciousCount=0;

const plogWrap=document.getElementById('plog-wrap');

// Pause scrolling when user scrolls UP
plogWrap.addEventListener('scroll',()=>{
  const atBottom=plogWrap.scrollTop<50;
  if(!atBottom && !paused){
    paused=true;
    document.getElementById('pause-badge').classList.add('visible');
  } else if(atBottom && paused){
    paused=false;
    document.getElementById('pause-badge').classList.remove('visible');
  }
});

function setFilter(f,btn){
  currentFilter=f;
  document.querySelectorAll('.pfilter').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderPackets();
}

function filterPackets(){
  searchTerm=document.getElementById('pkt-search').value.toLowerCase();
  renderPackets();
}

function clearPackets(){
  allPackets=[];suspiciousCount=0;
  document.getElementById('ptbody').innerHTML='';
  document.getElementById('ps-total').textContent='0';
  document.getElementById('ps-sus').textContent='0';
}

function matchPacket(p){
  if(currentFilter==='suspicious') return p.suspicion!=='';
  if(currentFilter!=='all' && p.proto!==currentFilter) return false;
  if(!searchTerm) return true;
  return (p.src+p.dst+p.proto+p.flags+p.info).toLowerCase().includes(searchTerm);
}

function colorFlags(flags){
  if(!flags) return '';
  return flags.split(' ').map(f=>`<span class="flag-${f}">${f}</span>`).join(' ');
}

function addPacketRow(p,prepend=true){
  const tbody=document.getElementById('ptbody');
  if(!matchPacket(p)) return;
  const tr=document.createElement('tr');
  if(p.suspicion) tr.className=p.suspicion;
  tr.className+=' new-row';
  tr.innerHTML=`
    <td style="color:var(--muted)">${p.no}</td>
    <td style="color:var(--muted)">${p.time}</td>
    <td style="color:${p.suspicion==='danger'?'var(--danger)':p.suspicion==='warn'?'var(--warn)':'var(--text)'}">${p.src||'-'}</td>
    <td>${p.dst||'-'}</td>
    <td><span class="proto-badge proto-${p.proto}">${p.proto}</span></td>
    <td style="color:var(--muted)">${p.len}</td>
    <td>${colorFlags(p.flags)}</td>
    <td style="color:var(--muted);font-size:.62rem">${p.info||''}</td>`;
  if(prepend) tbody.insertBefore(tr,tbody.firstChild);
  else tbody.appendChild(tr);
  // Keep max 500 rows in DOM
  while(tbody.children.length>500) tbody.removeChild(tbody.lastChild);
}

function renderPackets(){
  const tbody=document.getElementById('ptbody');
  tbody.innerHTML='';
  const filtered=allPackets.filter(matchPacket).slice(0,300);
  filtered.forEach(p=>addPacketRow(p,false));
}

function onNewPacket(p){
  allPackets.unshift(p);
  if(allPackets.length>1000) allPackets.pop();
  if(p.suspicion) suspiciousCount++;
  document.getElementById('ps-total').textContent=allPackets.length;
  document.getElementById('ps-sus').textContent=suspiciousCount;
  if(!paused && matchPacket(p)) addPacketRow(p,true);
}

// ══════════════════════════════════════
// MAP
// ══════════════════════════════════════
const map=L.map('map',{center:[5,20],zoom:3,zoomControl:true,attributionControl:false});
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:18,subdomains:'abcd'}).addTo(map);
const homeIcon=L.divIcon({html:`<div style="width:13px;height:13px;border-radius:50%;background:#00e887;border:2px solid #fff;box-shadow:0 0 14px #00e887;"></div>`,iconSize:[13,13],iconAnchor:[6,6],className:''});
L.marker([-3.386925,36.682995],{icon:homeIcon}).addTo(map).bindPopup('<div style="color:#00e887;font-weight:bold;">🛡 Protected Network<br><small style="color:#2d5a7a">Arusha, Tanzania</small></div>');
const mapMarkers={};

function getFlag(code){
  if(!code||code==='XX') return '';
  try{return String.fromCodePoint(...[...code.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65));}catch{return '';}
}
const CODES={Kenya:'KE',Tanzania:'TZ',Nigeria:'NG',Ethiopia:'ET',Ghana:'GH','South Africa':'ZA',Uganda:'UG',Rwanda:'RW',Germany:'DE',Russia:'RU',China:'CN',USA:'US',India:'IN',France:'FR',UK:'GB',Brazil:'BR',Japan:'JP',Australia:'AU',Canada:'CA',Netherlands:'NL'};
function cc(c){return CODES[c]||'XX';}

function addOrUpdateMarker(m){
  if(!m.lat||m.lat===0) return;
  const sz=m.count>=10?22:m.count>=5?16:11;
  const icon=L.divIcon({
    html:`<div style="width:${sz}px;height:${sz}px;border-radius:50%;border:2px solid #ff3f5e;background:rgba(255,63,94,.2);display:flex;align-items:center;justify-content:center;font-family:Share Tech Mono;font-size:8px;color:#ff3f5e;animation:mP 2s infinite;">${m.count>1?m.count:''}</div>`,
    iconSize:[sz,sz],iconAnchor:[sz/2,sz/2],className:''
  });
  const pop=`<div class="popi">${m.ip}</div>
    <div class="popr"><span>Country: </span>${m.country} ${getFlag(m.country_code)}</div>
    <div class="popr"><span>City: </span>${m.city}</div>
    <div class="popr"><span>Attacks: </span><b style="color:#ff3f5e">${m.count}</b></div>`;
  if(mapMarkers[m.ip]){mapMarkers[m.ip].setIcon(icon).setPopupContent(pop);}
  else{mapMarkers[m.ip]=L.marker([m.lat,m.lon],{icon}).addTo(map).bindPopup(pop);}
}

function drawLine(lat,lon){
  const line=L.polyline([[lat,lon],[-3.386925,36.682995]],{color:'#ff3f5e',weight:1,opacity:.45,dashArray:'4,6'}).addTo(map);
  setTimeout(()=>map.removeLayer(line),3500);
}

function updateMapStats(d){
  document.getElementById('m-tot').textContent=d.total_attacks;
  document.getElementById('m-ips').textContent=d.unique_ips;
  document.getElementById('m-ctr').textContent=d.unique_countries;
}

function updateClist(countries){
  const list=document.getElementById('clist');
  if(!countries.length) return;
  const max=countries[0][1];
  list.innerHTML=countries.map(([c,n],i)=>`
    <div>
      <div class="crow">
        <div class="crank">${i+1}</div>
        <div class="cflag">${getFlag(cc(c))}</div>
        <div class="cname">${c}</div>
        <div class="ccnt">${n}</div>
      </div>
      <div class="cbar-w"><div class="cbar" style="width:${Math.round(n/max*100)}%"></div></div>
    </div>`).join('');
}

function addMapAlert(ev){
  const feed=document.getElementById('mfeed');
  if(feed.querySelector('.empty')) feed.innerHTML='';
  const isB=ev.action==='BLOCKED';
  const d=document.createElement('div');
  d.className='malert';
  d.innerHTML=`
    <div class="matop">
      <div class="matype">${ev.attack_type}</div>
      <div class="mab ${isB?'blocked':'monitored'}">${ev.action}</div>
    </div>
    <div class="mameta">
      <span>${ev.src_ip}</span>${ev.city&&ev.city!=='Unknown'?' · '+ev.city:''}<br>
      ${ev.country&&ev.country!=='Unknown'?getFlag(ev.country_code)+' '+ev.country+' · ':''} ${ev.confidence}%
    </div>`;
  feed.insertBefore(d,feed.firstChild);
  while(feed.children.length>50) feed.removeChild(feed.lastChild);
}

// ══════════════════════════════════════
// SOCKET.IO — real-time events
// ══════════════════════════════════════
const socket=io();

// Every packet captured → Packet Log tab updates instantly
socket.on('new_packet', p => onNewPacket(p));

// Every second stats update → Dashboard tab
socket.on('stats_update', d => updateDash(d));

// When a threat is detected → both Dashboard and Map
socket.on('new_alert',  a  => addAlert(a));
socket.on('new_attack', ev => {
  addMapAlert(ev);
  if(ev.lat&&ev.lat!==0) drawLine(ev.lat,ev.lon);
});

// Map markers update
socket.on('map_update', d => {
  updateMapStats(d);
  updateClist(d.top_countries);
  d.markers.forEach(addOrUpdateMarker);
});

// ── INITIAL LOAD ──
fetch('/api/stats').then(r=>r.json()).then(d=>{
  updateDash(d);
  if(d.alerts) d.alerts.forEach(addAlert);
});
fetch('/api/packets').then(r=>r.json()).then(d=>{
  d.packets.forEach(p=>{allPackets.push(p);if(p.suspicion)suspiciousCount++;});
  document.getElementById('ps-total').textContent=allPackets.length;
  document.getElementById('ps-sus').textContent=suspiciousCount;
  renderPackets();
});
fetch('/api/map').then(r=>r.json()).then(d=>{
  updateMapStats(d);
  updateClist(d.top_countries);
  d.markers.forEach(addOrUpdateMarker);
  d.recent_events.forEach(addMapAlert);
});

// marker pulse
document.head.insertAdjacentHTML('beforeend','<style>@keyframes mP{0%,100%{box-shadow:0 0 0 0 rgba(255,63,94,.4);}50%{box-shadow:0 0 0 7px rgba(255,63,94,0);}}</style>');
</script>
</body>
</html>"""

# ─────────────────────────────────────────────
# START
# ─────────────────────────────────────────────
if __name__=='__main__':
    print('='*58)
    print(' 🛡️  NIDS — East Africa Network Defense')
    print(f'    Interface  : {INTERFACE}')
    print(f'    ML Model   : {"✅ Loaded" if ML_READY else "⚠️  Heuristic mode"}')
    print(f'    GeoIP      : {"✅ Loaded" if GEOIP_READER else "⚠️  Run: python nids_geoip.py --setup"}')
    print(f'    Dashboard  : http://localhost:5000')
    print(f'    Tabs       : Dashboard | Packet Log | Attack Map')
    print('='*58)

    if os.geteuid()!=0:
        print('\n[!] Not running as root — run with:')
        print(f'    sudo venv/bin/python nids_dashboard.py {INTERFACE}\n')

    threading.Thread(target=analyse_thread, daemon=True).start()
    threading.Thread(target=ticker_thread,  daemon=True).start()
    threading.Thread(target=capture_thread, daemon=True).start()

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
