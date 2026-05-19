"""
=============================================================
 NIDS - Phase 2: Live Packet Capture Engine
 Uses Scapy to capture network packets in real-time
 Extracts flow features compatible with CICIDS dataset
 Then feeds into ML model for prediction
=============================================================
 Run with sudo: sudo python nids_capture.py
=============================================================
"""

import time
import threading
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP


# 
# 1. FLOW TRACKER
# Tracks active network flows (like Wireshark does)
# A "flow" = packets between same src/dst IP+Port
# 

class NetworkFlow:
    """Represents a single network flow between two endpoints."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.protocol  = protocol

        self.start_time    = time.time()
        self.last_seen     = time.time()

        self.fwd_packets   = []   # packets going forward
        self.bwd_packets   = []   # packets going backward

        self.fwd_flags     = []
        self.bwd_flags     = []

    def add_packet(self, packet, direction='fwd'):
        size = len(packet)
        ts   = time.time()

        if direction == 'fwd':
            self.fwd_packets.append(size)
            if packet.haslayer(TCP):
                self.fwd_flags.append(packet[TCP].flags)
        else:
            self.bwd_packets.append(size)
            if packet.haslayer(TCP):
                self.bwd_flags.append(packet[TCP].flags)

        self.last_seen = ts

    def duration(self):
        return self.last_seen - self.start_time

    def extract_features(self) -> dict:
        """
        Extract CICIDS-compatible features from this flow.
        These match the features your ML model was trained on.
        """
        fwd = self.fwd_packets
        bwd = self.bwd_packets
        all_pkts = fwd + bwd

        def safe_stats(lst):
            if not lst:
                return 0, 0, 0, 0
            return (
                np.mean(lst),
                np.std(lst),
                np.max(lst),
                np.min(lst)
            )

        fwd_mean, fwd_std, fwd_max, fwd_min = safe_stats(fwd)
        bwd_mean, bwd_std, bwd_max, bwd_min = safe_stats(bwd)
        all_mean, all_std, all_max, all_min = safe_stats(all_pkts)

        duration = self.duration() or 1e-6  # avoid division by zero

        # Count TCP flags
        syn_count = sum(1 for f in self.fwd_flags if f and 'S' in str(f))
        ack_count = sum(1 for f in self.fwd_flags if f and 'A' in str(f))
        fin_count = sum(1 for f in self.fwd_flags if f and 'F' in str(f))
        rst_count = sum(1 for f in self.fwd_flags if f and 'R' in str(f))
        psh_count = sum(1 for f in self.fwd_flags if f and 'P' in str(f))
        urg_count = sum(1 for f in self.fwd_flags if f and 'U' in str(f))

        total_fwd = len(fwd)
        total_bwd = len(bwd)
        total_bytes = sum(all_pkts)

        features = {
            # Packet counts
            "Total Fwd Packets"              : total_fwd,
            "Total Backward Packets"         : total_bwd,
            "Total Length of Fwd Packets"    : sum(fwd),
            "Total Length of Bwd Packets"    : sum(bwd),

            # Packet size stats
            "Fwd Packet Length Max"          : fwd_max,
            "Fwd Packet Length Min"          : fwd_min,
            "Fwd Packet Length Mean"         : fwd_mean,
            "Fwd Packet Length Std"          : fwd_std,
            "Bwd Packet Length Max"          : bwd_max,
            "Bwd Packet Length Min"          : bwd_min,
            "Bwd Packet Length Mean"         : bwd_mean,
            "Bwd Packet Length Std"          : bwd_std,

            # Flow rates
            "Flow Duration"                  : duration * 1e6,  # microseconds
            "Flow Bytes/s"                   : total_bytes / duration,
            "Flow Packets/s"                 : len(all_pkts) / duration,

            # IAT (Inter-Arrival Time) — simplified
            "Flow IAT Mean"                  : duration / max(len(all_pkts), 1) * 1e6,
            "Flow IAT Std"                   : 0,
            "Flow IAT Max"                   : duration * 1e6,
            "Flow IAT Min"                   : 0,
            "Fwd IAT Total"                  : duration * 1e6,
            "Fwd IAT Mean"                   : duration / max(total_fwd, 1) * 1e6,
            "Fwd IAT Std"                    : 0,
            "Fwd IAT Max"                    : duration * 1e6,
            "Fwd IAT Min"                    : 0,
            "Bwd IAT Total"                  : duration * 1e6,
            "Bwd IAT Mean"                   : duration / max(total_bwd, 1) * 1e6,
            "Bwd IAT Std"                    : 0,
            "Bwd IAT Max"                    : duration * 1e6,
            "Bwd IAT Min"                    : 0,

            # TCP Flags
            "Fwd PSH Flags"                  : psh_count,
            "Bwd PSH Flags"                  : 0,
            "Fwd URG Flags"                  : urg_count,
            "Bwd URG Flags"                  : 0,
            "FIN Flag Count"                 : fin_count,
            "SYN Flag Count"                 : syn_count,
            "RST Flag Count"                 : rst_count,
            "PSH Flag Count"                 : psh_count,
            "ACK Flag Count"                 : ack_count,
            "URG Flag Count"                 : urg_count,
            "CWE Flag Count"                 : 0,
            "ECE Flag Count"                 : 0,

            # Ratios
            "Down/Up Ratio"                  : total_bwd / max(total_fwd, 1),
            "Average Packet Size"            : all_mean,
            "Avg Fwd Segment Size"           : fwd_mean,
            "Avg Bwd Segment Size"           : bwd_mean,

            # Header lengths
            "Fwd Header Length"              : total_fwd * 20,
            "Bwd Header Length"              : total_bwd * 20,
            "Fwd Header Length.1"            : total_fwd * 20,

            # Subflows
            "Subflow Fwd Packets"            : total_fwd,
            "Subflow Fwd Bytes"              : sum(fwd),
            "Subflow Bwd Packets"            : total_bwd,
            "Subflow Bwd Bytes"              : sum(bwd),

            # Window / Active / Idle
            "Init_Win_bytes_forward"         : 65535,
            "Init_Win_bytes_backward"        : 65535,
            "act_data_pkt_fwd"               : total_fwd,
            "min_seg_size_forward"           : fwd_min,
            "Active Mean"                    : 0,
            "Active Std"                     : 0,
            "Active Max"                     : 0,
            "Active Min"                     : 0,
            "Idle Mean"                      : 0,
            "Idle Std"                       : 0,
            "Idle Max"                       : 0,
            "Idle Min"                       : 0,

            # Bulk rates
            "Fwd Avg Bytes/Bulk"             : 0,
            "Fwd Avg Packets/Bulk"           : 0,
            "Fwd Avg Bulk Rate"              : 0,
            "Bwd Avg Bytes/Bulk"             : 0,
            "Bwd Avg Packets/Bulk"           : 0,
            "Bwd Avg Bulk Rate"              : 0,
        }

        return features


# 
# 2. FLOW MANAGER
# Manages all active flows, times out old ones
# 

class FlowManager:
    def __init__(self, timeout=60):
        self.flows   = {}
        self.timeout = timeout  # seconds before flow is considered done
        self.lock    = threading.Lock()

    def get_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Normalize: always put smaller IP first for consistency
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def get_direction(self, key, src_ip, src_port):
        return 'fwd' if (key[0] == src_ip and key[2] == src_port) else 'bwd'

    def add_packet(self, packet):
        if not packet.haslayer(IP):
            return None  # skip non-IP packets

        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        protocol = packet[IP].proto

        src_port = dst_port = 0
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        key = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        direction = self.get_direction(key, src_ip, src_port)

        with self.lock:
            if key not in self.flows:
                self.flows[key] = NetworkFlow(
                    src_ip, dst_ip, src_port, dst_port, protocol
                )
            self.flows[key].add_packet(packet, direction)

        return key

    def get_expired_flows(self):
        """Return flows that haven't seen a packet in `timeout` seconds."""
        now = time.time()
        expired = []
        with self.lock:
            for key, flow in list(self.flows.items()):
                if now - flow.last_seen > self.timeout:
                    expired.append((key, flow))
                    del self.flows[key]
        return expired

    def get_all_flows(self):
        with self.lock:
            return list(self.flows.items())


# 
# 3. ML PREDICTOR
# Loads saved model and predicts on flow features
# 

class Predictor:
    def __init__(self,
                 model_path='models/xgboost.pkl',
                 scaler_path='models/scaler.pkl',
                 encoder_path='models/label_encoder.pkl'):
        print("[*] Loading ML model...")
        self.model   = joblib.load(model_path)
        self.scaler  = joblib.load(scaler_path)
        self.encoder = joblib.load(encoder_path)
        print("[+] ML model loaded!\n")

    def predict(self, features: dict):
        """
        Predict attack type from flow features.

        Returns:
            label (str): 'BENIGN' or attack name
            confidence (float): % confidence
        """
        import pandas as pd
        df = pd.DataFrame([features])

        # Align columns with training data
        model_features = self.model.get_booster().feature_names
        for col in model_features:
            if col not in df.columns:
                df[col] = 0
        df = df[model_features]

        X   = self.scaler.transform(df)
        pred = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0]

        label      = self.encoder.inverse_transform([pred])[0]
        confidence = proba[pred] * 100

        return label, confidence


# 
# 4. ALERT LOGGER
# Logs detected attacks to console + file
# 

class AlertLogger:
    def __init__(self, log_file='logs/alerts.log'):
        import os
        os.makedirs('logs', exist_ok=True)
        self.log_file = log_file

    def alert(self, flow_key, label, confidence, flow: NetworkFlow):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip, dst_ip, src_port, dst_port, proto = flow_key

        msg = (
            f"[{timestamp}]  ATTACK DETECTED\n"
            f"  Type       : {label}\n"
            f"  Confidence : {confidence:.1f}%\n"
            f"  Source     : {src_ip}:{src_port}\n"
            f"  Destination: {dst_ip}:{dst_port}\n"
            f"  Protocol   : {proto}\n"
            f"  Duration   : {flow.duration():.2f}s\n"
            f"  Fwd Pkts   : {len(flow.fwd_packets)}\n"
            f"  Bwd Pkts   : {len(flow.bwd_packets)}\n"
            f"{'-'*50}"
        )

        print(msg)
        with open(self.log_file, 'a') as f:
            f.write(msg + '\n')

    def benign(self, flow_key, confidence):
        src_ip, dst_ip, src_port, dst_port, proto = flow_key
        print(f"[] BENIGN  {src_ip}:{src_port} → {dst_ip}:{dst_port}  ({confidence:.1f}%)")


# 
# 5. MAIN CAPTURE ENGINE
# Ties everything together
# 

class NIDSCaptureEngine:
    def __init__(self, interface='eth0', flow_timeout=30, confidence_threshold=70.0):
        self.interface   = interface
        self.flow_mgr    = FlowManager(timeout=flow_timeout)
        self.predictor   = Predictor()
        self.logger      = AlertLogger()
        self.threshold   = confidence_threshold
        self.packet_count = 0
        self.attack_count = 0

        print(f"[*] NIDS Capture Engine initialized")
        print(f"[*] Interface : {interface}")
        print(f"[*] Threshold : {confidence_threshold}% confidence\n")

    def process_packet(self, packet):
        """Called for every captured packet."""
        self.packet_count += 1
        key = self.flow_mgr.add_packet(packet)

        # Print progress every 100 packets
        if self.packet_count % 100 == 0:
            active = len(self.flow_mgr.flows)
            print(f"[~] Packets: {self.packet_count} | "
                  f"Active Flows: {active} | "
                  f"Attacks Found: {self.attack_count}")

    def analyze_expired_flows(self):
        """Periodically analyze completed flows with ML model."""
        while True:
            time.sleep(5)  # Check every 5 seconds
            expired = self.flow_mgr.get_expired_flows()

            for key, flow in expired:
                if len(flow.fwd_packets) < 2:
                    continue  # Skip flows with too few packets

                features = flow.extract_features()
                label, confidence = self.predictor.predict(features)

                if label != 'BENIGN' and confidence >= self.threshold:
                    self.attack_count += 1
                    self.logger.alert(key, label, confidence, flow)

                    #  Phase 3: Auto-response will be triggered here
                    # auto_responder.block_ip(key[0])  # Block source IP

                else:
                    self.logger.benign(key, confidence)

    def start(self):
        """Start capturing packets."""
        print(f"{'='*50}")
        print(f"   NIDS STARTED — Monitoring {self.interface}")
        print(f" Press Ctrl+C to stop")
        print(f"{'='*50}\n")

        # Start flow analysis in background thread
        analyzer = threading.Thread(
            target=self.analyze_expired_flows,
            daemon=True
        )
        analyzer.start()

        # Start packet capture (blocking)
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,      # don't store in memory
                filter="ip"       # only capture IP packets
            )
        except KeyboardInterrupt:
            print(f"\n[!] Capture stopped.")
            print(f"[+] Total packets  : {self.packet_count}")
            print(f"[+] Attacks found  : {self.attack_count}")


# 
# 6. ENTRY POINT
# 

if __name__ == "__main__":
    import sys

    # Get network interface from argument or default
    # To find your interface: run `ip a` in terminal
    interface = sys.argv[1] if len(sys.argv) > 1 else 'eth0'

    engine = NIDSCaptureEngine(
        interface=interface,
        flow_timeout=30,        # seconds before flow is analyzed
        confidence_threshold=70 # only alert if model is >70% confident
    )

    engine.start()
