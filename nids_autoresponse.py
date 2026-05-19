"""
=============================================================
 NIDS - Phase 3: Auto-Response Engine
 Automatically blocks malicious IPs using iptables
 Features:
   - IP blocking / unblocking via iptables
   - Rate limiting (block only after N attacks)
   - Whitelist (never block trusted IPs)
   - Auto-unblock after timeout
   - Full audit trail
   - Integration with Phase 2 capture engine
=============================================================
 Run with sudo: sudo python nids_autoresponse.py
=============================================================
"""

import os
import time
import subprocess
import threading
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict


# 
# 1. LOGGING SETUP
# 

os.makedirs('logs', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('logs/autoresponse.log'),
        logging.StreamHandler()
    ]
)
log = logging.getLogger('NIDS-AutoResponse')


# 
# 2. WHITELIST — IPs that should NEVER be blocked
# 

WHITELIST = {
    '127.0.0.1',        # localhost
    '::1',              # IPv6 localhost
    '192.168.1.1',      # common gateway
    '192.168.0.1',      # common gateway
    '10.0.0.1',         # common gateway
    # Add your university/supervisor IPs here:
    # '196.13.x.x',     # UDSM / ARU network range
}


# 
# 3. BLOCKED IP STORE
# Tracks all currently blocked IPs + history
# 

class BlockedIPStore:
    """
    Persistent store for blocked IPs.
    Saves to JSON so blocks survive restarts.
    """

    def __init__(self, store_file='logs/blocked_ips.json'):
        self.store_file = store_file
        self.blocked    = {}   # ip -> {blocked_at, unblock_at, reason, attack_type}
        self.history    = []   # full audit log
        self.lock       = threading.Lock()
        self._load()

    def _load(self):
        if os.path.exists(self.store_file):
            try:
                with open(self.store_file, 'r') as f:
                    data = json.load(f)
                    self.blocked = data.get('blocked', {})
                    self.history = data.get('history', [])
                log.info(f"Loaded {len(self.blocked)} previously blocked IPs")
            except Exception:
                pass

    def _save(self):
        with open(self.store_file, 'w') as f:
            json.dump({
                'blocked': self.blocked,
                'history': self.history[-500:]  # keep last 500 events
            }, f, indent=2)

    def add(self, ip, attack_type, confidence, duration_minutes=60):
        with self.lock:
            now = datetime.now()
            unblock_at = now + timedelta(minutes=duration_minutes)

            self.blocked[ip] = {
                'blocked_at'       : now.isoformat(),
                'unblock_at'       : unblock_at.isoformat(),
                'attack_type'      : attack_type,
                'confidence'       : confidence,
                'duration_minutes' : duration_minutes
            }

            self.history.append({
                'event'      : 'BLOCKED',
                'ip'         : ip,
                'attack_type': attack_type,
                'confidence' : confidence,
                'timestamp'  : now.isoformat()
            })

            self._save()

    def remove(self, ip):
        with self.lock:
            if ip in self.blocked:
                del self.blocked[ip]
                self.history.append({
                    'event'    : 'UNBLOCKED',
                    'ip'       : ip,
                    'timestamp': datetime.now().isoformat()
                })
                self._save()

    def is_blocked(self, ip):
        with self.lock:
            return ip in self.blocked

    def get_expired(self):
        """Return IPs whose block duration has passed."""
        now = datetime.now()
        expired = []
        with self.lock:
            for ip, info in list(self.blocked.items()):
                unblock_at = datetime.fromisoformat(info['unblock_at'])
                if now >= unblock_at:
                    expired.append(ip)
        return expired

    def summary(self):
        with self.lock:
            return dict(self.blocked)


# 
# 4. IPTABLES MANAGER
# Executes actual firewall commands
# 

class IPTablesManager:
    """
    Manages iptables rules to block/unblock IPs.
    Creates a dedicated NIDS chain for clean management.
    """

    CHAIN_NAME = 'NIDS_BLOCK'

    def __init__(self):
        self._setup_chain()

    def _run(self, cmd: str) -> tuple:
        """Run a shell command safely."""
        try:
            result = subprocess.run(
                cmd, shell=True,
                capture_output=True, text=True
            )
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return 1, '', str(e)

    def _setup_chain(self):
        """Create NIDS_BLOCK chain and link it to INPUT."""
        # Create the chain (ignore error if already exists)
        self._run(f'iptables -N {self.CHAIN_NAME} 2>/dev/null')

        # Link chain to INPUT if not already linked
        code, out, _ = self._run(
            f'iptables -C INPUT -j {self.CHAIN_NAME} 2>/dev/null'
        )
        if code != 0:
            self._run(f'iptables -I INPUT -j {self.CHAIN_NAME}')

        log.info(f"[iptables] Chain {self.CHAIN_NAME} ready")

    def block_ip(self, ip: str) -> bool:
        """Add DROP rule for this IP."""
        code, _, err = self._run(
            f'iptables -A {self.CHAIN_NAME} -s {ip} -j DROP'
        )
        if code == 0:
            log.info(f"[iptables]  BLOCKED {ip}")
            return True
        else:
            log.error(f"[iptables]  Failed to block {ip}: {err}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove DROP rule for this IP."""
        code, _, err = self._run(
            f'iptables -D {self.CHAIN_NAME} -s {ip} -j DROP'
        )
        if code == 0:
            log.info(f"[iptables]  UNBLOCKED {ip}")
            return True
        else:
            log.error(f"[iptables]  Failed to unblock {ip}: {err}")
            return False

    def list_blocked(self) -> list:
        """List all currently blocked IPs in the chain."""
        _, out, _ = self._run(
            f'iptables -L {self.CHAIN_NAME} -n --line-numbers'
        )
        return out

    def flush_all(self):
        """Remove ALL rules in NIDS chain (emergency clear)."""
        self._run(f'iptables -F {self.CHAIN_NAME}')
        log.warning("[iptables]   All NIDS block rules flushed!")

    def rate_limit_ip(self, ip: str, max_conn: int = 10) -> bool:
        """
        Rate limit an IP instead of fully blocking.
        Useful for suspicious but not confirmed attackers.
        """
        code, _, err = self._run(
            f'iptables -A {self.CHAIN_NAME} -s {ip} '
            f'-m limit --limit {max_conn}/minute --limit-burst {max_conn} '
            f'-j ACCEPT'
        )
        self._run(f'iptables -A {self.CHAIN_NAME} -s {ip} -j DROP')
        return code == 0


# 
# 5. ATTACK TRACKER
# Counts attacks per IP before blocking
# Prevents false positive blocks
# 

class AttackTracker:
    """
    Tracks attack count per IP.
    Only triggers block after threshold is reached.
    """

    def __init__(self, block_threshold=3, window_seconds=60):
        self.counts    = defaultdict(list)   # ip -> [timestamps]
        self.threshold = block_threshold      # attacks before block
        self.window    = window_seconds       # time window
        self.lock      = threading.Lock()

    def record(self, ip: str, attack_type: str) -> int:
        """Record an attack event. Returns current count in window."""
        now = time.time()
        with self.lock:
            # Remove old events outside window
            self.counts[ip] = [
                t for t in self.counts[ip]
                if now - t < self.window
            ]
            self.counts[ip].append(now)
            return len(self.counts[ip])

    def should_block(self, ip: str) -> bool:
        with self.lock:
            return len(self.counts[ip]) >= self.threshold

    def reset(self, ip: str):
        with self.lock:
            self.counts[ip] = []


# 
# 6. AUTO-RESPONSE ENGINE
# Main coordinator — receives alerts, decides action
# 

class AutoResponseEngine:
    """
    The brain of Phase 3.
    Receives attack alerts from Phase 2 and decides:
      - Block immediately (high confidence attacks)
      - Rate limit (medium confidence)
      - Monitor only (low confidence)
      - Never block (whitelisted IPs)
    """

    def __init__(self,
                 block_threshold=3,
                 block_duration_minutes=60,
                 high_confidence_threshold=90.0,
                 medium_confidence_threshold=70.0):

        self.iptables   = IPTablesManager()
        self.store      = BlockedIPStore()
        self.tracker    = AttackTracker(block_threshold=block_threshold)

        self.block_duration    = block_duration_minutes
        self.high_threshold    = high_confidence_threshold
        self.medium_threshold  = medium_confidence_threshold

        self.stats = {
            'total_alerts'    : 0,
            'ips_blocked'     : 0,
            'ips_rate_limited': 0,
            'ips_whitelisted' : 0,
            'auto_unblocked'  : 0,
        }

        # Start auto-unblock background thread
        unblock_thread = threading.Thread(
            target=self._auto_unblock_loop,
            daemon=True
        )
        unblock_thread.start()

        log.info(" AutoResponse Engine started")
        log.info(f"   Block threshold   : {block_threshold} attacks")
        log.info(f"   Block duration    : {block_duration_minutes} minutes")
        log.info(f"   High confidence   : >{high_confidence_threshold}% → instant block")
        log.info(f"   Medium confidence : >{medium_confidence_threshold}% → rate limit\n")

    def handle_alert(self, src_ip: str, attack_type: str, confidence: float):
        """
        Called by Phase 2 capture engine when an attack is detected.

        Args:
            src_ip      : Source IP of the attack
            attack_type : e.g. 'DDoS', 'PortScan', 'BruteForce'
            confidence  : ML model confidence (0-100)
        """
        self.stats['total_alerts'] += 1

        print(f"\n{'='*55}")
        print(f"  ALERT RECEIVED")
        print(f"    IP          : {src_ip}")
        print(f"    Attack Type : {attack_type}")
        print(f"    Confidence  : {confidence:.1f}%")
        print(f"{'='*55}")

        #  Check whitelist 
        if src_ip in WHITELIST:
            self.stats['ips_whitelisted'] += 1
            log.warning(f"[WHITELIST] {src_ip} is whitelisted — no action taken")
            return

        #  Already blocked 
        if self.store.is_blocked(src_ip):
            log.info(f"[SKIP] {src_ip} is already blocked")
            return

        #  Record attack & get count 
        count = self.tracker.record(src_ip, attack_type)
        log.info(f"[TRACKER] {src_ip} attack count: {count}/{self.tracker.threshold}")

        #  Decision Logic 
        if confidence >= self.high_threshold:
            # High confidence → block immediately, no threshold needed
            self._block(src_ip, attack_type, confidence, reason="HIGH_CONFIDENCE")

        elif confidence >= self.medium_threshold:
            if self.tracker.should_block(src_ip):
                # Repeated attacks → block
                self._block(src_ip, attack_type, confidence, reason="REPEATED_ATTACK")
            else:
                # First offense → rate limit
                self._rate_limit(src_ip, attack_type, confidence)

        else:
            # Low confidence → just log, monitor
            log.info(f"[MONITOR] {src_ip} — confidence too low to act ({confidence:.1f}%)")

    def _block(self, ip: str, attack_type: str, confidence: float, reason: str):
        """Block an IP completely."""
        success = self.iptables.block_ip(ip)
        if success:
            self.store.add(ip, attack_type, confidence, self.block_duration)
            self.stats['ips_blocked'] += 1
            self.tracker.reset(ip)

            print(f"\n   ACTION: BLOCKED")
            print(f"     Reason   : {reason}")
            print(f"     Duration : {self.block_duration} minutes")
            print(f"     Total blocked IPs: {self.stats['ips_blocked']}\n")

            log.warning(
                f"[BLOCKED] {ip} | {attack_type} | "
                f"{confidence:.1f}% | Reason: {reason}"
            )

    def _rate_limit(self, ip: str, attack_type: str, confidence: float):
        """Rate limit a suspicious IP."""
        success = self.iptables.rate_limit_ip(ip, max_conn=10)
        if success:
            self.stats['ips_rate_limited'] += 1
            print(f"\n   ACTION: RATE LIMITED")
            print(f"     Max 10 connections/minute allowed\n")
            log.warning(f"[RATE LIMITED] {ip} | {attack_type} | {confidence:.1f}%")

    def _auto_unblock_loop(self):
        """Background thread: automatically unblock IPs after their timeout."""
        while True:
            time.sleep(60)  # Check every minute
            expired = self.store.get_expired()
            for ip in expired:
                self.iptables.unblock_ip(ip)
                self.store.remove(ip)
                self.stats['auto_unblocked'] += 1
                log.info(f"[AUTO-UNBLOCK] {ip} block duration expired")

    def manual_block(self, ip: str, reason: str = "MANUAL"):
        """Manually block an IP (for admin use)."""
        if ip in WHITELIST:
            print(f" Cannot block whitelisted IP: {ip}")
            return
        self._block(ip, "MANUAL", 100.0, reason)

    def manual_unblock(self, ip: str):
        """Manually unblock an IP."""
        self.iptables.unblock_ip(ip)
        self.store.remove(ip)
        log.info(f"[MANUAL-UNBLOCK] {ip}")
        print(f" {ip} has been unblocked")

    def status(self):
        """Print current system status."""
        blocked = self.store.summary()
        rules   = self.iptables.list_blocked()

        print(f"\n{'='*55}")
        print(f"   NIDS AUTO-RESPONSE STATUS")
        print(f"{'='*55}")
        print(f" Total Alerts      : {self.stats['total_alerts']}")
        print(f" IPs Blocked       : {self.stats['ips_blocked']}")
        print(f" IPs Rate Limited  : {self.stats['ips_rate_limited']}")
        print(f" Auto Unblocked    : {self.stats['auto_unblocked']}")
        print(f" Currently Blocked : {len(blocked)}")
        print(f"\n Currently Blocked IPs:")
        if blocked:
            for ip, info in blocked.items():
                print(f"    {ip:<18} | {info['attack_type']:<15} | "
                      f"Unblocks: {info['unblock_at'][:16]}")
        else:
            print("    No IPs currently blocked")
        print(f"\n iptables Rules:")
        print(rules)
        print(f"{'='*55}\n")


# 
# 7. INTEGRATION WITH PHASE 2
# Shows how to connect capture engine to auto-response
# 

def run_full_nids():
    """
    Run the complete NIDS system:
    Phase 2 (Capture) + Phase 3 (Auto-Response) together.
    """
    import sys
    sys.path.insert(0, '.')
    from nids_capture import NIDSCaptureEngine

    # Initialize auto-response
    responder = AutoResponseEngine(
        block_threshold=3,           # block after 3 confirmed attacks
        block_duration_minutes=60,   # unblock after 1 hour
        high_confidence_threshold=90,
        medium_confidence_threshold=70
    )

    # Initialize capture engine
    interface = sys.argv[1] if len(sys.argv) > 1 else 'eth0'
    engine = NIDSCaptureEngine(
        interface=interface,
        flow_timeout=30,
        confidence_threshold=70
    )

    #  CONNECT Phase 2 → Phase 3
    # Monkey-patch the alert logger to also trigger auto-response
    original_alert = engine.logger.alert

    def enhanced_alert(flow_key, label, confidence, flow):
        original_alert(flow_key, label, confidence, flow)
        src_ip = flow_key[0]
        responder.handle_alert(src_ip, label, confidence)

    engine.logger.alert = enhanced_alert

    # Start the full system
    responder.status()
    engine.start()


# 
# 8. ENTRY POINT
# 

if __name__ == "__main__":
    import sys

    if '--status' in sys.argv:
        # Just show status of blocked IPs
        engine = AutoResponseEngine()
        engine.status()

    elif '--unblock' in sys.argv:
        # Manually unblock an IP
        idx = sys.argv.index('--unblock')
        ip  = sys.argv[idx + 1]
        engine = AutoResponseEngine()
        engine.manual_unblock(ip)

    elif '--block' in sys.argv:
        # Manually block an IP
        idx = sys.argv.index('--block')
        ip  = sys.argv[idx + 1]
        engine = AutoResponseEngine()
        engine.manual_block(ip)

    elif '--flush' in sys.argv:
        # Emergency: remove all blocks
        mgr = IPTablesManager()
        mgr.flush_all()
        print("  All NIDS block rules removed from iptables")

    else:
        # Run full NIDS (Phase 2 + Phase 3)
        run_full_nids()
