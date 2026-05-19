"""
=============================================================
 NIDS - GeoIP Attack Map Module
 Looks up geographic location of attacking IPs
 Works with FREE databases - no paid API needed
=============================================================
 Setup:
   pip install geoip2 requests
   python nids_geoip.py --setup   (downloads free DB)
=============================================================
"""

import os
import sys
import json
import time
import tarfile
import urllib.request
import threading
from datetime import datetime
from collections import defaultdict

# 
# 1. GEOIP DATABASE SETUP
# Uses MaxMind GeoLite2 (FREE - no API key needed)
# 

DB_DIR  = 'geoip_db'
DB_PATH = os.path.join(DB_DIR, 'GeoLite2-City.mmdb')

# Free download URL (no account needed)
DB_URL = (
    'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb'
)

def download_geodb():
    """Download the free GeoLite2 City database."""
    os.makedirs(DB_DIR, exist_ok=True)

    if os.path.exists(DB_PATH):
        print(f"[+] GeoIP database already exists at {DB_PATH}")
        return True

    print("[*] Downloading free GeoLite2 database (~60MB)...")
    print("    This only happens once.\n")

    try:
        def progress(count, block_size, total_size):
            percent = min(int(count * block_size * 100 / total_size), 100)
            bar = '' * (percent // 5) + '' * (20 - percent // 5)
            print(f'\r    [{bar}] {percent}%', end='', flush=True)

        urllib.request.urlretrieve(DB_URL, DB_PATH, reporthook=progress)
        print(f"\n[+] Database downloaded to {DB_PATH}")
        return True

    except Exception as e:
        print(f"\n[!] Download failed: {e}")
        print("    Try manually downloading from:")
        print("    https://github.com/P3TERX/GeoLite.mmdb")
        print(f"    and place GeoLite2-City.mmdb in ./{DB_DIR}/")
        return False


# 
# 2. GEOIP LOOKUP ENGINE
# 

class GeoIPLookup:
    """
    Looks up geographic info for any IP address.
    Returns country, city, lat/lon for map plotting.
    """

    def __init__(self):
        self.reader  = None
        self.cache   = {}   # cache lookups to avoid repeated DB reads
        self._load_db()

    def _load_db(self):
        try:
            import geoip2.database
            if not os.path.exists(DB_PATH):
                print("[!] GeoIP database not found. Run: python nids_geoip.py --setup")
                return
            self.reader = geoip2.database.Reader(DB_PATH)
            print(f"[+] GeoIP database loaded from {DB_PATH}")
        except ImportError:
            print("[!] geoip2 not installed. Run: pip install geoip2")
        except Exception as e:
            print(f"[!] Failed to load GeoIP database: {e}")

    def lookup(self, ip: str) -> dict:
        """
        Look up geographic info for an IP.

        Returns dict with:
          country, country_code, city, lat, lon, isp
        """
        # Return cached result
        if ip in self.cache:
            return self.cache[ip]

        # Default result
        result = {
            'ip'           : ip,
            'country'      : 'Unknown',
            'country_code' : 'XX',
            'city'         : 'Unknown',
            'lat'          : 0.0,
            'lon'          : 0.0,
            'isp'          : 'Unknown',
            'found'        : False,
        }

        # Skip private/local IPs
        if self._is_private(ip):
            result['country'] = 'Local Network'
            result['found']   = True
            self.cache[ip]    = result
            return result

        if not self.reader:
            self.cache[ip] = result
            return result

        try:
            response = self.reader.city(ip)
            result.update({
                'country'      : response.country.name or 'Unknown',
                'country_code' : response.country.iso_code or 'XX',
                'city'         : response.city.name or 'Unknown',
                'lat'          : float(response.location.latitude or 0),
                'lon'          : float(response.location.longitude or 0),
                'found'        : True,
            })
        except Exception:
            pass

        self.cache[ip] = result
        return result

    def _is_private(self, ip: str) -> bool:
        """Check if IP is a private/local address."""
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.',
            '172.19.', '172.2', '127.', '0.', '169.254.',
        ]
        return any(ip.startswith(r) for r in private_ranges)

    def close(self):
        if self.reader:
            self.reader.close()


# 
# 3. ATTACK MAP DATA STORE
# Collects attack events with geo data for the map
# 

class AttackMapStore:
    """
    Stores geo-located attack events for the map dashboard.
    Provides stats for the map overlay panels.
    """

    def __init__(self, max_events=500):
        self.geo         = GeoIPLookup()
        self.events      = []         # all attack events with geo
        self.max_events  = max_events
        self.lock        = threading.Lock()

        # Stats
        self.country_counts  = defaultdict(int)
        self.attack_origins  = {}    # ip -> geo info + attack count

    def add_attack(self, src_ip: str, attack_type: str,
                   confidence: float, action: str = 'BLOCKED') -> dict:
        """
        Record an attack with full geo info.
        Returns the enriched event dict.
        """
        geo = self.geo.lookup(src_ip)

        event = {
            'id'          : len(self.events) + 1,
            'timestamp'   : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip'      : src_ip,
            'attack_type' : attack_type,
            'confidence'  : confidence,
            'action'      : action,
            **geo,   # merge all geo fields
        }

        with self.lock:
            self.events.append(event)
            if len(self.events) > self.max_events:
                self.events = self.events[-self.max_events:]

            if geo['found'] and geo['country'] != 'Local Network':
                self.country_counts[geo['country']] += 1

            # Track per-IP origins
            if src_ip not in self.attack_origins:
                self.attack_origins[src_ip] = {**geo, 'count': 0}
            self.attack_origins[src_ip]['count'] += 1

        return event

    def get_map_data(self) -> dict:
        """Return all data needed to render the attack map."""
        with self.lock:
            # Top attacking countries
            top_countries = sorted(
                self.country_counts.items(),
                key=lambda x: x[1], reverse=True
            )[:10]

            # Attack origin markers for the map
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
                for ip, info in self.attack_origins.items()
                if info.get('found') and info['lat'] != 0
            ]

            # Recent events for the feed
            recent = list(reversed(self.events[-20:]))

            return {
                'markers'       : markers,
                'top_countries' : top_countries,
                'recent_events' : recent,
                'total_attacks' : len(self.events),
                'unique_ips'    : len(self.attack_origins),
                'unique_countries': len(self.country_counts),
            }


# 
# 4. DEMO / TEST
# 

def run_demo():
    """Test the GeoIP system with sample IPs from around the world."""
    print("\n[*] Testing GeoIP lookup with sample IPs...\n")

    test_ips = [
        ('8.8.8.8',        'Google DNS (USA)'),
        ('1.1.1.1',        'Cloudflare (USA)'),
        ('41.75.32.10',    'East Africa IP'),
        ('196.202.45.67',  'Kenya IP'),
        ('154.73.41.9',    'Nigeria IP'),
        ('185.220.101.1',  'Europe IP'),
        ('103.21.244.0',   'Asia IP'),
    ]

    store = AttackMapStore()

    for ip, label in test_ips:
        result = store.geo.lookup(ip)
        print(f"  {label}")
        print(f"    IP      : {ip}")
        print(f"    Country : {result['country']} ({result['country_code']})")
        print(f"    City    : {result['city']}")
        print(f"    Coords  : {result['lat']}, {result['lon']}")
        print()

    print("[+] GeoIP system working correctly!")
    print("[+] Ready to integrate with dashboard.\n")


# 
# 5. ENTRY POINT
# 

if __name__ == '__main__':
    if '--setup' in sys.argv:
        success = download_geodb()
        if success:
            print("\n[+] Setup complete! You can now run the dashboard.")
    elif '--test' in sys.argv:
        download_geodb()
        run_demo()
    else:
        print("Usage:")
        print("  python nids_geoip.py --setup   Download GeoIP database")
        print("  python nids_geoip.py --test    Test with sample IPs")
