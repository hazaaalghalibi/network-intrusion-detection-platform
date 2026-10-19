#!/usr/bin/env python3
"""
Generates synthetic Zeek (conn.log, dns.log, ssh.log) and Suricata (eve.json)
logs for the NIDR platform demo, in their real on-disk formats.

Everything is synthetic. "Malicious" IPs/domains come from
data/threat_intel/*.csv, which only use RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and the .test TLD (RFC 2606).
No real hosts are contacted or scanned — this only writes flat files.

Narrative (see docs/example_incident_report.md for the write-up):
  1. External recon host (198.51.100.23) port-scans the internet-facing
     bastion srv-jump-01 (10.0.0.10).
  2. Same host brute-forces SSH on srv-jump-01, eventually succeeds.
  3. From the compromised bastion, the attacker port-scans the internal LAN
     (lateral movement recon).
  4. srv-jump-01 starts beaconing to a known-bad C2 IP (203.0.113.66).
  5. srv-db-01 (10.0.0.12) is touched by the bastion, then sends a large
     burst of outbound traffic to the C2 IP (exfiltration).
  6. Unrelated: ws-eng-02 (10.0.0.24) is separately infected and performs
     DNS-tunneling-style queries against badc2exfil.test.
All of the above is interleaved with a full day of benign background traffic.

Usage: python3 scripts/generate_logs.py
Output: data/sample_logs/{conn.log,dns.log,ssh.log,eve.json}
"""
import csv
import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = DATA / "sample_logs"

random.seed(1337)  # deterministic output

DAY_START = datetime(2026, 6, 30, 0, 0, 0, tzinfo=timezone.utc)
INCIDENT_START = datetime(2026, 6, 30, 14, 0, 0, tzinfo=timezone.utc)

BENIGN_EXTERNAL_IPS = [
    f"203.0.113.{n}" for n in (10, 11, 12, 20, 21, 30, 31, 40, 41, 50)
] + [f"192.0.2.{n}" for n in (10, 11, 12, 20, 21)]

BENIGN_DOMAINS = [
    "example.com", "www.example.com", "mail.example.com",
    "example.org", "api.example.net", "cdn.example.org",
]

COMMON_PORTS = [80, 443, 443, 443, 22, 53]
SCAN_PORTS = [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993,
              995, 1433, 1521, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
              8080, 8443, 9200, 27017]

UID_ALPHABET = string.ascii_letters + string.digits


def load_assets():
    with open(DATA / "assets.json") as f:
        return json.load(f)


def load_threat_ips():
    ips = []
    with open(DATA / "threat_intel" / "malicious_ips.csv") as f:
        for row in csv.DictReader(_skip_comments(f)):
            ips.append(row["ip"])
    return ips


def load_threat_domains():
    domains = []
    with open(DATA / "threat_intel" / "malicious_domains.csv") as f:
        for row in csv.DictReader(_skip_comments(f)):
            domains.append(row["domain"])
    return domains


def _skip_comments(f):
    for line in f:
        if not line.startswith("#"):
            yield line


def zeek_uid():
    return "C" + "".join(random.choices(UID_ALPHABET, k=17))


def zeek_ts(dt):
    return f"{dt.timestamp():.6f}"


def fmt_zeek_time(dt):
    return dt.strftime("%Y-%m-%d-%H-%M-%S")


class ZeekWriter:
    """Writes a Zeek TSV log with the standard #fields/#types header."""

    def __init__(self, path, log_path_name, fields, types, open_ts):
        self.f = open(path, "w", newline="")
        self.fields = fields
        self.f.write("#separator \\x09\n")
        self.f.write("#set_separator\t,\n")
        self.f.write("#empty_field\t(empty)\n")
        self.f.write("#unset_field\t-\n")
        self.f.write(f"#path\t{log_path_name}\n")
        self.f.write(f"#open\t{fmt_zeek_time(open_ts)}\n")
        self.f.write("#fields\t" + "\t".join(fields) + "\n")
        self.f.write("#types\t" + "\t".join(types) + "\n")

    def write_row(self, row: dict):
        self.f.write("\t".join(str(row.get(k, "-")) for k in self.fields) + "\n")

    def close(self, close_ts):
        self.f.write(f"#close\t{fmt_zeek_time(close_ts)}\n")
        self.f.close()


CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
               "proto", "service", "duration", "orig_bytes", "resp_bytes",
               "conn_state", "local_orig", "local_resp", "missed_bytes",
               "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
CONN_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string",
              "interval", "count", "count", "string", "bool", "bool", "count",
              "string", "count", "count", "count", "count"]

DNS_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "proto", "trans_id", "query", "qclass_name", "qtype_name",
              "rcode_name", "AA", "RA", "answers", "TTLs", "rejected"]
DNS_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "count",
             "string", "string", "string", "string", "bool", "bool",
             "vector[string]", "vector[interval]", "bool"]

SSH_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "version", "auth_success", "auth_attempts", "client", "server"]
SSH_TYPES = ["time", "string", "addr", "port", "addr", "port", "count", "bool",
             "count", "string", "string"]


def conn_row(ts, src, sport, dst, dport, proto, service, duration, obytes,
             rbytes, state, history="ShADadfF"):
    opkts = max(1, obytes // 500)
    rpkts = max(1, rbytes // 500)
    return {
        "ts": zeek_ts(ts), "uid": zeek_uid(), "id.orig_h": src, "id.orig_p": sport,
        "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "service": service,
        "duration": f"{duration:.6f}", "orig_bytes": obytes, "resp_bytes": rbytes,
        "conn_state": state, "local_orig": "-", "local_resp": "-", "missed_bytes": 0,
        "history": history, "orig_pkts": opkts, "orig_ip_bytes": obytes + opkts * 40,
        "resp_pkts": rpkts, "resp_ip_bytes": rbytes + rpkts * 40,
    }


def random_subdomain(n=26):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    assets = load_assets()
    internal_ips = [a["ip"] for a in assets]
    threat_ips = load_threat_ips()
    threat_domains = load_threat_domains()

    scan_actor = "198.51.100.23"          # external recon / brute-force source
    c2_ip = "203.0.113.66"                # beacon + exfil destination
    exfil_drop_ip = "198.51.100.77"       # referenced only in the dropped file, not traffic
    tunnel_domain = "badc2exfil.test"
    bastion = "10.0.0.10"                 # srv-jump-01
    db_host = "10.0.0.12"                 # srv-db-01
    dns_victim = "10.0.0.24"              # ws-eng-02
    internal_dns = "10.0.0.29"            # srv-dns-01

    conn_rows, dns_rows, ssh_rows = [], [], []

    # ---- Background benign traffic across the full day ----
    for _ in range(2200):
        t = DAY_START + timedelta(seconds=random.uniform(0, 86400))
        src = random.choice(internal_ips)
        if random.random() < 0.6:
            dst = random.choice(internal_ips)
            while dst == src:
                dst = random.choice(internal_ips)
        else:
            dst = random.choice(BENIGN_EXTERNAL_IPS)
        dport = random.choice(COMMON_PORTS)
        proto = "tcp" if dport != 53 else "udp"
        service = {80: "http", 443: "ssl", 22: "ssh", 53: "dns"}.get(dport, "-")
        obytes, rbytes = random.randint(200, 8000), random.randint(200, 40000)
        conn_rows.append(conn_row(t, src, random.randint(49152, 65535), dst,
                                   dport, proto, service, random.uniform(0.01, 4.5),
                                   obytes, rbytes, "SF"))

    for _ in range(600):
        t = DAY_START + timedelta(seconds=random.uniform(0, 86400))
        src = random.choice(internal_ips)
        domain = random.choice(BENIGN_DOMAINS)
        dns_rows.append({
            "ts": zeek_ts(t), "uid": zeek_uid(), "id.orig_h": src,
            "id.orig_p": random.randint(49152, 65535), "id.resp_h": internal_dns,
            "id.resp_p": 53, "proto": "udp", "trans_id": random.randint(1, 65535),
            "query": domain, "qclass_name": "C_INTERNET", "qtype_name": "A",
            "rcode_name": "NOERROR", "AA": "F", "RA": "T",
            "answers": f"203.0.113.{random.randint(100,199)}", "TTLs": "300.000000",
            "rejected": "F",
        })

    for _ in range(40):
        t = DAY_START + timedelta(seconds=random.uniform(0, 86400))
        src = "10.0.0.28"  # ws-it-01, legitimate admin
        dst = random.choice([a["ip"] for a in assets if a["asset_type"] == "server"])
        ssh_rows.append({
            "ts": zeek_ts(t), "uid": zeek_uid(), "id.orig_h": src,
            "id.orig_p": random.randint(49152, 65535), "id.resp_h": dst,
            "id.resp_p": 22, "version": 2, "auth_success": "T", "auth_attempts": 1,
            "client": "SSH-2.0-OpenSSH_9.6", "server": "SSH-2.0-OpenSSH_9.6",
        })

    # ---- Scenario 1: external recon port scan against the bastion ----
    scan1_start = INCIDENT_START
    for i, port in enumerate(SCAN_PORTS):
        t = scan1_start + timedelta(seconds=i * random.uniform(0.4, 1.2))
        conn_rows.append(conn_row(t, scan_actor, random.randint(49152, 65535),
                                   bastion, port, "tcp", "-", 0.002, 60, 0, "S0",
                                   history="S"))

    # ---- Scenario 2: SSH brute force against the bastion, then success ----
    bf_start = scan1_start + timedelta(minutes=3)
    for i in range(24):
        t = bf_start + timedelta(seconds=i * random.uniform(3, 9))
        ssh_rows.append({
            "ts": zeek_ts(t), "uid": zeek_uid(), "id.orig_h": scan_actor,
            "id.orig_p": random.randint(49152, 65535), "id.resp_h": bastion,
            "id.resp_p": 22, "version": 2, "auth_success": "F", "auth_attempts": 1,
            "client": "SSH-2.0-libssh2_1.11", "server": "SSH-2.0-OpenSSH_9.6",
        })
        conn_rows.append(conn_row(t, scan_actor, random.randint(49152, 65535),
                                   bastion, 22, "tcp", "ssh", 0.4, 900, 700, "SF"))
    compromise_t = bf_start + timedelta(seconds=24 * 6 + 5)
    ssh_rows.append({
        "ts": zeek_ts(compromise_t), "uid": zeek_uid(), "id.orig_h": scan_actor,
        "id.orig_p": random.randint(49152, 65535), "id.resp_h": bastion,
        "id.resp_p": 22, "version": 2, "auth_success": "T", "auth_attempts": 25,
        "client": "SSH-2.0-libssh2_1.11", "server": "SSH-2.0-OpenSSH_9.6",
    })
    conn_rows.append(conn_row(compromise_t, scan_actor, random.randint(49152, 65535),
                               bastion, 22, "tcp", "ssh", 1.8, 3400, 2900, "SF"))

    # ---- Scenario 3: post-compromise lateral port scan from the bastion ----
    lateral_start = compromise_t + timedelta(minutes=5)
    lateral_targets = [a["ip"] for a in assets if a["ip"] != bastion]
    idx = 0
    for target in lateral_targets:
        for port in (22, 445, 3389, 3306, 5432, 80, 443):
            t = lateral_start + timedelta(seconds=idx * 0.3)
            idx += 1
            conn_rows.append(conn_row(t, bastion, random.randint(49152, 65535),
                                       target, port, "tcp", "-", 0.001, 60, 0, "S0",
                                       history="S"))

    # ---- Scenario 4: C2 beaconing from the compromised bastion ----
    beacon_start = lateral_start + timedelta(minutes=10)
    for i in range(20):
        t = beacon_start + timedelta(seconds=i * 90 + random.uniform(-2, 2))
        conn_rows.append(conn_row(t, bastion, random.randint(49152, 65535),
                                   c2_ip, 443, "tcp", "ssl", 0.3,
                                   random.randint(540, 620), random.randint(300, 380), "SF"))

    # ---- Scenario 5: outbound exfil burst from the DB server to the C2 IP ----
    # bastion touches the DB server first (lateral movement)
    touch_t = lateral_start + timedelta(seconds=5)
    conn_rows.append(conn_row(touch_t, bastion, random.randint(49152, 65535),
                               db_host, 5432, "tcp", "-", 0.05, 400, 200, "SF"))
    exfil_start = beacon_start + timedelta(minutes=25)
    for i in range(8):
        t = exfil_start + timedelta(seconds=i * 20)
        conn_rows.append(conn_row(t, db_host, random.randint(49152, 65535),
                                   c2_ip, 8443, "tcp", "-", 12.0,
                                   random.randint(35_000_000, 60_000_000),
                                   random.randint(2000, 5000), "SF"))

    # ---- Scenario 6: DNS tunneling from a separately infected workstation ----
    tunnel_start = INCIDENT_START + timedelta(minutes=40)
    for i in range(55):
        t = tunnel_start + timedelta(seconds=i * random.uniform(4, 12))
        sub = random_subdomain(random.randint(22, 40))
        dns_rows.append({
            "ts": zeek_ts(t), "uid": zeek_uid(), "id.orig_h": dns_victim,
            "id.orig_p": random.randint(49152, 65535), "id.resp_h": internal_dns,
            "id.resp_p": 53, "proto": "udp", "trans_id": random.randint(1, 65535),
            "query": f"{sub}.{tunnel_domain}", "qclass_name": "C_INTERNET",
            "qtype_name": "TXT", "rcode_name": "NOERROR", "AA": "F", "RA": "T",
            "answers": "(empty)", "TTLs": "60.000000", "rejected": "F",
        })

    # ---- Sort and write Zeek logs ----
    conn_rows.sort(key=lambda r: float(r["ts"]))
    dns_rows.sort(key=lambda r: float(r["ts"]))
    ssh_rows.sort(key=lambda r: float(r["ts"]))

    day_end = DAY_START + timedelta(days=1)

    w = ZeekWriter(OUT / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, DAY_START)
    for r in conn_rows:
        w.write_row(r)
    w.close(day_end)

    w = ZeekWriter(OUT / "dns.log", "dns", DNS_FIELDS, DNS_TYPES, DAY_START)
    for r in dns_rows:
        w.write_row(r)
    w.close(day_end)

    w = ZeekWriter(OUT / "ssh.log", "ssh", SSH_FIELDS, SSH_TYPES, DAY_START)
    for r in ssh_rows:
        w.write_row(r)
    w.close(day_end)

    # ---- Suricata eve.json alerts correlated with the same scenarios ----
    alerts = []
    sid = 20260001

    def add_alert(t, src, sport, dst, dport, proto, signature, category, severity):
        nonlocal sid
        alerts.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
            "flow_id": random.randint(10**9, 10**10),
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport,
            "proto": proto.upper(),
            "alert": {
                "action": "allowed", "gid": 1, "signature_id": sid, "rev": 1,
                "signature": signature, "category": category, "severity": severity,
            },
            "app_proto": {80: "http", 443: "tls", 22: "ssh", 53: "dns"}.get(dport, "-"),
            "host": "suricata-sensor-01",
        })
        sid += 1

    add_alert(scan1_start, scan_actor, 51000, bastion, 22, "tcp",
              "SCAN Multiple destination ports from single source - possible port scan",
              "Attempted Information Leak", 2)
    add_alert(bf_start + timedelta(seconds=30), scan_actor, 51010, bastion, 22, "tcp",
              "ATTACK-RESPONSE Multiple SSH authentication failures - possible brute force",
              "Attempted Administrator Privilege Gain", 1)
    add_alert(compromise_t, scan_actor, 51020, bastion, 22, "tcp",
              "POLICY SSH authentication succeeded following brute force burst",
              "Successful Admin Privilege Gain", 1)
    add_alert(lateral_start + timedelta(seconds=2), bastion, 52000, db_host, 3389, "tcp",
              "SCAN Internal host probing multiple ports across multiple hosts - lateral movement",
              "Attempted Information Leak", 1)
    add_alert(beacon_start + timedelta(seconds=90), bastion, 53000, c2_ip, 443, "tcp",
              "MALWARE-CNC Periodic beacon-like connection to threat-intel flagged host",
              "A Network Trojan was detected", 1)
    add_alert(exfil_start, db_host, 54000, c2_ip, 8443, "tcp",
              "POLICY Large outbound data transfer to threat-intel flagged host - possible exfiltration",
              "A Network Trojan was detected", 1)
    add_alert(tunnel_start + timedelta(seconds=20), dns_victim, 55000, internal_dns, 53, "udp",
              "POLICY DNS query for high-entropy subdomain - possible DNS tunneling",
              "Potentially Bad Traffic", 2)

    # a couple of standalone known-bad-IP contacts, not tied to the main scenarios
    filler_t = INCIDENT_START - timedelta(hours=3)
    add_alert(filler_t, "10.0.0.26", 56000, "203.0.113.99", 443, "tcp",
              "POLICY Outbound connection to threat-intel flagged botnet member",
              "A Network Trojan was detected", 2)

    alerts.sort(key=lambda a: a["timestamp"])
    with open(OUT / "eve.json", "w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")

    print(f"conn.log: {len(conn_rows)} rows")
    print(f"dns.log:  {len(dns_rows)} rows")
    print(f"ssh.log:  {len(ssh_rows)} rows")
    print(f"eve.json: {len(alerts)} alerts")
    print(f"threat_ips loaded: {len(threat_ips)}, threat_domains loaded: {len(threat_domains)}")


if __name__ == "__main__":
    main()
