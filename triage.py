"""
triage.py v2  -  PCAP triage for a HEADERS-ONLY capture (snap length 40 bytes)

WHY v2: this capture keeps only the first 40 bytes of each packet. We still get
IP addresses, TTL, the original packet size (ip.len), and TCP/UDP ports.
We do NOT get TCP flags or any payload. So everything here is based on
ports, packet counts, sizes, direction, and timing.

HOW TO RUN (same folder as the pcap):
    cd C:\\pcap_project
    python triage.py
Output: results\\triage_report.txt (+ CSVs). Every flag is a LEAD to confirm in Wireshark.
"""

import csv, glob, ipaddress, os, shutil, subprocess, sys, time
from collections import Counter, defaultdict

# ---------- knobs ----------
SCAN_LOWPORTS = 25     # >= this many distinct ports under 1024 on ONE target = vertical scan
SWEEP_HOSTS   = 25     # >= this many targets on ONE service port             = horizontal sweep
PING_HOSTS    = 25     # ICMP echo to >= this many hosts                      = ping sweep
ROLLUP_MIN    = 3      # >= this many servers in one /24 on a port -> show as /24
TOP_N         = 20
CAP           = 70000  # cap set sizes so RAM stays sane on floods
# ---------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
SLIM = os.path.join(HERE, "slim_v2.csv")
OUT  = os.path.join(HERE, "results")

FIELDS = ["frame.time_relative", "ip.src", "ip.dst", "ip.ttl", "ip.len", "ip.flags.df",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "icmp.type"]

KNOWN_HIGH = {1194, 1433, 1521, 1723, 1812, 1813, 1900, 2049, 3268, 3269, 3306, 3389,
              4444, 4500, 5060, 5353, 5355, 5432, 5900, 5985, 5986, 6667, 8000, 8080,
              8443, 8888, 9389, 11211}

PORT_NAMES = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
              67: "DHCP", 68: "DHCP-client", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
              110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
              138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
              162: "SNMP-trap", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos-pw",
              500: "IKE/VPN", 514: "Syslog", 587: "SMTP-sub", 636: "LDAPS", 993: "IMAPS",
              995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1900: "SSDP",
              2049: "NFS", 3268: "GlobalCatalog", 3269: "GlobalCatalog-SSL", 3306: "MySQL",
              3389: "RDP", 4444: "!!Metasploit-default", 5353: "mDNS", 5355: "LLMNR",
              5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL",
              6667: "IRC", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9389: "AD-WebSvc"}

ROLE_RULES = [({88, 389}, "Domain Controller (Kerberos+LDAP)"), ({3268}, "Domain Controller (GC)"),
              ({53}, "DNS"), ({67}, "DHCP server"), ({25}, "Mail"), ({110}, "Mail"), ({143}, "Mail"),
              ({80}, "Web"), ({443}, "Web"), ({8080}, "Web/proxy"), ({445}, "SMB file sharing"),
              ({21}, "FTP"), ({22}, "SSH"), ({23}, "Telnet (cleartext)"), ({3389}, "RDP"),
              ({1433}, "Database"), ({3306}, "Database"), ({5432}, "Database"),
              ({161}, "SNMP device"), ({514}, "Log server"), ({123}, "NTP")]


def pl(p):
    return f"{p}/{PORT_NAMES[p]}" if p in PORT_NAMES else str(p)


def find_tshark():
    for p in [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe",
              "/Applications/Wireshark.app/Contents/MacOS/tshark", "/usr/bin/tshark"]:
        if os.path.exists(p):
            return p
    return shutil.which("tshark")


def find_pcap():
    if len(sys.argv) > 1:
        return sys.argv[1]
    hits = [f for e in ("*.pcap", "*.pcapng", "*.cap") for f in glob.glob(os.path.join(HERE, e))]
    if len(hits) == 1:
        return hits[0]
    sys.exit("Need exactly one .pcap/.pcapng next to triage.py (or run: python triage.py file.pcap)")


def export():
    tshark, pcap = find_tshark(), find_pcap()
    if not tshark:
        sys.exit("Could not find tshark.exe (installs with Wireshark).")
    cmd = [tshark, "-r", pcap, "-n", "-Y", "ip", "-T", "fields",
           "-E", "header=y", "-E", "separator=,", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    print(f"[1/2] Exporting header fields from {os.path.basename(pcap)} with tshark...")
    print("      ~9 million packets: expect 5-20 minutes. The window will look frozen. That's fine.")
    t0 = time.time()
    with open(SLIM + ".part", "wb") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.DEVNULL, check=True)
    os.replace(SLIM + ".part", SLIM)
    print(f"      Done in {time.time() - t0:.0f}s")


def ti(x):
    if not x:
        return None
    try:
        return int(x, 16) if x.startswith("0x") else int(x)
    except ValueError:
        return None


def svc_like(p):
    return p < 1024 or p in KNOWN_HIGH


def pick_service(sp, dp):
    """Return 'dst' if the destination port is the service end, else 'src'."""
    s, d = svc_like(sp), svc_like(dp)
    if d and not s:
        return "dst"
    if s and not d:
        return "src"
    return "dst" if dp <= sp else "src"   # both or neither: lower port wins


def bm(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_multicast or ip.endswith(".255") or ip == "0.0.0.0"


def n24(ip):
    return ".".join(ip.split(".")[:3]) + ".0/24"


def ipkey(ip):
    return tuple(int(x) for x in ip.split("."))


def os_ttl(t):
    if t is None:
        return "?"
    return ("Linux/Unix (64)" if t <= 64 else "Windows (128)" if t <= 128 else "Router/Cisco/Solaris (255)")


def add_capped(s, v):
    if len(s) < CAP:
        s.add(v)


def analyze():
    print("[2/2] Crunching (progress every million packets)...")
    pk_out, pk_in, by_out = Counter(), Counter(), Counter()
    ttl, df = defaultdict(Counter), defaultdict(Counter)
    first, last = {}, {}
    conv = Counter()
    timeline = Counter()
    pair_ports = defaultdict(Counter)       # (src,dst) -> Counter(dport)   [for vertical scans]
    port_targets = defaultdict(set)         # (src,dport,proto) -> {dst}    [for sweeps]
    ep = {}                                 # (ipA,portA,ipB,portB,proto) -> counters
    bcast = defaultdict(set)
    icmp_echo, unreach = defaultdict(set), Counter()
    rows, tmax = 0, 0.0

    with open(SLIM, newline="", encoding="utf-8", errors="replace") as fh:
        rd = csv.reader(fh)
        next(rd, None)
        for r in rd:
            if len(r) < 11 or not r[1]:
                continue
            rows += 1
            if rows % 1_000_000 == 0:
                print(f"      {rows:,}")
            try:
                t = float(r[0])
            except ValueError:
                t = 0.0
            tmax = max(tmax, t)
            src, dst = r[1], r[2]
            iplen = ti(r[4]) or 0
            pk_out[src] += 1
            pk_in[dst] += 1
            by_out[src] += iplen
            ttl[src][ti(r[3])] += 1
            df[src][r[5] in ("1", "True", "true")] += 1
            first.setdefault(src, t)
            last[src] = t
            timeline[int(t // 10) * 10] += 1
            conv[(src, dst) if src < dst else (dst, src)] += 1

            if r[6]:
                proto, sp, dp = "tcp", ti(r[6]), ti(r[7])
            elif r[8]:
                proto, sp, dp = "udp", ti(r[8]), ti(r[9])
            else:
                if r[10]:
                    ty = ti(r[10])
                    if ty == 8:
                        add_capped(icmp_echo[src], dst)
                    elif ty == 3:
                        unreach[dst] += 1
                continue
            if sp is None or dp is None:
                continue
            if proto == "udp" and bm(dst):
                bcast[(dst, dp)].add(src)
                continue

            pc = pair_ports[(src, dst)]
            if len(pc) < CAP or dp in pc:
                pc[dp] += 1
            if svc_like(dp):
                add_capped(port_targets[(src, dp, proto)], dst)

            # store both endpoints; decide which side is the server AFTER the pass
            if (src, sp) <= (dst, dp):
                k, d = (src, sp, dst, dp, proto), 0
            else:
                k, d = (dst, dp, src, sp, proto), 1
            e = ep.get(k)
            if e is None:
                e = ep[k] = [0, 0, 0, 0, t, t, 0, 0]   # pkts a>b, b>a, big a>b, big b>a, t0, t1, len a>b, len b>a
            e[d] += 1
            e[6 + d] += iplen
            e[5] = t
            if proto == "udp" or iplen > 40:
                e[2 + d] += 1

    os.makedirs(OUT, exist_ok=True)

    # ---------- who is scanning (decided BEFORE assigning server/client) ----------
    vert = []
    for (s_, d_), pc in pair_ports.items():
        low = sum(1 for p in pc if p < 1024)
        if low >= SCAN_LOWPORTS:
            vert.append((s_, d_, low, len(pc), sum(pc.values())))
    sweeps = [(s_, p, pr, len(d_)) for (s_, p, pr), d_ in port_targets.items() if len(d_) >= SWEEP_HOSTS]
    scanners = {v[0] for v in vert} | {w[0] for w in sweeps}

    # endpoint fan-in: how many different peer IPs / peer ports each ip:port talks to
    peer_ips, peer_ports = defaultdict(set), defaultdict(set)
    for (a, pa, b, pb, pr) in ep:
        add_capped(peer_ips[(a, pa, pr)], b)
        add_capped(peer_ips[(b, pb, pr)], a)
        if len(peer_ports[(a, pa, pr)]) < 5000:
            peer_ports[(a, pa, pr)].add(pb)
        if len(peer_ports[(b, pb, pr)]) < 5000:
            peer_ports[(b, pb, pr)].add(pa)
    # nmap-style fixed source port: one port talking to many hosts' LOW ports
    fixed_src = {}
    for (ip, p, pr), ips in peer_ips.items():
        pp = peer_ports[(ip, p, pr)]
        if p >= 1024 and len(ips) >= 10 and len(pp) >= 20 and sum(1 for x in pp if x < 1024) / len(pp) >= 0.5:
            fixed_src[(ip, p, pr)] = (len(ips), len(pp))
            scanners.add(ip)

    def ephemeral(p):
        return 1025 <= p <= 5000 or p >= 49152

    def server_side(a, pa, b, pb, pr):
        """Return 0 if (a,pa) is the server end, 1 if (b,pb) is."""
        if a in scanners and b not in scanners:
            return 1
        if b in scanners and a not in scanners:
            return 0
        sa, sb = svc_like(pa), svc_like(pb)
        if sa != sb:
            return 0 if sa else 1
        fa, fb = len(peer_ips[(a, pa, pr)]), len(peer_ips[(b, pb, pr)])
        if fa != fb:
            return 0 if fa > fb else 1
        ea, eb = ephemeral(pa), ephemeral(pb)
        if ea != eb:
            return 1 if ea else 0
        return 0 if pa <= pb else 1

    svc, flow = {}, {}
    for (a, pa, b, pb, pr), e in ep.items():
        side = server_side(a, pa, b, pb, pr)
        if side == 0:
            server, port, client, cport = a, pa, b, pb
            req, rep, rep_big, rlen = e[1], e[0], e[2], e[7]
        else:
            server, port, client, cport = b, pb, a, pa
            req, rep, rep_big, rlen = e[0], e[1], e[3], e[6]
        s_ = svc.get((server, port, pr))
        if s_ is None:
            s_ = svc[(server, port, pr)] = {"clients": set(), "req": 0, "rep": 0, "rep_big": 0}
        add_capped(s_["clients"], client)
        s_["req"] += req
        s_["rep"] += rep
        s_["rep_big"] += rep_big
        fk = (client, server, port, pr)
        f = flow.get(fk)
        if f is None:
            f = flow[fk] = {"req": 0, "rep": 0, "cports": 0, "len": 0, "t0": e[4], "t1": e[5]}
        f["req"] += req
        f["rep"] += rep
        f["len"] += rlen
        f["cports"] += 1
        f["t0"] = min(f["t0"], e[4])
        f["t1"] = max(f["t1"], e[5])
    del ep
    L = ["=" * 78, "PCAP TRIAGE REPORT (headers-only capture)", "=" * 78,
         f"IPv4 packets: {rows:,}   Span: {tmax:,.1f} s   Avg rate: {rows / max(tmax, 1):,.0f} pkts/s",
         f"Unique sources: {len(pk_out):,}   Unique destinations: {len(pk_in):,}", ""]

    # ---------- 1. FLOODS ----------
    L += ["#" * 78, "# 1. HEAVIEST FLOWS  (client -> server:port). Floods and DoS show up here", "#" * 78,
          "Read it: huge req count + many client ports + tiny avg size + few replies = flood.",
          "Normal bulk transfer = big avg size and replies roughly matching requests.", ""]
    top_flows = sorted(flow.items(), key=lambda kv: -(kv[1]["req"] + kv[1]["rep"]))[:TOP_N]
    with open(os.path.join(OUT, "top_flows.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["client", "server", "port", "proto", "req_pkts", "reply_pkts", "req_per_sec",
                    "distinct_client_ports", "avg_req_iplen", "start_s", "end_s"])
        for (c, sv, p, pr), f in top_flows:
            dur = max(f["t1"] - f["t0"], 0.001)
            avg = f["len"] / max(f["req"], 1)
            cp = f["cports"]
            cps = f"{cp:,}"
            L.append(f"  {c:<16} -> {sv:<16} {pr.upper()} {pl(p):<14} req {f['req']:>10,} rep {f['rep']:>10,}"
                     f"  {f['req'] / dur:>8,.0f}/s  cports {cps:>6}  avg {avg:>5.0f}B  t={f['t0']:.0f}-{f['t1']:.0f}s")
            w.writerow([c, sv, p, pr, f["req"], f["rep"], f"{f['req'] / dur:.0f}", cp, f"{avg:.0f}",
                        f"{f['t0']:.1f}", f"{f['t1']:.1f}"])
    L.append("")

    # ---------- 2. SCANS ----------
    L += ["#" * 78, "# 2. SCANNING", "#" * 78,
          "Vertical = one source hitting many LOW ports (<1024) on one target.",
          "~1-2 packets per port is the classic scan signature.", ""]
    if not vert:
        L.append("  No vertical scans over threshold.")
    for s, d, low, tot, pk in sorted(vert, key=lambda x: -x[3]):
        ports = sorted(pair_ports[(s, d)])
        rng = f"{ports[0]}-{ports[-1]}"
        L.append(f"  >> {s:<16} -> {d:<16} {tot:>6,} distinct ports ({low} under 1024), range {rng},"
                 f" {pk / tot:.1f} pkts/port, active t={first[s]:.0f}-{last[s]:.0f}s")
    L += ["", "  Horizontal sweeps (one source, one service port, many targets):"]
    if not sweeps:
        L.append("    none over threshold")
    for s, p, pr, n in sorted(sweeps, key=lambda x: -x[3])[:40]:
        ex = sorted(port_targets[(s, p, pr)], key=ipkey)
        L.append(f"    {s:<16} {pr.upper()} {pl(p):<14} -> {n:,} hosts  ({ex[0]} ... {ex[-1]})")
    L += ["", "  Fixed source ports hitting many hosts' low ports (nmap-style SYN scan):"]
    if not fixed_src:
        L.append("    none")
    for (ip, p, pr), (ni, npp) in sorted(fixed_src.items(), key=lambda kv: -kv[1][0]):
        L.append(f"    {ip:<16} {pr.upper()} src port {p:<6} -> {ni} hosts, {npp} distinct target ports")
    L += ["", "  Ping sweeps:"]
    pings = [(s, d) for s, d in icmp_echo.items() if len(d) >= PING_HOSTS]
    if not pings:
        L.append("    none over threshold")
    for s, d in sorted(pings, key=lambda x: -len(x[1])):
        ex = sorted(d, key=ipkey)
        L.append(f"    {s:<16} pinged {len(d)} hosts ({ex[0]} ... {ex[-1]})")
    L += ["", "  Most ICMP 'unreachable' received (UDP scanning or dead targets):"]
    for ip, c in unreach.most_common(8):
        L.append(f"    {ip:<16} {c:,}")
    L.append("")

    # ---------- 3. SERVERS ----------
    L += ["#" * 78, "# 3. SERVERS: SERVICE PORTS PER HOST", "#" * 78,
          "Status: OPEN = replied with more than a bare 40-byte TCP packet (SYN-ACK/data) or UDP reply",
          "        RST?  = only bare 40-byte TCP replies (likely closed port answering a probe)",
          "        noreply = traffic in, nothing back (filtered, down, or flooded)",
          "Hosts whose ONLY clients were flagged scanners are summarized, not listed.", ""]
    hosts = defaultdict(dict)
    for (h, p, pr), s in svc.items():
        if bm(h):
            continue
        status = "OPEN" if s["rep_big"] else ("RST?" if s["rep"] else "noreply")
        real = s["clients"] - scanners
        hosts[h][(pr, p)] = (status, len(real), len(s["clients"]), s["req"] + s["rep"])

    def roles(h):
        ports = {p for (pr, p), v in hosts[h].items() if v[0] == "OPEN"}
        out = [lab for need, lab in ROLE_RULES if need <= ports]
        return list(dict.fromkeys(out))

    scan_only = []
    with open(os.path.join(OUT, "services_by_host.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "subnet24", "ttl", "os_hint", "df_pct", "roles", "open_tcp", "open_udp",
                    "rst_or_noreply", "pkts_sent", "pkts_recv"])
        for h in sorted(hosts, key=ipkey):
            t = ttl[h].most_common(1)[0][0] if ttl[h] else None
            dfp = df[h][True] / max(sum(df[h].values()), 1)
            ot = sorted(p for (pr, p), v in hosts[h].items() if pr == "tcp" and v[0] == "OPEN")
            ou = sorted(p for (pr, p), v in hosts[h].items() if pr == "udp" and v[0] == "OPEN")
            other = sorted(f"{pr}/{p}:{v[0]}" for (pr, p), v in hosts[h].items() if v[0] != "OPEN")
            w.writerow([h, n24(h), t, os_ttl(t), f"{dfp:.0%}", "; ".join(roles(h)),
                        " ".join(map(str, ot)), " ".join(map(str, ou)), " ".join(other[:200]),
                        pk_out[h], pk_in[h]])
            if all(v[1] == 0 for v in hosts[h].values()):
                scan_only.append(h)
                continue
            if not ot and not ou:
                continue
            L.append(f"  {h:<16} TTL {t} ({os_ttl(t)}), DF {dfp:.0%}   roles: {', '.join(roles(h)) or '-'}")
            for pr, lst in (("TCP", ot), ("UDP", ou)):
                if lst:
                    items = []
                    for p in lst:
                        st, rc, _, pk = hosts[h][(pr.lower(), p)]
                        items.append(f"{pl(p)}[{rc} clients, {pk:,} pkts]")
                    L.append(f"      {pr}: " + ", ".join(items))
    if scan_only:
        L += ["", f"  + {len(scan_only)} host(s) seen only via scans/sweeps (details in services_by_host.csv):"]
        for n, c in Counter(n24(h) for h in scan_only).most_common():
            L.append(f"      {n:<20} {c} host(s)")
    L.append("")

    # ---------- 4. BY PORT ----------
    L += ["#" * 78, "# 4. OPEN SERVICES GROUPED BY PORT (/24 rollup)", "#" * 78]
    byp = defaultdict(set)
    for h, d in hosts.items():
        for (pr, p), v in d.items():
            if v[0] == "OPEN":
                byp[(pr, p)].add(h)
    with open(os.path.join(OUT, "services_by_port.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["proto", "port", "service", "server_count", "servers"])
        for (pr, p) in sorted(byp):
            nets = defaultdict(list)
            for h in byp[(pr, p)]:
                nets[n24(h)].append(h)
            shown = []
            for n, hs in sorted(nets.items()):
                shown += [f"{n} ({len(hs)} hosts)"] if len(hs) >= ROLLUP_MIN else sorted(hs, key=ipkey)
            L.append(f"  {pr.upper()} {pl(p):<22} {len(byp[(pr, p)]):>4}: {', '.join(shown)}")
            w.writerow([pr, p, PORT_NAMES.get(p, ""), len(byp[(pr, p)]), "; ".join(shown)])
    L.append("")

    # ---------- 5-8 ----------
    L += ["#" * 78, "# 5. BROADCAST / MULTICAST", "#" * 78]
    for (d, p), s in sorted(bcast.items(), key=lambda kv: -len(kv[1]))[:TOP_N]:
        L.append(f"  {d:<18} UDP {pl(p):<16} from {len(s)} host(s): {', '.join(sorted(s, key=ipkey)[:6])}")
    L += ["", "#" * 78, "# 6. SUBNET MAP (/24s with active senders)", "#" * 78]
    nets = defaultdict(list)
    for h in pk_out:
        if not bm(h):
            nets[n24(h)].append(h)
    with open(os.path.join(OUT, "subnets.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["subnet24", "active_hosts", "pkts_sent", "hosts"])
        for n, hs in sorted(nets.items(), key=lambda kv: ipkey(kv[0].split("/")[0])):
            tot = sum(pk_out[h] for h in hs)
            hs_sorted = sorted(hs, key=ipkey)
            L.append(f"  {n:<20} hosts {len(hs):>5}  pkts sent {tot:>12,}   e.g. {', '.join(hs_sorted[:5])}")
            w.writerow([n, len(hs), tot, " ".join(hs_sorted)])
    L += ["", "#" * 78, "# 7. TOP TALKERS (sent)", "#" * 78]
    for h, c in pk_out.most_common(TOP_N):
        t = ttl[h].most_common(1)[0][0]
        L.append(f"  {h:<16} {c:>11,} pkts  {c / max(tmax, 1):>8,.0f}/s  TTL {t}  t={first[h]:.0f}-{last[h]:.0f}s"
                 + ("   !! scan/sweep" if h in scanners else ""))
    L += ["", "#" * 78, "# 8. TIMELINE (packets per 10 s)", "#" * 78]
    peak = max(timeline.values()) if timeline else 1
    for b in sorted(timeline):
        L.append(f"  t={b:>5}s {timeline[b]:>10,} " + "#" * int(50 * timeline[b] / peak))
    L += ["", "#" * 78, "# 9. TOP CONVERSATIONS", "#" * 78]
    for (a, b), c in conv.most_common(TOP_N):
        L.append(f"  {a:<16} <-> {b:<16} {c:>11,} pkts")

    with open(os.path.join(OUT, "triage_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    print("      Done. Open results\\triage_report.txt")


if __name__ == "__main__":
    if os.path.exists(SLIM):
        print("[1/2] slim_v2.csv exists, skipping export (delete it to re-export).")
    else:
        export()
    analyze()