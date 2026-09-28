# PCAP Triage Script

`triage.py` summarizes a large packet capture (millions of packets) into a short, readable report so an analyst knows where to look first in Wireshark.

Built for a Penn State capstone assignment analyzing a 9.36-million-packet capture that was truncated to 40 bytes per packet (headers only).

## What it does

1. Uses **tshark** (Wireshark's command-line engine) to export header fields from every packet into a CSV.
2. Reads that CSV and reports:
   - **Heaviest flows**, where floods and denial-of-service traffic show up
   - **Scanning**: vertical port scans, horizontal sweeps, ping sweeps and nmap-style fixed source ports
   - **Services per host** (server-side ports only), rolled up by /24 subnet
   - **Subnet map, top talkers, top conversations and a timeline**
   - **OS hints** from TTL values

Every result is a lead to confirm in Wireshark, not a verdict.

## Requirements

- Python 3 (standard library only, nothing to install)
- Wireshark installed (for tshark)

## Usage

Put `triage.py` in the same folder as your `.pcap` or `.pcapng` file, then run:

```
python triage.py
```

Results are written to a `results` folder. Start with `results/triage_report.txt`.

## Disclosure

This script was written by Claude (Claude.ai, Anthropic) through AI-assisted "vibe coding." I directed what it needed to do, ran it against the capture, reported its errors, and verified its output in Wireshark before using any finding in my report.

No capture data is included in this repository.
