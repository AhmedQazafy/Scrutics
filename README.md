# Scrutics

**Passive OT/ICS Network Asset Discovery and Classification**

Scrutics is a lightweight, passive network monitoring tool designed for OT/ICS environments. It listens silently on your network — never sending a single packet — and builds an asset inventory by observing traffic, identifying devices by MAC vendor, classifying industrial protocols, and analyzing device behavior over time.

> Built for small manufacturers, brownfield facilities, and OT teams who can't afford enterprise tools and can't risk active scanning.

---

## Why Passive-Only

Active scanning (nmap, ping sweeps) can crash legacy PLCs, freeze HMIs, and disrupt running processes. Scrutics operates exclusively in read-only mode — it observes what's already on the wire and classifies what it sees.

No probing. No risk.

Scrutics also enforces passive-only operation internally by patching Scapy transmit functions and verifying passive mode before every live capture.

---

## Core Features (v0.2)

- Passive packet capture via network tap or SPAN port
- MAC OUI lookup — identifies device vendor from MAC address
- Protocol classification — Modbus, DNP3, S7comm, EtherNet/IP, BACnet, OPC-UA, and standard IT protocols
- Behavioral baseline engine — learns normal device communication patterns
- Anomaly detection — detects new peers, directionality changes, and interval anomalies
- Multi-factor confidence scoring per device
- Zeek log parsing support
- Suricata EVE JSON parsing support
- PCAP and PCAPNG file analysis support
- Interactive Textual TUI
- Fully headless CLI mode for scripting and automation
- Session persistence with CSV export
- YAML-based custom classification rules
- Air-gap safe bundled ICS vendor database
- lightweight deployment

---

## Project Structure

```text
Scrutics/
├── scrutics/
│   ├── baseline/       # Behavioral baseline engine
│   ├── capture/        # Packet capture engine (Scapy)
│   ├── classifier/     # OUI lookup + protocol classification
│   ├── config/         # YAML custom rules
│   ├── db/             # Asset inventory store
│   ├── parsers/        # Zeek / Suricata / PCAP parsers
│   ├── ui/             # Textual TUI
│   ├── cli.py          # Headless CLI
│   └── passive.py      # Passive enforcement layer
├── sim/                # Docker OT simulation environment
├── tests/              # Unit tests
├── docs/               # Documentation
├── .github/workflows/  # CI/CD pipeline
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Usage

### Interactive TUI

```bash
sudo python3 -m scrutics
```

### Live Capture (also available in TUI with duration "0")

```bash
sudo python3 -m scrutics --live eth0
```

### Headless Mode

```bash
sudo python3 -m scrutics --live eth0 --headless
```

### File Analysis (added in TUI)

```bash
python3 -m scrutics --file capture.pcap
python3 -m scrutics --file eve.json --headless
```

---

## Status

🚧 Active development — v0.2.0-dev

---

## License

MIT

