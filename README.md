# Scrutics

**Passive OT/ICS Network Asset Discovery and Classification**

Scrutics is a lightweight, passive network monitoring tool designed for OT/ICS environments. It listens silently on your network — never sending a single packet — and builds an asset inventory by observing traffic, identifying devices by MAC vendor, and classifying them by industrial protocol behavior.

> Built for small manufacturers, brownfield facilities, and OT teams who can't afford enterprise tools and can't risk active scanning.

---

## Why Passive-Only

Active scanning (nmap, ping sweeps) can crash legacy PLCs, freeze HMIs, and disrupt running processes. Scrutics operates exclusively in read-only mode — it observes what's already on the wire and classifies what it sees. No probing. No risk.

---

## Core Features (v0.1)

- Passive packet capture via network tap or SPAN port
- MAC OUI lookup — identifies device vendor from MAC address
- Protocol classification — Modbus, DNP3, S7comm, EtherNet/IP, and standard IT protocols
- Confidence scoring per device
- Asset table output (terminal + CSV export)

---

## Project Structure

```
Scrutics/
├── scrutics/
│   ├── capture/        # Packet capture engine (Scapy)
│   ├── classifier/     # OUI lookup + protocol classification
│   └── db/             # Asset inventory store
├── tests/              # Unit tests
├── docs/               # Documentation
├── .github/workflows/  # CI/CD pipeline
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Status

🚧 Early development — v0.1 in progress

---

## License

MIT
