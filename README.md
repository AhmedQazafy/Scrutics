# Scrutics

**Passive OT/ICS Network Asset Discovery**

Scrutics is a lightweight, passive-only tool for discovering and classifying assets on operational technology (OT) and industrial control system (ICS) networks. It never transmits packets. It identifies PLCs, RTUs, HMIs, engineering workstations, and network devices by observing traffic passively, classifies them using OUI vendor matching and ICS protocol detection, builds a behavioral baseline, and exports results as CSV or forwards anomaly events to a SIEM in real time.

Designed for small OT teams, brownfield facilities, and security researchers who need network visibility without the cost, complexity, or active-scanning risk of enterprise platforms.

---

## Why Scrutics and not Zeek, Malcolm, or Grassmarlin?

| | Scrutics | Zeek | Malcolm | Grassmarlin |
|---|---|---|---|---|
| Deployment | `pip install` + one command | Requires scripting knowledge | Full Docker stack | Windows-only installer |
| Runs on Raspberry Pi | ✓ | Possible but complex | No | No |
| OT-specific out of the box | ✓ | Requires ICS scripts | ✓ (via Zeek) | ✓ |
| SIEM output (real time) | ✓ | Needs pipeline | Via OpenSearch | No |
| Reads Zeek/Suricata output | ✓ | — | — | — |
| Active development | ✓ | ✓ | ✓ | Archived |

Scrutics is not trying to replace Zeek or Malcolm for large environments. The target is a facility that has no existing OT visibility tooling, a small IT/OT team, and needs to answer "what is on my network and is it behaving normally" without deploying a full security stack. If you already run Zeek, Scrutics can also read its logs and enrich them with OT-specific classification.

---

## Features

- **Truly passive** — passive enforcement patches Scapy transmit functions at runtime and raises `PermissionError` on any transmit attempt. The guarantee is documented and testable.
- **Protocol-aware classification** — identifies Modbus TCP, S7comm, EtherNet/IP, DNP3, OPC-UA, BACnet/IP, and more from traffic observation alone.
- **OUI vendor matching** — cross-references MAC prefixes against an ICS-specific OUI database (Schneider, Siemens, Rockwell, and others).
- **Behavioral baseline** — learns normal communication patterns per device and flags deviations: new peers, changed directionality, interval anomalies.
- **Confidence scoring** — every asset gets a confidence percentage based on OUI match, protocol match, behavioral score, and directionality.
- **Real-time output** — `events.csv` and `anomalies.csv` are written continuously. A crash or kill does not lose your session data.
- **SIEM integration** — forward anomaly events in real time via syslog (JSON, CEF, LEEF, plain) or Splunk HEC.
- **Log file analysis** — analyze Zeek conn.log, Zeek ICS logs (modbus, dnp3, bacnet), and Suricata EVE JSON.
- **TUI and headless modes** — interactive terminal UI for hands-on use, or fully headless for scripts, servers, and Raspberry Pi deployments.
- **Hot rule reload** — edit `scrutics_rules.yaml` while running; Scrutics reloads it automatically on save. No restart required.
- **Zero new dependencies for SIEM** — syslog and Splunk HEC output use Python stdlib only.

---

## Requirements

- Python 3.10 or newer
- Linux (including WSL2 on Windows)
- Root or `CAP_NET_RAW` capability for live capture
- Dependencies: `scapy`, `textual`, `pyyaml`

Raspberry Pi 4 or newer recommended for continuous live deployment. Pi 3 works but may struggle with high-traffic networks.

---

## Installation

```bash
git clone https://github.com/AhmedQazafy/Scrutics.git
cd Scrutics
pip install -r requirements.txt
```

Live capture requires root:

```bash
sudo python3 -m scrutics
```

Or grant the capability without running everything as root:

```bash
sudo setcap cap_net_raw+eip $(which python3)
python3 -m scrutics
```

---

## Quick Start

**TUI (recommended for first use):**

```bash
sudo python3 -m scrutics
```

No arguments launches the TUI. Press `1` or click **Start Analysis** to begin.

**Headless live capture (60 seconds):**

```bash
sudo python3 -m scrutics --live eth0 --headless
```

**Headless infinite capture:**

```bash
sudo python3 -m scrutics --live eth0 --duration 0 --headless
```

**Analyze a PCAP file:**

```bash
python3 -m scrutics --file capture.pcap --headless
```

**Analyze a large PCAP quickly (no anomaly detection):**

```bash
python3 -m scrutics --file big.pcap --headless --no-baseline
```

---

## Usage Modes

### TUI Mode

Launched when no arguments are given, or when `--live`/`--file` is passed without `--headless`. Requires an interactive terminal.

The TUI has three panels:
- **Asset Inventory** — live-updating table of all discovered assets
- **Event Log** — classification events as they happen
- **Anomaly Feed** — behavioral anomalies with severity

**Keyboard shortcuts:**
| Key | Action |
|-----|--------|
| `1` | Start Analysis |
| `2` | File Options (load PCAP/log) |
| `3` | Toggle panel layout |
| `R` | Reload rules from `scrutics_rules.yaml` |
| `P` | Pause / Resume capture |
| `Q` | Quit |
| `←` `→` | Switch between panels |
| `Enter` | Enter panel (enables scroll/navigation) |
| `↑` `↓` | Scroll within active panel |

### Headless Mode

Use `--headless` for scripts, cron jobs, servers, or Raspberry Pi deployments where there is no interactive terminal.

In headless live mode, Scrutics prints a progress line every 100 packets and a full asset snapshot to the console every 60 seconds. All three CSV files are available in the session folder.

---

## Command Reference

```
python3 -m scrutics [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--live INTERFACE` | — | Network interface for live passive capture |
| `--file FILEPATH` | — | File to analyze (.pcap, .pcapng, .log, .json) |
| `--duration SECONDS` | `60` | Live capture duration. `0` = run until Ctrl+C |
| `--baseline SECONDS` | `60` | Observation window before anomaly detection activates |
| `--output DIR` | `./output` | Directory to save session folders |
| `--headless` | off | Disable TUI, print results to console |
| `--no-baseline` | off | Skip anomaly detection — inventory and classification only |
| `--version` | — | Print version and exit |

### Things that affect output quality

**Wrong interface** — the most common issue. Run `ip link show` to list interfaces. Scrutics must be on the interface that carries OT traffic — typically a SPAN/mirror port from your OT switch. If you run it on an interface with no traffic, it will appear frozen until the first packet arrives (the OUI database loads on startup but Scapy blocks until a packet is seen).

**`--duration 0` with `--headless` must run in the foreground** — if you run with `&` (background), pressing Ctrl+C sends the signal to the shell, not to Scrutics. Scrutics will not save `assets.csv` because its exit handler never fires. To stop a backgrounded Scrutics process cleanly:

```bash
# Find the PID
jobs -l

# Bring to foreground, then Ctrl+C
fg %1
```

Or send SIGTERM directly:

```bash
kill -TERM <pid>
```

**Large PCAP files** — use `--no-baseline` for files over ~100MB. Without it, the behavioral baseline engine runs per packet and can generate thousands of anomaly events, significantly slowing analysis. With `--no-baseline` you get fast, accurate inventory and classification without anomaly detection.

**WSL/Windows file locking** — on WSL2, if you have a session output folder open in Windows Explorer, Excel, or another application, `events.csv` may be locked when Scrutics tries to create it. Close the folder in Explorer before starting a new session.

**Baseline window** — `--baseline 60` means Scrutics observes for 60 seconds before locking the baseline and starting anomaly detection. On a network with predictable Modbus polling cycles, 60 seconds is usually enough. On slower or less regular networks, increase to 120–300 seconds to reduce false positives.

---

## Output Files

All output is saved to `output/scrutics_TIMESTAMP/`.

### `assets.csv`

Written when the session ends (Ctrl+C or duration reached). Contains one row per discovered asset.

| Column | Description |
|--------|-------------|
| `ip` | IP address |
| `mac` | MAC address |
| `vendor` | OUI vendor lookup result |
| `protocols` | Detected ICS/IT protocols |
| `role` | Inferred device role (e.g. "PLC / RTU") |
| `confidence` | HIGH / MEDIUM / LOW |
| `confidence_pct` | Numeric confidence 0–100 |
| `is_ot` | true / false / unknown |
| `baseline_status` | locked / observing |
| `anomaly_count` | Number of anomalies for this asset |
| `first_seen` | Timestamp of first packet |
| `last_seen` | Timestamp of most recent packet |

### `events.csv`

Written continuously in real time as events occur. Contains classification events: when a device is first seen, when its protocol is identified, when a vendor OUI matches.

### `anomalies.csv`

Written continuously in real time. Contains behavioral anomaly events with timestamp, IP, type, severity (HIGH/MEDIUM/LOW), and detail.

Anomaly types:
- `NEW_PEER` — device communicated with a new IP not seen during baseline
- `DIRECTIONALITY_CHANGE` — device that previously only received is now initiating, or vice versa
- `INTERVAL_ANOMALY` — communication interval significantly outside baseline pattern
- `SURICATA_ALERT` — alert forwarded from a Suricata EVE JSON file

---

## Configuration

Scrutics looks for a user configuration file in this order:

1. `./scrutics_rules.yaml` (current working directory — recommended)
2. `~/.scrutics/scrutics.yaml` (home directory)
3. Package default (empty rules, no sinks)

Copy the template to get started:

```bash
cp scrutics/config/custom_rules.yaml scrutics_rules.yaml
```

The configuration file has three sections: `rules`, `inventory`, and `output`.

### Behavioral Rule Constraints

Classification rules can include behavioral constraints that define what a matched device is *allowed to do*. These fire `BEHAVIORAL_VIOLATION` anomalies (severity: HIGH) immediately — independent of the baseline observation window — and are forwarded to all configured SIEM sinks.

This is the key difference from statistical baseline anomalies: behavioral constraints encode operator knowledge ("this PLC should never initiate a connection") rather than statistical deviation from observed behavior.

```yaml
rules:
  - name: "Modbus PLC Fleet"
    port: 502
    classify_as: "Modbus TCP"
    role: "PLC / RTU"
    is_ot: true
    # Behavioral constraints:
    never_initiates: true          # alert if device initiates any connection
    allowed_peers:                 # alert if device talks to unlisted IPs
      - "192.168.1.100"            #   SCADA server
      - "192.168.1.101"            #   Engineering workstation
    max_new_peers_per_hour: 2      # alert if more than 2 new peers in 60 min

  - name: "Siemens PLC"
    port: 102
    classify_as: "S7comm"
    role: "Siemens PLC"
    is_ot: true
    never_initiates: true
    alert_on_new_port: true        # alert the first time a new port is observed

  - name: "SCADA Server"
    port: 4840
    classify_as: "OPC-UA"
    role: "SCADA / HMI"
    is_ot: true
    allowed_ports: [4840, 80, 443, 22]  # alert on any other port
```

**Constraint fields:**

| Field | Type | Description |
|-------|------|-------------|
| `never_initiates` | bool | Alert if device ever initiates a connection |
| `allowed_peers` | list | Alert if device talks to an IP not in this list |
| `allowed_ports` | list | Alert if traffic seen on a port not in this list |
| `alert_on_new_port` | bool | Alert the first time each new port is observed |
| `max_new_peers_per_hour` | int | Alert if device exceeds N new peers in 60 minutes |

Violation anomaly type is `BEHAVIORAL_VIOLATION`. Subtypes in the detail field: `NEVER_INITIATES`, `DISALLOWED_PEER`, `DISALLOWED_PORT`, `NEW_PORT`, `PEER_RATE_EXCEEDED`.

### Custom Classification Rules

Custom rules take precedence over built-in rules. Useful for proprietary protocols, site-specific devices, or overriding a built-in classification.

```yaml
rules:
  # Classify by destination port
  - name: "OSIsoft PI Historian"
    port: 5461
    classify_as: "PI Historian"
    role: "Data Historian"
    is_ot: true
    confidence: HIGH

  # Classify by MAC prefix (vendor-specific)
  - name: "Legacy RTU Fleet"
    mac_prefix: "00:AB:CD"
    classify_as: "Legacy RTU"
    role: "Remote Terminal Unit"
    is_ot: true
    confidence: MEDIUM

  # Classify by port and protocol
  - name: "Custom Fieldbus"
    port: 9999
    protocol: UDP
    classify_as: "Proprietary Fieldbus"
    role: "Field Device"
    is_ot: true
```

**Rule fields:**
| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable label |
| `port` | No | Destination port to match |
| `protocol` | No | `TCP` or `UDP` (omit to match either) |
| `mac_prefix` | No | First 3 bytes of MAC e.g. `00:80:F4` |
| `classify_as` | Yes | Protocol label shown in output |
| `role` | Yes | Device role shown in output |
| `is_ot` | Yes | `true` or `false` |
| `confidence` | No | `HIGH`, `MEDIUM`, or `LOW` (default: HIGH) |

### Inventory Scope

By default, Scrutics only tracks RFC1918 private IP addresses as assets. Public IPs seen in traffic are recorded as peers but not as inventory assets. This prevents internet-routed traffic from polluting the asset table in environments with internet-connected devices.

```yaml
inventory:
  # Track only specific subnets (overrides RFC1918 default)
  cidrs:
    - "192.168.88.0/24"
    - "10.10.0.0/16"

  # Set to true to include public IPs as assets
  include_public_ips: false
```

### Hot Reload

While Scrutics is running, edit `scrutics_rules.yaml` and save. Scrutics checks the file every 2.5 seconds. If the file parses and validates successfully, rules and sinks are reloaded without restarting. If the file has errors, the old rules stay active and an error is shown in the TUI status bar or printed to console.

In the TUI, press `R` to reload manually. On Linux, `kill -HUP <pid>` also triggers reload (headless only).

---

## SIEM Integration

Configure output sinks in `scrutics_rules.yaml`. Multiple sinks can be active simultaneously. Anomaly events are delivered to all configured sinks in real time via a non-blocking background queue — a slow or unreachable SIEM never stalls packet capture.

### Wazuh

Add a syslog input on the Wazuh manager (port 514 UDP by default). Scrutics sends JSON events that Wazuh's JSON decoder handles natively.

```yaml
output:
  sinks:
    - type: syslog
      host: 192.168.1.10    # Wazuh manager IP
      port: 514
      protocol: udp
      format: json
```

In Wazuh, add to `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.1.0/24</allowed-ips>
</remote>
```

Scrutics events will appear in Wazuh with `program_name: scrutics`. Create a custom decoder and rules to alert on `severity: HIGH` anomalies as needed.

### Splunk

Use the Splunk HTTP Event Collector (HEC). Create an HEC token in Splunk and configure:

```yaml
output:
  sinks:
    - type: splunk_hec
      url: https://splunk.example.com:8088
      token: your-hec-token-here
      verify_ssl: true
      index: scrutics           # optional — uses default index if omitted
```

Events arrive with `sourcetype: scrutics:anomaly`. For lab environments with self-signed certificates, set `verify_ssl: false`.

### ArcSight / Generic CEF

```yaml
output:
  sinks:
    - type: syslog
      host: 192.168.1.20
      port: 514
      protocol: udp
      format: cef
```

CEF format: `CEF:0|Scrutics|Scrutics|v0.3|{type}|{type}|{severity}|src={ip} msg={detail}`

### IBM QRadar (LEEF)

```yaml
output:
  sinks:
    - type: syslog
      host: 192.168.1.30
      port: 514
      protocol: udp
      format: leef
```

### Multiple simultaneous sinks

```yaml
output:
  sinks:
    - type: syslog
      host: 192.168.1.10
      port: 514
      protocol: udp
      format: json
    - type: splunk_hec
      url: https://splunk.example.com:8088
      token: your-token
```

---

## Log File Integration

### Zeek

Scrutics can analyze Zeek log files directly. Supported log types:

| Zeek log | What Scrutics extracts |
|----------|----------------------|
| `conn.log` | All TCP/UDP flows — full inventory discovery |
| `modbus.log` | Modbus TCP flows → port 502 classification |
| `dnp3.log` | DNP3 flows → port 20000 classification |
| `bacnet.log` | BACnet flows → port 47808 classification |

Compressed logs (`.log.gz`) are supported.

```bash
# Analyze a Zeek conn.log
python3 -m scrutics --file /path/to/conn.log --headless

# Analyze a compressed Zeek log
python3 -m scrutics --file /path/to/conn.log.gz --headless
```

Scrutics detects Zeek format automatically by looking for the `#separator` and `#fields` header lines. MAC addresses are not available in Zeek logs, so OUI-based vendor matching will not apply — classification relies on protocol detection only.

### Suricata

Scrutics parses Suricata `eve.json` files. All event types are processed for flow information, and `alert` events are imported directly as anomalies with their original signature and severity.

```bash
python3 -m scrutics --file /var/log/suricata/eve.json --headless
```

Suricata ICS protocol events (`modbus`, `dnp3`, `enip`) are mapped to their corresponding ports automatically.

**Workflow — Scrutics + Suricata + Wazuh:**

1. Suricata runs on the SPAN port with ICS ruleset enabled
2. Scrutics reads `eve.json` periodically for inventory enrichment, or runs live on the same interface for passive discovery
3. Scrutics forwards anomalies to Wazuh via JSON syslog
4. Wazuh correlates Scrutics inventory data with Suricata alerts

---

## Deployment

### Identifying the right interface

Scrutics must run on the interface that carries OT network traffic. In most setups this means:

- A **SPAN/mirror port** from your OT managed switch, connected to the Scrutics host
- The **bridge interface** of a Docker/VM network (for lab environments)
- Directly on a host that is part of the OT network segment

List available interfaces:

```bash
ip link show
```

Common interface names: `eth0`, `ens3`, `enp2s0` for physical Ethernet; `br-xxxxxxxx` for Docker bridge networks; `virbr0` for libvirt.

If Scrutics appears to hang after startup without showing any asset or event activity, the most likely cause is that the selected interface has no traffic. Verify with:

```bash
sudo tcpdump -i <interface> -c 10
```

If tcpdump shows no packets, you are on the wrong interface or the SPAN port is not configured.

### Raspberry Pi deployment

```bash
# On the Pi
sudo apt install python3-pip
git clone https://github.com/AhmedQazafy/Scrutics.git
cd Scrutics
pip3 install -r requirements.txt

# Run as a systemd service for continuous operation
sudo nano /etc/systemd/system/scrutics.service
```

Example service file:

```ini
[Unit]
Description=Scrutics Passive OT Asset Discovery
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/pi/Scrutics
ExecStart=/usr/bin/python3 -m scrutics --live eth0 --duration 0 --headless
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable scrutics
sudo systemctl start scrutics
```

Session output accumulates in `output/scrutics_*/`. The rolling writer ensures data is preserved even if the service is stopped.

### Running in background correctly

If you need to run Scrutics in the background without systemd:

```bash
# Run in background, redirect output to log file
sudo python3 -m scrutics --live eth0 --duration 0 --headless > scrutics.log 2>&1 &
echo $! > scrutics.pid

# Stop cleanly (triggers asset CSV save)
kill -TERM $(cat scrutics.pid)
```

Do **not** use Ctrl+C on a backgrounded process (`&`). Ctrl+C sends SIGINT to the shell, not to Scrutics. The clean exit handler will not run and `assets.csv` will not be saved. Use `SIGTERM` as shown above, or bring the process to the foreground with `fg` before pressing Ctrl+C.

---

## Known Limitations

**Passive enforcement bypass** — Scrutics patches Scapy's transmit functions at runtime to enforce passive-only operation. This guarantee applies to Scrutics itself. Any code that captures a reference to Scapy's send functions *before* `enforce_passive()` is called can bypass the patch. This is a known limitation of runtime monkey-patching and does not affect normal use — Scrutics always calls `enforce_passive()` before any capture begins.

**MAC addresses unavailable in Zeek/Suricata logs** — OUI vendor matching requires a MAC address. File analysis of Zeek conn.log or Suricata EVE JSON relies on protocol detection only, which reduces confidence scores compared to live capture.

**Large PCAP files are slow** — Scrutics processes packets individually in Python via Scapy. A 200MB PCAP with 1M+ packets can take 10–20 minutes to analyze fully. Use `--no-baseline` to skip anomaly detection for faster inventory extraction. For very large captures, consider pre-filtering with `tcpdump -r big.pcap -w filtered.pcap 'port 502 or port 102 or port 44818'` before feeding to Scrutics.

**WSL2 file performance** — accessing the Windows filesystem from WSL2 (`/mnt/c/...`) is significantly slower than the Linux filesystem. For best performance, keep the Scrutics project directory on the Linux filesystem (e.g. `/home/user/Scrutics`) and copy PCAPs there for analysis.

**No IPv6 support** — Scrutics currently tracks IPv4 assets only. IPv6 traffic is ignored.

---

## Architecture

```
Network Traffic (SPAN port / pcap / Zeek log / Suricata EVE)
        │
        ▼
┌──────────────────────────────────────────┐
│           Passive Enforcement Layer       │
│  (Scapy transmit functions patched out)  │
└──────────────┬───────────────────────────┘
               │ packets / flows
               ▼
┌──────────────────────────────────────────┐
│           Capture Engine                 │
│  ┌─────────────┐   ┌──────────────────┐  │
│  │ OUI Lookup  │   │ Protocol Classify │  │
│  │ (ics_oui)   │   │ (builtin + YAML)  │  │
│  └─────────────┘   └──────────────────┘  │
│  ┌───────────────────────────────────┐   │
│  │       Baseline Engine             │   │
│  │  peers / intervals / direction    │   │
│  └───────────────────────────────────┘   │
└──────┬──────────────────────┬────────────┘
       │ assets               │ anomalies
       ▼                      ▼
┌─────────────┐    ┌──────────────────────────────┐
│ Asset       │    │ Rolling Writer  │ Sink Manager │
│ Inventory   │    │ (events.csv,    │ (syslog,     │
│             │    │  anomalies.csv) │  Splunk HEC) │
└──────┬──────┘    └──────────────────────────────┘
       │ on exit
       ▼
  assets.csv
       │
  ┌────┴────┐
  │   TUI   │  ←→  Event Log  /  Anomaly Feed
  └─────────┘
```

---