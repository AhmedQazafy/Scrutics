"""Zeek log parser for Scrutics. Supports conn.log, modbus.log, dnp3.log, bacnet.log."""

import gzip
from typing import Generator


def _open_zeek(filepath: str):
    if filepath.endswith(".gz"):
        return gzip.open(filepath, "rt", errors="ignore")
    return open(filepath, "r", errors="ignore")


def parse_zeek_log(filepath: str) -> Generator[dict, None, None]:
    with _open_zeek(filepath) as f:
        lines = f.readlines()

    meta = {"fields": [], "separator": "\t", "path": "unknown"}
    data_lines = []

    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("#separator"):
            parts = line.split(" ", 1)
            if len(parts) == 2:
                sep = parts[1].strip()
                meta["separator"] = sep.replace("\\t", "\t").replace("\\x09", "\t")
        elif line.startswith("#fields"):
            meta["fields"] = line.split(meta["separator"])[1:]
        elif line.startswith("#path"):
            parts = line.split(meta["separator"])
            meta["path"] = parts[1] if len(parts) > 1 else line.split(" ", 1)[-1].strip()
        elif not line.startswith("#"):
            data_lines.append(line)

    fields = meta["fields"]
    sep    = meta["separator"]
    if not fields:
        return

    for line in data_lines:
        if not line.strip():
            continue
        values = line.split(sep)
        if len(values) != len(fields):
            continue
        record = dict(zip(fields, values))
        record["_path"] = meta["path"]
        yield record


def extract_flows_from_zeek(filepath: str) -> list:
    flows = []
    for record in parse_zeek_log(filepath):
        path   = record.get("_path", "")
        src_ip = record.get("id.orig_h", "-")
        dst_ip = record.get("id.resp_h", "-")
        ts     = record.get("ts", "0")
        if src_ip == "-" or dst_ip == "-":
            continue
        try:    ts_float = float(ts)
        except: ts_float = 0.0

        if path == "modbus":
            flows.append({"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                          "dst_port": 502, "proto": "TCP", "timestamp": ts_float, "source": "zeek_modbus"})
        elif path == "dnp3":
            flows.append({"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                          "dst_port": 20000, "proto": "TCP", "timestamp": ts_float, "source": "zeek_dnp3"})
        elif path == "bacnet":
            flows.append({"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                          "dst_port": 47808, "proto": "UDP", "timestamp": ts_float, "source": "zeek_bacnet"})
        elif path == "conn":
            dst_port = record.get("id.resp_p", "-")
            proto    = record.get("proto", "tcp").upper()
            try:    dst_port_int = int(dst_port)
            except: dst_port_int = None
            flows.append({"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                          "dst_port": dst_port_int, "proto": proto, "timestamp": ts_float, "source": "zeek_conn"})
    return flows
