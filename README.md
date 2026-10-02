# FlowTrack

WAN traffic accounting for FortiGate firewalls — NetFlow v9 collector + web dashboard.

FortiGate keeps only ~7 days of logs in RAM, so "how much internet did we consume this month?" has no built-in answer. FlowTrack solves it: the firewall exports **full-rate (unsampled) NetFlow v9**, a tiny Python collector stores per-minute aggregates in SQLite, and a zero-dependency web UI shows monthly/daily/hourly usage with per-host breakdowns.

- Collector: ~300 lines of Python, one PyPI dep (`netflow`), < 50 MB RAM
- Dashboard: stdlib `http.server` + Chart.js (bundled locally) — no Node, no build step
- Storage: SQLite, a few KB per day; exact byte counts verified against controlled downloads

## Architecture

```
FortiGate ── NetFlow v9 (UDP 2055, full rate) ──▶ collector.py ──▶ SQLite (data.db)
                                                          ▲
dashboard ◀── http (LAN only) ───────────── web.py ◀──────┘  usage_min: per-minute × host (+ __WAN__ total row)
                                                        sessions: finalized flows
```

## FortiGate configuration

FortiOS exports NetFlow v9 only, full records, no sampling.

```
config system netflow
    set active-flow-timeout 60        # CRITICAL: default is 30 min — long-lived sessions
                                      # would be exported too late / never while open
    config collectors
        edit 1
            set collector-ip <COLLECTOR_IP>   # this box, LAN interface
            set source-ip <FW_LAN_IP>         # e.g. the 'internal' interface IP
        next
    end
end
config system interface
    edit "wan"
        ...
        set netflow-sampler both
    next
end
```

Notes (verified on FortiOS 7.4):

- One record per session **direction**; `IN_BYTES`/`OUT_BYTES` are cumulative since session start and re-reported every `active-flow-timeout`. The collector tracks the running max per 5-tuple and stores only deltas; a byte-count drop means 5-tuple reuse → old session finalized, new one started.
- Records appear in the DB ~60 s after the flow ends (timeout) — that's normal.
- `INPUT_SNMP`/`OUTPUT_SNMP` carry the interface **snmp-index**; WAN filtering uses it (`FLOWTRACK_WAN_SNMP_INDEX`, check with `show system interface wan`).

## Deploy

### 1. Collector host (any Linux box reachable from the firewall)

```bash
sudo mkdir -p /opt/flowtrack && sudo chown $USER /opt/flowtrack   # or keep root-owned
git clone https://github.com/henzelis/flowtrack /tmp/flowtrack-src
sudo cp /tmp/flowtrack-src/{collector.py,web.py,chart.umd.min.js} /opt/flowtrack/

# venv (system pip is PEP-668 locked on modern distros)
sudo python3 -m venv /opt/flowtrack/venv
sudo /opt/flowtrack/venv/bin/pip install netflow

# config — copy and edit the values for YOUR network
sudo cp deploy/flowtrack.env.example /etc/flowtrack.env
sudo nano /etc/flowtrack.env

# services
sudo cp deploy/flowtrack.service deploy/flowtrack-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now flowtrack flowtrack-web
```

### 2. Verify

```bash
systemctl status flowtrack flowtrack-web
ss -ulnp | grep 2055                       # collector listening
sqlite3 /opt/flowtrack/data.db "SELECT * FROM usage_min ORDER BY ts DESC LIMIT 5;"
# byte accuracy: controlled download through the WAN, compare with raw capture
curl -o /dev/null 'https://speed.cloudflare.com/__down?bytes=10000000'   # exactly N bytes
```

A 20 MB test gave `IN_BYTES ≈ 20.75 MB` — ~3–4 % overhead is TLS/retransmissions; byte counts are exact, no sampling.

### Configuration (env vars)

| Variable | Default | Meaning |
|---|---|---|
| `FLOWTRACK_BIND` | `0.0.0.0` | bind address for collector + web |
| `FLOWTRACK_PORT` | `2055` | NetFlow UDP port |
| `FLOWTRACK_DATA_DIR` | `/opt/flowtrack` | SQLite dir (collector) |
| `FLOWTRACK_DB` | `/opt/flowtrack/data.db` | DB path (web) |
| `FLOWTRACK_WEB_PORT` | `3020` | dashboard HTTP port — **LAN only, never publish via WAN** |
| `FLOWTRACK_WAN_SNMP_INDEX` | `1` | snmp-index of the WAN interface on FortiGate |
| `FLOWTRACK_FW_PUBLIC_IPS` | *(empty)* | FW's own public IP(s), comma-separated; traffic touching them is labeled host `firewall` |

## Dashboard

Open `http://<COLLECTOR_IP>:3020`:

- KPI cards: month total, today, top host, session count
- Per-day stacked bars for the selected month (last 7 months)
- Last 48 h hourly line chart
- Host table with down/up/total and % of WAN

Timezone is Europe/Kyiv (fixed UTC+3, no DST since 2022); all bucketing is integer math on `ts + 10800` — host TZ irrelevant.

## Known limitations (honest ones)

- No history before the collector started running; FortiGate RAM logs don't help there.
- Collector reboot loses at most ~1–2 min of unflushed buckets (open sessions survive via `state.json`).
- LAN-to-LAN traffic doesn't traverse the firewall → not visible. For "internet consumption" that's fine.

## Roadmap ideas

- SNMP polling of WAN counters as ground truth for cross-checks
- Retention policy (`DELETE FROM usage_min WHERE ts < ...`) — currently unbounded (~KB/day)
- IP→hostname enrichment (mDNS/ARP table) instead of raw IPs in the host table
