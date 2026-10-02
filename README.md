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

- One record per session **direction**; `IN_BYTES` == `OUT_BYTES` = bytes of that direction.
- Records are **deltas**, not cumulative: a long session is re-exported every `active-flow-timeout`, and each export covers only `[FIRST_SWITCHED, LAST_SWITCHED]` — the next export's `FIRST_SWITCHED` equals the previous `LAST_SWITCHED`. So the collector simply sums every record; no per-session state. (A short controlled download can't tell the two models apart — it fits in one export. Check a long-lived flow in a capture instead.)
- Each record's bytes are spread over the minutes its `[FIRST, LAST]` interval covers, so charts show when traffic flowed, not when it was exported.
- Direction comes from interfaces: `OUTPUT_SNMP` = WAN → **up**, `INPUT_SNMP` = WAN → **down**. Interface index `0` is the firewall itself (its VPN tunnels, syslog, management) → host `firewall`. Host = the inside endpoint as the firewall saw it (pre-NAT LAN IP).
- Records appear in the DB ~60 s after the flow ends (timeout) — that's normal.
- `INPUT_SNMP`/`OUTPUT_SNMP` carry the interface **snmp-index**; WAN filtering uses it (`FLOWTRACK_WAN_SNMP_INDEX`, check with `show system interface wan`).

## Deploy

### 1. Collector host (any Linux box reachable from the firewall)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin flowtrack
sudo mkdir -p /opt/flowtrack
git clone https://github.com/henzelis/flowtrack /tmp/flowtrack-src
sudo cp /tmp/flowtrack-src/{collector.py,web.py,chart.umd.min.js} /opt/flowtrack/

# venv (system pip is PEP-668 locked on modern distros)
sudo python3 -m venv /opt/flowtrack/venv
sudo /opt/flowtrack/venv/bin/pip install netflow
sudo chown -R flowtrack:flowtrack /opt/flowtrack   # services run as 'flowtrack', not root

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
| `FLOWTRACK_EXPORTERS` | *(empty)* | exporter IPs allowed to send NetFlow, comma-separated; empty = anyone (set it!) |
| `FLOWTRACK_TZ` | `Europe/Kyiv` | IANA time zone for day/month/hour buckets |

## Dashboard

Open `http://<COLLECTOR_IP>:3020`:

- KPI cards: month total, today (both with down/up split), top host, flow-record count
- Per-day stacked bars for the selected month (every month since data starts)
- Last 48 h hourly line chart
- Host table with down/up/total and % of WAN

Bucketing uses `FLOWTRACK_TZ` via `zoneinfo`, DST included (Europe/Kyiv still switches EET ⇄ EEST); labels come from the server, so neither the host's nor the browser's TZ matters.

## Known limitations (honest ones)

- No history before the collector started running; FortiGate RAM logs don't help there.
- Collector restart loses nothing it already received (buckets are flushed on SIGTERM; at most 15 s on a crash). Right after start, packets arriving before the FortiGate re-sends its template are skipped (`no_template` in the stats log line).
- LAN-to-LAN traffic doesn't traverse the firewall → not visible. For "internet consumption" that's fine.

## Roadmap ideas

- SNMP polling of WAN counters as ground truth for cross-checks
- Retention policy (`DELETE FROM usage_min WHERE ts < ...`) — currently unbounded (~KB/day)
- IP→hostname enrichment (mDNS/ARP table) instead of raw IPs in the host table
