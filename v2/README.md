# FlowTrack v2

Flow analytics for NetFlow v5/v9 and IPFIX exporters (FortiGate, Cisco, MikroTik, Juniper, pmacct …):
collector → ClickHouse → API → web UI.

```
exporters ── UDP 2055 ──▶ collector.py ──▶ ClickHouse (flows, usage_1h, exporter_stats)
                              │                      ▲
                              └─ optional raw copy ─▶ other collectors (FT_FORWARD)
browser ◀── http :3030 ── api.py (+ web/) ───────────┘
```

## What it does

- **Accounting.** FortiOS and NetFlow v9/IPFIX in general export *delta* counters per active-timeout
  interval, so traffic is the plain sum of records. Every record is kept for 30 days; hourly usage per
  host for 3 years (`usage_1h`, filled by a materialized view).
- **Inside / outside.** With `wan_ifs` set for an exporter, direction comes from the interfaces
  (leaves via WAN = upload, arrives via WAN = download; FortiOS interface 0 = the firewall itself).
  Without it, from RFC 1918 / CGNAT ranges.
- **Enrichment.** Country, city, coordinates and ASN of the outside address (DB-IP Lite, CC BY 4.0),
  L7 protocol from protocol + port, service name from ASN or port, NAT address, host names from
  `hosts.json` and reverse DNS.
- **Exporter health.** Records/s, templates, packets lost (sequence gaps), records skipped while
  waiting for a template — per exporter, per minute.
- **UI.** Overview, live inside↔outside exchange (top-10 each side), connection map and 3D globe,
  top hosts, services, raw flow records, events (sustained upload, bursts, new countries, export
  loss), devices and interfaces. Every value is a click-to-filter.

## Install

```bash
# 1. ClickHouse (local only)
sudo mkdir -p /opt/flowtrack-v2/clickhouse /etc/flowtrack-v2
PW=$(openssl rand -hex 16)
docker run -d --name flowtrack-ch --restart unless-stopped -p 127.0.0.1:8123:8123 --memory 4g \
  --ulimit nofile=262144:262144 -v /opt/flowtrack-v2/clickhouse:/var/lib/clickhouse \
  -e CLICKHOUSE_DB=flowtrack -e CLICKHOUSE_USER=flowtrack -e CLICKHOUSE_PASSWORD=$PW clickhouse/clickhouse-server:24

# 2. GeoIP (monthly files from https://db-ip.com/db/lite.php)
sudo mkdir -p /opt/flowtrack-v2/geoip && cd /opt/flowtrack-v2/geoip
M=$(date +%Y-%m); for f in city asn; do sudo curl -sO https://download.db-ip.com/free/dbip-$f-lite-$M.mmdb.gz \
  && sudo gunzip -f dbip-$f-lite-$M.mmdb.gz && sudo mv dbip-$f-lite-$M.mmdb dbip-$f.mmdb; done

# 3. Code + venv
sudo cp -r v2 /opt/flowtrack-v2/app
sudo python3 -m venv /opt/flowtrack-v2/venv && sudo /opt/flowtrack-v2/venv/bin/pip install netflow==0.12.2 maxminddb

# 4. Config
sudo cp deploy/flowtrack-v2.env.example /etc/flowtrack-v2/env        # set FT_CH_PASSWORD=$PW, FT_EXPORTERS
sudo cp deploy/exporters.json.example /etc/flowtrack-v2/exporters.json
sudo cp deploy/hosts.json.example /etc/flowtrack-v2/hosts.json
sudo useradd --system --no-create-home --shell /usr/sbin/nologin flowtrack
sudo chown root:flowtrack /etc/flowtrack-v2/env && sudo chmod 640 /etc/flowtrack-v2/env

# 5. Services
sudo cp deploy/flowtrack2-*.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now flowtrack2-collector flowtrack2-web
```

Open `http://<collector>:3030`. The UI has no login yet — keep port 3030 LAN-only.

## Configuration

| Variable | Meaning |
|---|---|
| `FT_PORT` / `FT_BIND` | NetFlow/IPFIX UDP listener (default `0.0.0.0:2055`) |
| `FT_EXPORTERS` | allowed exporter IPs, comma-separated (empty = any) |
| `FT_FORWARD` | `host:port,…` — copy every datagram unchanged to other collectors |
| `FT_WEB_PORT` / `FT_WEB_BIND` | UI + API (default `0.0.0.0:3030`) |
| `FT_CH_*` | ClickHouse URL, user, password, database |

`exporters.json` (per exporter IP): `name`, `vendor`, `model`, `wan_ifs`, `local_if`, `public_ips`,
`city`, `country`, `lat`, `lon`, `if_names`, `sampling`.

## Not yet

sFlow, SNMP interface names, login/roles, notifications (Telegram, e-mail), template persistence
across collector restarts (the first minute after a restart is skipped until the exporter resends
its templates).
