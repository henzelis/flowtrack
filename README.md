# FlowTrack

Self-hosted flow analytics for NetFlow v5/v9 and IPFIX: who talks to whom, how much, over which
service and from where, with live views, a connection map and multi-vendor exporter support.

```
exporters ── UDP 2055 ──▶ collector ──▶ ClickHouse ◀── API + web UI ── browser :3030
 FortiGate                 enrichment     raw flows 30 d
 Cisco · MikroTik          (GeoIP, ASN,   hourly usage 3 y
 Juniper · pmacct …         NAT, L7)      exporter health
```

## Features

**Collection**
- NetFlow v5, NetFlow v9 and IPFIX; templates are tracked per exporter.
- Correct accounting of delta counters. FortiOS (like NetFlow v9/IPFIX in general) re-exports a long
  session every `active-flow-timeout`, and each export covers only its own interval — the next export's
  `FIRST_SWITCHED` equals the previous `LAST_SWITCHED`. Traffic is therefore the plain sum of records.
- Inside/outside endpoint and direction from the exporter's WAN interfaces (leaves via WAN = upload,
  arrives via WAN = download; FortiOS interface `0` = the firewall itself), or from RFC 1918 / CGNAT
  ranges when no interfaces are configured.
- Enrichment: country, city, coordinates and ASN of the outside address
  ([DB-IP Lite](https://db-ip.com/db/lite.php), CC BY 4.0), L7 protocol from protocol + port,
  service name from ASN or port, post-NAT address, inside host names from a names file and reverse DNS.
- Exporter health: records/s, templates, packets lost (sequence gaps), records skipped while waiting
  for a template.
- Optional raw forwarding (`FT_FORWARD`) so another collector keeps receiving the same feed.

**Web UI**
- *Overview*: KPIs with trend against the previous period, live inside ↔ outside exchange, connection
  map and 3D globe, top services, hosts, conversations, latest flows.
- *Flows*: top-10 inside × top-10 outside exchange (ribbon width = bytes, packets or flows; colour =
  direction), inspector for the selected host or conversation, protocols, raw flow records with NAT,
  ASN and interfaces.
- *Hosts*, *Services*, *Geolocation* (live arcs as flows arrive, countries, ASNs), *Events*
  (sustained upload, bursts, new countries, export loss), *Devices* (exporters and interfaces).
- Every value is a click-to-filter; filters can also be typed: `ip:10.0.0.5 service:Telegram -country:US port:443`.
- Login with two roles: **admin** (users, devices) and **viewer** (read-only).

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh | sudo bash
```

The installer (English or Ukrainian) installs the dependencies — Python, Docker if missing (asks
first), ClickHouse in Docker, DB-IP GeoIP databases with a monthly refresh — then asks a few questions
with defaults: free NetFlow/IPFIX and web ports (busy ports are detected and the next free one is
offered), your exporter type, its IP and WAN interface, the admin password and whether to open the ports
in ufw/firewalld. The web interface is served over **HTTPS** with an automatically generated
self-signed certificate. It finishes with the URL, the certificate fingerprint and a ready-made exporter
configuration for your vendor.

Run the same command again to **upgrade**, **reconfigure** or **uninstall**. Unattended install:

```bash
curl -fsSL https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh | \
  sudo FT_ADMIN_PASSWORD='change-me-now' FT_VENDOR=Fortinet FT_EXPORTER_IP=192.0.2.1 bash -s -- --yes
```

Supported: Debian/Ubuntu (apt) and Fedora/RHEL/Rocky/Alma (dnf) with systemd, x86_64 or arm64. Details
are logged to `/var/log/flowtrack-install.log`. The manual steps below do the same by hand.

## Requirements

- Linux host reachable from the exporters (UDP 2055), Python 3.10+, Docker (for ClickHouse).
- Disk: measured about 22 bytes per flow record after ClickHouse compression (~4.5×), i.e. roughly
  25 MB per million records. A small office exporting ~5 records/s needs about 300 MB for the 30-day
  raw retention.

## Manual install

Run from a checkout of this repository.

```bash
# 1. Service user and directories
sudo useradd --system --no-create-home --shell /usr/sbin/nologin flowtrack
sudo mkdir -p /opt/flowtrack/clickhouse /opt/flowtrack/geoip /etc/flowtrack

# 2. ClickHouse, reachable from this host only
PW=$(openssl rand -hex 16)
docker run -d --name flowtrack-ch --restart unless-stopped -p 127.0.0.1:8123:8123 --memory 4g \
  --ulimit nofile=262144:262144 -v /opt/flowtrack/clickhouse:/var/lib/clickhouse \
  -e CLICKHOUSE_DB=flowtrack -e CLICKHOUSE_USER=flowtrack -e CLICKHOUSE_PASSWORD=$PW \
  clickhouse/clickhouse-server:24

# 3. GeoIP databases (monthly files, free, CC BY 4.0)
M=$(date +%Y-%m)
for f in city asn; do
  curl -s https://download.db-ip.com/free/dbip-$f-lite-$M.mmdb.gz | gunzip | sudo tee /opt/flowtrack/geoip/dbip-$f.mmdb >/dev/null
done

# 4. Code and Python environment
sudo mkdir -p /opt/flowtrack/app && sudo cp -r *.py schema.sql web deploy /opt/flowtrack/app/
sudo python3 -m venv /opt/flowtrack/venv
sudo /opt/flowtrack/venv/bin/pip install netflow==0.12.2 maxminddb

# 5. Configuration
sudo cp deploy/flowtrack.env.example /etc/flowtrack/env
sudo sed -i "s/^FT_CH_PASSWORD=.*/FT_CH_PASSWORD=$PW/" /etc/flowtrack/env
sudo cp deploy/exporters.json.example /etc/flowtrack/exporters.json   # edit for your devices
sudo cp deploy/hosts.json.example /etc/flowtrack/hosts.json           # optional host names
sudo chown root:flowtrack /etc/flowtrack/env && sudo chmod 640 /etc/flowtrack/env

# 6. HTTPS certificate (self-signed; replace with your own if you have one)
sudo mkdir -p /etc/flowtrack/tls
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=$(hostname)" \
  -addext "subjectAltName=DNS:$(hostname),IP:$(hostname -I | awk '{print $1}')" \
  -keyout /etc/flowtrack/tls/key.pem -out /etc/flowtrack/tls/cert.pem
sudo chown -R root:flowtrack /etc/flowtrack/tls && sudo chmod 750 /etc/flowtrack/tls && sudo chmod 640 /etc/flowtrack/tls/key.pem

# 7. Services
sudo cp deploy/flowtrack-* /etc/systemd/system/ && sudo chmod +x /opt/flowtrack/app/deploy/geoip-update.sh
sudo systemctl daemon-reload
sudo systemctl enable --now flowtrack-collector flowtrack-web flowtrack-geoip.timer
```

Open `https://<collector>:3030` and sign in as **admin / flowtrack**. The UI keeps reminding you until
the password is changed (user menu → *Change password*). The schema is created by the collector on its
first start.

Services run as the unprivileged `flowtrack` user with a read-only system (`ProtectSystem=strict`);
users, sessions and devices added from the UI are stored in `/var/lib/flowtrack`.

## Configuration

`/etc/flowtrack/env`:

| Variable | Default | Meaning |
|---|---|---|
| `FT_BIND`, `FT_PORT` | `0.0.0.0`, `2055` | NetFlow/IPFIX UDP listener |
| `FT_EXPORTERS` | *(empty = any)* | allowed exporter IPs, comma-separated; devices added in the UI are allowed automatically |
| `FT_FORWARD` | *(empty)* | `host:port,…` — copy every datagram unchanged to other collectors |
| `FT_WEB_BIND`, `FT_WEB_PORT` | `0.0.0.0`, `3030` | web UI and API |
| `FT_TLS_CERT`, `FT_TLS_KEY` | `/etc/flowtrack/tls/*.pem` | HTTPS certificate and key; empty = plain HTTP |
| `FT_CH_URL`, `FT_CH_USER`, `FT_CH_PASSWORD`, `FT_CH_DB` | | ClickHouse connection |

Devices can be described in `/etc/flowtrack/exporters.json` or from the UI (*Devices → Connect
device*, admins only; the collector picks changes up within a minute):

```json
{
  "192.0.2.1": {
    "name": "fw-main", "vendor": "Fortinet", "model": "FortiGate 40F",
    "wan_ifs": [1], "local_if": 0, "public_ips": ["198.51.100.10"],
    "city": "Kyiv", "country": "UA", "lat": 50.45, "lon": 30.52,
    "if_names": {"1": "wan", "0": "local"}, "sampling": "1:1"
  }
}
```

`wan_ifs` are the exporter's interface indexes (`INPUT_SNMP`/`OUTPUT_SNMP`); `public_ips` mark traffic
the device itself originates; coordinates place the site on the map.

## Exporter configuration

**FortiGate (FortiOS 7.x)** — NetFlow v9, full rate:

```
config system netflow
    set active-flow-timeout 60
    config collectors
        edit 1
            set collector-ip <COLLECTOR_IP>
            set collector-port 2055
            set source-ip <FW_LAN_IP>
        next
    end
end
config system interface
    edit "wan"
        set netflow-sampler both
    next
end
```

`active-flow-timeout` defaults to 30 minutes; at 60 s long sessions show up in near real time. The WAN
interface index is shown by `show system interface wan | grep snmp-index`.

**Cisco IOS-XE**

```
flow exporter FLOWTRACK
 destination <COLLECTOR_IP>
 transport udp 2055
 template data timeout 60
flow monitor FT-MON
 exporter FLOWTRACK
 record netflow ipv4 original-input
interface GigabitEthernet0/0/0
 ip flow monitor FT-MON input
 ip flow monitor FT-MON output
```

**MikroTik RouterOS 7**

```
/ip traffic-flow set enabled=yes interfaces=ether1 active-flow-timeout=1m
/ip traffic-flow target add dst-address=<COLLECTOR_IP> port=2055 version=ipfix
```

**Juniper**, **pmacct / Linux** and others: the *Connect device* dialog in the UI shows ready-made
snippets.

## Security notes

- Passwords are stored as scrypt hashes with per-user salt; only SHA-256 digests of session tokens are
  stored. Sessions use an `HttpOnly`, `SameSite=Strict` cookie and expire after 7 days of inactivity.
- Five failed logins from one address within five minutes block further attempts for a while.
- Roles are enforced by the API, not only hidden in the UI.
- The web interface is HTTPS-only (TLS 1.2+). Plain `http://` on the same port is redirected to
  `https://`, and the session cookie is marked `Secure`. The installer creates a self-signed certificate
  (ECDSA P-256, valid 825 days, all host addresses in SAN) and renews it on upgrade when it expires
  within 30 days. Browsers warn about self-signed certificates once — compare the SHA-256 fingerprint
  the installer prints. To use your own certificate, place it at `/etc/flowtrack/tls/cert.pem` and
  `key.pem` (readable by group `flowtrack`) and restart `flowtrack-web`; the installer keeps it.
  `FT_TLS=no` at install time keeps plain HTTP (e.g. behind a TLS reverse proxy — then set
  `X-Forwarded-Proto: https` there).
- ClickHouse listens on `127.0.0.1` only; user filters reach it as bound query parameters.

## API

JSON over HTTP, same session cookie as the UI. Read endpoints take `range` (`1h`, `6h`, `24h`, `7d`,
`30d`) and `f` (JSON list of `{"k": …, "v": …, "neg": bool}` filters; keys `ip`, `dst`, `service`, `l7`,
`country`, `city`, `port`, `device`, `asn`, `dir`, `proto`).

| Endpoint | Returns |
|---|---|
| `GET /api/summary` | totals for the period and the previous one |
| `GET /api/series?by=` | time series, optionally split by `service`, `int_ip`, … |
| `GET /api/top?dim=` | top-N by `int_ip`, `ext_ip`, `conv`, `service`, `l7`, `country`, `city`, `asn`, `ext_port`, `exporter` |
| `GET /api/river` | top inside × top outside links (live 2-minute window or whole period) |
| `GET /api/flows`, `GET /api/live?since=` | raw records; records newer than a timestamp |
| `GET /api/geo`, `GET /api/host?ip=` | per-city aggregates; one host's details |
| `GET /api/devices`, `GET /api/alerts`, `GET /api/meta` | exporters and interfaces; detections; metadata |
| `POST /api/login`, `/api/logout`, `/api/me/password` | session and own password |
| `GET/POST /api/users…`, `POST /api/devices/save`, `/api/devices/delete` | admin only |

## Roadmap

sFlow; SNMP polling for interface names and counter cross-checks; notifications (Telegram, e-mail,
webhook); host names from DHCP leases; template persistence across collector restarts (today the first
minute after a restart is skipped until the exporter resends its templates).

## Repository layout

| Path | What it is |
|---|---|
| `collector.py` | NetFlow v5/v9 + IPFIX listener, enrichment, batched inserts into ClickHouse |
| `api.py`, `auth.py` | JSON API, users and sessions, static web server |
| `common.py`, `schema.sql` | ClickHouse client, GeoIP/ASN/service enrichment; database schema |
| `web/` | the web UI (plain HTML/CSS/JS, ECharts vendored — no build step) |
| `deploy/` | systemd units, GeoIP refresh, configuration examples |
| `install.sh` | the one-line installer |

## License

MIT — see [LICENSE](LICENSE). IP geolocation by [DB-IP](https://db-ip.com), licensed under CC BY 4.0.
