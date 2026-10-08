# FlowTrack

Self-hosted flow analytics for NetFlow v5/v9 and IPFIX: who talks to whom, how much, over which
service and from where, with live views, a connection map and multi-vendor exporter support.

```
exporters ── UDP 2055 ──▶ collector ──▶ ClickHouse ◀── API + web UI ── browser :3030
 FortiGate                 enrichment     raw flows 30 d
 Cisco · MikroTik          (GeoIP, ASN,   hourly usage 3 y
 Juniper · pmacct …         NAT, L7)      exporter health
```

## Screenshots

*Demo data (a small office and a branch); no real network is shown.*

![Overview](docs/screenshots/overview.png)

| | |
|---|---|
| ![Flows](docs/screenshots/flows.png) **Flows** — who exchanges how much with whom; click to filter | ![Top hosts](docs/screenshots/hosts.png) **Top hosts** — volume, trend, services and destinations |
| ![Geolocation](docs/screenshots/geo.png) **Geolocation** — live connection map, countries, ASNs | ![Devices](docs/screenshots/devices.png) **Devices** — exporters, interfaces, collector health |

## Features

**Collection**
- NetFlow v5, NetFlow v9 and IPFIX from exporters on IPv4 or IPv6 (the collector and the web
  interface listen on both). Templates are tracked per exporter and saved, so a collector restart does
  not drop the first minutes of data while waiting for the exporter to resend them.
- Correct accounting of delta counters. FortiOS (like NetFlow v9/IPFIX in general) re-exports a long
  session every `active-flow-timeout`, and each export covers only its own interval — the next export's
  `FIRST_SWITCHED` equals the previous `LAST_SWITCHED`. Traffic is therefore the plain sum of records.
- Inside/outside endpoint and direction from the exporter's WAN interfaces (leaves via WAN = upload,
  arrives via WAN = download; FortiOS interface `0` = the firewall itself), or from RFC 1918 / CGNAT
  ranges when no interfaces are configured.
- Enrichment: country, city, coordinates and ASN of the outside address
  ([DB-IP Lite](https://db-ip.com/db/lite.php), CC BY 4.0), L7 protocol from protocol + port,
  service name from ASN or port, post-NAT address, inside host names from a names file and reverse DNS.
- Sampled exporters: the sampling rate is read from the record itself, from NetFlow v9 / IPFIX options
  records, from the NetFlow v5 header, or taken from the device settings (`"sampling": "1:N"`), and bytes
  and packets are scaled up accordingly. The rate is stored with every record and shown per device.
- Exporter health: records/s, templates, packets lost (sequence gaps), records skipped while waiting
  for a template, effective sampling rate.
- Several decoding workers (`FT_WORKERS`): one receiver process only reads the socket and spreads
  packets over the workers, templates go to all of them — so even a single busy exporter uses many
  cores, and a slow database never stalls the socket.
- Collector health: packets dropped by the kernel (socket buffer full), by the worker queues, and records
  lost while ClickHouse was unreachable — shown in Settings → Devices and raised as an event.
- Optional raw forwarding (`FT_FORWARD`) so another collector keeps receiving the same feed.

**Web UI**
- *Overview*: KPIs with trend against the previous period, live inside ↔ outside exchange, connection
  map and 3D globe, top services, hosts, conversations, latest flows.
- *Flows*: top-10 inside × top-10 outside exchange (ribbon width = bytes, packets or flows; colour =
  direction), inspector for the selected host or conversation, protocols, raw flow records with NAT,
  ASN and interfaces.
- *Hosts*, *Services*, *Geolocation* (live arcs as flows arrive, countries, ASNs), *Events*
  (sustained upload, bursts, new countries, export loss), *Settings* — tabs for language and version, devices
  (exporters and interfaces), users, and the edition / license.
- Any period within the kept flow details (30 days in Community, see [Editions](#editions)): a preset, *Custom period…* (from / to, to the minute) or
  drag across a traffic chart to zoom in — every page follows, and the link keeps the period, so an
  incident view can be bookmarked or shared.
- Every value is a click-to-filter; filters can also be typed: `ip:10.0.0.5 service:Telegram -country:US port:443`.
- Login with two roles: **admin** (users, devices) and **viewer** (read-only).
- English and Ukrainian, switchable per browser (the user menu); the browser language picks the default.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh | sudo bash
```

No `curl` on the host (e.g. a fresh Ubuntu Desktop)? Use `wget` — the installer then installs `curl`
itself:

```bash
wget -qO- https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh | sudo bash
```

The installer (English or Ukrainian) installs the dependencies — Python, Docker if missing (asks
first), ClickHouse in Docker, DB-IP GeoIP databases, refreshed when a new monthly edition is out (checked daily) — then asks a few questions
with defaults: free NetFlow/IPFIX and web ports (busy ports are detected and the next free one is
offered), your exporter type, its IP and WAN interface, the admin password and whether to open the ports
in ufw/firewalld. The web interface is served over **HTTPS** with an automatically generated
self-signed certificate. It finishes with the URL, the certificate fingerprint and a ready-made exporter
configuration for your vendor.

Unattended install:

```bash
curl -fsSL https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh | \
  sudo FT_ADMIN_PASSWORD='change-me-now' FT_VENDOR=Fortinet FT_EXPORTER_IP=192.0.2.1 bash -s -- --yes
```

Supported: Debian/Ubuntu (apt) and Fedora/RHEL/Rocky/Alma (dnf) with systemd, x86_64 or arm64. Details
are logged to `/var/log/flowtrack-install.log`.

### Upgrade

Which version you run is shown at the bottom of every page (newer versions also in Settings → General; or
`cat /opt/flowtrack/app/VERSION` on the server).

| Your version | How to upgrade |
|---|---|
| **1.3.4 or newer** | `sudo flowtrack upgrade` |
| **1.3.3 or older** (any, from 1.0.0 on) | once: `curl -fsSL https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh \| sudo bash -s -- --upgrade --yes`<br>(no `curl`: `wget -qO- https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh \| sudo bash -s -- --upgrade --yes`)<br>from then on: `sudo flowtrack upgrade` |

The upgrade asks no questions: it installs the newest version, keeps settings, users, devices, the license and all
collected data, and restarts the services (the collector pauses for a few seconds; exporters' templates are kept).
If the newest version is already installed, `flowtrack upgrade` says so and changes nothing.

Other commands on the server:

| Command | What it does |
|---|---|
| `flowtrack status` | version, services, edition |
| `sudo flowtrack license request` / `activate FILE` / `deactivate` | license of this server (see [Editions](#editions)) |
| `sudo flowtrack reconfigure` | the installer's questions again: ports, device, admin password, firewall |
| `sudo flowtrack uninstall` | remove FlowTrack; asks whether to keep the data |

## Requirements

- Linux host reachable from the exporters (UDP 2055), Python 3.10+, Docker (for ClickHouse).
- Disk: measured about 22 bytes per flow record after ClickHouse compression (~4.5×), i.e. roughly
  25 MB per million records. A small office exporting ~5 records/s needs about 300 MB for the 30-day
  raw retention. The pre-aggregated totals that make long periods fast (1.3.3) add about a fifth of that on a typical
  network, up to two thirds where hosts talk to very many different outside addresses.

## Configuration

`/etc/flowtrack/env`:

| Variable | Default | Meaning |
|---|---|---|
| `FT_BIND`, `FT_PORT` | interface of the default route, `2055` | where NetFlow/IPFIX is received: interface name(s) and/or IP address(es), comma-separated, or `0.0.0.0` for all |
| `FT_EXPORTERS` | *(empty = any)* | allowed exporter IPs, comma-separated; devices added in the UI are allowed automatically |
| `FT_FORWARD` | *(empty)* | `host:port,…` — copy every datagram unchanged to other collectors |
| `FT_WORKERS` | `auto` | decoding processes; `auto` = half the CPU threads, at most 4 |
| | | With specific interfaces, both services also answer on localhost (health checks, `ssh -L`, a local reverse proxy) and restart themselves when an interface's address changes (DHCP). |
| `FT_RCVBUF` | `33554432` | UDP receive buffer in bytes (capped by `net.core.rmem_max`, which the installer raises to 32 MB) |
| `FT_WEB_BIND`, `FT_WEB_PORT` | interface of the default route, `3030` | web UI and API, same syntax — e.g. NetFlow on the external interface, the web UI only on the internal one |
| `FT_TLS_CERT`, `FT_TLS_KEY` | `/etc/flowtrack/tls/*.pem` | HTTPS certificate and key; empty = plain HTTP |
| `FT_CH_URL`, `FT_CH_USER`, `FT_CH_PASSWORD`, `FT_CH_DB` | | ClickHouse connection |

Devices can be described in `/etc/flowtrack/exporters.json` or from the UI (*Settings → Devices → Connect
device*, admins only; the collector picks changes up within a minute):

```json
{
  "192.0.2.1": {
    "name": "fw-main", "vendor": "Fortinet", "model": "FortiGate 100F",
    "wan_ifs": [3], "local_if": 0, "public_ips": ["198.51.100.10"],
    "city": "Amsterdam", "country": "NL", "lat": 52.37, "lon": 4.9,
    "if_names": {"3": "wan1", "0": "local"}, "sampling": "1:1"
  }
}
```

`wan_ifs` are the exporter's interface indexes (`INPUT_SNMP`/`OUTPUT_SNMP`); `public_ips` mark traffic
the device itself originates; coordinates place the site on the map.

## Exporter configuration

**Which interfaces.** Enable export on every interface whose traffic you want to see: the WAN for
internet traffic, internal interfaces (LAN, VLANs, VPN tunnels) for traffic between your own networks.
Monitoring both directions (ingress and egress) is fine: when a flow is reported on the way in and again
on the way out, FlowTrack keeps one copy if the record carries the direction field (NetFlow v9
`DIRECTION` / IPFIX `flowDirection`), and Settings → Devices warns when an exporter sends copies that
cannot be told apart. The *Internet / Internal / All* selector in the top bar switches between internet
traffic and traffic between inside addresses.

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
    edit "internal"
        set netflow-sampler both
    next
end
```

`active-flow-timeout` defaults to 30 minutes; at 60 s long sessions show up in near real time. Interface
indexes: `show system interface <name> | grep snmp-index`. FortiOS exports per session, so a session that
crosses two sampled interfaces is still reported once. Wi-Fi SSID (VAP) interfaces cannot be sampled:
traffic between two SSIDs is not visible; traffic between an SSID and a sampled interface is.
FortiOS starts exporting sessions created after the sampler was enabled.

**Cisco IOS-XE** (Flexible NetFlow) — a record with `flow direction`, so egress copies can be removed:

```
flow record FT-REC
 match ipv4 source address
 match ipv4 destination address
 match ipv4 protocol
 match transport source-port
 match transport destination-port
 match interface input
 match flow direction
 collect interface output
 collect counter bytes long
 collect counter packets long
 collect timestamp sys-uptime first
 collect timestamp sys-uptime last
flow exporter FLOWTRACK
 destination <COLLECTOR_IP>
 transport udp 2055
 template data timeout 60
flow monitor FT-MON
 exporter FLOWTRACK
 record FT-REC
 cache timeout active 60
interface GigabitEthernet0/0/0
 ip flow monitor FT-MON input
 ip flow monitor FT-MON output
interface GigabitEthernet0/0/1
 ip flow monitor FT-MON input
 ip flow monitor FT-MON output
```

**MikroTik RouterOS 7**

```
/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m
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
- Services run as the unprivileged `flowtrack` user with a read-only system (`ProtectSystem=strict`);
  users, sessions and devices added from the UI are stored in `/var/lib/flowtrack`.

## API

JSON over HTTP, same session cookie as the UI. Read endpoints take `range` (`1h`, `6h`, `24h`, `7d`,
`30d`) or `from` + `to` (unix seconds, from 1 minute up to the retention of flow details) and `f` (JSON list of `{"k": …, "v": …, "neg": bool}` filters; keys `ip`, `dst`, `service`, `l7`,
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

## Editions

| | **FlowTrack Community** (free) | **FlowTrack Pro** (license for one server) |
|---|---|---|
| Records per second | up to **5,000** (averaged over a minute, so bursts pass) | no limit, or per license |
| Flow details kept | **30 days** (hourly totals per host: 3 years) | per license, e.g. 90 days |
| Term | — | subscription with an end date; afterwards the Community limits apply again |
| Every feature, now and in future versions | ✓ | ✓ |

Both editions are the same software: a license changes only the limits. 5,000 records/s covers homes and small and medium offices — a busy 1 Gbit/s internet edge typically exports a
few thousand. Above the limit, records are not stored but counted: Settings → License and an event show how many.
Every flow record is kept for the days of the edition it was received under, and that is never shortened: when a
license ends, new records are kept 30 days, records received under the license keep their days but only the last
30 days are shown — older records show again with the next license. A new license keeps the stored records as long
as its own term (records are raised, never lowered), and while it is active everything stored is shown.

**Activation works offline.** A license is issued for one installation and works on that server only:

1. Settings → License (administrators) shows the **Instance ID** and an **activation request** (`FTR-…`), or run
   `sudo flowtrack license request` on the server. Send the request to your vendor — e-mail, a file, or read it out
   by phone from a closed network.
2. You receive a license (`FTL-…`, as text or a `.lic` file). Paste or load it in Settings → License, or run
   `sudo flowtrack license activate flowtrack.lic` (or `sudo flowtrack upgrade --license flowtrack.lic` to
   upgrade at the same time).

The license is bound to the server's machine ID, board UUID and network cards (as salted hashes — nothing else
leaves the server); replacing a network card or the board alone keeps it working. A copied disk or a shared
license does not work elsewhere. To move FlowTrack to another server, **deactivate** the license in Settings →
License (or `sudo flowtrack license deactivate`) and send the return code (`FTX-…`) together with the new server's
activation request. Settings → License (and the badge under the logo) warns 30 days before a license ends and an
event two weeks before.

## Performance

Measured on 2026-10-08 with FlowTrack 1.3.3 in a VM with 4 vCPUs of an Intel Core i5-1145G7 (a laptop-class CPU)
and 4 GB of RAM; ClickHouse runs in the same VM with the 2 GiB the installer gives it on such a machine.

**Receiving.** Real FortiGate NetFlow v9 packets (about 10 records each) offered at a steady rate for 2 minutes;
counted is what was stored once the queues had drained:

| Workers (`FT_WORKERS`) | Stored completely | Above that |
|---|---|---|
| 1 | 41,700 records/s | 52,000 records/s offered → 97.8 % stored |
| 2 (the default with 4 CPU threads) | 83,300 records/s | 125,000 records/s for 15 s → 92 % stored |
| 4 | 104,000 records/s | 125,000 records/s offered → 97.2 % stored |

Short bursts above these rates are absorbed by the queues (one worker took 62,500 records/s for 15 s without loss).
Whatever does not fit is dropped at the worker queues, counted and shown in Settings → Devices — never silently. One
worker decodes and enriches about **74,000 records per second** on one core (the decoder is compiled); the rest of
the CPU goes to the receiver and to ClickHouse's inserts and merges. For scale: a small office firewall exports a few
records per second, a busy 1 Gbit/s internet edge typically a few thousand. FlowTrack Community stores up to 5,000
records/s (see [Editions](#editions)).

**Pages.** A synthetic busy network of 40 million records a day (about 460 records/s on average; 5,000 inside hosts,
200,000 outside addresses, 12 million host–peer pairs) in the same VM. Overview page, all panels loading at once,
first load (nothing cached):

| Period | Ready in | Rows read by ClickHouse |
|---|---|---|
| 1 hour | 0.5 s | 16 million |
| 6 hours | about 2 s | 69 million |
| 24 hours | 6–7 s | 205 million |

Most of the 24 hours goes to Top conversations (pairs of an inside host and an outside address are read from the
flow records); the other panels read the 5-minute and hourly totals. Periods of several days at this scale have not
been measured yet. Answers for 6 hours or more are kept on the server for 60 s, so reloads and other users with the
same period get them at once. On a small office network (about 4 records/s, 330,000 records a day; real data) every
Overview request for 24 hours or 7 days is answered in under 0.1 s.

## Roadmap

**Next — scale and reach**
- Automated tests and CI (GitHub Actions), API tokens for scripts and monitoring

**Features**
- Notifications: Telegram, e-mail, webhook
- Host names from DHCP leases (FortiGate API) and SNMP interface names / counter cross-checks
- sFlow v5
- FortiGate application names from `APPLICATION_TAG`
- DSCP / traffic class: breakdown and colouring by QoS marking
- Detections: port scans, IP reputation lists
- Scheduled reports; configurable retention; ClickHouse backups

## Repository layout

| Path | What it is |
|---|---|
| `collector.py` | NetFlow v5/v9 + IPFIX listener, enrichment, batched inserts into ClickHouse |
| `api.py`, `auth.py` | JSON API, users and sessions, static web server |
| `common.py`, `schema.sql` | ClickHouse client, GeoIP/ASN/service enrichment; database schema |
| `rollups.py` | 5-minute and hourly totals for long periods: tables, filling the history, which one a query reads |
| `web/` | the web UI (plain HTML/CSS/JS, ECharts vendored — no build step) |
| `deploy/` | systemd units, GeoIP refresh, configuration examples |
| `install.sh` | the one-line installer |

## License

[Elastic License 2.0](LICENSE): free to use, run and modify, including in companies; not allowed: offering
FlowTrack as a hosted service or circumventing the license checks. The FlowTrack core (`ftcore`) ships compiled under
the FlowTrack End User License Agreement. Versions up to 1.1.0 were published under MIT and stay so.
IP geolocation by [DB-IP](https://db-ip.com), licensed under CC BY 4.0.
