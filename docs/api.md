# API

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

JSON over HTTP — with the session cookie of the UI, or with an **API token** (see below). Read endpoints take `range` (`1h`, `6h`, `24h`, `7d`,
`30d`) or `from` + `to` (unix seconds, from 1 minute up to the retention of flow details) and `f` (JSON list of `{"k": …, "v": …, "neg": bool}` filters; keys `ip` / `dst` (an address or a network such as
`172.16.0.0/24`), `net` (a named network), `service`, `l7`, `country`, `city`, `port`, `device`, `asn`, `dir`, `proto`,
`iface`, `in_if`, `out_if`, `dscp` (1.16: EF, AF41, CS1 … or 0–63); several positive filters of one key match any of them).

| Endpoint | Returns |
|---|---|
| `GET /api/summary` | totals for the period and the previous one |
| `GET /api/series?by=` | time series, optionally split by `service`, `int_ip`, … |
| `GET /api/ifload?device=` | load of each interface of a device: 5-minute in / out bit rates, average / p95 / peak and shares of the capacity |
| `GET /api/capacity?days=&tz=` | (1.13) every interface over whole local days (`days` 7 / 30 / 90 / 180 / 365, `tz` an IANA zone): daily p95 / peak in and out, the period's p95, trend, forecast (`full_in` / `over_in` days, `horizon`), status; fullest first; (1.14) `source` (`snmp` / `sflow` / `flows`), `seen_pct` {in, out} = flows' bytes against the interface counters; `days` rows end with 1 when the day came from the counters |
| `GET /api/capacity/iface?device=&if=&days=&tz=` | (1.13) one interface: weekday × hour load (`heat.in` / `heat.out`, 7 × 24 bit/s, Monday first) and the top hosts / services, `recent` vs `earlier` bytes split at `mid` |
| `GET /api/usage?period=&tz=` | (1.15) usage by host: `period` = `month` / `prev_month` / `7` / `30` / `90` / `180` / `365` (as far as the edition keeps data), `tz` an IANA zone; `total` and `prev` {up, dn, hosts} (`prev` only when the data reach back), `series` [[t, up, dn, hosts]] per day (per month over 92 days), `hosts` (500 busiest: k, name, net, up, dn, days, prev_up, prev_dn), `more` = hosts not listed. Filters and `t` as everywhere |
| `GET /api/qos` | (1.16) QoS marking under the period and filters: `classes` [{k = DSCP, bytes, packets, flows}] (255 = not reported), `series` [[t, k, bytes]], `interfaces` (class mix of what enters each), `remarked` [{device, from, to, bytes}], `both_known`, `services` (5 per class), `names` |
| `GET /api/top?dim=` | top-N by `int_ip`, `ext_ip`, `conv`, `service`, `l7`, `country`, `city`, `asn`, `ext_port`, `exporter`; `limit` 1–500 (default 10) or `all` (every row, up to 100,000 — not for `conv`); `format=csv` for a CSV file — see [Export](#export-every-host-of-a-network) |
| `GET /api/river` | top inside × top outside links (live 2-minute window or whole period) |
| `GET /api/flows`, `GET /api/live?since=` | raw records; records newer than a timestamp |
| `GET /api/geo`, `GET /api/host?ip=` | per-city aggregates; one host's details |
| `GET /api/paths`, `GET /api/devmap` | traffic through one device (the `device` filter): interface pairs, hosts behind them |
| `GET /api/topology?pov=&depth=` | layer-3 neighbours of a device, links with what each end sent and received |
| `GET /api/path?src=&dst=` | the hops from a source to a destination (address or network) across the devices |
| `GET /api/alerts` | events of the period and filters: `alerts` (every event, priority first) and `stats` — `total`, `sev` {crit, warn, info}, `kinds` {kind: {n, sev, title}}, `series` {from, to, step, rows [[t, kind, n]] = events that began in each step}, `before` (began before the period), `truncated`; (1.16.1) with `limit` (0–500) a part instead: the newest first, `offset`, `sev`, `kind`, `q` (text / address), `matched`; `tz` (IANA zone) for whole local days |
| `GET /api/devices`, `GET /api/meta` | exporters and interfaces; metadata |
| `GET /api/top?dim=net`, `GET /api/series?by=net` | traffic by your named networks |
| `GET /api/networks`, `GET /api/hosts/names`, `GET /api/ports` | your names of networks, hosts and ports |
| `GET /api/backups` | backups, their schedule and the last result |
| `POST /api/login`, `/api/logout`, `/api/me/password`, `/api/me/prefs` | session, own password, own preferences (e.g. the default Path analysis view) |
| `GET/POST /api/users…`, `POST /api/devices/save`, `/api/devices/delete` | admin only |

## API tokens

For scripts, monitoring (Zabbix, Grafana, your own) and integrations: *Settings → API → New token*. A token is shown
once — FlowTrack keeps only its SHA-256 — and is sent in a header:

```bash
curl -k -H "Authorization: Bearer ftapi_…" "https://flowtrack.example.com:3030/api/summary?range=24h&f=[]"
curl -k -H "Authorization: Bearer ftapi_…" "https://flowtrack.example.com:3030/api/top?dim=int_ip&limit=10&range=1h&f=%5B%7B%22k%22%3A%22net%22%2C%22v%22%3A%22Office%22%7D%5D"
```

| Access | What the token can do |
|---|---|
| **Read only** | every `GET` a viewer can make: the pages' data, events, devices, report PDFs |
| **Read and change** | also what an administrator reads and changes (devices, host / port / network names, events settings and exceptions, notifications, reports, backups now) |

Never with a token, whatever its access: users, tokens, the license, deleting backups, your own password. A token can
have an end date (30 / 90 / 365 days) and is revoked in *Settings → API*; the list shows when and from where each one
was last used. Wrong tokens count with the failed logins of the address: 5 in 5 minutes → `429` for a while.
Answers: `401` unknown or ended token, `403` not allowed for this token.

## Export: every host of a network

Upload and download of each host of a network over any period — for billing, reports in Excel or your own system.
`/api/top` with `dim=int_ip`, the network as a filter, the period, and `limit=all`:

```bash
TOKEN=ftapi_…            # Settings → API → New token, read only is enough
curl -k -G "https://flowtrack.example.com:3030/api/top" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'dim=int_ip' --data-urlencode 'limit=all' \
  --data-urlencode 'from=1792368000' --data-urlencode 'to=1792454400' \
  --data-urlencode 'f=[{"k":"ip","v":"10.0.1.0/24"}]'
```

```json
{"total": 27996906454, "truncated": false,
 "rows": [{"k": "10.0.1.100", "name": "nas", "up": 271794048, "dn": 15556114390, "fl": 32607, "pk": 14964092}, …]}
```

- `up` — bytes the host sent (uploaded), `dn` — bytes it received (downloaded), `fl` — flow records, `pk` — packets,
  `name` — the host's name when FlowTrack knows it; `total` — all the traffic under the filters. Rows: the busiest first.
- **The network**: `{"k":"ip","v":"10.0.1.0/24"}` (any CIDR, IPv4 or IPv6) or a named network of *Settings → Flow
  configuration*: `{"k":"net","v":"Office"}`. Any other filter narrows it further, as in the search box:
  `{"k":"device","v":"fw-main"}`, `{"k":"service","v":"YouTube"}`, `{"k":"country","v":"US","neg":true}`.
- **The period**: `from` + `to` in unix seconds, or `range=1h|6h|24h|7d|30d` (ending now); at most the days your
  edition keeps flow details (Community: 31).
- **Traffic**: `t=internet` (default, with outside addresses), `t=internal` (between your hosts), `t=all`.
- **`limit=all`** returns every host, up to 100,000; `"truncated": true` means there were more — narrow the filters (a
  smaller network, a shorter period). A number keeps to 1–500 (`0` or `-1` mean 1). Names come from what FlowTrack
  knows already: an export never starts reverse DNS lookups.
- **CSV**: add `format=csv` — a file `flowtrack-int_ip.csv` (UTF-8 with a BOM, opens in Excel as is):

```bash
curl -k -G "https://flowtrack.example.com:3030/api/top" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'dim=int_ip' --data-urlencode 'limit=all' --data-urlencode 'format=csv' \
  --data-urlencode 'range=30d' --data-urlencode 'f=[{"k":"net","v":"Office"}]' -o office-hosts.csv
```

```csv
host,name,upload_bytes,download_bytes,flows,packets,total_bytes
10.0.1.100,nas,271794048,15556114390,32607,14964092,15827908438
```

  A cut list ends with a `# truncated …` line. The same works for every other `dim` (services, countries, outside
  addresses, ports, ASNs, devices, named networks with `dim=net`): the first column is named by it.
- One host over time: `GET /api/series` with `{"k":"ip","v":"10.0.1.100"}` gives the chart's points.

## Webhooks

*Settings → Events → Notifications → Webhook*: new events go out as an HTTP `POST` with a JSON body, with the same
priority threshold, kinds and hourly limit as Telegram and e-mail (the SIEM channel below has no hourly limit). Formats: **FlowTrack JSON** (below), **Slack /
Mattermost / Rocket.Chat** (`{"text": …}`) and **Discord** (`{"content": …}`) — for those, paste their incoming
webhook address. An optional extra header (`Authorization: Bearer …`, `X-Api-Key: …`) is sent with each request.

```json
{"source": "FlowTrack", "version": "1.11.0", "link": "https://flowtrack.example.com:3030", "more": 0,
 "events": [{"kind": "port_scan", "severity": "warn", "title": "Port scan",
             "text": "203.0.113.5 (NL, Example) tried 9 ports of ours: 22, 80, 443, …",
             "details": {"src": "203.0.113.5", "hits": 3, "first_seen": "2026-10-18 10:00:00", "…": "…"}}]}
```

`more` counts events held back by the hourly limit. With a **secret**, every request carries `X-FlowTrack-Timestamp`
(unix seconds) and `X-FlowTrack-Signature: sha256=<hex>` = HMAC-SHA256(secret, `<timestamp>.<raw body>`). Check it
over the raw body and refuse old timestamps:

```python
import hashlib, hmac, time
def valid(secret, headers, body):
    ts = headers['X-FlowTrack-Timestamp']
    want = hmac.new(secret.encode(), ts.encode() + b'.' + body, hashlib.sha256).hexdigest()
    return abs(time.time() - int(ts)) < 300 and hmac.compare_digest(headers['X-FlowTrack-Signature'], 'sha256=' + want)
```

A failed delivery (no answer, not 2xx) is tried again for up to an hour; *Send a test* shows the receiver's answer.

## SIEM / syslog

*Settings → Events → Notifications → Syslog / SIEM*: every new event as its own **RFC 5424** syslog message — no hourly
limit, the priority threshold and kinds of its own. Transport **UDP** (514), **TCP** or **TLS** (6514, certificate
checked unless you untick it; messages end with a newline), facility `local0`…`local7` (syslog severity: info 6,
warn 4, crit 2). Two bodies:

**CEF** (ArcSight, QRadar, Splunk, Microsoft Sentinel):

```
<132>1 2026-10-18T15:43:03.85Z flowtrack-host FlowTrack - port_scan - CEF:0|FlowTrack|FlowTrack|1.11.0|port_scan|Port scan|6|rt=1792338183853 msg=203.0.113.5 (NL, Example) tried 9 ports of ours… src=203.0.113.5 dst=198.51.100.1 dpt=22 proto=TCP dvc=192.0.2.1 cnt=2 cs1Label=country cs1=NL cs2Label=org cs2=Example cn1Label=asn cn1=64500 cs3Label=key cs3=203.0.113.5 start=1792335600000 end=1792336200000
```

**JSON** (Elastic, Graylog, Splunk, Wazuh) — the same header, then one JSON object: `@timestamp`, `source`,
`version`, `host`, `kind`, `severity`, `title`, `text`, `src`, `dst`, `port`, `proto`, `device`, `hits`, `value`,
`first_seen`, `last_seen` (ISO 8601, UTC), `key`, `country`, `org`, `asn` and `details` (the rule's own data — ports,
targets, sources — lists cut to 50 items). CEF severity: info 3, warn 6, crit 9. *Send a test* sends one message; over
UDP check that it arrived (UDP has no answer).

