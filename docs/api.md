# API

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

JSON over HTTP — with the session cookie of the UI, or with an **API token** (see below). Read endpoints take `range` (`1h`, `6h`, `24h`, `7d`,
`30d`) or `from` + `to` (unix seconds, from 1 minute up to the retention of flow details) and `f` (JSON list of `{"k": …, "v": …, "neg": bool}` filters; keys `ip` / `dst` (an address or a network such as
`172.16.0.0/24`), `net` (a named network), `service`, `l7`, `country`, `city`, `port`, `device`, `asn`, `dir`, `proto`,
`iface`, `in_if`, `out_if`; several positive filters of one key match any of them).

| Endpoint | Returns |
|---|---|
| `GET /api/summary` | totals for the period and the previous one |
| `GET /api/series?by=` | time series, optionally split by `service`, `int_ip`, … |
| `GET /api/top?dim=` | top-N by `int_ip`, `ext_ip`, `conv`, `service`, `l7`, `country`, `city`, `asn`, `ext_port`, `exporter` |
| `GET /api/river` | top inside × top outside links (live 2-minute window or whole period) |
| `GET /api/flows`, `GET /api/live?since=` | raw records; records newer than a timestamp |
| `GET /api/geo`, `GET /api/host?ip=` | per-city aggregates; one host's details |
| `GET /api/paths`, `GET /api/devmap` | traffic through one device (the `device` filter): interface pairs, hosts behind them |
| `GET /api/topology?pov=&depth=` | layer-3 neighbours of a device, links with what each end sent and received |
| `GET /api/path?src=&dst=` | the hops from a source to a destination (address or network) across the devices |
| `GET /api/devices`, `GET /api/alerts`, `GET /api/meta` | exporters and interfaces; detections; metadata |
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

## Webhooks

*Settings → Events → Notifications → Webhook*: new events go out as an HTTP `POST` with a JSON body, with the same
priority threshold, kinds and hourly limit as Telegram and e-mail. Formats: **FlowTrack JSON** (below), **Slack /
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

