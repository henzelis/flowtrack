# API

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

JSON over HTTP, same session cookie as the UI. Read endpoints take `range` (`1h`, `6h`, `24h`, `7d`,
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
