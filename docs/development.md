# Repository layout and roadmap

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

| Path | What it is |
|---|---|
| `collector.py` | NetFlow v5/v9 + IPFIX listener, enrichment, batched inserts into ClickHouse |
| `api.py`, `auth.py` | JSON API, users and sessions, static web server |
| `common.py`, `schema.sql` | ClickHouse client, GeoIP/ASN/service enrichment; database schema |
| `topology.py` | Path analysis: layer-3 neighbours of the devices, link states, the hops of a path |
| `rollups.py` | 5-minute and hourly totals for long periods: tables, filling the history, which one a query reads |
| `backup.py` | backups and restore: ClickHouse BACKUP + settings, copies to S3 / SFTP / FTP, encryption, `flowtrack backup` / `restore` |
| `web/` | the web UI (plain HTML/CSS/JS, ECharts vendored — no build step) |
| `web/i18n/` | language dictionaries for the UI and the server's texts (see [Translations](translations.md)) |
| `deploy/` | systemd units, GeoIP refresh, configuration examples |
| `install.sh` | the one-line installer |

## Roadmap

**Next — scale and reach**
- Distributed collectors and several sites in one interface; high availability
- CI (GitHub Actions) running the test suite on every push
- Recommended server sizes for each range of records/s, measured on real hardware

**Features**
- Host names from DHCP leases (FortiGate API); SNMP interface counters cross-checked with the flows (exact link load,
  bursts shorter than 5 minutes)
- FortiGate application names from `APPLICATION_TAG` (already stored with every record, not shown yet)
- DSCP / traffic class: breakdown and colouring by QoS marking
