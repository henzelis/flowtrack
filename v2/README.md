# FlowTrack v2

This directory holds the current FlowTrack: `collector.py` (NetFlow v5/v9 + IPFIX → ClickHouse),
`api.py` (JSON API and web server), `auth.py` (users and sessions), `common.py` (ClickHouse client and
enrichment), `schema.sql`, the web UI in `web/` and deployment files in `deploy/`.

Features, installation, configuration and the API are documented in the
[repository README](../README.md).
