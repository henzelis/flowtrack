# Install, upgrade and server commands

[← FlowSphera](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

```bash
curl -fsSL https://raw.githubusercontent.com/telesphera/flowsphera/main/install.sh | sudo bash
```

No `curl` on the host (e.g. a fresh Ubuntu Desktop)? Use `wget` — the installer then installs `curl`
itself:

```bash
wget -qO- https://raw.githubusercontent.com/telesphera/flowsphera/main/install.sh | sudo bash
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
curl -fsSL https://raw.githubusercontent.com/telesphera/flowsphera/main/install.sh | \
  sudo FT_ADMIN_PASSWORD='change-me-now' FT_VENDOR=Fortinet FT_EXPORTER_IP=192.0.2.1 bash -s -- --yes
```

Without `FT_ADMIN_PASSWORD` the installer makes a random password for `admin` and shows it at the end.

Supported: Debian/Ubuntu (apt) and Fedora/RHEL/Rocky/Alma (dnf) with systemd, x86_64 or arm64. Details
are logged to `/var/log/flowsphera-install.log`.

## Upgrade

Which version you run is shown at the bottom of every page (newer versions also in Settings → General; or
`cat /opt/flowsphera/app/VERSION` on the server).

| Your version | How to upgrade |
|---|---|
| **1.3.4 or newer** | `sudo flowsphera upgrade` |
| **1.3.3 or older** (any, from 1.0.0 on) | once: `curl -fsSL https://raw.githubusercontent.com/telesphera/flowsphera/main/install.sh \| sudo bash -s -- --upgrade --yes`<br>(no `curl`: `wget -qO- https://raw.githubusercontent.com/telesphera/flowsphera/main/install.sh \| sudo bash -s -- --upgrade --yes`)<br>from then on: `sudo flowsphera upgrade` |

The upgrade asks no questions: it installs the newest version, keeps settings, users, devices, the license and all
collected data, and restarts the services (the collector pauses for a few seconds; exporters' templates are kept).
If the newest version is already installed, `flowsphera upgrade` says so and changes nothing.

Other commands on the server:

| Command | What it does |
|---|---|
| `flowsphera status` | version, services, edition |
| `sudo flowsphera license status` / `activate KEY` / `renew` / `deactivate` | license of this server (`renew`: ask the license server for a renewal now; see [Editions](editions.md)) |
| `sudo flowsphera reconfigure` | the installer's questions again: ports, device, admin password, firewall |
| `sudo flowsphera uninstall` | remove FlowSphera; asks whether to keep the data |

## Requirements

- Linux host reachable from the exporters (UDP 2055), Python 3.10+, Docker (for ClickHouse).
- Disk: measured about 22 bytes per flow record after ClickHouse compression (~4.5×), i.e. roughly
  25 MB per million records. A small office exporting ~5 records/s needs about 300 MB for the 30-day
  raw retention. The pre-aggregated totals that make long periods fast (1.3.3) add about a fifth of that on a typical
  network, up to two thirds where hosts talk to very many different outside addresses.
