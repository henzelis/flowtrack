<p align="center">
  <img src="docs/media/banner-en.webp" alt="FlowTrack — see every flow, trust every number" width="100%">
</p>

<p align="center">
  <a href="https://github.com/henzelis/flowtrack/tags"><img alt="Version" src="https://img.shields.io/github/v/tag/henzelis/flowtrack?filter=v*&sort=semver&style=flat-square&color=2F7BFF&label=version"></a>
  <img alt="NetFlow v5/v9 · IPFIX · sFlow v5" src="https://img.shields.io/badge/NetFlow%20v5%2Fv9%20·%20IPFIX%20·%20sFlow%20v5-27D3F5?style=flat-square">
  <img alt="Linux x86_64 · arm64" src="https://img.shields.io/badge/Linux-x86__64%20·%20arm64-0B1736?style=flat-square">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Elastic%202.0-8B5CFF?style=flat-square"></a>
</p>

<p align="center">
  <b>English</b> · <a href="README.uk.md">Українська</a>
  <br><br>
  <a href="#install-in-one-command"><b>Install</b></a> ·
  <a href="#a-tour">Tour</a> ·
  <a href="#works-with-your-equipment">Supported devices</a> ·
  <a href="#editions">Editions</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="mailto:henzelis@gmail.com?subject=FlowTrack">Contact</a>
</p>

**FlowTrack** turns the NetFlow, IPFIX and sFlow your firewalls, routers and switches already send into a clear, live
picture of your network: who talks to whom, how much, over which service, from where and along which path. It runs on
your own server, installs with one command and is ready in minutes.

<p align="center">
  <img src="docs/media/en/live-map.webp" alt="Live connection map: new connections arrive as arcs" width="100%">
</p>

## Why FlowTrack

<table>
<tr>
<td width="33%" valign="top"><b>Ready in minutes</b><br>One command installs everything — database, web interface, HTTPS — and hands you a ready-made configuration for your firewall or router.</td>
<td width="33%" valign="top"><b>Numbers you can trust</b><br>Correct accounting of long sessions, sampling and duplicate exports; every lost packet is counted and shown, never silently dropped.</td>
<td width="33%" valign="top"><b>See the path, not just the flows</b><br>How traffic crosses your devices, interface by interface — and which link really has a problem.</td>
</tr>
<tr>
<td valign="top"><b>Security built in</b><br>Port scans, password guessing, floods, contact with known malicious addresses — with alerts to Telegram and e-mail.</td>
<td valign="top"><b>Made for the wall</b><br>Live maps, a 3D globe and animated traffic views that run full screen on a NOC display — smooth, light on the CPU.</td>
<td valign="top"><b>Yours</b><br>Self-hosted, no cloud, no telemetry. Every feature is free; a license only raises the limits and activates offline.</td>
</tr>
</table>

## A tour

### Path analysis — watch traffic move through your network

Every device that exports flows, its neighbours, and the traffic on each link as both ends recorded it — in motion,
in the direction it really goes. A real gap is shown only when traffic goes in and nothing comes back; everything else
is explained in plain words. Trace any source → destination path hop by hop, with NAT.

<p align="center"><img src="docs/media/en/path-lines-live.webp" alt="Path analysis, Lines view, traffic moving along the links" width="100%"></p>

Pick the look that suits you — every user keeps their own default view:

<table>
<tr>
<td width="33%" align="center"><img src="docs/media/en/path-stars.webp" alt="Stars view"><br><b>Stars</b></td>
<td width="33%" align="center"><img src="docs/media/en/path-metro.webp" alt="Metro view"><br><b>Metro</b></td>
<td width="33%" align="center"><img src="docs/media/en/path-river.webp" alt="River view"><br><b>River</b></td>
</tr>
</table>

### Overview — the whole network at a glance

Totals with trends, the live connection map or a 3D globe, top services, hosts and conversations. Every panel opens
full screen.

<p align="center"><img src="docs/media/en/overview.webp" alt="Overview page" width="100%"></p>

<p align="center"><img src="docs/media/en/globe.webp" alt="3D globe with live connections" width="100%"></p>

### Flows — who exchanges how much with whom

The busiest inside hosts and outside addresses as a living diagram: width is volume, colour is direction. Click to
inspect, Shift+click to filter, down to the raw records with NAT, ASN and interfaces.

<p align="center"><img src="docs/media/en/flows.webp" alt="Flows page" width="100%"></p>

### Through device — inside one firewall

Input interface → device → output interface, the hosts behind each, and what each path carries.

<p align="center"><img src="docs/media/en/through-device.webp" alt="Through device page" width="100%"></p>

### Top hosts and your own networks

Name your networks once (*172.16.0.0/24 → Office*) and see the traffic, trend and main services of each — or of every
single host.

<p align="center"><img src="docs/media/en/hosts-networks.webp" alt="Top hosts by named network" width="100%"></p>

### Services, countries, ASNs

<table>
<tr>
<td width="50%"><img src="docs/media/en/services.webp" alt="Services page"></td>
<td width="50%"><img src="docs/media/en/geo.webp" alt="Geolocation page"></td>
</tr>
</table>

### Find anything by typing

`ip:10.0.0.5 service:Telegram -country:US port:443 net:Office` — the search box guides you through every filter, and
every value on every page is a click-to-filter. Any period, down to the minute; the link keeps it, so an incident view
can be shared.

<p align="center"><img src="docs/media/en/search.webp" alt="Search box with filter guide" width="80%"></p>

### Security events

Port scans, password guessing on SSH / RDP / management ports, floods and DDoS against your usual peak, inside hosts
that scan, contact with addresses on eight public reputation lists (plus your own), sustained uploads, new countries
and exporter health. FlowTrack works out who opened each connection and which of your services are public, so busy
web sites stay quiet. New events go to Telegram (your own bot) and e-mail.

## Works with your equipment

Ready configuration — with a **Copy** button — for each vendor and export protocol, right in *Settings → Devices*:

<p align="center"><img src="docs/media/en/connect-device.webp" alt="Connect a device: ready configuration with a Copy button" width="100%"></p>

**Fortinet** · **Cisco** · **MikroTik** · **Juniper** · **Palo Alto** · **Check Point** · **SonicWall** · **Huawei** ·
**Arista** · **HPE Aruba** · **VyOS / EdgeOS** · **pfSense / OPNsense** · **Linux** (pmacct, softflowd, hsflowd) · and
any other NetFlow v5 / v9, IPFIX or sFlow v5 exporter, over IPv4 or IPv6. Optional SNMP v2c / v3 names the interfaces.

## Install in one command

```bash
curl -fsSL https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh | sudo bash
```

The installer (English or Ukrainian) sets up everything, asks a few questions with sensible defaults and finishes with
the address of your FlowTrack and the configuration for your exporter. Later: `sudo flowtrack upgrade` — settings,
users and data stay.

- **Runs on** Debian / Ubuntu and Fedora / RHEL / Rocky / Alma, x86_64 or arm64.
- **Disk**: about 25 MB per million flow records; a small office needs a few hundred MB for 30 days.
- **Speed**: one decoding worker handles about 40,000 records/s, four about 100,000 — on a 4-core laptop-class CPU.

Unattended install, upgrades, all server commands: [docs/install.md](docs/install.md).

## Editions

| | **Community** — free | **Pro** — license for one server |
|---|---|---|
| Every feature, now and in future versions | ✓ | ✓ |
| Flow records per second | up to **5,000** | no limit (or per license) |
| Flow details kept | **30 days** (hourly totals: 3 years) | per license, e.g. 90 days |
| Activation | — | offline: no connection to us needed |

5,000 records/s covers homes, small and medium offices; a busy 1 Gbit/s internet edge typically exports a few thousand.
**For a Pro license, a demo or help with deployment: [henzelis@gmail.com](mailto:henzelis@gmail.com?subject=FlowTrack%20Pro).**
Details: [docs/editions.md](docs/editions.md).

## Documentation

| | |
|---|---|
| [Install and upgrade](docs/install.md) | one-line, unattended, upgrade, server commands, requirements |
| [Exporter configuration](docs/exporters.md) | FortiGate, Cisco, MikroTik, Juniper, Linux and more |
| [Features in detail](docs/features.md) | everything FlowTrack collects, computes and shows |
| [Backups and restore](docs/backups.md) | schedule, S3 / SFTP / FTP copies, encryption, restore on a new server |
| [Configuration](docs/configuration.md) | `/etc/flowtrack/env` |
| [Security](docs/security.md) | passwords, sessions, HTTPS, what runs where |
| [API](docs/api.md) | JSON endpoints and filters |
| [Performance](docs/performance.md) | measured receiving and page speeds |
| [Editions and licensing](docs/editions.md) | limits, offline activation, moving a license |
| [Translations](docs/translations.md) | adding a language: one file |
| [Repository layout and roadmap](docs/development.md) | for contributors |

## License

[Elastic License 2.0](LICENSE): free to use, run and modify, including in companies; not allowed: offering FlowTrack as
a hosted service or circumventing the license checks. The FlowTrack core (`ftcore`) ships compiled under the FlowTrack
End User License Agreement. Versions up to 1.1.0 were published under MIT and stay so. IP geolocation by
[DB-IP](https://db-ip.com), licensed under CC BY 4.0. Screenshots show demo data, no real network.
