# Changelog

FlowTrack follows [semantic versioning](https://semver.org): MAJOR.MINOR.PATCH. The version is in `VERSION`, shown
in Settings → General, at the bottom of every page, in the collector log and by the installer.

## 1.3.0 — 2026-10-06

- **Online activation with a license key.** Paste a license key (`FTK-…`) in Settings → License, run
  `sudo flowtrack-license activate FTK-…`, or give it to the installer (`--license FTK-…`): FlowTrack activates it
  at the FlowTrack license server and receives a license for this server. Licenses from a key are confirmed by the
  license server every day (a lease of 30 days, so a few days without internet do not matter); Settings → License
  shows until when, the last check and a "Check now" button. Deactivating frees the key for another server at
  once; a renewed key reaches the server at its next check; a revoked one falls back to the Community limits.
- Licenses issued offline (`FTL-…`) work as before and need no network.
- The license server is `https://lic.telesphera.net:8443` with a pinned certificate; `FT_LICENSE_SERVER` in
  `/etc/flowtrack/env` points FlowTrack to another address (e.g. inside the network of the server itself), and
  the installer keeps that setting.
- Compiled core 1.3.0: trusts the license server's key for online licenses and their confirmations only.
- **License files from the license server.** A `.lic` issued by the vendor for this server's activation request works
  at once (it carries the license server's first confirmation) and is then confirmed online every day like a key —
  so it can be revoked, renewed and moved. An offline license (for closed networks) never needs the server.
- `flowtrack-license` (the command) now uses the license server set in `/etc/flowtrack/env`, like the services.
- Overview → Network traffic: one **Live / Period** switch for Map, Graph and 3D. Live shows the last 2 minutes
  (the graph used to show only that, so a host that was quiet just now showed nothing even for "last 24 hours");
  Period shows the whole selected range. An empty map or globe now says that nothing matches the filter instead of
  showing connections from the whole period while the graph was empty.
- Settings → Devices: the Sampling column shows the current ratio — after changing 1:100 back to 1:1 it kept
  showing 1:100 for up to 15 minutes.

## 1.2.0 — 2026-10-06

- **License: Elastic License 2.0** instead of MIT (1.1.0 and earlier stay MIT). FlowTrack stays free to use and
  modify; providing it as a hosted service and circumventing the license checks are not allowed.
- **Compiled core (`ftcore`).** NetFlow v5/v9 and IPFIX decoding, license checks and the edition's limits run in a
  compiled module instead of Python; the `netflow` Python package is no longer used. Stored data is the same as
  before (checked record by record on real FortiGate captures and 4,000 synthetic v5/v9/IPFIX packets). A worker
  stores 3.8–6.4 times more records per second.
- **One product for everyone.** Every feature is in every edition; a license raises only the records/s limit and
  how long flow details are kept. The Pro module, the installer's `--pro` option and `/opt/flowtrack/pro` are gone.
- The installer downloads the compiled core named in `ftcore.lock` from the GitHub release and checks its SHA-256;
  `--core FILE` installs it on servers without access to github.com. Linux x86_64 and arm64, any glibc from 2.17,
  Python 3.8 or newer. The `netflow` and `cryptography` Python packages are no longer needed (upgrades remove them).
- IPFIX that FlowTrack could not read before: variable-length fields, reduced-size counters (e.g. 3-byte octet
  counts), unknown and enterprise fields (enterprise fields were read as the standard field of the same number),
  template withdrawal, reserved set ids. A packet whose template is not known yet no longer loses the records of
  its other sets; templates in a packet apply to its data even when they come after it.

## 1.1.0 — 2026-10-06 (on main, never tagged; superseded by 1.2.0)

- **Licenses bound to the installation, activated offline.** Every installation has an Instance ID (from the machine
  ID) and shows an activation request (`FTR-…`) in Settings → License and with the new `flowtrack-license` command.
  A license (`FTL-…`) is issued for that request and works on that server only: it is bound to the machine ID and
  to the board UUID or one of the network cards, so a copied disk or a shared license does not work elsewhere.
  The codes are short enough to read out by phone; no network connection is needed. Deactivation gives a return
  code (`FTX-…`) to move the license to another server; the server refuses that license afterwards. A clock turned
  back is detected. FlowTrack 1.0 keys (`FT1.…`) are no longer accepted.
- The core checks licenses itself (the `cryptography` package is installed always); the Pro module only adds
  features. Installer: `--license CODE|FILE` no longer needs `--pro`; the summary shows the Instance ID and, in
  Community, the activation request.
- Licensing messages in Ukrainian; an event when a license does not work on this server.

## 1.0.0 — 2026-10-05

First numbered release.

- **Editions.** FlowTrack Community (this repository, MIT): up to 5,000 records/s, 14 days of flow details for new
  installs (older installs keep 30). FlowTrack Pro: a module plus a time-limited license key — no records/s limit,
  longer retention, Pro features as they ship. Installer: `--pro FILE|URL`, `--license KEY|FILE`.
- **Settings page** with tabs: General (language, version), Devices (exporters, interfaces, collector), Users
  (administrators), License. Replaces the Devices and Users pages; old links open the matching tab. An edition badge
  under the logo shows Community / Pro and warns before a license ends.
- **Custom periods** on every page: from / to to the minute, or drag across a traffic chart to zoom in; kept in the URL.
- **Flows:** a click on the exchange diagram highlights and shows details, Shift+click filters; clicks on the
  Services / Ports chart bands filter. Live windows no longer move when filters change.
- Collector: drops packets an exporter sends twice; counts records over the edition limit.
