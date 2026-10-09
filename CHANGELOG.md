# Changelog

FlowTrack follows [semantic versioning](https://semver.org): MAJOR.MINOR.PATCH. The version is in `VERSION`, shown
in Settings → General, at the bottom of every page, in the collector log and by the installer.

## 1.5.1 — 2026-10-09

- *Through device* shows the interfaces' addresses read over SNMP (on the device box, its tooltips and the interfaces
  table); without SNMP or a hand-entered address the networks seen in the records stay, as before.
- *Path analysis* draws the internet as one cloud above the devices: every device's WAN link goes up into it (its own
  volume and directions, the WAN interface and address beside it) and the devices sit in a row under it — a tunnel
  between two sites now shows below the internet it runs over. The internet card next to the Point of View and the
  internet chips above other devices are gone. A traced path that stays inside dims the cloud and the WAN links.
- *Path analysis* labels each link end the same way as *Through device*: the interface name, and its address under it.
- The 3D globe turns smoothly: the mouse wheel over it scrolls the page instead of zooming the globe (zooming stopped the
  rotation until the next data update; Ctrl/⌘ + wheel still zooms), and it starts turning again 3 s after a drag.
- City names on the 3D globe no longer sink into it as it turns: they are drawn over the globe, only on its near side,
  fading towards the rim, one per site, without covering each other.

## 1.5.0 — 2026-10-09

- **SNMP v2c and v3.** A device can now be polled over SNMP (Settings → Devices → the device → *Read interface
  names and IP addresses over SNMP*, off by default). FlowTrack reads the interfaces' names, descriptions, state
  and IP addresses with prefix (IF-MIB, IP-MIB; IPv4 and IPv6) when the device is saved and then every hour, or
  at once with *Poll now* under Interfaces. v3 supports MD5 / SHA / SHA-224…512 authentication and DES / AES /
  AES-192 / AES-256 privacy. *Test SNMP* in the dialog polls with the typed settings before saving and names the
  likely cause of a failure (no answer, unknown user, wrong password).
- The device dialog adds the SNMP configuration for the chosen vendor (FortiGate, Cisco, MikroTik, Juniper, Linux)
  to the NetFlow snippet, filled in with the typed values. The protocol lists offer only what that vendor's agent accepts
  (RouterOS: MD5 / SHA1 and DES / AES-128; FortiOS: no AES-192; Cisco and Junos: AES-128).
- *Through device* and *Path analysis* name interfaces from SNMP and show their addresses; the subnets read over
  SNMP also place devices next to each other on *Path analysis*. Names and addresses entered by hand still win.
- *Path analysis* without interface addresses shows what the records reveal on each end, as *Through device* does:
  the network both ends share, the inside network or the NAT address.
- **Check for renewal** in Settings → License (and `sudo flowtrack license renew`) for every installed license: an
  offline or expired license gets the renewed one from the license server when the vendor extended its key (before,
  only online licenses checked in, so an offline one stayed expired until a new file was loaded). Offline licenses
  still never contact the server by themselves.
- MikroTik's NetFlow snippet exports NetFlow v9 (`version=9`) instead of IPFIX.
- Settings → Devices: interface names or addresses saved within a few seconds of opening the page showed the old
  values until the next visit.
- The installer adds the net-snmp tools (`snmp` / `net-snmp-utils`); `sudo flowtrack upgrade` installs them too.
  Community and passwords are stored for the service only (`/var/lib/flowtrack/snmp.json`, mode 600), passed to the
  tools in a private configuration file (not on the command line) and never sent back to the browser.

## 1.4.1 — 2026-10-08

- **A host filter shows what the host sent AND what it received, on every page.** Between two inside networks a
  record names the sender as the inside host, so `host: X` kept only what X sent: the replies to an SSH session or
  a web page opened from X were missing and "received" showed 0. With one host chosen, the pages now read every
  record from that host's side — sent and received, the peers as destinations, the conversations both ways; in
  *Flows* a received record shows ←. Excluding a host (`-ip:X`) leaves it out at either end. With a host chosen
  the pages read the flow records, not the 5-minute totals.
- **The inside host of traffic arriving through destination NAT.** MikroTik exports the replies to masqueraded
  hosts (and FortiGate the traffic to a VIP) with the public address as the destination and the inside host in the
  NAT field, so that traffic counted for the router's public address instead of the host. The collector now keeps
  the inside host and puts the public address into the NAT field, as for outgoing traffic. Records collected before
  the upgrade stay as they were.
- Path analysis: a host filter takes the host's packets in both directions; an internet link without traffic in the
  period is drawn as "no traffic" instead of "observed".

## 1.4.0 — 2026-10-08

- **Path analysis** — a new page next to *Through device*: traffic across several devices instead of one.
  - Choose a device as the *Point of View*: its layer-3 neighbours are drawn around it (1, 2 or 3 hops deep), each
    link as a ribbon (from / to the internet, internal) with the interface and address at both ends. A device with
    no layer-3 neighbour cannot be chosen.
  - Neighbours come from the same data as *Through device*: interfaces of two devices in one subnet (Settings →
    Devices → Interfaces) and, without any addresses set, from the records themselves — one device's own addresses
    and inside networks seen on another's interface, and the same conversation recorded by both. A tunnel between
    two sites (GRE, IPsec) is found this way too.
  - Every link shows what each end sent and the other received: a red dashed line marks a link whose far end sends
    no NetFlow, or a *gap* where much less arrived than was sent.
  - *Path*: enter a source and a destination (an address or a network) and get the hops in order — the interfaces
    each device used, NAT, other exits, the share of conversations each device recorded, and where the path is not
    seen whole. ⇄ shows the reply direction.
  - API: `GET /api/topology?pov=&depth=`, `GET /api/path?src=&dst=`.

## 1.3.4 — 2026-10-08

- **Upgrade with one command: `sudo flowtrack upgrade`.** The installer now puts a `flowtrack` command on the
  server: `upgrade` fetches the newest version and upgrades without questions (settings, users, devices and data are
  kept; it says so when the newest version is already installed; `--force` installs it again, `--license FILE`
  activates a license at the same time), `status` shows the version, services and edition, `license …` is the same
  as `flowtrack-license …`, `reconfigure` asks the installer's questions again and `uninstall` removes FlowTrack. It
  speaks the language chosen at install. Installs from before 1.3.4 get the command with one last upgrade through
  the install command (`… install.sh | sudo bash -s -- --upgrade --yes`).
- README: the manual installation steps are gone (the installer does all of it); upgrading is one line.

## 1.3.3 — 2026-10-08

Pages over hours and days read pre-aggregated totals instead of every flow record.

- **Rollup tables.** The collector keeps 5-minute totals per device × direction × service / application / protocol /
  country / AS, × port, × city, × inside host, and hourly totals per host × service and per outside address. They
  fill themselves as records arrive (materialized views) and are kept exactly as long as the records they sum.
  Overview, Top lists, trends by dimension and the period map read whole buckets from them and only the edges of a
  period from the records, so every number stays exact. Conversations, flows, paths and the host page still read
  the records. Measured on 40 million synthetic records a day, 4 vCPUs: Overview 24 h reads 191 million rows instead
  of 353 million, 21 CPU-seconds instead of 31–35, ready in ~6 s instead of ~9 s; the remaining time is mostly Top
  conversations.
- **Upgrade from any earlier version** (including 1.2 and older, whose records first get their retention per record):
  on its first start 1.3.3 creates the tables, which fill from the next bucket boundary on (5 minutes, or the next
  full hour for the hourly ones), and then adds the stored history in the background, newest day first, while
  receiving goes on. Until a day is in, pages read it from the records as before. A restart in the middle of it
  redoes the unfinished day (nothing is counted twice).
- **Disk:** the totals add about a fifth to the records on a typical network (measured on a small office: 2.1 MB next
  to 10.6 MB of records), up to two thirds where hosts talk to very many different outside addresses.
- The period map lists places with equal traffic in a fixed order (it could change between two loads).
- `FT_ROLLUPS=0` in `/etc/flowtrack/env` makes the web API read only the records (for comparisons).

## 1.3.2 — 2026-10-07

Faster pages over long periods on busy networks (reported: a VM with 4 CPUs and 8 GB of RAM, ~720 records/s, 40
million records a day — Overview for 24 hours took ~20 s at 100 % CPU and some panels failed). Measured on 40
million synthetic records a day, 4 vCPUs:

- **ClickHouse gets half of the RAM** (1–8 GiB; was a quarter rounded down to whole GiB, so 8 GB of RAM gave 1 GiB
  and the panels of one page did not fit into it together). `--upgrade` applies it to existing installs (ClickHouse
  restarts once, the collector keeps the records meanwhile).
- **Top lists read the data once:** the total for the percentages comes from the same query (it was a second full
  pass for every list); what an outside address is (service, country, city, AS) is looked up only for the addresses
  shown; distinct addresses are counted by a 64-bit hash (the same numbers, less than half the work).
- **Top conversations and Top hosts → main service** no longer run out of memory on millions of host-peer pairs:
  exact while they fit, otherwise the heaviest candidates are found with a bounded-memory count and their numbers
  are exact.
- **The same request once:** widgets of a page that ask the same question share one answer (Overview asked for the
  trend twice, and the map overlay repeated the top lists); answers over 6 hours or more are kept for 60 s on the
  server, so reloads, other users and other pages with the same period do not read the day again.

## 1.3.1 — 2026-10-07

- **Community keeps flow details for 30 days** (was 14). Compiled core 1.3.1.
- **Retention per record.** Every flow record is kept for the days of the edition it was received under (column
  `flows.keep_days`, TTL `ts + keep_days`). When a license ends, new records are kept 30 days and records received
  under the license keep their days, but the UI and the API show only the last 30 days; older records show again with
  the next license. A new license raises the stored records to its days (never lowers them); while it is active the
  UI shows everything stored. On the first start of 1.3.1 every record keeps the retention its table had (installs
  from before 1.3.1 had one TTL for the whole table), then the Community 30 days apply to records that had less.
- Settings → License explains this next to "Flow details kept"; the license-ended event names the Community days.

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
