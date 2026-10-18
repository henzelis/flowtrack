# Changelog

FlowTrack follows [semantic versioning](https://semver.org): MAJOR.MINOR.PATCH. The version is in `VERSION`, shown
in Settings → General, at the bottom of every page, in the collector log and by the installer.

## 1.11.1 — 2026-10-18

- **Filter hints in the report forms**: the *Filters* field of a report and of *Report for a period* now has the guide
  of the search box — every key with an example on focus, suggestions while typing (device names, named networks,
  directions, protocols), ↑ ↓ / Tab / Enter to take one (it completes the word, nothing is applied until you save),
  and what is wrong with a value right away, also for words typed earlier. Saved filters show devices by their name.

## 1.11.0 — 2026-10-18

- **API tokens** (*Settings → API*): scripts and monitoring systems read FlowTrack — and, with a *Read and change*
  token, change what an administrator changes — through `Authorization: Bearer ftapi_…`, without a password. Shown
  once, kept as a fingerprint, optional end date, revoked with one click; the list shows when and from where each was
  last used. A token never manages users, tokens or the license, nor deletes backups; wrong tokens count with the
  failed logins. Examples and the endpoints: *Settings → API* and [docs/api.md](docs/api.md#api-tokens).
- **Webhooks** (*Settings → Events → Notifications → Webhook*): new events as an HTTP POST — FlowTrack JSON for your
  own systems, or messages to Slack, Mattermost, Rocket.Chat or Discord — with the same priority, kinds and hourly
  limit as the other channels, an optional HMAC-SHA256 signature (`X-FlowTrack-Signature`) and an extra header,
  retries for an hour, and *Send a test*.
- **SIEM / syslog export** (*Settings → Events → Notifications → Syslog / SIEM*): every new event as its own RFC 5424
  syslog message over UDP, TCP or TLS, in **CEF** (ArcSight, QRadar, Splunk, Microsoft Sentinel) or **JSON** (Elastic,
  Graylog, Splunk, Wazuh) — source, target, port, protocol, device, first / last seen, country, organisation, ASN and
  the rule's details; facility local0–local7, its own priority threshold and kinds, no hourly limit, *Send a test*.

## 1.10.0 — 2026-10-18

- **Report for a period**: the report button in the top bar makes a PDF of exactly the period and filters on screen —
  an attack or an outage you zoomed into — or of any *from – to* you type (also in Settings → Reports). Anyone can
  download it; administrators can also e-mail it to the addresses they enter. A period without records says so instead
  of showing another one.
- **Settings → General** is one even row of cards — version, edition, language, account — with the mail server
  under it. The top bar keeps one row on laptops: up to 1280 px the search has a row of its own, up to 1440 px the
  account shows as the avatar alone.
- **Scheduled reports** (Settings → Reports). A PDF of the last day, week (Monday to Sunday) or calendar month goes by
  e-mail at its hour, through the mail server of the notifications, to the report's own recipients: totals against
  the period before, traffic over time, the busiest inside hosts, outside networks, services, countries, your named
  networks, security events and the state of the devices — in English or Ukrainian, in the time zone you choose.
  A weekly report goes on the weekday you choose (for the 7 days before it), a monthly one on the day of the month you
  choose, 1–28 (for the month before it). A report can be narrowed by filters (`net:Office`, `device:…`) and to
  internet or inside traffic; *Download PDF* and *Send now* work at any time. The numbers come from the same queries as
  the pages. A report is never bare zeros: when FlowTrack has records of only a part of the period (it began collecting
  then), or of none of it yet, the report shows what there is and says so in a note on top. The mail server (SMTP) has
  its own place, *Settings → General → Mail server*, with a test letter to any address: the reports and the e-mail
  notifications both send through it (Notifications → E-mail keeps only the recipients, priority and language).
  Without it the form and the list say that nothing is sent, and a report that cannot go out or failed shows in the bell. A server
  that was off at the hour sends the report when it is back; a failed sending is tried again every 15 minutes.

## 1.9.5 — 2026-10-17

- **Templates belong to their domain** (core 1.5.0). A NetFlow v9 template id is unique only within its source ID, an
  IPFIX one within its observation domain: line cards of a router or virtual systems of a firewall may each define
  template 256 with another layout. FlowTrack kept one template per id and device, so such devices could have their
  records read with another card's layout. Now templates, the sampling rate sent in options records and the
  duplicate detection by the direction field are kept per domain; when only one domain sends the sampler options (some
  devices send them under another source ID than the flows), that rate applies to all. Templates saved by earlier
  versions serve any domain until the device resends them (within minutes). Devices with one domain, like FortiGate
  and MikroTik, count exactly as before.

## 1.9.4 — 2026-10-17

Security review fixes.

- **Forged packets cannot fill the memory** (core 1.4.2). NetFlow / IPFIX / sFlow come over UDP, whose sender address
  anyone can forge. The collector now tracks at most 16 sources that are neither configured nor in `FT_EXPORTERS`
  (`FT_MAX_NEW_EXPORTERS`; one idle for 15 minutes makes room, the log says when packets of further ones were
  ignored), and forgets idle ones in the core too; the core keeps at most 512 fields per template, 1,024 templates and
  50,000 fields per exporter, and 1,024 exporters. Before, packets from 300,000 forged addresses took 650 MB; now
  nothing grows. Configured devices are never affected.
- **Encrypted backups are trusted only encrypted.** While this server encrypts its copies, a restore from S3 / SFTP /
  FTP refuses a copy that is not encrypted (anyone able to write there could have put it); `--unencrypted` for a copy
  you made before turning encryption on. A damaged or hostile encrypted file can no longer ask for a huge scrypt cost
  or a gigabyte chunk.
- **Fonts served by FlowTrack itself.** Manrope and JetBrains Mono (SIL Open Font License 1.1, in `web/fonts/`) no
  longer load from Google: the browser asks nobody else, also on networks without internet.
- **The backup service no longer follows links.** It runs as root and writes its status into the folder of the
  `flowtrack` user; it now creates those files only anew and never through a link left there, and so do the start of
  the collector and the web service (`hw.board`). A restore of the settings removes links in the way, refuses a linked
  folder, never restores setuid bits and takes only `/etc/flowtrack/…` and `/var/lib/flowtrack/…` themselves. A copy on
  S3 / SFTP / FTP whose list names a base that is not a backup ID is refused.
- **Content-Security-Policy**: the web interface runs only its own script files (the start-up script moved out of
  the page into `boot.js`); the Server header no longer shows the Python version.
- **Changing your own password**: wrong current passwords count as failed logins (5 in 5 minutes → a pause).
- **Unattended install** without `FT_ADMIN_PASSWORD` makes a random password for `admin` and shows it at the end,
  instead of the well-known default.
- **SFTP copies** never use SHA-1 RSA signatures (`ssh-rsa`, CVE-2026-44405 in paramiko); RSA keys keep working.
- The top bar stays on one row from 1280 px wide (the search box gives way first; Ukrainian wrapped at 1400 px); on
  tablets the search gets a row of its own.
- Path analysis on a phone: the view switcher wraps instead of pushing the page sideways (Ukrainian was 30 px too wide).
- Wrong filter values (`dir:`, non-Latin digits) and a negative `since` are a 400 with the reason, not a database error;
  a bad Content-Length is a 400.

## 1.9.3 — 2026-10-17

- **Stars fills the screen.** Path analysis → Stars spreads the neighbours evenly round the Point of View (all but the
  top, where the internet is), sets a device two hops away near the one it is reached through, and lets the rings use
  the room they get — the whole screen in wall mode — instead of lining small networks up along the bottom.
- **A new README** in English and Ukrainian: what FlowTrack does and looks like, with live animations and fresh
  screenshots from the demo network; the technical chapters moved to `docs/` (install, exporters, features, backups,
  configuration, security, API, editions, performance, translations, development).

## 1.9.2 — 2026-10-16

- **No more false gaps on Path analysis.** A working network often shows two ends of a link that do not agree —
  sampled exports, sessions reported at different times, traffic coming back another way, tunnels (the inner traffic
  is on the tunnel interface), traffic to the device itself, policy drops, a big download one way — and FlowTrack
  marked all of that as a red gap. Now a **gap** is only one end sending real traffic (1 MB or more) towards the other,
  getting nothing back, while the other end's interface records nothing at all. A silent interface whose neighbour
  does receive from it is **One end silent** (amber): the link works, NetFlow is probably off on that interface.
  Everything else is **Observed**.
- **Hints say why.** The map tooltip and the Links table explain a link whose ends differ (how much one end recorded
  of what the other sent, and the usual reasons), and what to check for a gap or a silent end (NetFlow on that
  interface — the FortiGate command —, its number in Settings → Devices, the link itself; a short live window). The
  state and its hints always use all the traffic, whatever the Internet / Internal selector shows.
- **The path search agrees.** A device that recorded none of the traced traffic but carried other traffic on its
  interface on the way is **not seen here — another route?** (amber: asymmetric routing, another exit, a tunnel);
  one whose interface records nothing on a working link is **NetFlow off?** (amber); only a real gap is red.

- **The live map no longer pauses on a refresh.** Live, Path analysis asks for fresh numbers every 10 s; the moving
  traffic used to vanish and start over then, which looked like an outage. Now the particles keep flying along their
  links and the density and speed ease to the new values over a few seconds; River's strands keep their place.
- **Full screen without distortion.** Path analysis (every view, Classic too) stretched its picture to the taller
  full-screen panel — text and shapes squeezed in one direction. The map is now drawn again at the size of the panel,
  never scaled, and back at its own size when it returns to the page.

## 1.9.1 — 2026-10-16

- **Path analysis views stay alive on a quiet network.** The density and speed of the moving traffic are now set
  against the busiest link on the map (by the square root of its share), so the busiest one is always lively and the
  others in proportion; a small network or a 24-hour average no longer looks almost still.

## 1.9.0 — 2026-10-16

- **Path analysis comes alive: five map views.** A switch over the map: **Classic** (as before), **Lines** (the same
  places, thin lines, the traffic running along them as light), **Stars** (the Point of View in the middle, the
  neighbours on rings around it by hops, comets on arcs, a ring with each device's share of the traffic), **Metro**
  (stations and lines at 0 / 45 / 90 degrees, the packets as trains — clean from across the room) and **River**
  (columns by hops from the internet, bands as wide as their traffic with strands flowing by direction). The motion is
  the data: each link's traffic moves the way it really goes, as dense and as fast as its rate over the last
  2 minutes (live) or the period's average, cyan from the internet, orange to it, violet inside; gaps and links
  without traffic stay dashed. Hover, the tooltips, a click to look from a device and the path search work in every
  view; interface labels are placed where they overlap nothing. Light on the computer: one canvas, 30 frames a
  second at most, the still part drawn once; nothing moves in a hidden tab or with reduced motion.
- **Each user's own view.** A lamp marks your default view; «Make it my default» keeps it with your account, so it
  opens the same in any browser — a wall screen can stay on Stars while a desk keeps Classic.
- **Wall mode on Path analysis.** The full-screen button next to the title, as on the Overview.
- **Path analysis: the internet is a compact sign.** The big cloud over the map is now the same small «Internet» pill
  as in the waiting animation; the map gets its top third back, the WAN links go up into it as before.

## 1.8.9 — 2026-10-16

- **Full-screen lists show more.** Top hosts, Top conversations and Recent flows show 20 rows on the full screen,
  Top services 12 services and the rest; back in the page they show their usual few again.
- **The Graph full screen fills the screen.** Network traffic → Graph asks for as many inside / outside pairs as the
  height of the panel holds (15 on a 1080 p screen, 20 on a taller one) with full-size cards; back in the page it shows
  its usual 8 again, and a resized window is followed.

## 1.8.8 — 2026-10-16

- **Overview panels full screen.** A small button next to each panel's title (the map / graph / 3D, Top services,
  Top hosts, Traffic trend, Top conversations, Recent flows) opens it over the whole screen — the browser's own full
  screen, so it suits a wall display; the map, the charts and the share ring grow with it. The button again or Esc
  brings it back; opening a host card or a dialog leaves full screen first.
- **Copy buttons on ready-made texts.** The configuration for the device (Settings → Devices → Connect a device) and
  the restore command have a Copy button; it copies what the box shows at that moment (after choosing another
  vendor, protocol, sampling or interfaces).
- **Delete backups in Settings → Backups.** Delete… on a backup shows what goes (a full backup takes its changes with
  it: they cannot be restored without it), how much it frees, and when no full backup would be left; the signed-in
  administrator's own password confirms it (wrong ones count with the failed logins: 5 in 5 minutes and it waits).
  Copies on S3 / SFTP / FTP go only when ticked. On the server: `sudo flowtrack backup delete ID [--copies]`.
- **Keeping old backups says when it fails.** A backup folder or a copy that could not be deleted was passed over in
  silence (and reported as deleted); now it is in the log, on Settings → Backups ("old backups not deleted" with the
  reason) and in the exit code of `flowtrack backup prune`. An error after a backup was made (copies, keeping) no
  longer stops the run before it is recorded.

## 1.8.7 — 2026-10-16

- **Named networks.** Settings → Flow configuration → Network names: a network with its mask and a name
  (172.16.0.0/24 → Office); several networks may share one name and count together; an address belongs to the
  narrowest network that holds it. `net:Office` filters every page and the events by it (`-net:` leaves it out at
  either end; a name with spaces is typed with `_`, any case; a name typed alone is recognised too); the search box
  lists the names. Top hosts has a Hosts | Networks switch: the table, the trend, the share ring and the detail table
  by network, the addresses in none of them in a row of their own, › shows the hosts of a network. A host's panel
  names its network and filters by it.
- **Waiting fills in.** Tables waited for show rows with bars while the data is read (they showed one cycling value),
  and the answer fills in as in the waiting mock-up: the rows settle one after another, the bars grow to their value,
  share rings fill round. Through device, Path analysis, Ports, Top hosts and every other page.
- **Fixed: a port name added and removed within half a minute** left an empty rename waiting, and the collector
  logged a database error about it every minute from then on. Nothing was renamed wrongly; the waiting entry is
  cleared on upgrade.
- **Icons drawn true.** The circles of several icons were drawn with their centre one radius to the side (the
  start point of the arc lay on the circle): Path analysis (its nodes cut by the edge), Top hosts and Add user (heads
  beside the bodies), Geolocation (the dot off the pin's centre), the nodes of the panels. Through device connects
  all six ports; Settings is a gear instead of a sun (brightness); the bell's clapper is round like every other line.

## 1.8.6 — 2026-10-15

- **Filter by network.** `ip:172.16.0.0/24` keeps the inside hosts of that network on every page (what they send and
  what they receive, as a host filter does), `dst:203.0.113.0/24` the outside addresses, `-ip:10.10.0.0/16` leaves a
  network out; several networks and hosts of one key mean any of them; IPv6 too (`ip:2001:db8:1::/64`). A network
  typed alone (`172.16.0.0/24`) is taken as inside or outside by its addresses. The chip says "network". Events
  follow it. A host's panel has "The whole network /24".
- **The search box guides.** A click in it opens every filter with what it does and an example; typing suggests
  what the word can be (`ser` → `service:`, `dir:` → up / down / internal, `device:` → the devices, an address →
  inside host or outside address), ↑ ↓ to pick, Enter or Tab to take. A wrong value (`ip:10.0.0.300/24`, a /33)
  says why and is not applied.

## 1.8.5 — 2026-10-15

- **Waiting that shows the work.** A page that waits for the database no longer says only "Loading…":
  - *Through device* draws a sketch of the map at once — the device with its real interface names, the hosts as dots —
    and the lines grow host → interface → through the device → interface → address, packets running along the
    finished routes; the map takes its place when the answer comes.
  - *Path analysis* assembles the devices and their links the same way.
  - Tables "decode" (characters cycle until the answer), KPI tiles cycle one number, pie charts spin a ring with the
    share read in the middle; the answer fades in.
  - Nothing shows for answers under 0.4 s; one canvas of 30 frames a second at most (below 1 % of one core), paused
    when the browser tab is hidden; the system setting "reduce motion" leaves still pictures.
- **Progress and Cancel.** After 1.5 s a pill at the bottom says how far the database is ("Read 18.4 M of 41 M
  records · 44 % · ~4 s left", from ClickHouse's own counters of this page's queries) and has Cancel: it stops this
  page's queries on the server. `GET /api/progress`, `POST /api/cancel`.
- The "Loading…" text was Ukrainian in every language; it is gone.

## 1.8.4 — 2026-10-15

A service release: the settings are easier to find and harder to get wrong.

- Settings → **Flow configuration**, a new tab for how FlowTrack names and treats the traffic: port names (from
  General), host names (new), the roles of our services with the sensitive / public ports (from Events).
- **Port names** are a table: add one with a form (TCP / UDP, port 1–65535, a name up to 40 characters — Add works
  only when everything is right; the hint says what FlowTrack calls the port now, or that it already has a name),
  change or delete a row in place. The table shows what each port is called without your name.
- **Name a port from the report:** on the Ports page a ✎ next to the protocol opens the same name for that port.
- **Host names** of your network in the UI (IP → name, shown next to the address everywhere, over the names from
  DNS). Stored in the state folder over /etc/flowtrack/hosts.json, which stays as it is.
- Settings → **Events** in four parts — Detections, Notifications, IP reputation, Exceptions — one at a time.
- **Exceptions** are two tables with a checked form instead of free text: excluded connections (direction, source,
  target, port; any field empty = any) and ignored addresses, networks or ASNs. Saved row by row; the Events Save and
  Restore defaults keep them, and the service roles.
- **Unsaved changes:** leaving Events, Backups or Flow configuration (another tab, page or filter, closing the
  browser tab) with changes not saved asks first.
- The services on our side: the 12 busiest (and those with a role of their own) are shown, a search box and "Show
  all" for the rest — a busy network had hundreds of rows there.
- An exclusion reads "↑ 10.0.0.5 → 203.0.113.7:443" in the dialogs.
- API: `GET/POST /api/hosts/names`, `POST /api/events/exceptions`, `POST /api/events/services`; `GET /api/ports`
  returns `items` and `known`, `POST /api/ports` takes `items: [{proto, port, name}]`.

## 1.8.3 — 2026-10-15

- Several values of one filter: typed in the search box, `device:ROUTER-A` and then `device:ROUTER-B` show the traffic
  of both (any of them matches) — likewise several hosts, outside addresses, countries, services… A device can be
  typed by its name. A click on a chart or a table still replaces the value of its kind. Events follow the same rule.
- Events: exclusions of a connection in one direction — "up 10.0.0.5 -> 203.0.113.7:443" (a nightly backup from a
  host of ours), "down * -> 10.0.0.9:8443" (a monitoring system that calls our service). Settings → Events, or the
  Exclude button of an event, which proposes the rule of that event. Excluded events are neither shown nor notified.
- Port names: your own name of a protocol + port (Settings → General), e.g. "tcp/8443 HTTPS management" instead of
  "TCP other" in every report. New records get it at once, the stored records of the last 30 days within a minute,
  the totals of longer periods are summed again after the current hour.
- Devices that send RUNNING TOTALS of long sessions (seen on a FortiGate 200F: a site-to-site tunnel exported every
  30 minutes with all its bytes since the start — 16 TiB each time, hundreds of TiB a day that never existed) are
  found by the collector on their own: the same session comes again with the same start and its counters never go
  down. From then on only what a session grew by since its last export is stored, over that time. The device is
  remembered across restarts, all its packets go to one collector worker (so every export of a session is seen),
  and Settings → Devices marks it "running totals corrected". Devices that start a new interval at every export,
  or whose counters go up and down, are left alone; the records stored before the upgrade stay as they are. Core 1.4.1.

## 1.8.2 — 2026-10-15

- Path analysis opens at once on a busy network: the neighbours found in the background are shown while newer ones
  are worked out, instead of a page waiting ~20 s each time the SNMP data or the device settings had changed.
- Path analysis map: a device card grows with the links on its sides and every link end gets its own place — the
  interface name and address above its line — so labels no longer pile on each other; the map grows taller when the
  devices need it; links between devices of one column go down the column instead of around the map edge; link
  states (Gap, No observation) are drawn over the labels.
- Geolocation: Live connections lists new connections also from devices without a location; the map says which
  devices have none (lines start at a device's location — Settings → Devices, Latitude / Longitude).

## 1.8.1 — 2026-10-14

Busy networks (measured with a day of 2,400 records/s — about 200 million records — on 4 CPUs and 8 GB of RAM):
- Through device and Path analysis read new pre-aggregated totals per interface pair (5-minute paths, hourly inside
  hosts and outside addresses per path) instead of a day of records. The device list behind Through device (bytes
  per interface, the networks seen on each) reads them too. Their history is filled in the background after the
  upgrade, like the other totals.
- Path analysis works out which devices are neighbours in the background every 10 minutes (from the last hour, at
  once when the devices change); a page over a period only adds the volumes of the links.
- Live map, globe and Live connections: the newest data always — the 20 biggest connections of the last seconds,
  one per device × direction × place — instead of the oldest 300 records after the last poll, which left the map
  minutes behind and ever further. At most 20 lines on the map and the globe.
- Through device draws the 20 biggest paths by the chosen metric.
- Queries of a page the browser has left (another page, other filters) are cancelled instead of running on and
  holding up the next page; every web query has a time and memory limit and says what to do when it hits it
  (a shorter period or a filter) instead of "database error"; live views go first.
- Path search counts the conversations approximately (constant memory); finding neighbours samples half a million
  records of the hour (two million took over 1 GiB).
- Through device: the outside addresses beyond a WAN port — the biggest few are found approximately, then counted
  exactly (grouping all of a day's addresses with their names took 1.5 GiB).
- Pre-aggregated totals: the hourly ones (outside addresses, hosts × services, the new per-interface ones) fill their
  history an hour at a time. A day of a busy network in one query needed ~3 GiB, and on a server with 8 GB of RAM the
  fill failed and was tried again every minute without end.
- Restore: `flowtrack restore --only-data` also takes a backup whose settings were left out on purpose.

## 1.8.0 — 2026-10-14

- Backups: *Settings → Backups* and `sudo flowtrack backup | restore`. The flow data (ClickHouse `BACKUP`) and every
  setting (devices, users, notifications, SNMP, events, TLS certificate), on a schedule — a full backup weekly or
  daily, the changes since it on the other days — or with *Back up now*. Kept in a folder on the server
  (`/var/backups/flowtrack`, `--backup-dir` to choose another, e.g. a NAS) and copied to S3 (any S3 storage), SFTP
  (key or password, the server key checked) or FTP / FTPS; the copies can be encrypted with a passphrase
  (AES-256-GCM). Keeping by the number of full backups, here and on the copies; a failed copy is retried with the next
  backup. *Check* compares the files with ClickHouse's list (`--deep`: a restore into a scratch database).
- Restore from the folder or from S3 / SFTP / FTP, also on a new server: the current flow data is set aside until the
  backup is in place and comes back if the restore fails (`flowtrack restore --undo` after an interruption); the
  license files only with `--with-license`; a backup from a newer FlowTrack is refused.
- The installer mounts the backups folder into the ClickHouse container (the container is recreated once, the data
  stays), adds the Python packages boto3 and paramiko, and the units `flowtrack-backup.service/.timer/.path`.
  Uninstalling keeps the backups.

## 1.7.3 — 2026-10-14

- Through device follows the Internet / Internal / All traffic selector: the device map, the paths and interfaces
  tables, the totals and the path inspector show the chosen traffic (before, always all of it).
- Path analysis: the volumes on the links follow the selector too. Neighbours, link states (gaps) and the path search
  still use all traffic — two devices may class the same packets differently (one as internet, the other as inside
  traffic), so a narrower view would show gaps that are not there.

## 1.7.2 — 2026-10-14

- Connect a device: the configuration names the device's own interfaces instead of examples. With SNMP on, the form
  lists the interfaces SNMP found (name, description, addresses, down, WAN) to tick — after Test SNMP for a new device,
  from the last poll when editing; up interfaces with an address are ticked at first. With SNMP off the names are typed
  (comma-separated). The choice is kept with the device; a vendor whose configuration has no interface commands lists
  them as a note.
- Sampling in the device configuration: the device's own commands with the rate of the form instead of a note —
  FortiGate `netflow-sample-rate` (FortiOS 7.6 and newer; 7.4 and older send every session), MikroTik
  `packet-sampling`, Cisco `flow-sampler-map` for classic NetFlow v5, Huawei `ip netstream sampler fix-packets`,
  softflowd `-s`. Palo Alto, Check Point, SonicWall and pfSense / OPNsense have no sampling setting: the form warns at the
  Sampling field that a rate there would multiply their volumes.

## 1.7.1 — 2026-10-14

- Pre-aggregated tables: a record that reached the collector more than ten minutes late, just before the moment an
  upgrade to 1.3.3 or later switched the tables on, was summed up nowhere (seen as two records missing on long
  periods). Two hours after that moment the last two hours before it are now summed up again when they differ from
  the records; installs upgraded earlier get it once at the next start.
- Connect a device: the configuration for the device follows the Sampling field. sFlow uses the entered rate
  (until one is entered, the vendor's usual 1:1000 / 1:1024); NetFlow / IPFIX gets a sampler where it is set in the same
  configuration (Cisco Flexible NetFlow, Juniper, Arista, VyOS, pmacct); for the others the configuration says to set
  the same rate on the device. It changes as you type.

## 1.7.0 — 2026-10-14

- **sFlow v5.** Switches, firewalls and Linux hosts that send sFlow are received on UDP 6343 (`FT_SFLOW_PORT`; sFlow
  sent to the NetFlow port is recognised as well). The compiled core 1.4.0 decodes the sampled packet headers
  (Ethernet with VLAN tags, IPv4, IPv6 with extension headers, TCP / UDP / ICMP), sums the samples per minute and
  interfaces into flows and scales them by the sampling rate; lost datagrams are counted from their sequence numbers.
  Tested against pmacct's sFlow probe: within 0.5 % of the bytes actually transferred at 1:20 sampling.
- **Interface counters.** The counters an sFlow agent sends are kept (90 days). Settings → Devices → Interfaces
  shows each port's in / out load with its share of the speed, the speed, the state, errors and discards — ports
  without sampled traffic included.
- Connect a device: sFlow instructions for Fortinet, Cisco Nexus, Juniper, Huawei, Arista, HPE Aruba (new),
  VyOS / EdgeOS, Linux (hsflowd, pmacct) and Other, on the sFlow port: switches sample incoming traffic on every
  port; a router or firewall doing NAT samples its LAN side in both directions, not the WAN (checked on a FortiGate:
  on the WAN sFlow sees the public address, not the inside host). On a FortiGate with FortiAPs in tunnel mode sFlow
  sees Wi-Fi only as the access point's CAPWAP traffic, so the form recommends NetFlow v9 there for per-host traffic.
- Detections that count sessions (port scans, password guessing) see only the sampled part of sFlow traffic;
  floods, bursts and IP reputation work as with NetFlow. A device should send either NetFlow / IPFIX or sFlow to
  FlowTrack, not both (the traffic would count twice).
- Installer: the sFlow port when free, opened in ufw / firewalld with the others, in the summary and the
  configuration; an upgrade prints how to open it.
- Path analysis: a device that sends data without a description no longer breaks the page (it is named by its
  address).
- **Who connects to whom inside the network.** Traffic between inside hosts is kept client -> server: the host that
  started the session (by the ports: the server is on a well-known port, otherwise on the lower one) and the server
  with its service port, both directions of the session in one conversation. Upload = what the client sent to the
  server, download = what the server answered — before, every inside record counted as upload of its sender, so the
  Internal view showed no download at all, and a server's answers were named by the client's random port
  ("TCP other" instead of SSH, SMB …). Flows → Internal: clients on the left, the servers they connect to on the
  right, both directions in the ribbons; Top conversations show client, server, sent and answered.
- **Connections per host.** Top hosts → Internal: what each host sent and received, how many inside hosts it
  connected to (→) and how many connected to it (←) — a host that suddenly reaches many others is how malware
  spreads (also in the CSV export).
- Records stored before the upgrade are turned client -> server once, after the first full hour on the new version
  (the collector log says when; the per-hour usage and pre-aggregated tables are summed again for that period).
  The lateral-scan detection is unchanged: it still judges each probe by its own packets.
- Charts: the sparklines of the Internal view no longer count inside traffic twice; Unique hosts counts both ends.

## 1.6.6 — 2026-10-13

- **Export protocol per vendor.** Settings → Devices → *Connect a device* offers the protocols each vendor can send
  (NetFlow v5, NetFlow v9, IPFIX; the recommended one marked ★), with the device configuration for each. New
  vendors: Palo Alto, Check Point, SonicWall, Huawei, Arista, VyOS / EdgeOS, pfSense / OPNsense, and *Other* with
  generic instructions; Linux also shows softflowd.
- The description keeps the chosen protocol; editing a device preselects what it sends now. FlowTrack still recognises
  every packet by itself — the choice never blocks data — and the Devices page shows *expected …* when another
  protocol arrives than the description says.
- Installer: the MikroTik hint uses NetFlow v9 like the web form (was IPFIX), the Cisco one names
  `export-protocol netflow-v9`, and the end of the install points to *Connect a device* for other vendors and
  protocols.

## 1.6.5 — 2026-10-13

- Settings → Events → Notifications → Telegram: **Find chat checks an entered chat ID** with Telegram ("✓ name ·
  private chat — the chat ID is right", or why not). Before, it only listed the chats that wrote to the bot — and
  Telegram keeps those messages for 24 hours, so a working chat could show "no chats". The empty list now says so.

## 1.6.4 — 2026-10-13

- **E-mail notifications.** Settings → Events → *Notifications* now has tabs Telegram | E-mail. Any SMTP server or
  service: STARTTLS, SSL/TLS or none, the server certificate verified by default, an optional login, several
  recipients. One letter per 10-minute check (HTML with a plain-text part), critical first, with a link to the
  Events page; *Send a test* checks the way and explains what went wrong (login, recipients, STARTTLS, certificate,
  port).
- Each channel has its own switch, minimum priority, language, hourly limit and kinds (an *E-mail* column next to the
  *Telegram* one in the detections table), and sends from its own thread: a mail server that does not answer never
  holds up the detections or Telegram. The FlowTrack address for links is shared by the channels.
- The SMTP password is kept like the bot token: in /var/lib/flowtrack/notify.json (readable by the service only),
  never sent to the browser (the field shows "saved") and never written to the log.

## 1.6.3 — 2026-10-13

- **Languages are dictionaries.** The code now holds English only; every other language is one file,
  `web/i18n/<code>.json` (`uk.json` = Ukrainian), used by the web UI and the server's texts alike (errors, events,
  Telegram messages). A new language needs no code change: add a file, and it appears in the language list by
  itself. How to write one: README → *Translations*.
- The language is chosen in Settings → General, from a list of the installed languages (it left the user menu, where
  more languages would not fit). The Telegram message language uses the same list.
- Ukrainian: correct plural forms ("лишилося 5 днів", "2 експортери"), one translation for the same term across
  pages.
- A test checks the dictionaries against the code: every text translated, nothing left over, the same placeholders.

## 1.6.2 — 2026-10-12

- **Telegram notifications.** Settings → Events → *Telegram notifications*: your own bot (token from @BotFather) and
  chat; *Find chat* lists the chats that wrote to the bot, *Send a test* checks the way. A new event is sent once —
  what goes on is not sent again, and looking back over the past at the first start sends nothing. The events of one
  10-minute check go as one message, critical first, in Ukrainian or English, with a link to the Events page.
  What goes out: a minimum priority (warning by default, so the daily summaries stay quiet), a tick per kind in the
  detections table, and at most 20 messages an hour (the rest are counted in the next one).
- The bot token is kept in /var/lib/flowtrack/notify.json (readable by the service only), never sent to the browser
  (the field shows "saved") and never written to the log. Sending runs in its own thread with retries: an
  unreachable Telegram never holds up the detections.
- Settings → Events: the thresholds column of the detections table no longer breaks the table's row lines.

## 1.6.1 — 2026-10-12

- **IP reputation.** Eight free public lists of malicious addresses — abuse.ch Feodo Tracker and ThreatFox (botnet
  controllers, malware hosts), Spamhaus DROP (criminal netblocks), ET compromised, CINS Army, blocklist.de, DShield
  (hosts seen attacking), Tor exits — plus an own list in the settings. The collector downloads each once a day
  (ThreatFox every 6 hours) straight from its publisher; a failed download keeps the previous copy.
- Three new events: *Contact with malware infrastructure* (critical: a host of yours opened a connection to a botnet
  controller or malware host), *Contact with a listed address* (warning, the other lists), and *Listed addresses
  calling us* (info: one summary a day, by list). Scans, password guessing and aggressive clients say when their
  source is on a list.
- No cost on the receiving path: the detector looks the window's outside addresses up every 10 minutes, one binary
  search each in a merged table of all lists (0.3 s per window on 40 M records a day, 0.03 s on a small network).
  Lists can never flag private ranges or the whole internet (networks wider than /8, or overlapping special ranges,
  are dropped).
- Settings → Events: the lists with their entries and last update, each on or off; the own list.

## 1.6.0 — 2026-10-12

- **Port scans, password guessing and DDoS on the *Events* page.** The collector checks every 10 minutes (and the
  last day at its first start) and keeps what it finds: one event per source or service that grows while the
  activity goes on (first and last time, how often), not one line per flow.
  - *Port scan*: one outside address calls 10+ ports of yours, 3+ of your management services, or one port on 10+
    of your addresses within 10 minutes.
  - *Password guessing*: 30+ sessions from one address to a sensitive service (SSH, RDP, management, VPN portals …)
    in 10 minutes. The single knocks of internet-wide scanners are summed up instead: one *Probes of …* event a day
    per service, with the number of addresses and their countries.
  - *Aggressive client*: 200+ sessions in 10 minutes from one address to a public service (a web site).
  - *DDoS / flood*: new sessions to a service, inbound traffic of a device, or UDP from amplifier ports (DNS, NTP,
    SSDP, memcached …) at 10× its own usual peak (99th percentile of the last week) and above a floor, in 3 of 10
    minutes.
  - *Inside host scans the internet* / *Scan inside the network*: a host of yours calls many addresses or ports and
    gets no answers — a sign of malware.
- Who opened a connection is worked out from the records (NetFlow has no such field; FortiGate sends no TCP flags):
  the two records of a session and both halves of a NAT translation are joined, and the services on your side are
  learned hourly from what outside addresses call. Your web sites are recognised as public and only floods and
  aggressive clients count there; the firewall's own lookups (FortiGuard, DNS) are not mistaken for scans.
- **Settings → Events** (administrators): every kind on or off, its priority (info / warning / critical) and
  thresholds; the learned services with their role (public, sensitive, ordinary); addresses, networks and ASNs to
  ignore; the sensitive and public ports. *Ignore* on an event adds its source to the list.
- The *Events* page follows the period and the filters like every other page: a host, an outside address, a
  device, a country, an ASN or a port shows only the events about it (an address also matches the events that list
  it — a probe summary with it among the sources); filters that do not apply to events (service, protocol,
  interfaces) are named on the page. An event's *Filter* sets an outside attacker as *ext. IP* (it used to set
  *host*, which matches inside addresses only, so the other pages showed nothing). It also filters by priority and
  lists what is watched with each kind's priority.
- Firewalls export only the traffic they let through: scans of closed ports are not seen there, calls to open
  services and published ports are.
- *Geolocation → Live connections*: a very long destination no longer pushes the bytes of every row out of the
  panel until it scrolls away; long names end with “…”.

## 1.5.1 — 2026-10-09

- *Through device* shows the interfaces' addresses read over SNMP (on the device box, its tooltips and the interfaces
  table); without SNMP or a hand-entered address the networks seen in the records stay, as before.
- *Path analysis* draws the internet as one cloud above the devices: every device's WAN link goes up into it (its own
  volume and directions, the WAN interface and address beside it) and the devices sit in a row under it — a tunnel
  between two sites now shows below the internet it runs over. The internet card next to the Point of View and the
  internet chips above other devices are gone. A traced path that stays inside dims the cloud and the WAN links.
- *Path analysis* labels each link end the same way as *Through device*: the interface name, and its address under it.
- The 3D globe turns smoothly: it no longer stops for a moment (and turns back a little) at every data update every
  15 s; the mouse wheel over it scrolls the page instead of zooming the globe (that stopped the rotation until the next
  update; Ctrl/⌘ + wheel still zooms); it starts turning again 3 s after a drag.
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
  expired license gets the renewed one from the license server as soon as the vendor extended its key, without
  waiting for the daily check.
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
- The license server is `https://lic.telesphera.net:8443` with a pinned certificate; `FT_LICENSE_SERVER` in
  `/etc/flowtrack/env` points FlowTrack to another address (e.g. inside the network of the server itself), and
  the installer keeps that setting.
- Compiled core 1.3.0: trusts the license server's key for online licenses and their confirmations only.
- **License files from the license server.** A `.lic` issued by the vendor for this server's activation request works
  at once (it carries the license server's first confirmation) and is then confirmed online every day like a key —
  so it can be revoked, renewed and moved.
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

- **Licenses bound to the installation.** Every installation has an Instance ID (from the machine
  ID) and shows an activation request (`FTR-…`) in Settings → License and with the new `flowtrack-license` command.
  A license (`FTL-…`) is issued for that request and works on that server only: it is bound to the machine ID and
  to the board UUID or one of the network cards, so a copied disk or a shared license does not work elsewhere.
  Deactivation gives a return
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
