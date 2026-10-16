# Editions and licensing

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

| | **FlowTrack Community** (free) | **FlowTrack Pro** (license for one server) |
|---|---|---|
| Records per second | up to **5,000** (averaged over a minute, so bursts pass) | no limit, or per license |
| Flow details kept | **30 days** (hourly totals per host: 3 years) | per license, e.g. 90 days |
| Term | — | subscription with an end date; afterwards the Community limits apply again |
| Every feature, now and in future versions | ✓ | ✓ |

Both editions are the same software: a license changes only the limits. 5,000 records/s covers homes and small and medium offices — a busy 1 Gbit/s internet edge typically exports a
few thousand. Above the limit, records are not stored but counted: Settings → License and an event show how many.
Every flow record is kept for the days of the edition it was received under, and that is never shortened: when a
license ends, new records are kept 30 days, records received under the license keep their days but only the last
30 days are shown — older records show again with the next license. A new license keeps the stored records as long
as its own term (records are raised, never lowered), and while it is active everything stored is shown.

**Activation works offline.** A license is issued for one installation and works on that server only:

1. Settings → License (administrators) shows the **Instance ID** and an **activation request** (`FTR-…`), or run
   `sudo flowtrack license request` on the server. Send the request to your vendor — e-mail, a file, or read it out
   by phone from a closed network.
2. You receive a license (`FTL-…`, as text or a `.lic` file). Paste or load it in Settings → License, or run
   `sudo flowtrack license activate flowtrack.lic` (or `sudo flowtrack upgrade --license flowtrack.lic` to
   upgrade at the same time).

The license is bound to the server's machine ID, board UUID and network cards (as salted hashes — nothing else
leaves the server); replacing a network card or the board alone keeps it working. A copied disk or a shared
license does not work elsewhere. To move FlowTrack to another server, **deactivate** the license in Settings →
License (or `sudo flowtrack license deactivate`) and send the return code (`FTX-…`) together with the new server's
activation request. Settings → License (and the badge under the logo) warns 30 days before a license ends and an
event two weeks before.
