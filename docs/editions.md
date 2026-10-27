# Editions and licensing

[← FlowSphera](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

| | **FlowSphera Community** (free) | **FlowSphera Pro** (license for one server) |
|---|---|---|
| Records per second | up to **5,000** (averaged over a minute, so bursts pass) | no limit, or per license |
| Data kept (flows and every total built from them) | **30 days** | per license, e.g. 90 days |
| Term | — | subscription with an end date; afterwards the Community limits apply again |
| Every feature, now and in future versions | ✓ | ✓ |

Both editions are the same software: a license changes only the limits. 5,000 records/s covers homes and small and medium offices — a busy 1 Gbit/s internet edge typically exports a
few thousand. Above the limit, records are not stored but counted: Settings → License and an event show how many.
Every flow record is kept for the days of the edition it was received under, and that is never shortened: when a
license ends, new records are kept 30 days, records received under the license keep their days but only the last
30 days are shown — older records show again with the next license. A new license keeps the stored records as long
as its own term (records are raised, never lowered), and while it is active everything stored is shown.

**Activation takes a minute.** After the purchase you receive a **license key** (`FTK-…`). Activate it on the server
where FlowSphera runs, in any of three ways:

- **Settings → License** (administrators): paste the key and press *Activate*;
- on the server: `sudo flowtrack license activate FTK-…`;
- while installing or upgrading: `… install.sh | sudo bash -s -- --license FTK-…`.

FlowSphera fetches the license from the FlowSphera license server and the new limits apply at once. The license is
bound to that server: it holds there and nowhere else, so a copied disk or a shared key does not work on another
machine. Once a day FlowSphera confirms the license with the license server and picks up a renewal by itself — nothing
to re-enter when you extend the subscription (*Check for renewal* in Settings → License, or
`sudo flowtrack license renew`, asks at once). If the server cannot be reached for a while, the license keeps working;
only after 30 days without a confirmation do the Community limits apply until it is reached again.

What leaves your server: the key or license, the server's Instance ID and salted hashes of its hardware — no flow
data, no addresses, nothing about your network.

**Moving to another server**: *Deactivate* in Settings → License (or `sudo flowtrack license deactivate`) frees the
key; then activate the same key on the new server. Settings → License (and the badge under the logo) warns 30 days
before a license ends and an event two weeks before.
