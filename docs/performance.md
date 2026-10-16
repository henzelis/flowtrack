# Performance

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

Measured on 2026-10-08 with FlowTrack 1.3.3 in a VM with 4 vCPUs of an Intel Core i5-1145G7 (a laptop-class CPU)
and 4 GB of RAM; ClickHouse runs in the same VM with the 2 GiB the installer gives it on such a machine.

**Receiving.** Real FortiGate NetFlow v9 packets (about 10 records each) offered at a steady rate for 2 minutes;
counted is what was stored once the queues had drained:

| Workers (`FT_WORKERS`) | Stored completely | Above that |
|---|---|---|
| 1 | 41,700 records/s | 52,000 records/s offered → 97.8 % stored |
| 2 (the default with 4 CPU threads) | 83,300 records/s | 125,000 records/s for 15 s → 92 % stored |
| 4 | 104,000 records/s | 125,000 records/s offered → 97.2 % stored |

Short bursts above these rates are absorbed by the queues (one worker took 62,500 records/s for 15 s without loss).
Whatever does not fit is dropped at the worker queues, counted and shown in Settings → Devices — never silently. One
worker decodes and enriches about **74,000 records per second** on one core (the decoder is compiled); the rest of
the CPU goes to the receiver and to ClickHouse's inserts and merges. For scale: a small office firewall exports a few
records per second, a busy 1 Gbit/s internet edge typically a few thousand. FlowTrack Community stores up to 5,000
records/s (see [Editions](editions.md)).

**Pages.** A synthetic busy network of 40 million records a day (about 460 records/s on average; 5,000 inside hosts,
200,000 outside addresses, 12 million host–peer pairs) in the same VM. Overview page, all panels loading at once,
first load (nothing cached):

| Period | Ready in | Rows read by ClickHouse |
|---|---|---|
| 1 hour | 0.5 s | 16 million |
| 6 hours | about 2 s | 69 million |
| 24 hours | 6–7 s | 205 million |

Most of the 24 hours goes to Top conversations (pairs of an inside host and an outside address are read from the
flow records); the other panels read the 5-minute and hourly totals. Periods of several days at this scale have not
been measured yet. Answers for 6 hours or more are kept on the server for 60 s, so reloads and other users with the
same period get them at once. On a small office network (about 4 records/s, 330,000 records a day; real data) every
Overview request for 24 hours or 7 days is answered in under 0.1 s.

**A busy network (1.8.1).** 2,400 records/s — a day of about 207 million records (7.3 GiB) plus the live stream —
in a VM with 4 vCPUs and 8 GB of RAM (ClickHouse 3.9 GiB). Requests the pages send for 24 hours, nothing cached:

| Request | 1.8.0 | 1.8.1 |
|---|---|---|
| Devices list (Through device, Settings) | 30 s, failed | 2.1 s |
| Through device: paths / path inspector | 10.9 s / 3.6 s | 0.7 s / 0.2 s |
| Through device: device map | 43 s | 7.6 s |
| Path analysis: neighbours and links | 30 s, failed | 0.2 s |
| Path search | 30 s, failed | 17 s |
| Live map: age of the newest arc | 120 s and growing | 0–1 s |
