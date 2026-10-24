-- FlowTrack ClickHouse schema. Applied idempotently by the collector on start.
-- All timestamps are UTC.

-- One row per flow record (one direction of a session for FortiOS; whatever the exporter sends otherwise).
-- int_* = the inside endpoint, ext_* = the outside endpoint, decided per exporter (WAN interfaces) or by RFC 1918.
-- Between two inside hosts (1.7.0): int_* = the client, ext_* = the server (common.server_is_src); dir 'internal' =
-- the client's packets, 'internal_back' = the server's answer.
CREATE TABLE IF NOT EXISTS flows
(
    ts         DateTime CODEC(Delta, ZSTD),      -- flow end; used for bucketing
    ts_start   DateTime64(3) CODEC(Delta, ZSTD),
    exporter   LowCardinality(String),           -- exporter IP
    in_if      UInt32,
    out_if     UInt32,
    dir        Enum8('up' = 1, 'down' = 2, 'internal' = 3, 'transit' = 4, 'internal_back' = 5),
    int_ip     String,
    int_port   UInt16,
    ext_ip     String,
    ext_port   UInt16,
    proto      UInt8,
    nat_ip     String,
    nat_port   UInt16,
    bytes      UInt64,
    packets    UInt64,
    l7         LowCardinality(String),           -- HTTPS, QUIC, DNS, L2TP ... (from protocol + port)
    service    LowCardinality(String),           -- Google, Telegram, Cloudflare ... (from ASN / port)
    country    LowCardinality(String),           -- ISO code of ext_ip
    city       LowCardinality(String),
    lat        Float32,
    lon        Float32,
    asn        UInt32,
    as_org     LowCardinality(String),
    app_tag    UInt64,                           -- exporter-specific application id (FortiOS APPLICATION_TAG)
    sampling   UInt32 DEFAULT 1,                 -- 1 of N packets sampled; bytes/packets are already scaled up
    keep_days  UInt16 DEFAULT 30,                -- days this record is kept: the edition's retention when received
    dscp       UInt8 DEFAULT 255,                -- (1.16.0) DSCP on the way in; 255 = the exporter did not send it
    dscp_out   UInt8 DEFAULT 255                 -- (1.16.0) DSCP on the way out (a device that re-marks says so)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, int_ip, ext_ip)
TTL ts + toIntervalDay(keep_days);   -- per record; tables from before 1.3.1 are moved to it by common.flows_keep_days

-- tables from before 1.7.0: the direction of a server's answer between inside hosts (adding an Enum value only
-- changes metadata)
ALTER TABLE flows MODIFY COLUMN dir Enum8('up' = 1, 'down' = 2, 'internal' = 3, 'transit' = 4, 'internal_back' = 5);

-- (1.15.0) usage_1h (hourly totals per host, kept 3 years whatever the edition) is gone: nothing showed it, and data is
-- kept as long as the license says. The traffic of each host over the edition's days is in agg_host (rollups.py).
DROP VIEW IF EXISTS usage_1h_mv;
DROP TABLE IF EXISTS usage_1h;

-- Collector health per exporter, one row per minute.
CREATE TABLE IF NOT EXISTS exporter_stats
(
    ts            DateTime,
    exporter      LowCardinality(String),
    version       UInt16,
    packets       UInt64,
    records       UInt64,
    lost          UInt64,
    no_template   UInt64,
    decode_errors UInt64,
    templates     UInt16,
    sampling      UInt32 DEFAULT 1
)
ENGINE = MergeTree
ORDER BY (exporter, ts)
TTL ts + INTERVAL 90 DAY;

-- Receiver health, one row per minute: packets read from the socket and everything lost on the way.
-- socket_drops: the kernel discarded datagrams because the socket buffer was full (collector too slow
-- or a burst larger than the buffer); queue_drops: packets the workers could not take in time;
-- dropped_rows: decoded flows discarded because ClickHouse was unreachable for too long.
CREATE TABLE IF NOT EXISTS collector_stats
(
    ts            DateTime,
    workers       UInt8,
    packets       UInt64,
    socket_drops  UInt64,
    queue_drops   UInt64,
    dropped_rows  UInt64,
    rcvbuf        UInt32,
    rx_queue_peak UInt32,
    buffered      UInt32
)
ENGINE = MergeTree
ORDER BY ts
TTL ts + INTERVAL 90 DAY;

-- columns added after the first release (no-ops on new databases)
ALTER TABLE flows ADD COLUMN IF NOT EXISTS sampling UInt32 DEFAULT 1;
ALTER TABLE exporter_stats ADD COLUMN IF NOT EXISTS sampling UInt32 DEFAULT 1;
-- where the exporter observed the packet: 0 ingress, 1 egress, 255 not reported
ALTER TABLE flows ADD COLUMN IF NOT EXISTS obs UInt8 DEFAULT 255;
-- days the record is kept (1.3.1); common.flows_keep_days then gives older records the table's old TTL
ALTER TABLE flows ADD COLUMN IF NOT EXISTS keep_days UInt16 DEFAULT 30;
-- (1.16.0) QoS marking: records from before it are «not sent» (255)
ALTER TABLE flows ADD COLUMN IF NOT EXISTS dscp UInt8 DEFAULT 255;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS dscp_out UInt8 DEFAULT 255;
-- egress copies dropped because the same traffic was already reported on ingress
ALTER TABLE exporter_stats ADD COLUMN IF NOT EXISTS dup_dropped UInt64 DEFAULT 0;
-- packets the exporter sent again (identical except the sequence number), dropped by the receiver
ALTER TABLE exporter_stats ADD COLUMN IF NOT EXISTS dup_packets UInt64 DEFAULT 0;
-- records not stored because the edition's records/s limit was exceeded
ALTER TABLE collector_stats ADD COLUMN IF NOT EXISTS license_drops UInt64 DEFAULT 0;

-- Detections (1.6.0, detect.py). Services learned hourly: L = our address:port that outside addresses call,
-- R = an outside address:port that we call; one row per endpoint, refreshed by every learning run.
CREATE TABLE IF NOT EXISTS ev_services
(
    kind    Enum8('L' = 1, 'R' = 2),
    ip      String,
    port    UInt16,
    proto   UInt8,
    peers   UInt32,
    updated DateTime
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY (kind, ip, port, proto)
TTL updated + INTERVAL 2 DAY;

-- (1.17.0) What the detector learns from, kept as each 10-minute window is looked at (detect.keep_window), so the
-- hourly learning reads these small tables instead of a day and a week of records again every hour.
-- The candidates of learned services, per hour: L = our address:port called from outside (the outside addresses and
-- their ports), R = an outside address:port we call (our ports, and those of them that are well-known). uniq() states
-- merge into exactly what uniq() over all the records gives.
CREATE TABLE IF NOT EXISTS ev_learn_l
(
    ts      DateTime,
    ip      String,
    port    UInt16,
    proto   UInt8,
    s_peers AggregateFunction(uniq, String),
    s_ports AggregateFunction(uniq, UInt16)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, ip, port, proto)
TTL ts + INTERVAL 2 DAY;

CREATE TABLE IF NOT EXISTS ev_learn_r
(
    ts      DateTime,
    ip      String,
    port    UInt16,
    proto   UInt8,
    s_peers AggregateFunction(uniq, UInt16),
    s_low   AggregateFunction(uniqIf, UInt16, UInt8)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, ip, port, proto)
TTL ts + INTERVAL 2 DAY;

-- Each minute of the windows: sessions to each learned service of ours (svc), inbound bit/s per device (wan) and from
-- amplifier ports (refl) — the DDoS baselines are their 99th percentile over a week. A window looked at again
-- writes the same rows: read with FINAL.
CREATE TABLE IF NOT EXISTS ev_minute
(
    m        DateTime,
    kind     Enum8('svc' = 1, 'wan' = 2, 'refl' = 3),
    exporter LowCardinality(String),
    ip       String,
    port     UInt16,
    proto    UInt8,
    v        Float64
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(m)
ORDER BY (kind, exporter, ip, port, proto, m)
TTL m + INTERVAL 8 DAY;

-- (1.17.0) The minutes in which an inside host sent more than 5 Mbit/s to one outside address and port (the windows
-- keep them): «Sustained upload» reads these instead of 3 hours of records every minute.
CREATE TABLE IF NOT EXISTS ev_upload
(
    m        DateTime,
    int_ip   String,
    ext_ip   String,
    service  LowCardinality(String),
    ext_port UInt16,
    b        UInt64
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(m)
ORDER BY (m, int_ip, ext_ip, service, ext_port)
TTL m + INTERVAL 1 DAY;

-- One row per event (kind + key: the source, or the service); a window that sees it again writes a newer version
-- (ver) with last_seen, hits and info updated. Read with FINAL.
CREATE TABLE IF NOT EXISTS events
(
    kind       LowCardinality(String),
    key        String,
    first_seen DateTime,
    last_seen  DateTime,
    hits       UInt32,                   -- 10-minute windows it was seen in
    exporter   LowCardinality(String),
    src        String,
    dst        String,
    port       UInt16,
    proto      UInt8,
    value      Float64,                  -- the rule's measure at its peak (ports, sessions, addresses, bits/s)
    info       String,                   -- JSON: ports, targets, sources, country, org, asn ...
    ver        UInt64
)
ENGINE = ReplacingMergeTree(ver)
ORDER BY (kind, key, first_seen)
TTL last_seen + INTERVAL 90 DAY;

-- Interface counters from sFlow counter samples (1.7.0): the agent's own ifInOctets … as they arrive (cumulative,
-- every few seconds per interface); rates come from the difference of two rows.
CREATE TABLE IF NOT EXISTS if_counters
(
    ts           DateTime CODEC(Delta, ZSTD),
    exporter     LowCardinality(String),
    if_index     UInt32,
    if_type      UInt32,
    speed        UInt64,                         -- bit/s
    direction    UInt8,                          -- 0 unknown, 1 full duplex, 2 half, 3 in, 4 out
    status       UInt8,                          -- bit 0 admin up, bit 1 oper up
    in_octets    UInt64,
    in_ucast     UInt64,
    in_mcast     UInt64,
    in_bcast     UInt64,
    in_discards  UInt64,
    in_errors    UInt64,
    in_unknown   UInt64,
    out_octets   UInt64,
    out_ucast    UInt64,
    out_mcast    UInt64,
    out_bcast    UInt64,
    out_discards UInt64,
    out_errors   UInt64
)
ENGINE = MergeTree
ORDER BY (exporter, if_index, ts)
TTL ts + INTERVAL 90 DAY;
-- (1.14.0) counters read over SNMP every minute go here too: src 'snmp' (sFlow counter samples: 'sflow'); wide = 0 for
-- the 32-bit ifTable counters of devices without ifXTable (a wrap between two reads is undone when rates are made)
ALTER TABLE if_counters ADD COLUMN IF NOT EXISTS src LowCardinality(String) DEFAULT 'sflow';
ALTER TABLE if_counters ADD COLUMN IF NOT EXISTS wide UInt8 DEFAULT 1;

-- (1.16.2) The counters' rates in 5-minute buckets (ifcounters.Rates): Capacity reads these instead of making rates from
-- every read of every interface over the whole period each time (a FortiGate with hundreds of interfaces read every
-- minute: 21 M reads in a month, ~5 GB for one page). b = octets, sdt = seconds between the reads, pk = the busiest
-- read-to-read rate (bit/s), d 0 = into the device, 1 = out. A bucket is always made whole in one pass: one made again
-- is the same row (read with FINAL).
CREATE TABLE IF NOT EXISTS if_rate5
(
    t5       DateTime,
    exporter LowCardinality(String),
    i        UInt32,
    src      LowCardinality(String),
    d        UInt8,
    b        Int64,
    sdt      Int64,
    pk       Float64
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(t5)
ORDER BY (exporter, i, src, d, t5)
TTL t5 + INTERVAL 90 DAY;
