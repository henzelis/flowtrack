-- FlowTrack ClickHouse schema. Applied idempotently by the collector on start.
-- All timestamps are UTC.

-- One row per flow record (one direction of a session for FortiOS; whatever the exporter sends otherwise).
-- int_* = the inside endpoint, ext_* = the outside endpoint, decided per exporter (WAN interfaces) or by RFC 1918.
CREATE TABLE IF NOT EXISTS flows
(
    ts         DateTime CODEC(Delta, ZSTD),      -- flow end; used for bucketing
    ts_start   DateTime64(3) CODEC(Delta, ZSTD),
    exporter   LowCardinality(String),           -- exporter IP
    in_if      UInt32,
    out_if     UInt32,
    dir        Enum8('up' = 1, 'down' = 2, 'internal' = 3, 'transit' = 4),
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
    sampling   UInt32 DEFAULT 1                  -- 1 of N packets sampled; bytes/packets are already scaled up
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, int_ip, ext_ip)
TTL ts + INTERVAL 30 DAY;

-- Long-term usage per hour x exporter x inside host x direction (kept for years; raw flows for 30 days).
CREATE TABLE IF NOT EXISTS usage_1h
(
    ts       DateTime,
    exporter LowCardinality(String),
    int_ip   String,
    dir      Enum8('up' = 1, 'down' = 2, 'internal' = 3, 'transit' = 4),
    bytes    UInt64,
    packets  UInt64,
    flows    UInt64
)
ENGINE = SummingMergeTree
ORDER BY (ts, exporter, int_ip, dir)
TTL ts + INTERVAL 3 YEAR;

CREATE MATERIALIZED VIEW IF NOT EXISTS usage_1h_mv TO usage_1h AS
SELECT toStartOfHour(ts) AS ts, exporter, int_ip, dir,
       sum(bytes) AS bytes, sum(packets) AS packets, count() AS flows
FROM flows
GROUP BY ts, exporter, int_ip, dir;

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

-- columns added after the first release (no-ops on new databases)
ALTER TABLE flows ADD COLUMN IF NOT EXISTS sampling UInt32 DEFAULT 1;
ALTER TABLE exporter_stats ADD COLUMN IF NOT EXISTS sampling UInt32 DEFAULT 1;
