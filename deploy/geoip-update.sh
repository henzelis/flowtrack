#!/bin/sh
# Refresh the DB-IP Lite databases (free, CC BY 4.0). Run monthly by flowtrack2-geoip.timer.
set -eu
DIR=${FT_GEOIP_DIR:-/opt/flowtrack-v2/geoip}
mkdir -p "$DIR"
for f in city asn; do
  ok=0
  for m in "$(date +%Y-%m)" "$(date -d "$(date +%Y-%m-01) -1 day" +%Y-%m 2>/dev/null || date +%Y-%m)"; do
    if curl -fsSL "https://download.db-ip.com/free/dbip-$f-lite-$m.mmdb.gz" | gunzip > "$DIR/dbip-$f.mmdb.tmp" 2>/dev/null && [ -s "$DIR/dbip-$f.mmdb.tmp" ]; then
      mv "$DIR/dbip-$f.mmdb.tmp" "$DIR/dbip-$f.mmdb"; ok=1; break
    fi
  done
  rm -f "$DIR/dbip-$f.mmdb.tmp"
  [ "$ok" = 1 ] || { echo "geoip: could not download dbip-$f" >&2; exit 1; }
done
chmod 644 "$DIR"/dbip-*.mmdb
# the collector caches lookups; restart it so new data is used
systemctl try-restart flowtrack2-collector.service 2>/dev/null || true
