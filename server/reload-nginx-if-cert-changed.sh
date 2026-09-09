#!/bin/bash
# nginx caches certificates in memory, so a renewal on disk is invisible until
# a reload. Run this daily from cron; it only reloads when the file changed.
CERT=/volume1/docker/acme/example.com_ecc/fullchain.cer
STATE=/volume1/docker/frp/.cert-hash
LOG=/volume1/docker/frp/cert-reload.log

[ -r "$CERT" ] || { echo "$(date '+%F %T') missing cert: $CERT" >> "$LOG"; exit 1; }
NEW=$(md5sum "$CERT" | awk '{print $1}')
OLD=$(cat "$STATE" 2>/dev/null)

if [ "$NEW" != "$OLD" ]; then
  if nginx -t >/dev/null 2>&1; then
    /usr/syno/bin/synosystemctl reload nginx >/dev/null 2>&1   # Synology DSM
    # systemctl reload nginx                                    # generic Linux
    echo "$NEW" > "$STATE"
    echo "$(date '+%F %T') certificate changed -> nginx reloaded" >> "$LOG"
  else
    echo "$(date '+%F %T') nginx -t failed -> reload skipped" >> "$LOG"
  fi
fi
