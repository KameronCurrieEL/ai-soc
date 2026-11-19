#!/usr/bin/env bash
# Download DB-IP "IP to Country Lite" (free, CC BY 4.0, no account) for OFFLINE IP -> country lookups.
# This is the only network call for geolocation: lookups never leave the machine.
# DB-IP publishes monthly; early in a month the new file may not exist yet -> fall back to last month.
set -euo pipefail

dest_dir="data/geo"
dest="$dest_dir/dbip-country-lite.csv.gz"
mkdir -p "$dest_dir"

for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"; do
  url="https://download.db-ip.com/free/dbip-country-lite-${month}.csv.gz"
  echo "trying $url"
  if curl -fsSL --max-time 120 -o "$dest.tmp" "$url"; then
    gzip -t "$dest.tmp"                       # refuse a truncated/HTML error download
    mv "$dest.tmp" "$dest"
    echo "saved $dest ($(du -h "$dest" | cut -f1), $month). Attribution: IP geolocation by DB-IP (db-ip.com)"
    exit 0
  fi
done
rm -f "$dest.tmp"
echo "download failed; the dashboard still works, public IPs show 'country unknown'" >&2
exit 1
