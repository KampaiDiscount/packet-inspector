#!/usr/bin/env bash
# Start the local Kali capture and its loopback-only evidence dashboard.
set -Eeuo pipefail

capture_unit='packet-audit@eth0.service'
web_unit='packet-audit-web@eth0.service'
dashboard_url='http://127.0.0.1:8765/'

if (( EUID != 0 )); then
    printf 'Run this script as root.\n' >&2
    exit 1
fi

systemctl start "$capture_unit"
if ! systemctl is-active --quiet "$capture_unit"; then
    printf 'Packet Audit capture did not become active.\n' >&2
    systemctl --no-pager --full status "$capture_unit" >&2 || true
    exit 1
fi

if ! systemctl start "$web_unit"; then
    printf 'Capture is active, but the dashboard failed to start.\n' >&2
    systemctl --no-pager --full status "$web_unit" >&2 || true
    exit 1
fi

for _ in {1..15}; do
    if systemctl is-active --quiet "$web_unit" &&
       curl --fail --silent --show-error --max-time 2 --output /dev/null "$dashboard_url" 2>/dev/null; then
        printf 'Packet Audit capture: active (%s)\n' "$capture_unit"
        printf 'Local dashboard: ready at %s (%s)\n' "$dashboard_url" "$web_unit"
        printf 'Check the dashboard capture-health banner; an active service alone does not prove complete coverage.\n'
        exit 0
    fi
    sleep 1
done

printf 'Capture is active, but the local dashboard did not become ready.\n' >&2
systemctl --no-pager --full status "$web_unit" >&2 || true
exit 1
