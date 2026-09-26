#!/usr/bin/env bash
# Drain Packet Audit and stop its dashboard. ARP/Ettercap state is independent.
set -uo pipefail

capture_unit='packet-audit@eth0.service'
web_unit='packet-audit-web@eth0.service'
failed=0

if (( EUID != 0 )); then
    printf 'Run this script as root.\n' >&2
    exit 1
fi

# The service sends SIGINT and waits for the workers, evidence writer and raw
# ring to flush. Do not kill its child processes directly.
if ! systemctl stop "$web_unit"; then
    printf 'Could not stop %s.\n' "$web_unit" >&2
    failed=1
fi
if ! systemctl stop "$capture_unit"; then
    printf 'Could not stop %s cleanly.\n' "$capture_unit" >&2
    failed=1
fi

for unit in "$web_unit" "$capture_unit"; do
    if systemctl is-active --quiet "$unit"; then
        printf '%s is still active.\n' "$unit" >&2
        failed=1
    fi
done

if (( failed != 0 )); then
    systemctl --no-pager --full status "$capture_unit" "$web_unit" >&2 || true
    exit 1
fi

result=$(systemctl show --property=Result --value "$capture_unit")
main_status=$(systemctl show --property=ExecMainStatus --value "$capture_unit")

if [[ "$main_status" == '3' ]]; then
    printf 'Packet Audit capture and dashboard are stopped.\n'
    printf 'The final capture verdict was INCOMPLETE (service exit 3).\n' >&2
    printf 'Inspect the final summary in /var/lib/packet-audit/eth0/evidence/.\n' >&2
    exit 3
fi
if [[ "$result" != 'success' || "$main_status" != '0' ]]; then
    printf 'Packet Audit is stopped, but capture exited abnormally (result=%s, status=%s).\n' "$result" "$main_status" >&2
    printf 'Inspect: journalctl -u %s -n 50 --no-pager\n' "$capture_unit" >&2
    exit 1
fi

printf 'Packet Audit capture and dashboard are stopped.\n'
printf 'The final capture verdict was complete.\n'
