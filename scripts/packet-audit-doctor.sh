#!/usr/bin/env bash
# Read-only Kali preflight for Packet Audit.

set -uo pipefail

CONFIG_PATH="/etc/packet-audit/packet-audit.toml"
INTERFACE=""
SERVICE_USER="packet-audit"
STATE_ROOT="/var/lib/packet-audit"
ERRORS=0
WARNINGS=0

usage() {
    cat <<'EOF'
Usage: packet-audit-doctor [OPTIONS]

Read-only preflight for an authorized Packet Audit capture.

Options:
  --config PATH       TOML configuration path
  --interface NAME    Interface override (otherwise read from the config)
  --service-user USER Account expected to run the systemd service
  --state-root PATH   Base state directory (default: /var/lib/packet-audit)
  -h, --help          Show this help
EOF
}

while (($#)); do
    case "$1" in
        --config)
            (($# >= 2)) || { printf 'missing value for --config\n' >&2; exit 2; }
            CONFIG_PATH="$2"
            shift 2
            ;;
        --interface)
            (($# >= 2)) || { printf 'missing value for --interface\n' >&2; exit 2; }
            INTERFACE="$2"
            shift 2
            ;;
        --service-user)
            (($# >= 2)) || { printf 'missing value for --service-user\n' >&2; exit 2; }
            SERVICE_USER="$2"
            shift 2
            ;;
        --state-root)
            (($# >= 2)) || { printf 'missing value for --state-root\n' >&2; exit 2; }
            STATE_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

ok() {
    printf '[ OK ] %s\n' "$*"
}

warn() {
    WARNINGS=$((WARNINGS + 1))
    printf '[WARN] %s\n' "$*" >&2
}

fail() {
    ERRORS=$((ERRORS + 1))
    printf '[FAIL] %s\n' "$*" >&2
}

require_command() {
    local command_name="$1"
    if command -v "${command_name}" >/dev/null 2>&1; then
        ok "command available: ${command_name}"
    else
        fail "required command is missing: ${command_name}"
    fi
}

for required in python3 ip dumpcap getcap stat df id timeout tail od; do
    require_command "${required}"
done

if ((ERRORS)); then
    printf '\nPreflight cannot continue: %d required command(s) missing.\n' "${ERRORS}" >&2
    exit 1
fi

if [[ ! -r "${CONFIG_PATH}" ]]; then
    fail "configuration is not readable: ${CONFIG_PATH}"
else
    ok "configuration is readable: ${CONFIG_PATH}"
fi

CONFIG_INTERFACE=""
OUTPUT_JSONL=""
OPERATIONAL_JSONL=""
CONSOLE_UNREDACTED=""
CONSOLE_FINDINGS=""
RAW_CAPTURE_DIR=""
RAW_ENABLED=""
RAW_FILE_MB=""
RAW_FILES=""
RAW_DURATION=""
STOP_ON_RAW_FAILURE=""

if [[ -r "${CONFIG_PATH}" ]]; then
    config_dump="$(python3 - "${CONFIG_PATH}" <<'PY'
from pathlib import Path
import sys
import tomllib

path = Path(sys.argv[1])
try:
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"CONFIG_ERROR={type(exc).__name__}: {exc}")
    raise SystemExit(1)

capture = cfg.get("capture", {})
output = cfg.get("output", {})
raw = cfg.get("raw_capture", {})
values = {
    "CONFIG_INTERFACE": capture.get("interface", ""),
    "OUTPUT_JSONL": output.get("output_jsonl", "./evidence/findings-unredacted.jsonl"),
    "OPERATIONAL_JSONL": output.get("operational_jsonl", "./evidence/operations.jsonl"),
    "CONSOLE_UNREDACTED": str(output.get("console_unredacted", False)).lower(),
    "CONSOLE_FINDINGS": str(output.get("console_findings", False)).lower(),
    "RAW_CAPTURE_DIR": raw.get("raw_capture_dir", "./evidence/pcap-ring"),
    "RAW_ENABLED": str(raw.get("raw_capture_enabled", True)).lower(),
    "RAW_FILE_MB": raw.get("raw_capture_file_mb", 256),
    "RAW_FILES": raw.get("raw_capture_files", 24),
    "RAW_DURATION": raw.get("raw_capture_duration_seconds", 300),
    "STOP_ON_RAW_FAILURE": str(raw.get("stop_on_raw_capture_failure", True)).lower(),
}
for key, value in values.items():
    text = str(value).replace("\n", " ").replace("\r", " ")
    print(f"{key}={text}")
PY
    )"
    config_status=$?
    if ((config_status != 0)); then
        fail "configuration TOML could not be parsed: ${config_dump}"
    else
        while IFS='=' read -r key value; do
            case "${key}" in
                CONFIG_INTERFACE) CONFIG_INTERFACE="${value}" ;;
                OUTPUT_JSONL) OUTPUT_JSONL="${value}" ;;
                OPERATIONAL_JSONL) OPERATIONAL_JSONL="${value}" ;;
                CONSOLE_UNREDACTED) CONSOLE_UNREDACTED="${value}" ;;
                CONSOLE_FINDINGS) CONSOLE_FINDINGS="${value}" ;;
                RAW_CAPTURE_DIR) RAW_CAPTURE_DIR="${value}" ;;
                RAW_ENABLED) RAW_ENABLED="${value}" ;;
                RAW_FILE_MB) RAW_FILE_MB="${value}" ;;
                RAW_FILES) RAW_FILES="${value}" ;;
                RAW_DURATION) RAW_DURATION="${value}" ;;
                STOP_ON_RAW_FAILURE) STOP_ON_RAW_FAILURE="${value}" ;;
            esac
        done <<<"${config_dump}"
        ok "configuration TOML parsed"
    fi
fi

if [[ "${CONSOLE_FINDINGS}" == "true" ]]; then
    warn "console_findings=true can create high journal volume and writer backpressure"
else
    ok "per-finding console notices are disabled"
fi

if [[ "${CONSOLE_UNREDACTED}" == "true" ]]; then
    fail "console_unredacted=true would place secret material in the service journal"
else
    ok "unredacted console output is disabled"
fi

if [[ -z "${INTERFACE}" ]]; then
    INTERFACE="${CONFIG_INTERFACE}"
fi

if [[ -z "${INTERFACE}" ]]; then
    fail "no interface was supplied and capture.interface is empty"
elif [[ ! "${INTERFACE}" =~ ^[[:alnum:]_.:-]{1,15}$ ]]; then
    fail "interface name is not a safe Linux interface identifier: ${INTERFACE}"
elif [[ ! -d "/sys/class/net/${INTERFACE}" ]]; then
    fail "kernel interface does not exist: ${INTERFACE}"
else
    ok "kernel interface exists: ${INTERFACE}"
    if ip link show dev "${INTERFACE}" | grep -q 'state UP'; then
        ok "interface reports state UP: ${INTERFACE}"
    else
        warn "interface is present but does not report state UP: ${INTERFACE}"
    fi
    if [[ "${INTERFACE}" == "lo" ]]; then
        warn "loopback was selected; confirm that this is the intended evidence source"
    fi
fi

if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    ok "service account exists: ${SERVICE_USER}"
    service_groups="$(id -nG "${SERVICE_USER}" 2>/dev/null || true)"
    if tr ' ' '\n' <<<"${service_groups}" | grep -qx 'wireshark'; then
        ok "${SERVICE_USER} belongs to the wireshark capture group"
    else
        fail "${SERVICE_USER} is not a member of the wireshark capture group"
    fi
else
    fail "service account does not exist: ${SERVICE_USER}"
fi

DUMPCAP_PATH="$(command -v dumpcap)"
DUMPCAP_CAPS="$(getcap "${DUMPCAP_PATH}" 2>/dev/null || true)"
if [[ "${DUMPCAP_CAPS}" == *cap_net_raw* && "${DUMPCAP_CAPS}" == *cap_net_admin* ]]; then
    ok "dumpcap has cap_net_raw and cap_net_admin"
else
    fail "dumpcap file capabilities are incomplete: ${DUMPCAP_CAPS:-none}"
fi

dumpcap_inventory="$(timeout 10 dumpcap -D 2>&1)"
dumpcap_status=$?
if ((dumpcap_status != 0)); then
    fail "dumpcap could not list capture interfaces: ${dumpcap_inventory}"
elif [[ -n "${INTERFACE}" ]] && grep -Fq "${INTERFACE}" <<<"${dumpcap_inventory}"; then
    ok "dumpcap inventory includes ${INTERFACE}"
else
    fail "dumpcap inventory does not include ${INTERFACE:-the configured interface}"
fi

config_mode="$(stat -c '%a' "${CONFIG_PATH}" 2>/dev/null || true)"
if [[ -n "${config_mode}" ]]; then
    config_mode_value=$((8#${config_mode}))
    if (( (config_mode_value & 0027) == 0 )); then
        ok "configuration is not accessible to other users (mode ${config_mode})"
    else
        warn "configuration mode ${config_mode} permits access beyond owner/service group expectations"
    fi
fi

INSTANCE_STATE="${STATE_ROOT}/${INTERFACE:-unknown}"

resolve_state_path() {
    local configured_path="$1"
    if [[ "${configured_path}" == /* ]]; then
        printf '%s\n' "${configured_path}"
    else
        printf '%s/%s\n' "${INSTANCE_STATE}" "${configured_path#./}"
    fi
}

check_private_directory_path() {
    local path="$1"
    local label="$2"
    if [[ -L "${path}" ]]; then
        fail "${label} must not be a symbolic link: ${path}"
        return 1
    fi
    if [[ ! -d "${path}" ]]; then
        fail "${label} must exist as a real directory: ${path}"
        return 1
    fi
    local mode
    mode="$(stat -c '%a' "${path}" 2>/dev/null || true)"
    if [[ ! "${mode}" =~ ^[0-7]{3,4}$ ]]; then
        fail "${label} permissions could not be read: ${path}"
        return 1
    fi
    local mode_value=$((8#${mode}))
    # Evidence directories are normally mode 0700; owner-only variants remain
    # acceptable when they are still writable and searchable by this account.
    if (( (mode_value & 0077) != 0 )); then
        fail "${label} permits group/other access (mode ${mode}): ${path}"
        return 1
    fi
    if [[ ! -w "${path}" || ! -x "${path}" ]]; then
        fail "${label} is not writable/searchable: ${path}"
        return 1
    fi
    ok "${label} is a private real directory (mode ${mode}): ${path}"
    return 0
}

check_unredacted_file() {
    local configured_path="$1"
    local label="$2"
    local resolved
    resolved="$(resolve_state_path "${configured_path}")"
    local parent
    parent="$(dirname -- "${resolved}")"
    check_private_directory_path "${parent}" "${label} immediate parent" || return
    if [[ -L "${resolved}" ]]; then
        fail "${label} must not be a symbolic link: ${resolved}"
        return
    fi
    if [[ -e "${resolved}" ]]; then
        if [[ ! -f "${resolved}" ]]; then
            fail "${label} must be a regular file: ${resolved}"
            return
        fi
        local mode
        mode="$(stat -c '%a' "${resolved}" 2>/dev/null || true)"
        if [[ ! "${mode}" =~ ^[0-7]{3,4}$ ]]; then
            fail "${label} permissions could not be read: ${resolved}"
            return
        fi
        local mode_value=$((8#${mode}))
        if (( mode_value != 0600 )); then
            fail "${label} must be mode 0600, found ${mode}: ${resolved}"
            return
        fi
        if [[ ! -r "${resolved}" || ! -w "${resolved}" ]]; then
            fail "${label} is not readable and writable: ${resolved}"
            return
        fi
        local size
        size="$(stat -c '%s' "${resolved}" 2>/dev/null || true)"
        if [[ "${size}" =~ ^[0-9]+$ ]] && ((size > 0)); then
            local last_hex
            last_hex="$(tail -c 1 -- "${resolved}" | od -An -tx1 | tr -d '[:space:]')"
            if [[ "${last_hex}" != "0a" ]]; then
                fail "${label} has a non-newline partial JSONL tail: ${resolved}"
                return
            fi
        elif [[ ! "${size}" =~ ^[0-9]+$ ]]; then
            fail "${label} size could not be read: ${resolved}"
            return
        fi
        ok "${label} is restricted and append-ready (mode ${mode}): ${resolved}"
    else
        ok "${label} does not exist yet; its private parent is append-ready: ${parent}"
    fi
}

if [[ -n "${OUTPUT_JSONL}" ]]; then
    check_unredacted_file "${OUTPUT_JSONL}" "unredacted findings JSONL"
fi

if [[ -n "${OPERATIONAL_JSONL}" ]]; then
    check_unredacted_file "${OPERATIONAL_JSONL}" "operational JSONL"
fi

resolved_output="$(resolve_state_path "${OUTPUT_JSONL}")"
resolved_operations="$(resolve_state_path "${OPERATIONAL_JSONL}")"
normalized_output="$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "${resolved_output}")"
normalized_operations="$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "${resolved_operations}")"
if [[ "${normalized_output}" == "${normalized_operations}" ]]; then
    fail "findings and operations destinations resolve to the same pathname"
elif [[ ! -L "${resolved_output}" && -f "${resolved_output}" \
    && ! -L "${resolved_operations}" && -f "${resolved_operations}" ]]; then
    output_inode="$(stat -Lc '%d:%i' "${resolved_output}" 2>/dev/null || true)"
    operations_inode="$(stat -Lc '%d:%i' "${resolved_operations}" 2>/dev/null || true)"
    if [[ -n "${output_inode}" && "${output_inode}" == "${operations_inode}" ]]; then
        fail "findings and operations destinations resolve to the same file/inode"
    fi
fi

if [[ "${RAW_ENABLED}" == "true" ]]; then
    resolved_raw_dir="$(resolve_state_path "${RAW_CAPTURE_DIR}")"
    check_private_directory_path "${resolved_raw_dir}" "raw capture directory" || true

    if [[ "${RAW_FILE_MB}" =~ ^[0-9]+$ && "${RAW_FILES}" =~ ^[0-9]+$ ]]; then
        raw_capacity_mb=$((RAW_FILE_MB * RAW_FILES))
        ok "configured raw ring nominal size ceiling: ${raw_capacity_mb} MiB"
    else
        fail "raw ring size/count values are not positive integers"
    fi
    if [[ "${RAW_DURATION}" =~ ^[0-9]+$ && "${RAW_FILES}" =~ ^[0-9]+$ ]]; then
        raw_window_seconds=$((RAW_DURATION * RAW_FILES))
        ok "configured duration-based ring window: up to ${raw_window_seconds} seconds (size rotation may shorten it)"
    fi
    if [[ "${STOP_ON_RAW_FAILURE}" == "true" ]]; then
        ok "analysis will stop when the independent raw ring fails"
    else
        warn "stop_on_raw_capture_failure is false; findings may continue without recoverable raw evidence"
    fi
else
    warn "raw capture ring is disabled"
fi

disk_target="${INSTANCE_STATE}"
[[ -e "${disk_target}" ]] || disk_target="${STATE_ROOT}"
if [[ -e "${disk_target}" ]]; then
    disk_line="$(df -Pk "${disk_target}" | awk 'NR==2 {print $4 " " $5}')"
    ok "state filesystem available blocks/use: ${disk_line:-unknown}"
else
    fail "state root does not exist: ${STATE_ROOT}"
fi

PACKET_AUDIT_BIN=""
if [[ -x /opt/packet-audit/venv/bin/packet-audit ]]; then
    PACKET_AUDIT_BIN="/opt/packet-audit/venv/bin/packet-audit"
elif command -v packet-audit >/dev/null 2>&1; then
    PACKET_AUDIT_BIN="$(command -v packet-audit)"
fi

if [[ -n "${PACKET_AUDIT_BIN}" ]]; then
    if [[ ! -d "${INSTANCE_STATE}" ]]; then
        warn "CLI path checks are deferred until systemd creates ${INSTANCE_STATE} on first start"
    elif (cd -- "${INSTANCE_STATE}" && "${PACKET_AUDIT_BIN}" doctor --config "${CONFIG_PATH}" --interface "${INTERFACE}"); then
        ok "Packet Audit CLI doctor passed"
    else
        fail "Packet Audit CLI doctor failed"
    fi

    cli_interfaces="$(timeout 10 "${PACKET_AUDIT_BIN}" list-interfaces 2>&1)"
    cli_interface_status=$?
    if ((cli_interface_status != 0)); then
        fail "Packet Audit could not list interfaces: ${cli_interfaces}"
    elif [[ -n "${INTERFACE}" ]] && grep -Fq "${INTERFACE}" <<<"${cli_interfaces}"; then
        ok "Packet Audit interface inventory includes ${INTERFACE}"
    else
        fail "Packet Audit interface inventory does not include ${INTERFACE}"
    fi
else
    fail "packet-audit CLI is not installed or on PATH"
fi

printf '\nPacket Audit preflight: %d failure(s), %d warning(s).\n' "${ERRORS}" "${WARNINGS}"
if ((ERRORS)); then
    exit 1
fi
exit 0
