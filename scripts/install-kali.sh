#!/usr/bin/env bash
# Install Packet Audit on a Kali/Debian system without enabling or starting it.

set -Eeuo pipefail
# Code and the virtual environment must remain readable by the locked service
# account even when the invoking shell uses umask 077. Sensitive paths below
# receive explicit private modes; both services use UMask=0077 at runtime.
umask 022

readonly SERVICE_USER="packet-audit"
readonly SERVICE_GROUP="packet-audit"
readonly CAPTURE_GROUP="wireshark"
readonly INSTALL_ROOT="/opt/packet-audit"
readonly VENV_DIR="${INSTALL_ROOT}/venv"
readonly CONFIG_DIR="/etc/packet-audit"
readonly CONFIG_PATH="${CONFIG_DIR}/packet-audit.toml"
readonly STATE_ROOT="/var/lib/packet-audit"
readonly DOCTOR_PATH="/usr/local/libexec/packet-audit-doctor"
readonly UNIT_PATH="/etc/systemd/system/packet-audit@.service"
readonly WEB_UNIT_PATH="/etc/systemd/system/packet-audit-web@.service"

SKIP_SYSTEM_DEPS=false

usage() {
    printf '%s\n' \
        'Usage: sudo bash ./scripts/install-kali.sh [--skip-system-deps]' \
        '' \
        'Installs Packet Audit and its localhost-only dashboard without starting either.' \
        '  --skip-system-deps  Do not run apt or alter debconf; verify existing dependencies.' \
        '  -h, --help          Show this help.' \
        '' \
        'Existing configuration and evidence are preserved. Stop running Packet Audit' \
        'capture/dashboard services before upgrading their shared Python environment.'
}

log() {
    printf '[packet-audit installer] %s\n' "$*"
}

die() {
    printf '[packet-audit installer] ERROR: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --skip-system-deps) SKIP_SYSTEM_DEPS=true ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (use --help)" ;;
    esac
    shift
done

if [[ ${EUID} -ne 0 ]]; then
    die "run this installer as root (for example: sudo bash ./scripts/install-kali.sh)"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

[[ -f "${PROJECT_ROOT}/pyproject.toml" ]] || die "pyproject.toml not found under ${PROJECT_ROOT}"
[[ -f "${PROJECT_ROOT}/config/example.toml" ]] || die "config/example.toml is missing"
[[ -f "${PROJECT_ROOT}/systemd/packet-audit@.service" ]] || die "systemd unit template is missing"
[[ -f "${PROJECT_ROOT}/systemd/packet-audit-web@.service" ]] || die "dashboard systemd unit template is missing"
[[ -f "${PROJECT_ROOT}/scripts/packet-audit-doctor.sh" ]] || die "doctor script is missing"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
        kali:*|debian:*|*:debian*) ;;
        *) die "this installer targets Kali/Debian; detected ${PRETTY_NAME:-unknown OS}" ;;
    esac
else
    die "/etc/os-release is unavailable"
fi

# Do not replace Python modules or dependencies underneath live workers. Leave
# the operator in control of the capture outage; this installer never stops it.
command -v systemctl >/dev/null 2>&1 || die "systemctl is unavailable"
active_units="$(systemctl list-units --all --type=service \
    --state=active,activating,reloading --no-legend --plain --no-pager \
    'packet-audit@*.service' 'packet-audit-web@*.service')" \
    || die "could not query running Packet Audit services"
if [[ -n "${active_units//[[:space:]]/}" ]]; then
    die "stop running Packet Audit capture/dashboard services before upgrading; no service was stopped"
fi

export DEBIAN_FRONTEND=noninteractive

readonly -a APT_PACKAGES=(
    python3
    python3-venv
    python3-pip
    python3-dev
    build-essential
    pkg-config
    libpcap-dev
    libcap2-bin
    tshark
)

if [[ "${SKIP_SYSTEM_DEPS}" == "true" ]]; then
    log "skipping apt/debconf; checking installed system dependencies"
else
    # Ask the Debian Wireshark packaging to permit capture only for members of
    # its dedicated group. File capabilities are verified below in both modes.
    if command -v debconf-set-selections >/dev/null 2>&1; then
        printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean true' \
            | debconf-set-selections
    fi
    log "installing required Kali packages (apt may upgrade their dependencies)"
    apt-get update
    apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}"
fi

for required in python3 gcc make pkg-config dumpcap tshark getcap setcap systemctl \
    getent id groupadd useradd usermod passwd install ip timeout stat df tail od; do
    command -v "${required}" >/dev/null 2>&1 \
        || die "missing required command ${required}; install system dependencies before retrying"
done

python3 - <<'PY'
from pathlib import Path
import sys
import sysconfig
import ensurepip
import venv

if sys.version_info < (3, 11):
    raise SystemExit(
        f"Packet Audit requires Python 3.11 or newer; found {sys.version.split()[0]}"
    )
if not (Path(sysconfig.get_path("include")) / "Python.h").is_file():
    raise SystemExit("Matching Python development headers are missing; install python3-dev")
PY

pkg-config --exists libpcap \
    || die "libpcap development metadata is missing; install libpcap-dev"
read -r -a pcap_cflags <<<"$(pkg-config --cflags libpcap)"
printf '#include <pcap.h>\n' | gcc "${pcap_cflags[@]}" -E -x c - >/dev/null \
    || die "libpcap headers/compiler are unusable; install libpcap-dev and build-essential"

if ! getent group "${SERVICE_GROUP}" >/dev/null; then
    log "creating system group ${SERVICE_GROUP}"
    groupadd --system "${SERVICE_GROUP}"
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    log "creating locked system account ${SERVICE_USER}"
    useradd \
        --system \
        --gid "${SERVICE_GROUP}" \
        --home-dir "${STATE_ROOT}" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        "${SERVICE_USER}"
else
    current_primary_group="$(id -gn "${SERVICE_USER}")"
    if [[ "${current_primary_group}" != "${SERVICE_GROUP}" ]]; then
        log "adding existing ${SERVICE_USER} account to ${SERVICE_GROUP} without changing its primary group"
        usermod --append --groups "${SERVICE_GROUP}" "${SERVICE_USER}"
    fi
fi

getent group "${CAPTURE_GROUP}" >/dev/null \
    || die "the tshark package did not create the ${CAPTURE_GROUP} capture group"
usermod --append --groups "${CAPTURE_GROUP}" "${SERVICE_USER}"
passwd --lock "${SERVICE_USER}" >/dev/null 2>&1 || true

install -d -m 0755 -o root -g root "${INSTALL_ROOT}"
install -d -m 0750 -o root -g "${SERVICE_GROUP}" "${CONFIG_DIR}"
install -d -m 0750 -o root -g "${SERVICE_GROUP}" "${STATE_ROOT}"
install -d -m 0755 -o root -g root "$(dirname -- "${DOCTOR_PATH}")"

install -m 0644 -o root -g root "${PROJECT_ROOT}/README.md" "${INSTALL_ROOT}/README.md"
install -m 0644 -o root -g root "${PROJECT_ROOT}/LOGIN_FIELDS.md" "${INSTALL_ROOT}/LOGIN_FIELDS.md"
install -m 0644 -o root -g root "${PROJECT_ROOT}/COVERAGE.md" "${INSTALL_ROOT}/COVERAGE.md"
install -m 0644 -o root -g root "${PROJECT_ROOT}/RELIABILITY.md" "${INSTALL_ROOT}/RELIABILITY.md"
install -m 0644 -o root -g root "${PROJECT_ROOT}/NOTICE.md" "${INSTALL_ROOT}/NOTICE.md"
install -m 0644 -o root -g root "${PROJECT_ROOT}/LICENSE" "${INSTALL_ROOT}/LICENSE"

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    log "creating Python virtual environment"
    python3 -m venv "${VENV_DIR}"
fi

log "installing/updating Packet Audit in ${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install \
    --disable-pip-version-check \
    --upgrade pip setuptools wheel
"${VENV_DIR}/bin/python" -m pip install \
    --disable-pip-version-check \
    --upgrade "${PROJECT_ROOT}"

if [[ ! -e "${CONFIG_PATH}" ]]; then
    log "installing initial configuration"
    install -m 0640 -o root -g "${SERVICE_GROUP}" \
        "${PROJECT_ROOT}/config/example.toml" "${CONFIG_PATH}"
else
    log "preserving existing ${CONFIG_PATH}"
    chown root:"${SERVICE_GROUP}" "${CONFIG_PATH}"
    chmod 0640 "${CONFIG_PATH}"
fi

install -m 0755 -o root -g root \
    "${PROJECT_ROOT}/scripts/packet-audit-doctor.sh" "${DOCTOR_PATH}"
install -m 0644 -o root -g root \
    "${PROJECT_ROOT}/systemd/packet-audit@.service" "${UNIT_PATH}"
install -m 0644 -o root -g root \
    "${PROJECT_ROOT}/systemd/packet-audit-web@.service" "${WEB_UNIT_PATH}"

DUMPCAP_PATH="$(command -v dumpcap || true)"
[[ -n "${DUMPCAP_PATH}" ]] || die "dumpcap is missing after tshark installation"

# Restrict direct dumpcap execution to root and the Wireshark capture group. The
# systemd unit also grants the same two capabilities only to its service cgroup;
# no capabilities are attached to Python itself.
chown root:"${CAPTURE_GROUP}" "${DUMPCAP_PATH}"
chmod 0750 "${DUMPCAP_PATH}"
setcap 'cap_net_raw,cap_net_admin=eip' "${DUMPCAP_PATH}"

dumpcap_caps="$(getcap "${DUMPCAP_PATH}" || true)"
[[ "${dumpcap_caps}" == *cap_net_raw* && "${dumpcap_caps}" == *cap_net_admin* ]] \
    || die "dumpcap does not have both cap_net_raw and cap_net_admin"

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
else
    die "systemctl is unavailable; the Kali service template was installed but cannot be loaded"
fi

log "installation complete"
printf '%s\n' \
    "Configuration: ${CONFIG_PATH}" \
    "Start:        sudo systemctl start packet-audit@eth0.service" \
    "Stop:         sudo systemctl stop packet-audit@eth0.service" \
    "Dashboard:    sudo systemctl start packet-audit-web@eth0.service" \
    "Dashboard URL: http://127.0.0.1:8765/ (token-free, loopback only)" \
    "" \
    "Replace eth0 with your capture interface. First start creates private evidence" \
    "directories and runs the read-only doctor automatically before capture." \
    "The dashboard is independent and read-only; stopping it does not stop capture." \
    "Its default port supports one dashboard instance at a time. Use an SSH tunnel" \
    "to view it remotely; do not expose unredacted findings on a LAN listener." \
    "" \
    "No service was enabled or started. No forwarding, firewall, ARP, or interception state was changed."
