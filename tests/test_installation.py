from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_skip_system_dependencies_still_verifies_runtime_and_build_inputs() -> None:
    installer = read("scripts/install-kali.sh")
    assert "--skip-system-deps) SKIP_SYSTEM_DEPS=true" in installer
    assert "if [[ \"${SKIP_SYSTEM_DEPS}\" == \"true\" ]]; then" in installer
    assert "umask 022" in installer
    for required in (
        "import ensurepip",
        "import venv",
        'sysconfig.get_path("include")',
        '"Python.h"',
        "pkg-config --exists libpcap",
        "#include <pcap.h>",
        "gcc",
        "make",
        "setcap",
        "dumpcap",
    ):
        assert required in installer
    # System package/configuration mutations belong only to the non-skip branch.
    skip_branch = installer.split(
        'if [[ "${SKIP_SYSTEM_DEPS}" == "true" ]]; then', 1
    )[1].split("else", 1)[0]
    assert "apt-get" not in skip_branch
    assert "debconf-set-selections" not in skip_branch


def test_installer_installs_dashboard_but_does_not_start_or_enable_services() -> None:
    installer = read("scripts/install-kali.sh")
    assert 'readonly WEB_UNIT_PATH="/etc/systemd/system/packet-audit-web@.service"' in installer
    assert '"${PROJECT_ROOT}/systemd/packet-audit-web@.service" "${WEB_UNIT_PATH}"' in installer
    assert not re.search(r"(?m)^\s*systemctl\s+(?:enable|start|restart|stop)\b", installer)
    assert "First start creates private evidence" in installer
    assert "runs the read-only doctor automatically" in installer
    assert '"Doctor: ' not in installer
    assert "systemctl list-units --all --type=service" in installer
    assert "stop running Packet Audit capture/dashboard services before upgrading" in installer


def test_dashboard_unit_is_loopback_read_only_and_independent_of_capture() -> None:
    unit = read("systemd/packet-audit-web@.service")
    assert (
        "ExecStart=/opt/packet-audit/venv/bin/packet-audit serve "
        "--evidence-dir /var/lib/packet-audit/%i/evidence "
        "--host 127.0.0.1 --port 8765 "
        "--no-auth"
    ) in unit
    for directive in (
        "User=packet-audit",
        "Group=packet-audit",
        "RuntimeDirectory=packet-audit-web/%i",
        "RuntimeDirectoryMode=0700",
        "UMask=0077",
        "ProtectSystem=strict",
        "ReadOnlyPaths=/var/lib/packet-audit/%i",
        "InaccessiblePaths=-/var/lib/packet-audit/%i/evidence/pcap-ring",
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=\n",
        "AmbientCapabilities=\n",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
        "RestrictAddressFamilies=AF_UNIX AF_INET",
    ):
        assert directive in unit
    assert not re.search(r"(?m)^(?:Requires|PartOf|BindsTo|Wants)=", unit)
    assert not re.search(r"(?m)^Exec(?:StartPre|Stop|StopPost|Reload)=", unit)
    assert "CAP_NET_RAW" not in unit
    assert "CAP_NET_ADMIN" not in unit
    assert "AF_PACKET" not in unit
    assert "StateDirectory=" not in unit


def test_source_manifest_includes_dashboard_unit() -> None:
    assert "recursive-include systemd *.service" in read("MANIFEST.in")
    assert "include LOGIN_FIELDS.md" in read("MANIFEST.in")
    assert '"${PROJECT_ROOT}/LOGIN_FIELDS.md" "${INSTALL_ROOT}/LOGIN_FIELDS.md"' in read("scripts/install-kali.sh")
