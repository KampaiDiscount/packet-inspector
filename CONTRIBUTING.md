# Contributing

Report bugs and propose changes through
[GitHub Issues](https://github.com/KampaiDiscount/packet-inspector/issues) or a
pull request. For vulnerabilities, follow [SECURITY.md](SECURITY.md).

## Development setup

Use Python 3.11+ on Linux. Install Python development headers, a compiler,
`python3-venv` and `libpcap-dev` before installing the pinned native binding:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e . pytest==8.4.2 build twine
python -m pytest
bash -n scripts/install-kali.sh scripts/packet-audit-doctor.sh
python -m build
python -m twine check dist/*
```

Use synthetic fixtures and documentation-range addresses in tests. Do not
commit capture files, real credentials, assessment evidence or private tokens.
Regression checks should cover the behavior being fixed, including loss and
incompleteness reporting where relevant. CI runs on Linux with Python 3.11 and
3.13; live hardware qualification remains a separate deployment check.

Include the command, package/OS/Python versions, expected behavior, actual
behavior and sanitized diagnostics in bug reports. Avoid claiming that a
detected candidate proves credential validity or compromise.

Preserve existing license notices. Contributions are distributed under the
repository's [GPL-3.0-or-later license](LICENSE).
