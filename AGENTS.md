# Repository Guidelines

## Project Structure & Module Organization
- server.py: Minimal HTTP time service. Exposes `/` (HTML) and `/time` (JSON). Config via env: `HOST`, `PORT`, `LOG_LEVEL`, `LOG_DIR`, `LOG_FILE`.
- raspi-ntp/: Raspberry Pi NTP setup (chrony + gpsd). Includes `setup.sh`, `healthcheck.sh`, and example configs.
- deploy/armbian/: Systemd units, helper scripts, and deployment notes for Armbian/NanoPi.
- README.md: Quick start for the HTTP demo and RPi notes.

## Build, Test, and Development Commands
- Run locally: `python3 server.py --host 0.0.0.0 --port 8000`
- Optional venv: `python3 -m venv .venv && source .venv/bin/activate`
- Verify endpoint: `curl http://localhost:8000/time`
- RPi setup (on device): `sudo raspi-ntp/setup.sh` then check `chronyc sources -v` and `gpspipe -r | head`.

## Coding Style & Naming Conventions
- Python: PEP 8; 4‑space indents; prefer type hints for new/changed functions; add short docstrings.
- Logging: use `logging` (already wired in `server.py`); do not `print()` for app logs.
- Shell: `bash` with `set -euo pipefail`; lowercase, hyphenated script names (e.g., `timeserver-healthcheck`).
- Files/paths: kebab-case for scripts, snake_case for Python identifiers.

## Testing Guidelines
- No formal suite yet. For logic additions, include `pytest` tests under `tests/` named `test_*.py`.
- Focus tests on pure helpers (e.g., `now_payload()`), and a simple HTTP smoke test.
- Run (if added): `python3 -m pytest -q`.
- Manual check: `curl -s localhost:8000/time | jq .` and review logs in `LOG_DIR` if set.

## Commit & Pull Request Guidelines
- Style: concise subject in imperative mood. Use scoped prefixes similar to history: `server: …`, `docs(armbian): …`, `deploy/armbian: …`.
- PRs must include: summary, what changed and why, how to verify (commands/output), and any device-specific notes (RPi/Armbian).
- Link related issues; include screenshots or logs for NTP/GPS validation when relevant.

## Security & Configuration Tips
- Do not hardcode credentials or device paths; use env vars and documented configs.
- Network: HTTP listens on `8000/tcp`; NTP on `123/udp`. Restrict via firewall (see `deploy/armbian/scripts/update-ntp-allow`).
- Systemd: ensure `LOG_DIR` exists (unit files precreate it). Run with least privileges appropriate to the target device.

