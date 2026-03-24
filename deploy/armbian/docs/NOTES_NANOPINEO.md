# NanoPi Neo deployment notes (2025-09-08)

- Hostname/IP: `nanopineo` / `192.168.151.57`
- OS: Armbian (Debian 12), kernel `6.12.43-current-sunxi`
- App: offline_timeserver running via systemd on `0.0.0.0:8000`
- GPS: u-blox 7 on `/dev/ttyACM0` (`/dev/serial/by-id/...u-blox_7... -> ../../ttyACM0`)
- NTP: chrony with `refclock SHM 0` (gpsd), `local stratum 10`
- Firewall: nftables input policy drop; allows SSH 22/tcp, HTTP 8000/tcp; NTP 123/udp only from `end0` subnet
- Automation: `update-ntp-allow` (refresh every 10m) and `timeserver-healthcheck` (every 5m)

See `deploy/armbian/docs/DEPLOY_ARMbian.md` for full steps.
