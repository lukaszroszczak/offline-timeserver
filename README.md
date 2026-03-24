# timeserver

Zestaw narzędzi do lokalnego serwowania czasu w odłączonej sieci:

- Prosty serwer HTTP (demo) zwracający czas jako JSON.
- Konfiguracja SBC (np. Raspberry Pi) jako serwera NTP z GPS (+PPS) dla LAN.

Ważne: serwer czasu w sieci używa standardowo protokołu NTP na porcie UDP/123 (nie 53 — to port DNS). Jeśli chcesz, możemy dodać DNS/DHCP (dnsmasq) na 53, aby rozgłaszać adres serwera NTP klientom (DHCP option 42).

## 1) Python HTTP demo + panel admin

- Wymagania: Python 3.8+
- Start: `python3 server.py` (domyślnie 0.0.0.0:80)
- Weryfikacja: `curl -s http://localhost/time`
- Endpointy:
  - `GET /` — info + panel (web panel na porcie 80)
  - `GET /time` — aktualny czas UTC w JSON
  - `GET /login` — logowanie do panelu
  - `GET /admin` — panel administracyjny (status GPS/NTP/sieć)
  - `GET /api/status` — status w JSON (wymaga logowania)
  - `POST /api/network` — prosta konfiguracja Wi‑Fi przez `nmcli` (wymaga logowania)

- Uwierzytelnianie panelu:
  - Zmiennie: `ADMIN_USER`, `ADMIN_PASS`, `SECRET_KEY` (do podpisu ciasteczek).
  - Domyślnie (dev): `admin`/`admin`. Zmień w produkcji.
  - Przykład: `ADMIN_USER=admin ADMIN_PASS='supersecret' SECRET_KEY='…' python3 server.py`

Uwaga: port 80 wymaga uprawnień roota. Dewelopersko możesz użyć: `python3 server.py --host 0.0.0.0 --port 8000`.

## 2) Raspberry Pi jako serwer NTP z GPS

W katalogu `raspi-ntp/` znajdziesz skrypty i szablony konfiguracji dla chrony + gpsd.

Skrót założeń:

- Źródło czasu: moduł GPS (NMEA, opcjonalnie PPS) przez `/dev/ttyACM0` lub `/dev/ttyUSB0`.
- Usługa NTP: `chrony` (nasłuch na UDP/123, serwuje czas dla LAN).
- Offline: brak serwerów z Internetu, `local stratum` ustawione dla stabilnego działania bez GPS.
- (Opcjonalnie) DNS/DHCP: `dnsmasq` na porcie 53, rozgłasza NTP (DHCP Option 42).

Szybki start na Raspberry Pi (Bookworm/Bullseye):

1. Podłącz GPS (USB lub UART). Jeśli masz PPS, podłącz go np. do GPIO18.
2. `sudo apt update && sudo apt install -y chrony gpsd gpsd-clients pps-tools`
3. Skopiuj i dostosuj pliki z `raspi-ntp/` (opis w `raspi-ntp/README.md`).
4. Uruchom `sudo raspi-ntp/setup.sh` (zatrzyma usługi, podmieni konfigurację, włączy NTP dla LAN).
5. Weryfikacja: `chronyc sources -v`, `chronyc tracking`, `gpsmon`/`gpspipe -r`.

Klienci w sieci powinni wskazywać adres SBC jako serwer NTP (np. 192.168.x.x). Jeśli używasz DHCP, rozgłaszaj go przez Option 42 (przykład w `raspi-ntp/dnsmasq.conf.example`).

## Checklist RPi (offline LAN)

- Sprzęt: GPS USB (`/dev/ttyACM0` lub `/dev/ttyUSB0`); opcjonalnie PPS do GPIO18.
- System: `sudo apt update && sudo apt install -y chrony gpsd gpsd-clients pps-tools`
- Repo: `git clone <repo>` i przejdź do `raspi-ntp/`.
- Urządzenie GPS: ustaw w `raspi-ntp/gpsd.default` właściwy port (domyślnie `/dev/ttyACM0`).
- Setup: `sudo ./setup.sh` — podmienia configi, włącza usługi, dopisuje overlay PPS (jeśli włączony).
- Reboot (jeśli PPS): `sudo reboot` (aktywuje `/dev/pps0`).
- Firewall: otwarty `UDP/123` na interfejsie LAN (chrony).
- Weryfikacja: `chronyc sources -v`, `chronyc tracking`, `gpspipe -r | head`.
- Healthcheck: `sudo raspi-ntp/healthcheck.sh` (zbiera kluczowe statusy i podsumowuje OK/WARN/FAIL).
- Klienci: wskaż IP RPi jako serwer NTP lub rozgłoś przez DHCP Option 42 (dnsmasq przykład).
- Zakresy sieci: w `chrony.conf` wpisy `allow` dopasowane do Twojej adresacji.

## Podsumowanie (TL;DR)

```
# Na Raspberry Pi
sudo apt update && sudo apt install -y chrony gpsd gpsd-clients pps-tools
git clone git@github.com:lukaszroszczak/offline_timeserver.git
cd offline_timeserver/raspi-ntp
sudo ./setup.sh                 # ustawia gpsd + chrony (SHM z gpsd, opcjonalny PPS)
sudo reboot                     # tylko jeśli używasz PPS (dtoverlay)

# Sprawdzenie
chronyc sources -v
chronyc tracking
gpspipe -r | head

# Klienci
# - Linux: chrony/ntpd -> <IP_RPi> lub `ntpdate -q <IP_RPi>`
# - Windows: w32tm /config /manualpeerlist:<IP_RPi> /syncfromflags:manual /update && w32tm /resync
# - DHCP: dnsmasq -> dhcp-option=option:ntp-server,<IP_RPi>
```

Uwaga: na Debian Bookworm plik overlay to `/boot/firmware/config.txt`, na starszych `/boot/config.txt`.
