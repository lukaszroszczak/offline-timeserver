# Raspberry Pi NTP z GPS (chrony + gpsd)

Ten zestaw konfiguruje SBC (np. Raspberry Pi) jako serwer NTP bazujący na GPS.

- NTP port: UDP/123 (standard). Port 53 to DNS, można go użyć z `dnsmasq` do DHCP/DNS i rozgłaszania serwera NTP (DHCP option 42).
- Źródła czasu: NMEA z portu szeregowego; opcjonalnie PPS dla wysokiej precyzji.

## Sprzęt

- GPS USB (np. u-blox) -> pojawi się jako `/dev/ttyACM0` lub `/dev/ttyUSB0`.
- PPS (opcjonalnie): podłącz linię PPS do GPIO18 (pin 12) i masę do GND.

## Instalacja pakietów

```
sudo apt update
sudo apt install -y chrony gpsd gpsd-clients pps-tools dnsmasq
```

## Szybki start — checklist

- Sprzęt: GPS USB (`/dev/ttyACM0`/`/dev/ttyUSB0`), opcjonalnie PPS -> GPIO18.
- Klon repo: `git clone <repo>` i `cd offline_timeserver/raspi-ntp`.
- Ustaw urządzenie w `gpsd.default` (domyślnie `/dev/ttyACM0`).
- Uruchom: `sudo ./setup.sh` (konfiguruje gpsd i chrony przez SHM + PPS).
- Jeśli PPS: sprawdź/dodaj `dtoverlay=pps-gpio,gpiopin=18` i zrestartuj.
- Otwórz UDP/123 w firewallu na interfejsie LAN.
- Weryfikuj: `chronyc sources -v`, `chronyc tracking`, `gpspipe -r | head`.
- Klienci: ustawiają NTP na IP SBC; DHCP Option 42 (dnsmasq) rozgłasza adres.

## Konfiguracja krok po kroku

1) Włącz PPS (opcjonalnie):

- Edytuj `/boot/firmware/config.txt` (Bookworm) lub `/boot/config.txt` (starsze):
  - Dodaj: `dtoverlay=pps-gpio,gpiopin=18`
  - Jeśli używasz UART (nie USB): `enable_uart=1`
- Zrestartuj: `sudo reboot`
- Sprawdź: `ls -l /dev/pps0` i `sudo ppstest /dev/pps0`

2) Skonfiguruj gpsd (jedyny czytelnik portu GPS):

- Plik wzorcowy: `gpsd.default` (skopiuj do `/etc/default/gpsd`).
- Ustaw `DEVICES="/dev/ttyACM0"` (lub odpowiedni port) i `GPSD_OPTIONS="-n"`.
- Włącz i uruchom: `sudo systemctl enable gpsd`, `sudo systemctl restart gpsd`.
- Test: `gpsmon` lub `gpspipe -r | head` powinny pokazać zdania NMEA.

3) Skonfiguruj chrony (NTP):

- Plik wzorcowy: `chrony.conf` (skopiuj do `/etc/chrony/chrony.conf`). Zawiera źródło `refclock SHM` czytane z gpsd oraz (opcjonalnie) `refclock PPS`.
- Dostosuj sieci w `allow` (np. `192.168.0.0/16`).
- Restart: `sudo systemctl restart chrony`.
- Test źródeł: `chronyc sources -v` (powinny być NMEA i ewentualnie PPS), `chronyc tracking`.

4) (Opcjonalnie) dnsmasq (DNS/DHCP) do rozgłaszania NTP:

- Plik przykładowy: `dnsmasq.conf.example`.
- Ustaw `dhcp-option=option:ntp-server,<IP_SBC>` i interfejs.
- Restart: `sudo systemctl restart dnsmasq`.

## Uwierzytelnianie i bezpieczeństwo

- Otwórz UDP/123 w firewallu na interfejsie LAN; nie wystawiaj na WAN.
- Użyj `allow` w chrony, aby ograniczyć klientów do Twojej sieci.

## Przydatne komendy diagnostyczne

```
chronyc sources -v
chronyc tracking
sudo journalctl -u gpsd -u chrony -f
sudo ppstest /dev/pps0
sudo gpspipe -r | head -n 20
```

## Automatyczna konfiguracja

Skrypt `setup.sh` wykona instalację i podmianę konfiguracji. Uruchamiaj jako root na Raspberry Pi:

```
sudo raspi-ntp/setup.sh
```

Zanim uruchomisz, upewnij się, że poprawne są ścieżki urządzeń (`/dev/ttyACM0`/`/dev/ttyUSB0`) i (jeśli używasz) PPS na GPIO18.
