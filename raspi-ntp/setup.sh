#!/usr/bin/env bash
set -euo pipefail

# Prosty instalator dla Raspberry Pi (Debian/Raspberry Pi OS)
# Używa chrony + gpsd + (opcjonalnie) dnsmasq

DEVICE_DEFAULT="/dev/ttyACM0"   # zmień na /dev/ttyUSB0 lub UART jeśli trzeba
USE_PPS=${USE_PPS:-1}            # 1=konfiguruj PPS na GPIO18, 0=pomiń
LAN_ALLOW=${LAN_ALLOW:-"192.168.0.0/16 10.0.0.0/8 172.16.0.0/12"}

need_root() { [ "$(id -u)" = 0 ] || { echo "Uruchom jako root" >&2; exit 1; }; }
file_backup() { [ -f "$1" ] && cp -a "$1" "$1.bak.$(date +%s)" || true; }
append_once() { local line="$1" file="$2"; grep -qsF -- "$line" "$file" || echo "$line" >>"$file"; }

main() {
  need_root
  local dev="${DEVICE:-$DEVICE_DEFAULT}"

  echo "[1/6] Instalacja pakietów"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y chrony gpsd gpsd-clients pps-tools >/dev/null

  echo "[2/6] Konfiguracja gpsd ($dev) — będzie jedynym czytelnikiem GPS"
  file_backup /etc/default/gpsd
  install -m 0644 -o root -g root "$(dirname "$0")/gpsd.default" /etc/default/gpsd
  sed -i "s#^DEVICES=.*#DEVICES=\"$dev\"#" /etc/default/gpsd
  systemctl enable gpsd >/dev/null 2>&1 || true
  systemctl restart gpsd || true

  if [ "$USE_PPS" = "1" ]; then
    echo "[3/6] Włączanie PPS na GPIO18 (dtoverlay=pps-gpio)"
    local cfg
    if [ -f /boot/firmware/config.txt ]; then cfg=/boot/firmware/config.txt; else cfg=/boot/config.txt; fi
    append_once "dtoverlay=pps-gpio,gpiopin=18" "$cfg"
  else
    echo "[3/6] PPS pominięty (USE_PPS=0)"
  fi

  echo "[4/6] Konfiguracja chrony (czyta czas z gpsd przez SHM)"
  file_backup /etc/chrony/chrony.conf
  install -m 0644 -o root -g root "$(dirname "$0")/chrony.conf" /etc/chrony/chrony.conf
  # Dostosuj allow do zmiennej
  if [ -n "$LAN_ALLOW" ]; then
    for net in $LAN_ALLOW; do
      grep -qs "^allow $net$" /etc/chrony/chrony.conf || echo "allow $net" >> /etc/chrony/chrony.conf
    done
  fi
  systemctl restart chrony || true

  echo "[5/6] Informacje o firewallu i usługach"
  echo " - Upewnij się, że UDP/123 otwarty na interfejsie LAN"
  echo " - Sprawdź: chronyc sources -v / tracking"
  echo " - Sprawdź GPS: gpspipe -r | head -n 10"

  echo "[6/6] (Opcjonalnie) dnsmasq: zobacz raspi-ntp/dnsmasq.conf.example"
  echo "Gotowe. Zrestartuj system, aby uaktywnić PPS (jeśli włączony)."
}

main "$@"
