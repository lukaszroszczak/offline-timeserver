#!/bin/bash
set -euo pipefail

# --- GPS device ---
GPS_DEVICE="${GPS_DEVICE:-/dev/ttyACM0}"
echo "[entrypoint] GPS device: $GPS_DEVICE"

# Dynamicznie nadpisz /etc/default/gpsd na podstawie zmiennej środowiskowej
cat > /etc/default/gpsd <<EOF
DEVICES="$GPS_DEVICE"
GPSD_OPTIONS="-n"
START_DAEMON="true"
USBAUTO="false"
EOF

# Eksportuj dla supervisord (%(ENV_GPS_DEVICE)s w supervisord.conf)
export GPS_DEVICE

# Ostrzeżenie jeśli urządzenie nie istnieje (gpsd zaczeka na podłączenie)
if [ ! -e "$GPS_DEVICE" ]; then
    echo "[entrypoint] WARN: $GPS_DEVICE nie znaleziony — gpsd będzie czekać na urządzenie"
fi

# Utwórz katalogi runtime
mkdir -p /var/run/gpsd /var/log/chrony /var/log/timeserver /run/chrony

# Uruchom supervisord jako PID 1
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
