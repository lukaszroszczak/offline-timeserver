#!/usr/bin/env bash
# Healthcheck dla offline_timeserver na Raspberry Pi
# Sprawdza gpsd, chrony (SHM, PPS), gps-time-bridge, stratum i nasłuch NTP.

set -uo pipefail

ok=()
warn=()
fail=()

log() { printf "%s\n" "$*"; }
add_ok() { ok+=("$*"); }
add_warn() { warn+=("$*"); }
add_fail() { fail+=("$*"); }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

get_gps_device() {
  local dev conf=/etc/default/gpsd
  if [ -r "$conf" ]; then
    dev=$(awk -F '="|"' '/^DEVICES=/{print $2}' "$conf" | awk '{print $1}')
    if [ -n "${dev:-}" ] && [ -e "$dev" ]; then
      echo "$dev"; return 0
    fi
  fi
  for c in /dev/ttyACM* /dev/ttyUSB*; do
    [ -e "$c" ] || continue
    echo "$c"; return 0
  done
  echo ""; return 1
}

ppstest_run() {
  local dev=/dev/pps0
  if [ ! -e "$dev" ]; then
    add_warn "Brak $dev (PPS nieaktywny)"; return 0
  fi
  if ! has_cmd ppstest; then
    add_warn "Brak narzędzia ppstest (pps-tools) — pomijam test PPS"; return 0
  fi
  if timeout 3s ppstest "$dev" >/dev/null 2>&1 || timeout 3s sudo ppstest "$dev" >/dev/null 2>&1; then
    add_ok "PPS: /dev/pps0 odpowiada (ppstest)"
  else
    add_warn "PPS: /dev/pps0 nie odpowiada (ppstest nieudany)"
  fi
}

section() { printf "\n== %s ==\n" "$*"; }

main() {
  section "Wersje narzędzi"
  has_cmd chronyc && chronyc --version 2>/dev/null | head -n1 || log "chronyc: brak"
  has_cmd gpsd && gpsd -V 2>/dev/null | head -n1 || log "gpsd: brak"
  has_cmd gpspipe && gpspipe -h >/dev/null 2>&1 && log "gpspipe: OK" || log "gpspipe: brak"

  section "Usługi systemowe"
  if has_cmd systemctl; then
    systemctl is-active --quiet gpsd    && add_ok  "gpsd: aktywny"    || add_fail "gpsd: nieaktywny"
    systemctl is-active --quiet chrony  && add_ok  "chrony: aktywny"  || add_fail "chrony: nieaktywny"
    if systemctl is-active --quiet gps-time-bridge 2>/dev/null; then
      add_ok "gps-time-bridge: aktywny"
    else
      add_fail "gps-time-bridge: nieaktywny — brak dostarczania czasu GPS do chrony"
    fi
    if systemctl is-active --quiet offline-timeserver 2>/dev/null; then
      add_ok "offline-timeserver (panel webowy): aktywny"
    else
      add_warn "offline-timeserver (panel webowy): nieaktywny"
    fi
  else
    add_warn "Brak systemctl — pomijam sprawdzanie usług"
  fi

  section "Urządzenia GPS/PPS"
  local gps_dev
  gps_dev=$(get_gps_device) || true
  if [ -n "$gps_dev" ]; then
    add_ok "GPS device: $gps_dev"
  else
    add_fail "Nie znaleziono urządzenia GPS (/dev/ttyACM* ani /dev/ttyUSB*)"
  fi
  if [ -e /dev/pps0 ]; then
    add_ok "PPS device: /dev/pps0"
  else
    add_warn "Brak /dev/pps0 (PPS nieaktywne — opcjonalne)"
  fi

  section "Dane z GPS"
  if has_cmd gpspipe; then
    gps_json=$(timeout 4s gpspipe -w -n 5 2>/dev/null || true)
    if echo "$gps_json" | grep -q '"class":"TPV"'; then
      gps_time=$(echo "$gps_json" | grep '"class":"TPV"' | grep -o '"time":"[^"]*"' | head -1 | cut -d'"' -f4)
      gps_mode=$(echo "$gps_json" | grep '"class":"TPV"' | grep -o '"mode":[0-9]*' | head -1 | cut -d: -f2)
      if [ -n "$gps_time" ]; then
        add_ok "GPS czas dostępny: $gps_time (mode=$gps_mode)"
      else
        add_warn "GPS TPV bez pola time — brak sygnału"
      fi
    else
      add_warn "GPS: brak komunikatów TPV z gpsd"
    fi
  else
    add_warn "gpspipe niedostępny — pomijam test GPS"
  fi

  section "Synchronizacja czasu (chrony)"
  if has_cmd chronyc; then
    chronyc sources -v 2>/dev/null | sed -n '1,25p'
    tracking=$(chronyc tracking 2>/dev/null)
    echo "$tracking" | sed -n '1,10p'

    stratum=$(echo "$tracking" | awk -F: '/^Stratum/{gsub(/ /,"",$2); print $2}')
    refid=$(echo "$tracking"   | awk -F: '/^Reference ID/{print $2}' | xargs)

    if [ "${stratum:-99}" -le 2 ] 2>/dev/null; then
      add_ok "Stratum: ${stratum} — zsynchronizowany z GPS (ref: ${refid})"
    elif [ "${stratum:-99}" -le 9 ] 2>/dev/null; then
      add_warn "Stratum: ${stratum} — zsynchronizowany, ale nie z GPS (ref: ${refid})"
    else
      add_fail "Stratum: ${stratum:-?} — brak synchronizacji GPS (ref: ${refid:-?})"
    fi

    if chronyc sources 2>/dev/null | grep -q '#\*'; then
      add_ok "chrony: aktywne źródło refclock (SHM)"
    else
      add_warn "chrony: refclock SHM nie jest aktywnym źródłem"
    fi
  else
    add_fail "Brak chronyc — czy chrony jest zainstalowane?"
  fi

  section "Nasłuch NTP (UDP/123)"
  if has_cmd ss; then
    if ss -ulpn | grep -q ':123'; then
      add_ok "Port UDP/123 nasłuchuje"
    else
      add_fail "Port UDP/123 nie nasłuchuje — sprawdź chrony i firewall"
    fi
  else
    add_warn "Brak 'ss' — pomijam sprawdzanie portu"
  fi

  section "Panel webowy (HTTP)"
  if has_cmd curl; then
    http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 http://localhost/time 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
      add_ok "Panel webowy: odpowiada HTTP 200 na /time"
    else
      add_fail "Panel webowy: brak odpowiedzi lub błąd (HTTP $http_code)"
    fi
  fi

  section "PPS test (opcjonalny)"
  ppstest_run

  section "Podsumowanie"
  for m in "${ok[@]:-}";   do [ -n "$m" ] && printf "OK:    %s\n" "$m"; done
  for m in "${warn[@]:-}"; do [ -n "$m" ] && printf "WARN:  %s\n" "$m"; done
  for m in "${fail[@]:-}"; do [ -n "$m" ] && printf "FAIL:  %s\n" "$m"; done
  printf "\nOK: %d  WARN: %d  FAIL: %d\n" "${#ok[@]}" "${#warn[@]}" "${#fail[@]}"

  [ "${#fail[@]}" -eq 0 ] || exit 1
}

main "$@"
