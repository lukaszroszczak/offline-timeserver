FROM debian:bookworm-slim

# Instalacja zależności systemowych
# Używamy debian:bookworm-slim (nie python:slim) — chrony, gpsd, gpsd-clients
# są pakietami Debian i lepiej zarządzać nimi jednym apt
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    chrony \
    gpsd \
    gpsd-clients \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Katalog roboczy
WORKDIR /app

# Kod aplikacji — tylko pliki Python potrzebne do działania
COPY server.py .
COPY gps-time-bridge.py .

# Konfiguracje Docker-specific
COPY docker/chrony-docker.conf /etc/chrony/chrony.conf
COPY docker/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Katalogi dla logów i runtime
RUN mkdir -p \
    /var/log/timeserver \
    /var/log/chrony \
    /var/run/chrony \
    /var/run/gpsd \
    /run/chrony \
    /var/lib/chrony

# Dokumentacyjne porty (przy --network host nie mają znaczenia funkcjonalnego)
EXPOSE 80
EXPOSE 123/udp

# Healthcheck — panel odpowiada + chrony działa
# start-period=120s: GPS cold start może trwać kilka minut
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD curl -sf http://localhost:${PORT:-80}/time > /dev/null && \
        chronyc tracking | grep -q "Stratum" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
