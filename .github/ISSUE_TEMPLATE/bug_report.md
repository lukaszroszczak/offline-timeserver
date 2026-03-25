---
name: Zgłoszenie błędu
about: Opisz napotkany problem
labels: bug
---

**Środowisko**
- Platforma: [ ] Raspberry Pi  [ ] Armbian/NanoPi  [ ] Docker  [ ] inne
- System operacyjny: <!-- np. Debian Bookworm, Ubuntu 24.04 -->
- Wersja Python (jeśli dotyczy): `python3 --version`
- Wersja chrony: `chronyc --version`
- Wersja gpsd: `gpsd --version`

**Opis problemu**
<!-- Co się dzieje, a co powinno się dziać -->

**Kroki do odtworzenia**
1.
2.
3.

**Logi**
```
# Wklej tutaj wynik poniższych komend (stosownie do problemu):
# journalctl -u offline-timeserver -n 50
# chronyc tracking
# chronyc sources -v
# gpspipe -r | head -5
```
