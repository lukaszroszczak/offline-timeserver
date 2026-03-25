#!/usr/bin/env python3
"""
gps-time-bridge: Feeds GPS time from gpsd to chrony SHM 0.

Works at mode=1 (no position fix) - for indoor/server room deployments.
GPS time is valid from a single satellite; position fix is not required.

SHM 0 layout on armv7l Raspbian Bookworm (64-bit time_t, little-endian):
  offset  0: mode       (int32)  - 1 = check count before/after
  offset  4: count      (int32)  - incremented before/after each write
  offset  8: clockSec   (int64)  - GPS time (seconds since epoch)
  offset 16: clockUSec  (int32)  - GPS time (microseconds part)
  offset 20: [padding 4 bytes]
  offset 24: rcvSec     (int64)  - system time when sample was received
  offset 32: rcvUSec    (int32)  - system time (microseconds part)
  offset 36: leap       (int32)  - 0=normal, 1=+1s, 2=-1s, 3=unsync
  offset 40: precision  (int32)  - log2 of accuracy (e.g. -6 = ~16ms)
  offset 44: nsamples   (int32)  - not used by chrony
  offset 48: valid      (int32)  - 1 = sample valid
  offset 52: clockNSec  (uint32) - nanoseconds part of GPS time
  offset 56: rcvNSec    (uint32) - nanoseconds part of receive time
  offset 60: dummy[8]   (int32[8])
  Total: 96 bytes
"""

import ctypes
import ctypes.util
import json
import logging
import subprocess
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger('gps-time-bridge')

SHM_KEY = 0x4E545030   # NTP SHM 0 (same key used by gpsd and chrony)
SHM_SIZE = 96
GPS_PRECISION = -6     # log2 accuracy: 2^-6 = ~16ms, conservative for NMEA

_libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
_libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
_libc.shmget.restype = ctypes.c_int
_libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
_libc.shmat.restype = ctypes.c_void_p


def _attach_shm() -> int:
    shmid = _libc.shmget(SHM_KEY, 0, 0)
    if shmid < 0:
        raise OSError(f"shmget(0x{SHM_KEY:08x}) failed: errno={ctypes.get_errno()}")
    ptr = _libc.shmat(shmid, None, 0)
    if ptr == ctypes.c_size_t(-1).value:
        raise OSError(f"shmat failed: errno={ctypes.get_errno()}")
    return ptr


def _write_sample(ptr: int, gps_ts: float, rcv_ts: float) -> None:
    """Write one GPS time sample to SHM. Thread-safe via count increment protocol."""
    gps_sec = int(gps_ts)
    gps_usec = int((gps_ts - gps_sec) * 1_000_000)
    rcv_sec = int(rcv_ts)
    rcv_usec = int((rcv_ts - rcv_sec) * 1_000_000)

    count = ctypes.c_int32.from_address(ptr + 4).value

    # Signal "being updated" (odd count)
    ctypes.c_int32.from_address(ptr + 4).value = count + 1

    ctypes.c_int32.from_address(ptr + 0).value = 1
    ctypes.c_int64.from_address(ptr + 8).value = gps_sec
    ctypes.c_int32.from_address(ptr + 16).value = gps_usec
    ctypes.c_int64.from_address(ptr + 24).value = rcv_sec
    ctypes.c_int32.from_address(ptr + 32).value = rcv_usec
    ctypes.c_int32.from_address(ptr + 36).value = 0              # leap: normal
    ctypes.c_int32.from_address(ptr + 40).value = GPS_PRECISION
    ctypes.c_int32.from_address(ptr + 44).value = 0              # nsamples
    ctypes.c_uint32.from_address(ptr + 52).value = (gps_usec * 1000) % 1_000_000_000
    ctypes.c_uint32.from_address(ptr + 56).value = (rcv_usec * 1000) % 1_000_000_000
    ctypes.c_int32.from_address(ptr + 48).value = 1              # valid=1 (last!)

    # Signal "update complete" (even count)
    ctypes.c_int32.from_address(ptr + 4).value = count + 2


def _run_gpspipe():
    """Yield JSON messages from gpspipe indefinitely."""
    while True:
        try:
            proc = subprocess.Popen(
                ['gpspipe', '-w'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in proc.stdout:
                line = line.strip()
                if line.startswith('{'):
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            log.warning("gpspipe error: %s", e)
        finally:
            try:
                proc.kill()
            except Exception:
                pass
        log.info("gpspipe exited, retrying in 5s...")
        time.sleep(5)


def main():
    log.info("gps-time-bridge starting (SHM key=0x%08x)", SHM_KEY)

    ptr = None
    last_write = 0.0
    samples = 0

    for msg in _run_gpspipe():
        if msg.get('class') != 'TPV':
            continue

        gps_time_str = msg.get('time')
        if not gps_time_str:
            continue

        try:
            from datetime import datetime
            gps_dt = datetime.fromisoformat(gps_time_str.replace('Z', '+00:00'))
            gps_ts = gps_dt.timestamp()
        except (ValueError, KeyError):
            continue

        rcv_ts = time.time()

        # Rate limit: one sample per second
        if rcv_ts - last_write < 0.9:
            continue
        last_write = rcv_ts

        # Attach to SHM on first write (or after detach)
        if ptr is None:
            try:
                ptr = _attach_shm()
                log.info("Attached to chrony SHM 0")
            except OSError as e:
                log.error("Cannot attach to SHM: %s - chrony/gpsd running?", e)
                time.sleep(10)
                continue

        try:
            _write_sample(ptr, gps_ts, rcv_ts)
            samples += 1
            if samples % 60 == 1:
                mode = msg.get('mode', '?')
                log.info("SHM updated: time=%s mode=%s (samples=%d)", gps_time_str, mode, samples)
        except Exception as e:
            log.error("SHM write failed: %s", e)
            ptr = None


if __name__ == '__main__':
    main()
