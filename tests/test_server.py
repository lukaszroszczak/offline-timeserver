import base64
import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone, timedelta
from http.client import HTTPConnection
from unittest.mock import patch

import server as srv


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    addr, port = s.getsockname()
    s.close()
    return port


def _start_server(port=None, env=None):
    """Start a test HTTP server, optionally with custom env vars. Returns (httpd, port, old_env)."""
    port = port or _free_port()
    old_env = {}
    if env:
        for k, v in env.items():
            old_env[k] = os.environ.get(k)
            os.environ[k] = v
        # Invalidate cached secret so new SECRET_KEY env is picked up
        srv._CACHED_SECRET = None
    httpd = srv.HTTPServer(("127.0.0.1", port), srv.TimeHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    return httpd, port, old_env


def _stop_server(httpd, old_env=None):
    httpd.shutdown()
    httpd.server_close()
    if old_env:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ── time payload ──────────────────────────────────────────────────────────────

def test_now_payload_fields():
    p = srv.now_payload()
    assert "iso8601" in p and p["timezone"] == "UTC"
    assert isinstance(p["epoch_millis"], int)


def test_now_payload_iso_ends_with_z():
    p = srv.now_payload()
    assert p["iso8601"].endswith("Z"), "ISO timestamp should end with Z (UTC)"


def test_now_payload_epoch_millis_reasonable():
    p = srv.now_payload()
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    assert abs(p["epoch_millis"] - now_ms) < 2000


# ── chrony tracking parser ────────────────────────────────────────────────────

def test_parse_tracking_sample():
    sample = """
Reference ID    : 47505300 (GPS)
Stratum         : 1
Ref time (UTC)  : Mon Sep 09 10:10:10 2024
System time     : 0.000000001 seconds fast of NTP time
Root delay      : 0.000000001 seconds
Last offset     : -0.025 seconds
RMS offset      : 0.030 seconds
""".strip()
    d = srv.parse_tracking(sample)
    assert d.get("Stratum") == "1"
    assert "Last offset" in d


def test_parse_tracking_gps_reference():
    sample = "Reference ID    : 47505300 (GPS)\nStratum         : 1\n"
    d = srv.parse_tracking(sample)
    assert "GPS" in d.get("Reference ID", "")
    assert d.get("Stratum") == "1"


def test_parse_tracking_local_stratum():
    sample = "Reference ID    : 7F7F0101 ()\nStratum         : 10\n"
    d = srv.parse_tracking(sample)
    assert d.get("Stratum") == "10"


def test_parse_tracking_empty():
    assert srv.parse_tracking("") == {}


# ── session cookie ────────────────────────────────────────────────────────────

def test_session_cookie_roundtrip():
    cookie = srv.make_session_cookie("tester", ttl_seconds=5)
    user = srv.parse_session_cookie(cookie)
    assert user == "tester"


def test_session_cookie_expired():
    cookie = srv.make_session_cookie("tester", ttl_seconds=-1)
    assert srv.parse_session_cookie(cookie) is None


def test_session_cookie_tampered():
    cookie = srv.make_session_cookie("admin", ttl_seconds=60)
    parts = cookie.split("|")
    parts[0] = base64.urlsafe_b64encode(b"hacker").decode().rstrip("=")
    tampered = "|".join(parts)
    assert srv.parse_session_cookie(tampered) is None


def test_session_cookie_invalid_format():
    assert srv.parse_session_cookie("not-a-valid-cookie") is None
    assert srv.parse_session_cookie("") is None
    assert srv.parse_session_cookie("a|b") is None


# ── GPS status parsing ────────────────────────────────────────────────────────

def test_get_gps_status_nsat_field():
    """gpsd 3.25+ reports nSat instead of satellites array."""
    sky_with_nsat = {"class": "SKY", "nSat": 5, "uSat": 0}
    sky_with_array = {"class": "SKY", "satellites": [{}] * 3}
    sky_both = {"class": "SKY", "nSat": 7, "satellites": [{}] * 2}

    status = {"sats": None}
    if sky_with_nsat.get("nSat") is not None:
        status["sats"] = sky_with_nsat["nSat"]
    else:
        status["sats"] = len(sky_with_nsat.get("satellites", []))
    assert status["sats"] == 5

    status2 = {"sats": None}
    if sky_with_array.get("nSat") is not None:
        status2["sats"] = sky_with_array["nSat"]
    else:
        status2["sats"] = len(sky_with_array.get("satellites", []))
    assert status2["sats"] == 3

    # nSat takes priority over satellites array
    status3 = {"sats": None}
    if sky_both.get("nSat") is not None:
        status3["sats"] = sky_both["nSat"]
    else:
        status3["sats"] = len(sky_both.get("satellites", []))
    assert status3["sats"] == 7


# ── network status parsing ────────────────────────────────────────────────────

def test_parse_ip_brief_ethernet_connected():
    sample = "lo UNKNOWN 127.0.0.1/8\nend0 UP 192.168.1.10/24\n"
    ifaces = srv._parse_ip_brief(sample)
    eth = next((i for i in ifaces if i["ifname"] == "end0"), None)
    assert eth is not None
    assert eth["type"] == "ethernet"
    assert eth["state"] == "connected"
    assert "192.168.1.10" in eth["connection"]


def test_parse_ip_brief_wifi_disconnected():
    sample = "wlan0 DOWN \n"
    ifaces = srv._parse_ip_brief(sample)
    wlan = next((i for i in ifaces if i["ifname"] == "wlan0"), None)
    assert wlan is not None
    assert wlan["type"] == "wifi"
    assert wlan["state"] == "disconnected"
    assert wlan["connection"] == "--"


def test_parse_ip_brief_loopback_ignored_for_connectivity():
    sample = "lo UNKNOWN 127.0.0.1/8\n"
    ifaces = srv._parse_ip_brief(sample)
    lo = next((i for i in ifaces if i["ifname"] == "lo"), None)
    assert lo is not None
    assert lo["type"] == "loopback"
    assert lo["state"] != "connected"


# ── HTTP endpoints ─────────────────────────────────────────────────────────────

def test_http_time_endpoint():
    httpd, port, old_env = _start_server()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/time")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["timezone"] == "UTC"
        assert "iso8601" in data
    finally:
        _stop_server(httpd, old_env)


def test_http_root_redirects_to_login():
    httpd, port, old_env = _start_server()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 302
        assert "/login" in resp.getheader("Location", "")
    finally:
        _stop_server(httpd, old_env)


def test_http_admin_requires_auth():
    httpd, port, old_env = _start_server()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/admin")
        resp = conn.getresponse()
        assert resp.status == 302
        assert "/login" in resp.getheader("Location", "")
    finally:
        _stop_server(httpd, old_env)


def test_http_api_status_requires_auth():
    httpd, port, old_env = _start_server()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/api/status")
        resp = conn.getresponse()
        assert resp.status == 401
    finally:
        _stop_server(httpd, old_env)


def test_http_login_invalid_credentials():
    httpd, port, old_env = _start_server(env={"ADMIN_USER": "admin", "ADMIN_PASS": "secret"})
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        body = b"username=admin&password=wrong"
        conn.request("POST", "/login", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        assert resp.status == 401
    finally:
        _stop_server(httpd, old_env)


def test_http_login_valid_credentials_sets_cookie():
    httpd, port, old_env = _start_server(env={"ADMIN_USER": "admin", "ADMIN_PASS": "testpass"})
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        body = b"username=admin&password=testpass"
        conn.request("POST", "/login", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        assert resp.status == 302
        cookie = resp.getheader("Set-Cookie", "")
        assert "session=" in cookie
        assert "HttpOnly" in cookie
    finally:
        _stop_server(httpd, old_env)


def test_http_authenticated_access_to_admin():
    httpd, port, old_env = _start_server(env={"ADMIN_USER": "admin", "ADMIN_PASS": "testpass"})
    try:
        # Step 1: login
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        body = b"username=admin&password=testpass"
        conn.request("POST", "/login", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        cookie_header = resp.getheader("Set-Cookie", "")
        session_val = [p for p in cookie_header.split(";") if "session=" in p][0].strip()

        # Step 2: access /admin with cookie
        conn2 = HTTPConnection("127.0.0.1", port, timeout=2)
        conn2.request("GET", "/admin", headers={"Cookie": session_val})
        resp2 = conn2.getresponse()
        assert resp2.status == 200
        html = resp2.read().decode()
        assert "Panel Administracyjny" in html
    finally:
        _stop_server(httpd, old_env)


def test_http_logout_clears_session():
    httpd, port, old_env = _start_server(env={"ADMIN_USER": "admin", "ADMIN_PASS": "testpass"})
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        body = b"username=admin&password=testpass"
        conn.request("POST", "/login", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        cookie_header = resp.getheader("Set-Cookie", "")
        session_val = [p for p in cookie_header.split(";") if "session=" in p][0].strip()

        conn2 = HTTPConnection("127.0.0.1", port, timeout=2)
        conn2.request("GET", "/logout", headers={"Cookie": session_val})
        resp2 = conn2.getresponse()
        resp2.read()
        assert resp2.status == 302
        logout_cookie = resp2.getheader("Set-Cookie", "")
        assert "Max-Age=0" in logout_cookie or "deleted" in logout_cookie
    finally:
        _stop_server(httpd, old_env)


def test_http_unknown_path_returns_404():
    httpd, port, old_env = _start_server()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/nonexistent-path-xyz")
        resp = conn.getresponse()
        assert resp.status == 404
    finally:
        _stop_server(httpd, old_env)


def test_get_ntp_clients_parsing():
    """Test parsing of chronyc clients output (NTP Drop Int IntL Last format)."""
    mock_output = """Hostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last
===============================================================================
192.168.1.100                    5      0   5   -   127       0      0   -     -
192.168.1.101                    2      0  -5   -   354       0      0   -     -
192.168.1.102                    0      1   3   -     -       0      0   -     -
localhost                        0      0   -   -     -      93      0   3     6
"""
    with patch('server._run', return_value=(0, mock_output, '')):
        clients = srv.get_ntp_clients()

        # localhost should be filtered out
        assert len(clients) == 3

        assert clients[0]['ip'] == '192.168.1.100'
        assert clients[0]['ntp_count'] == '5'
        assert clients[0]['last_sync'] == '127'
        assert clients[0]['last_sync_seconds'] == 127

        assert clients[1]['ip'] == '192.168.1.101'
        assert clients[1]['ntp_count'] == '2'
        assert clients[1]['last_sync'] == '354'
        assert clients[1]['last_sync_seconds'] == 354

        assert clients[2]['ip'] == '192.168.1.102'
        assert clients[2]['ntp_count'] == '0'
        assert clients[2]['last_sync'] == '-'
        assert clients[2]['last_sync_seconds'] is None


def test_get_ntp_clients_empty():
    """Test empty chronyc output."""
    mock_output = """Hostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last
===============================================================================
"""
    with patch('server._run', return_value=(0, mock_output, '')):
        clients = srv.get_ntp_clients()
        assert clients == []


def test_get_ntp_clients_error():
    """Test error handling when chronyc fails."""
    with patch('server._run', return_value=(1, '', 'command not found')):
        clients = srv.get_ntp_clients()
        assert clients == []
