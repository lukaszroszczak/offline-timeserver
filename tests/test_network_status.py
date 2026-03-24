import re

from server import _parse_ip_brief


def test_parse_ip_brief_detects_ethernet_connected():
    sample = """
lo               UNKNOWN        127.0.0.1/8 ::1/128 
end0             UP             192.168.151.57/24 metric 100 fe80::81:d3ff:fee2:d30b/64 
""".strip()
    interfaces = _parse_ip_brief(sample)
    # Find end0
    end0 = next((i for i in interfaces if i["ifname"] == "end0"), None)
    assert end0 is not None
    assert end0["type"] == "ethernet"
    assert end0["state"] == "connected"
    assert end0["connection"].startswith("192.168.151.57/")


def test_parse_ip_brief_handles_no_ipv4():
    sample = """
wlan0            DOWN           
""".strip()
    interfaces = _parse_ip_brief(sample)
    wlan0 = next((i for i in interfaces if i["ifname"] == "wlan0"), None)
    assert wlan0 is not None
    assert wlan0["type"] == "wifi"
    assert wlan0["state"] == "disconnected"
    assert wlan0["connection"] == "--"

