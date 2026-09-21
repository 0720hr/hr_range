import json
from pathlib import Path

import pytest

from enrich import get_level, get_srcip, is_public

FIXTURES = Path(__file__).parent / "fixtures"


def load(rule_id):
    with open(FIXTURES / f"alert_{rule_id}.json") as f:
        return json.load(f)


def test_takeover_alert_has_ip_and_level_13():
    alert = load("40112")
    assert get_srcip(alert) == "172.18.0.3"
    assert get_level(alert) == 13


def test_escalation_alerts_have_no_ip():
    assert get_srcip(load("100003")) is None
    assert get_srcip(load("100004")) is None


@pytest.mark.parametrize("ip, expected", [
    ("8.8.8.8", True),
    ("172.32.5.1", True),
    ("172.18.0.3", False),
    ("172.31.255.255", False),
    ("100.64.0.1", False),
    ("224.0.0.1", False),
    ("127.0.0.1", False),
    ("", False),
    (None, False),
    ("not-an-ip", False),
])
def test_is_public(ip, expected):
    assert is_public(ip) == expected
