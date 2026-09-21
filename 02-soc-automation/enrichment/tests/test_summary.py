import json
from pathlib import Path

import enrich

FIXTURES = Path(__file__).parent / "fixtures"


def load(rule_id):
    with open(FIXTURES / f"alert_{rule_id}.json") as f:
        return json.load(f)


def fail_if_called(*args, **kwargs):
    raise AssertionError("VirusTotal should not have been called")


def test_private_ip_is_never_looked_up(monkeypatch):
    monkeypatch.setattr(enrich, "lookup_ip", fail_if_called)
    summary = enrich.summarize(load("40112"), "fake-key")
    assert summary["srcip"] == "172.18.0.3"
    assert summary["level"] == 13
    assert summary["enrichment"] == "skipped: no public IP"


def test_alert_without_ip_is_never_looked_up(monkeypatch):
    monkeypatch.setattr(enrich, "lookup_ip", fail_if_called)
    summary = enrich.summarize(load("100004"), "fake-key")
    assert summary["srcip"] is None
    assert summary["enrichment"] == "skipped: no public IP"


def test_public_ip_is_looked_up(monkeypatch):
    monkeypatch.setattr(enrich, "lookup_ip", lambda ip, key: {"malicious": 5})
    alert = {"rule": {"id": "40112", "level": 13}, "data": {"srcip": "8.8.8.8"}}
    assert enrich.summarize(alert, "fake-key")["enrichment"] == {"malicious": 5}


def test_failed_lookup_still_keeps_the_alert(monkeypatch):
    monkeypatch.setattr(enrich, "lookup_ip", lambda ip, key: {"error": "VirusTotal returned HTTP 429"})
    alert = {"rule": {"id": "40112", "level": 13}, "data": {"srcip": "8.8.8.8"}}
    summary = enrich.summarize(alert, "fake-key")
    assert summary["level"] == 13
    assert summary["srcip"] == "8.8.8.8"
    assert summary["enrichment"] == {"error": "VirusTotal returned HTTP 429"}


def test_missing_api_key_skips_lookup(monkeypatch):
    monkeypatch.setattr(enrich, "lookup_ip", fail_if_called)
    alert = {"data": {"srcip": "8.8.8.8"}}
    assert enrich.summarize(alert, None)["enrichment"] == "skipped: no API key"
