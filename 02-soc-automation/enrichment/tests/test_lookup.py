import requests

import enrich


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.body = body

    def json(self):
        if self.body is None:
            raise ValueError("not JSON")
        return self.body


def fake_get_returning(response):
    def fake_get(url, headers, timeout):
        return response
    return fake_get


def test_lookup_reads_the_useful_fields(monkeypatch):
    body = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5},
        "as_owner": "Example ISP",
        "country": "NL",
    }}}
    monkeypatch.setattr(enrich.requests, "get", fake_get_returning(FakeResponse(200, body)))
    assert enrich.lookup_ip("8.8.8.8", "fake-key") == {
        "malicious": 5, "owner": "Example ISP", "country": "NL",
    }


def test_rate_limit_returns_an_error_not_a_crash(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get_returning(FakeResponse(429)))
    assert enrich.lookup_ip("8.8.8.8", "fake-key") == {"error": "VirusTotal returned HTTP 429"}


def test_web_page_instead_of_json_returns_an_error(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get_returning(FakeResponse(200, None)))
    assert enrich.lookup_ip("8.8.8.8", "fake-key") == {"error": "VirusTotal did not return JSON"}


def test_network_failure_returns_an_error(monkeypatch):
    def broken_get(url, headers, timeout):
        raise requests.ConnectionError("no network")
    monkeypatch.setattr(enrich.requests, "get", broken_get)
    assert enrich.lookup_ip("8.8.8.8", "fake-key") == {"error": "could not reach VirusTotal: ConnectionError"}
