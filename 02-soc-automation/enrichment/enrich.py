import ipaddress
import json
import os
import sys

import requests

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def get_srcip(alert):
    return alert.get("data", {}).get("srcip")


def get_level(alert):
    return alert.get("rule", {}).get("level")


def is_public(ip):
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def lookup_ip(ip, api_key):
    try:
        response = requests.get(VT_URL + ip, headers={"x-apikey": api_key}, timeout=10)
    except requests.RequestException as error:
        return {"error": f"could not reach VirusTotal: {type(error).__name__}"}

    if response.status_code != 200:
        return {"error": f"VirusTotal returned HTTP {response.status_code}"}

    try:
        body = response.json()
    except ValueError:
        return {"error": "VirusTotal did not return JSON"}

    attributes = body.get("data", {}).get("attributes", {})
    return {
        "malicious": attributes.get("last_analysis_stats", {}).get("malicious"),
        "owner": attributes.get("as_owner"),
        "country": attributes.get("country"),
    }


def summarize(alert, api_key):
    ip = get_srcip(alert)
    summary = {
        "rule": alert.get("rule", {}).get("id"),
        "level": get_level(alert),
        "description": alert.get("rule", {}).get("description"),
        "agent": alert.get("agent", {}).get("name"),
        "srcip": ip,
    }
    if not is_public(ip):
        summary["enrichment"] = "skipped: no public IP"
    elif not api_key:
        summary["enrichment"] = "skipped: no API key"
    else:
        summary["enrichment"] = lookup_ip(ip, api_key)
    return summary


def main():
    if len(sys.argv) != 2:
        print("usage: python enrich.py ALERT_FILE")
        return 2
    try:
        with open(sys.argv[1]) as f:
            alert = json.load(f)
    except (OSError, json.JSONDecodeError) as error:
        print(f"could not read alert: {error}")
        return 1
    summary = summarize(alert, os.environ.get("VT_API_KEY"))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
