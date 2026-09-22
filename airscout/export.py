"""JSON / CSV export of a scan snapshot."""

from __future__ import annotations

import csv
import json
import time
from typing import List

from .models import AccessPoint, Client


def _ap_dict(ap: AccessPoint) -> dict:
    return {
        "bssid": ap.bssid,
        "ssid": ap.display_ssid,
        "hidden": ap.hidden,
        "channel": ap.channel,
        "band": ap.band,
        "signal_dbm": ap.signal,
        "encryption": ap.encryption,
        "ciphers": sorted(ap.ciphers),
        "akms": sorted(ap.akms),
        "pmf": ap.pmf,
        "wps": ap.wps,
        "vendor": ap.vendor,
        "beacons": ap.beacons,
        "clients": sorted(ap.clients),
        "first_seen": ap.first_seen,
        "last_seen": ap.last_seen,
    }


def _client_dict(c: Client) -> dict:
    return {
        "mac": c.mac, "bssid": c.bssid, "signal_dbm": c.signal,
        "packets": c.packets, "probes": sorted(c.probes),
        "vendor": c.vendor, "first_seen": c.first_seen, "last_seen": c.last_seen,
    }


def write_json(path: str, aps: List[AccessPoint], clients: List[Client]) -> None:
    data = {
        "generated_at": time.time(),
        "access_points": [_ap_dict(a) for a in aps],
        "stations": [_client_dict(c) for c in clients],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_csv(path: str, aps: List[AccessPoint]) -> None:
    fields = ["bssid", "ssid", "hidden", "channel", "band", "signal_dbm",
              "encryption", "ciphers", "pmf", "wps", "vendor", "beacons", "clients"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(fields)
        for ap in aps:
            d = _ap_dict(ap)
            d["ciphers"] = "+".join(d["ciphers"])
            d["clients"] = len(d["clients"])
            writer.writerow([d[f] for f in fields])
