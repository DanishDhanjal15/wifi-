"""Data models for the entities AirScout tracks while sniffing."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AccessPoint:
    """A discovered access point, built up from beacon / probe-response frames."""

    bssid: str
    ssid: str = ""
    hidden: bool = False
    channel: Optional[int] = None
    band: str = ""
    signal: Optional[int] = None          # last RSSI in dBm
    encryption: str = "?"                  # OPEN / WEP / WPA / WPA2 / WPA3 / mixed
    ciphers: set = field(default_factory=set)
    akms: set = field(default_factory=set)
    pmf: str = "n/a"                       # management frame protection: off/optional/required
    wps: bool = False
    vendor: str = ""
    beacons: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    clients: set = field(default_factory=set)   # MACs seen associated with this BSSID

    def touch(self, signal: Optional[int]) -> None:
        self.last_seen = time.time()
        if signal is not None:
            self.signal = signal

    @property
    def age(self) -> float:
        return time.time() - self.last_seen

    @property
    def display_ssid(self) -> str:
        if self.hidden or not self.ssid:
            return "<hidden>"
        return self.ssid


@dataclass
class Client:
    """A station (client device) seen probing or exchanging data frames."""

    mac: str
    bssid: str = ""                        # associated AP, if known
    signal: Optional[int] = None
    vendor: str = ""
    packets: int = 0
    probes: set = field(default_factory=set)   # SSIDs this station has probed for
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def touch(self, signal: Optional[int]) -> None:
        self.last_seen = time.time()
        self.packets += 1
        if signal is not None:
            self.signal = signal

    @property
    def age(self) -> float:
        return time.time() - self.last_seen


@dataclass
class DeauthEvent:
    """A single observed deauthentication / disassociation frame (defensive IDS)."""

    ts: float
    src: str
    dst: str
    bssid: str
    reason: Optional[int]
    kind: str          # "deauth" or "disassoc"
