"""802.11 frame parsing: RSSI, channel, and a full RSN/WPA/WPS security profile.

Everything here is read-only decoding of frames the adapter overhears. Scapy is
imported lazily so the package can be inspected / installed on a machine without
libpcap before it is actually run on the capture host.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .utils import band_of, freq_to_channel

# Cipher suite selector types (OUI 00-0F-AC for RSN, 00-50-F2 for WPA).
_CIPHERS = {1: "WEP40", 2: "TKIP", 4: "CCMP", 5: "WEP104", 6: "BIP", 8: "GCMP", 9: "GCMP256", 10: "CCMP256"}
# Authentication and key-management (AKM) selector types.
_AKMS = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256",
         6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE", 11: "802.1X-SUITEB", 18: "OWE"}


@dataclass
class SecurityProfile:
    encryption: str = "OPEN"
    ciphers: set = None
    akms: set = None
    pmf: str = "off"          # off / optional / required
    wps: bool = False

    def __post_init__(self):
        if self.ciphers is None:
            self.ciphers = set()
        if self.akms is None:
            self.akms = set()


def _elements(pkt):
    """Yield (id, info_bytes) for every information element in a beacon/probe frame."""
    from scapy.layers.dot11 import Dot11Elt

    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        try:
            yield int(elt.ID), bytes(elt.info)
        except Exception:
            pass
        elt = elt.payload.getlayer(Dot11Elt)


def _suite_type(suite: bytes) -> Optional[int]:
    """Last byte of a 4-byte cipher/AKM selector is its type."""
    return suite[3] if len(suite) == 4 else None


def _parse_rsn(data: bytes) -> Tuple[set, set, Optional[int]]:
    """Parse an RSN (802.11i) element into (ciphers, akms, rsn_capabilities)."""
    ciphers: set = set()
    akms: set = set()
    rsn_cap: Optional[int] = None
    try:
        idx = 2                                   # skip 2-byte version
        idx += 4                                  # group cipher suite
        pair_count = int.from_bytes(data[idx:idx + 2], "little"); idx += 2
        for _ in range(pair_count):
            t = _suite_type(data[idx:idx + 4]); idx += 4
            if t in _CIPHERS:
                ciphers.add(_CIPHERS[t])
        akm_count = int.from_bytes(data[idx:idx + 2], "little"); idx += 2
        for _ in range(akm_count):
            t = _suite_type(data[idx:idx + 4]); idx += 4
            if t in _AKMS:
                akms.add(_AKMS[t])
        if len(data) >= idx + 2:
            rsn_cap = int.from_bytes(data[idx:idx + 2], "little")
    except Exception:
        pass
    return ciphers, akms, rsn_cap


def parse_security(pkt) -> SecurityProfile:
    """Derive a full security profile from a beacon or probe-response frame."""
    from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp

    prof = SecurityProfile()
    has_rsn = False
    has_wpa = False

    for eid, info in _elements(pkt):
        if eid == 48:                             # RSN
            has_rsn = True
            ciphers, akms, rsn_cap = _parse_rsn(info)
            prof.ciphers |= ciphers
            prof.akms |= akms
            if rsn_cap is not None:
                mfpc = bool(rsn_cap & 0x0080)
                mfpr = bool(rsn_cap & 0x0040)
                prof.pmf = "required" if mfpr else ("optional" if mfpc else "off")
        elif eid == 221:                          # vendor specific
            if info[:4] == b"\x00\x50\xf2\x01":   # Microsoft WPA (WPA1)
                has_wpa = True
                # WPA1 element carries its own cipher/akm lists; TKIP is typical.
                prof.ciphers.add("TKIP")
            elif info[:4] == b"\x00\x50\xf2\x04":  # WPS
                prof.wps = True

    # Classify.
    if has_rsn:
        if "SAE" in prof.akms and "PSK" in prof.akms:
            prof.encryption = "WPA2/WPA3"
        elif "SAE" in prof.akms:
            prof.encryption = "WPA3"
        elif "OWE" in prof.akms:
            prof.encryption = "OWE"
        elif prof.akms & {"802.1X", "802.1X-SHA256", "FT-802.1X", "802.1X-SUITEB"}:
            prof.encryption = "WPA2-Ent"
        else:
            prof.encryption = "WPA2"
    elif has_wpa:
        prof.encryption = "WPA"
    else:
        # No RSN/WPA: distinguish WEP (privacy bit set) from truly open.
        cap = 0
        layer = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
        if layer is not None:
            try:
                cap = int(layer.cap)
            except Exception:
                cap = 0
        prof.encryption = "WEP" if (cap & 0x0010) else "OPEN"

    return prof


def get_signal(pkt) -> Optional[int]:
    """Extract RSSI (dBm) from the RadioTap header, if the driver provides it."""
    from scapy.layers.dot11 import RadioTap

    try:
        if pkt.haslayer(RadioTap):
            sig = getattr(pkt[RadioTap], "dBm_AntSignal", None)
            if sig is not None:
                return int(sig)
    except Exception:
        pass
    return None


def get_channel(pkt) -> Tuple[Optional[int], str]:
    """Return (channel, band). Prefers the DS-parameter element, falls back to freq."""
    from scapy.layers.dot11 import RadioTap

    channel = None
    for eid, info in _elements(pkt):
        if eid == 3 and info:                     # DS Parameter Set
            channel = info[0]
            break
    if channel is None:
        try:
            if pkt.haslayer(RadioTap):
                channel = freq_to_channel(getattr(pkt[RadioTap], "ChannelFrequency", None))
        except Exception:
            channel = None
    return channel, band_of(channel)


def get_ssid(pkt) -> Tuple[str, bool]:
    """Return (ssid, hidden). Hidden APs advertise a zero-length or null SSID."""
    for eid, info in _elements(pkt):
        if eid == 0:                              # SSID element
            if not info or all(b == 0 for b in info):
                return "", True
            try:
                return info.decode("utf-8", "replace"), False
            except Exception:
                return info.decode("latin-1", "replace"), False
    return "", True
