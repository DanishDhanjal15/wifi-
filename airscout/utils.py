"""Small helpers: privilege checks, interface inspection, MAC/OUI utilities."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import List, Optional


def is_root() -> bool:
    """True if the process has the privileges needed to sniff in monitor mode."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Non-POSIX (e.g. Windows dev box). AirScout only runs for real on Linux.
        return False


def run(cmd: List[str], timeout: int = 5) -> subprocess.CompletedProcess:
    """Run a command, never raising on non-zero exit. Returns the CompletedProcess."""
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def have(binary: str) -> bool:
    """True if an external tool (iw, ip, airmon-ng…) is on PATH."""
    return shutil.which(binary) is not None


def list_wifi_interfaces() -> List[str]:
    """Best-effort list of wireless interface names via `iw dev`."""
    if not have("iw"):
        return []
    out = run(["iw", "dev"]).stdout
    return re.findall(r"Interface\s+(\S+)", out)


def interface_type(iface: str) -> Optional[str]:
    """Return the interface type reported by `iw dev <iface> info` (e.g. 'monitor')."""
    if not have("iw"):
        return None
    out = run(["iw", "dev", iface, "info"]).stdout
    m = re.search(r"type\s+(\S+)", out)
    return m.group(1) if m else None


def is_monitor_mode(iface: str) -> bool:
    return interface_type(iface) == "monitor"


# ---------------------------------------------------------------------------
# MAC / OUI helpers. A tiny built-in vendor table keeps the tool dependency-free;
# it is intentionally small and only meant to add colour, not to be exhaustive.
# ---------------------------------------------------------------------------

_OUI = {
    "001018": "Broadcom", "0050f2": "Microsoft", "000c43": "Ralink",
    "00256c": "Wi2Wi", "001aef": "Sagemcom", "d85d4c": "TP-Link",
    "5c633c": "TP-Link", "b0487a": "TP-Link", "1c61b4": "TP-Link",
    "e8de27": "TP-Link", "00e04c": "Realtek", "52540": "QEMU/KVM",
    "001b63": "Apple", "3c0754": "Apple", "a4c361": "Apple",
    "d0817a": "Apple", "f0d1a9": "Apple", "ac1f6b": "Super Micro",
    "0018e7": "Cameo", "c83a35": "Tenda", "c8d719": "Cisco",
    "0021d8": "Cisco", "0024b2": "Netgear", "a040a0": "Netgear",
    "20e52a": "Netgear", "00095b": "Netgear", "e091f5": "Netgear",
    "001e2a": "Netgear", "784476": "Xiaomi", "50ec50": "Xiaomi",
    "64cc2e": "Xiaomi", "8cbebe": "Xiaomi", "fc64ba": "Xiaomi",
    "ecadb8": "Apple", "dca632": "Raspberry Pi", "b827eb": "Raspberry Pi",
    "e45f01": "Raspberry Pi", "d83add": "Raspberry Pi", "2c3ae8": "Espressif",
    "240ac4": "Espressif", "a020a6": "Espressif", "7c9ebd": "Espressif",
    "001349": "ASUS", "2c4d54": "ASUS", "38d547": "ASUS",
    "04d4c4": "ASUS", "d017c2": "ASUS", "086a0a": "Amazon",
    "fc65de": "Amazon", "68540a": "Amazon", "cc9ea4": "Samsung",
    "5cc9d3": "Samsung", "e8508b": "Samsung", "08d42b": "Samsung",
}


def mac_vendor(mac: str) -> str:
    """Look up a coarse vendor name from a MAC's OUI, or '' if unknown."""
    if not mac:
        return ""
    clean = mac.replace(":", "").replace("-", "").lower()
    for prefix in (clean[:6], clean[:5]):
        if prefix in _OUI:
            return _OUI[prefix]
    return ""


def is_broadcast(mac: str) -> bool:
    return mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")


def freq_to_channel(freq: Optional[int]) -> Optional[int]:
    """Convert a RadioTap centre frequency (MHz) to a Wi-Fi channel number."""
    if not freq:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if 5000 <= freq < 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:            # 6 GHz (802.11ax), rarely reachable here
        return (freq - 5950) // 5
    return None


def band_of(channel: Optional[int]) -> str:
    if channel is None:
        return ""
    if channel <= 14:
        return "2.4GHz"
    if channel <= 177:
        return "5GHz"
    return "6GHz"
