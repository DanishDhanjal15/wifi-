"""Turn an observed access point into human-readable security findings.

This is the defensive heart of AirScout: point it at *your own* network and it
tells you what an attacker would notice and what to harden. Every finding maps
to a concrete mitigation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .models import AccessPoint

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "good": 5}


@dataclass
class Finding:
    severity: str          # critical / high / medium / low / info / good
    title: str
    detail: str
    fix: str


def audit_ap(ap: AccessPoint) -> List[Finding]:
    """Return an ordered list of findings for a single access point."""
    findings: List[Finding] = []
    enc = ap.encryption

    if enc == "OPEN":
        findings.append(Finding(
            "critical", "Open network (no encryption)",
            "Traffic is sent in clear text; anyone nearby can read it.",
            "Enable WPA2-AES or, ideally, WPA3-SAE with a strong passphrase.",
        ))
    elif enc == "WEP":
        findings.append(Finding(
            "critical", "WEP encryption",
            "WEP is broken and can be recovered in minutes regardless of key length.",
            "Switch to WPA2-AES or WPA3 immediately.",
        ))
    elif enc == "WPA":
        findings.append(Finding(
            "high", "Legacy WPA (WPA1/TKIP)",
            "WPA1 with TKIP has known weaknesses and cripples throughput.",
            "Move to WPA2-AES or WPA3.",
        ))
    elif enc == "WPA2":
        findings.append(Finding(
            "info", "WPA2-Personal",
            "WPA2-AES is acceptable but has no protection against offline "
            "passphrase guessing once a handshake is captured.",
            "Use a long, random passphrase (16+ chars) and enable WPA3 if supported.",
        ))
    elif enc in ("WPA2/WPA3", "WPA3", "OWE"):
        findings.append(Finding(
            "good", f"{enc} in use",
            "Modern key management (SAE/OWE) resists offline guessing.",
            "Keep firmware current; prefer WPA3-only once all clients support it.",
        ))

    if "TKIP" in ap.ciphers and enc not in ("WEP", "OPEN"):
        findings.append(Finding(
            "medium", "TKIP cipher offered",
            "TKIP is deprecated and weakens an otherwise-modern network.",
            "Set the cipher to AES/CCMP only (disable TKIP mixed mode).",
        ))

    if ap.wps:
        findings.append(Finding(
            "high", "WPS enabled",
            "WPS PIN registration is vulnerable to online PIN attacks and "
            "offline (Pixie-Dust) recovery on many routers.",
            "Disable WPS entirely in the router admin panel.",
        ))

    if enc in ("WPA2", "WPA2/WPA3", "WPA3") and ap.pmf == "off":
        findings.append(Finding(
            "medium", "Management Frame Protection off",
            "Without 802.11w (PMF), deauth/disassoc frames can be spoofed to "
            "knock clients off the network.",
            "Enable PMF (802.11w) as 'required', or at least 'optional'.",
        ))

    if ap.hidden:
        findings.append(Finding(
            "low", "Hidden SSID",
            "Hiding the SSID is not a security control; clients still leak the "
            "name in probe requests and it complicates connectivity.",
            "Rely on strong WPA3/WPA2 rather than SSID hiding.",
        ))

    if not findings:
        findings.append(Finding("info", "No obvious issues",
                                "No weak configuration detected from passive data.",
                                "Continue to keep firmware and passphrases strong."))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return findings


def worst_severity(findings: List[Finding]) -> str:
    return min((f.severity for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 9))
