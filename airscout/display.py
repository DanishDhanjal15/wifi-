"""Rich-based rendering for live scans, audits and the deauth monitor.

Falls back to plain text if `rich` is not installed so the tool still runs.
"""

from __future__ import annotations

import time
from typing import List

from .audit import Finding
from .models import AccessPoint, Client, DeauthEvent

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    _HAVE_RICH = True
    console = Console()
except Exception:                                   # pragma: no cover
    _HAVE_RICH = False
    console = None


_ENC_STYLE = {
    "OPEN": "bold red", "WEP": "bold red", "WPA": "yellow",
    "WPA2": "green", "WPA2-Ent": "green", "WPA2/WPA3": "bold green",
    "WPA3": "bold green", "OWE": "cyan", "?": "dim",
}
_SEV_STYLE = {
    "critical": "bold white on red", "high": "bold red", "medium": "yellow",
    "low": "cyan", "info": "dim", "good": "bold green",
}


def _sig_text(signal):
    if signal is None:
        return Text("  ·", style="dim") if _HAVE_RICH else "  ·"
    style = "green" if signal >= -60 else ("yellow" if signal >= -75 else "red")
    txt = f"{signal:>4}"
    return Text(txt, style=style) if _HAVE_RICH else txt


def build_ap_table(aps: List[AccessPoint], channel, frames: int, elapsed: float) -> "Table":
    table = Table(title=f"Access points — ch {channel or '?'} · {len(aps)} seen · "
                        f"{frames} frames · {elapsed:0.0f}s",
                  expand=True, header_style="bold")
    table.add_column("BSSID", no_wrap=True)
    table.add_column("SSID", overflow="fold")
    table.add_column("Ch", justify="right", width=4)
    table.add_column("Band", width=6)
    table.add_column("Sig", justify="right", width=5)
    table.add_column("Security", overflow="fold")
    table.add_column("PMF", width=8)
    table.add_column("WPS", width=4)
    table.add_column("Clients", justify="right", width=7)
    table.add_column("Vendor", overflow="fold")

    for ap in aps[:40]:
        enc = ap.encryption
        sec = enc
        if ap.ciphers:
            sec += " / " + "+".join(sorted(ap.ciphers))
        table.add_row(
            ap.bssid,
            Text(ap.display_ssid, style="dim italic" if ap.hidden else ""),
            str(ap.channel or ""),
            ap.band,
            _sig_text(ap.signal),
            Text(sec, style=_ENC_STYLE.get(enc, "")),
            ap.pmf,
            Text("yes", style="red") if ap.wps else Text("no", style="dim"),
            str(len(ap.clients)) or "",
            ap.vendor,
        )
    return table


def build_client_table(clients: List[Client]) -> "Table":
    table = Table(title=f"Stations — {len(clients)} seen", expand=True, header_style="bold")
    table.add_column("MAC", no_wrap=True)
    table.add_column("Assoc BSSID", no_wrap=True)
    table.add_column("Sig", justify="right", width=5)
    table.add_column("Pkts", justify="right", width=6)
    table.add_column("Probes for", overflow="fold")
    table.add_column("Vendor", overflow="fold")
    for c in clients[:25]:
        table.add_row(
            c.mac, c.bssid or Text("—", style="dim"), _sig_text(c.signal),
            str(c.packets), ", ".join(sorted(c.probes)[:6]), c.vendor,
        )
    return table


def build_deauth_panel(deauths: List[DeauthEvent], window: float = 10.0) -> "Panel":
    now = time.time()
    recent = [d for d in deauths if now - d.ts <= window]
    rate = len(recent)
    alert = rate >= 5
    body = Table.grid(expand=True) if _HAVE_RICH else None
    lines = []
    for d in list(deauths)[-10:][::-1]:
        reason = f" reason={d.reason}" if d.reason is not None else ""
        lines.append(f"[{time.strftime('%H:%M:%S', time.localtime(d.ts))}] "
                     f"{d.kind} {d.src} → {d.dst} (bssid {d.bssid}){reason}")
    text = "\n".join(lines) or "No deauth/disassoc frames observed."
    title = (f"⚠ POSSIBLE DEAUTH ATTACK — {rate} frames in last {window:0.0f}s"
             if alert else f"Deauth/disassoc monitor — {rate} in last {window:0.0f}s")
    style = "bold red" if alert else "green"
    if _HAVE_RICH:
        return Panel(Text(text), title=title, border_style=style)
    return f"== {title} ==\n{text}"


def print_audit(ap: AccessPoint, findings: List[Finding]) -> None:
    header = (f"{ap.display_ssid}  ({ap.bssid})  ch {ap.channel or '?'} · "
              f"{ap.band} · {ap.encryption} · sig {ap.signal}")
    if not _HAVE_RICH:
        print("\n" + header)
        print("-" * len(header))
        for f in findings:
            print(f"[{f.severity.upper():8}] {f.title}\n    {f.detail}\n    fix: {f.fix}")
        return
    console.print(Panel(Text(header, style="bold"), border_style="blue"))
    table = Table(expand=True, show_lines=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Finding")
    table.add_column("Recommended fix")
    for f in findings:
        table.add_row(
            Text(f.severity.upper(), style=_SEV_STYLE.get(f.severity, "")),
            Text(f.title, style="bold") + Text(f"\n{f.detail}", style="dim"),
            f.fix,
        )
    console.print(table)
