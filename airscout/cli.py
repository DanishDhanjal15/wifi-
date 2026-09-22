"""AirScout command-line interface.

Subcommands:
    scan      live discovery of nearby APs and stations (passive)
    audit     capture briefly, then report security findings for your network
    monitor   live deauth/disassociation detector (defensive IDS)
    ifaces    list wireless interfaces and their mode
"""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .utils import (interface_type, is_monitor_mode, is_root,
                    list_wifi_interfaces)


def _preflight(iface: str) -> bool:
    """Validate privileges and interface state before capturing."""
    ok = True
    if not is_root():
        print("error: monitor-mode capture needs root. Re-run with sudo.", file=sys.stderr)
        ok = False
    itype = interface_type(iface)
    if itype is None:
        print(f"warning: could not query '{iface}' via `iw` — is the name correct?",
              file=sys.stderr)
    elif itype != "monitor":
        print(f"error: '{iface}' is in '{itype}' mode, not 'monitor'.", file=sys.stderr)
        print("       enable monitor mode first, e.g.:", file=sys.stderr)
        print(f"         sudo ip link set {iface} down", file=sys.stderr)
        print(f"         sudo iw dev {iface} set type monitor", file=sys.stderr)
        print(f"         sudo ip link set {iface} up", file=sys.stderr)
        ok = False
    return ok


def _run_scan(scanner, duration, refresh, render_fn):
    """Shared live loop for scan/monitor. render_fn(scanner) -> renderable/str."""
    try:
        from rich.live import Live
        from .display import _HAVE_RICH
    except Exception:
        _HAVE_RICH = False

    scanner.start()
    start = time.time()
    try:
        if _HAVE_RICH:
            from rich.live import Live
            with Live(render_fn(scanner), refresh_per_second=4, screen=False) as live:
                while duration == 0 or time.time() - start < duration:
                    time.sleep(refresh)
                    live.update(render_fn(scanner))
        else:
            while duration == 0 or time.time() - start < duration:
                time.sleep(max(refresh, 1.0))
                print(render_fn(scanner))
    except KeyboardInterrupt:
        pass
    finally:
        scanner.stop()


def cmd_scan(args) -> int:
    if not _preflight(args.iface):
        return 2
    from rich.console import Group

    from .display import build_ap_table, build_client_table
    from .export import write_csv, write_json
    from .scanner import Scanner

    scanner = Scanner(args.iface, band=args.band, channel=args.channel,
                      dwell=args.dwell, include_dfs=args.include_dfs)

    def render(sc):
        aps, clients, _deauths, frames = sc.state.snapshot()
        elapsed = time.time() - sc.state.started
        ap_tbl = build_ap_table(aps, sc.current_channel, frames, elapsed)
        if args.clients:
            return Group(ap_tbl, build_client_table(clients))
        return ap_tbl

    _run_scan(scanner, args.duration, args.refresh, render)

    aps, clients, _d, _f = scanner.state.snapshot()
    if args.json:
        write_json(args.json, aps, clients)
        print(f"wrote {len(aps)} APs / {len(clients)} stations to {args.json}")
    if args.csv:
        write_csv(args.csv, aps)
        print(f"wrote {len(aps)} APs to {args.csv}")
    return 0


def cmd_audit(args) -> int:
    if not _preflight(args.iface):
        return 2
    from .audit import audit_ap
    from .display import console, print_audit
    from .scanner import Scanner

    target = (args.bssid or "").lower()
    print(f"Collecting for {args.duration}s "
          f"({'all networks' if not (args.bssid or args.ssid) else 'target only'})…")
    scanner = Scanner(args.iface, band=args.band, channel=args.channel,
                      dwell=args.dwell, include_dfs=args.include_dfs)
    scanner.start()
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        scanner.stop()

    aps, _clients, _d, _f = scanner.state.snapshot()

    def matches(ap):
        if target:
            return ap.bssid == target
        if args.ssid:
            return ap.ssid == args.ssid
        return True

    selected = [a for a in aps if matches(a)]
    if not selected:
        print("No matching access points were observed. Move closer or scan longer.")
        return 1

    results = []
    for ap in selected:
        findings = audit_ap(ap)
        print_audit(ap, findings)
        results.append((ap, findings))

    if args.json:
        import json
        payload = [{
            "bssid": ap.bssid, "ssid": ap.display_ssid, "encryption": ap.encryption,
            "findings": [f.__dict__ for f in findings],
        } for ap, findings in results]
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\nwrote audit for {len(results)} network(s) to {args.json}")
    return 0


def cmd_monitor(args) -> int:
    if not _preflight(args.iface):
        return 2
    from .display import build_deauth_panel
    from .scanner import Scanner

    # A fixed channel gives the cleanest deauth picture; default to hopping otherwise.
    scanner = Scanner(args.iface, band=args.band, channel=args.channel, dwell=args.dwell)

    def render(sc):
        _aps, _clients, deauths, _frames = sc.state.snapshot()
        return build_deauth_panel(deauths, window=args.window)

    print("Watching for deauth/disassociation frames. Ctrl-C to stop.")
    _run_scan(scanner, args.duration, args.refresh, render)
    return 0


def cmd_ifaces(_args) -> int:
    ifaces = list_wifi_interfaces()
    if not ifaces:
        print("No wireless interfaces found (or `iw` is not installed).")
        return 1
    for i in ifaces:
        print(f"{i:16} type={interface_type(i) or '?':10} "
              f"{'[monitor]' if is_monitor_mode(i) else ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="airscout",
        description="Passive Wi-Fi recon, 802.11 analysis and security auditing. "
                    "AirScout only listens — it never transmits.",
    )
    p.add_argument("--version", action="version", version=f"airscout {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("-i", "--iface", required=True, help="monitor-mode interface, e.g. wlan0mon")
        sp.add_argument("-b", "--band", choices=["2.4", "5", "both"], default="both")
        sp.add_argument("-c", "--channel", type=int, default=None,
                        help="lock to one channel instead of hopping")
        sp.add_argument("--dwell", type=float, default=0.35, help="seconds per channel")
        sp.add_argument("--include-dfs", action="store_true", help="also hop DFS 5 GHz channels")
        sp.add_argument("--refresh", type=float, default=0.5, help="UI refresh interval (s)")

    sp = sub.add_parser("scan", help="live discovery of nearby APs and stations")
    add_common(sp)
    sp.add_argument("-d", "--duration", type=int, default=0, help="seconds (0 = until Ctrl-C)")
    sp.add_argument("--clients", action="store_true", help="also show a station table")
    sp.add_argument("--json", help="write results to a JSON file on exit")
    sp.add_argument("--csv", help="write AP results to a CSV file on exit")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("audit", help="security audit of your own network(s)")
    add_common(sp)
    sp.add_argument("-d", "--duration", type=int, default=15, help="capture seconds")
    sp.add_argument("--bssid", help="audit only this BSSID")
    sp.add_argument("--ssid", help="audit only this SSID")
    sp.add_argument("--json", help="write findings to a JSON file")
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("monitor", help="live deauth/disassoc detector (defensive IDS)")
    add_common(sp)
    sp.add_argument("-d", "--duration", type=int, default=0, help="seconds (0 = until Ctrl-C)")
    sp.add_argument("--window", type=float, default=10.0, help="alert window (s)")
    sp.set_defaults(func=cmd_monitor)

    sp = sub.add_parser("ifaces", help="list wireless interfaces and their mode")
    sp.set_defaults(func=cmd_ifaces)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ImportError as exc:
        print(f"error: missing dependency ({exc}). Run: pip install -r requirements.txt",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
