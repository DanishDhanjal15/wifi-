"""Capture orchestration: an async sniffer plus a channel hopper feeding shared state.

The scanner only *listens*. It classifies frames it overhears and updates an
in-memory view of nearby access points and stations. Nothing is transmitted.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Dict, Optional

from .channels import ChannelHopper, build_plan
from .models import AccessPoint, Client, DeauthEvent
from .parser import get_channel, get_signal, get_ssid, parse_security
from .utils import band_of, is_broadcast, mac_vendor


class ScanState:
    """Thread-safe store of everything seen so far."""

    def __init__(self, deauth_history: int = 200):
        self.lock = threading.Lock()
        self.aps: Dict[str, AccessPoint] = {}
        self.clients: Dict[str, Client] = {}
        self.deauths: deque[DeauthEvent] = deque(maxlen=deauth_history)
        self.frame_count = 0
        self.started = time.time()

    def snapshot(self):
        """Return sorted copies for display/export without holding the lock long."""
        with self.lock:
            aps = sorted(self.aps.values(),
                         key=lambda a: (a.signal if a.signal is not None else -999),
                         reverse=True)
            clients = sorted(self.clients.values(),
                             key=lambda c: c.last_seen, reverse=True)
            deauths = list(self.deauths)
            frames = self.frame_count
        return aps, clients, deauths, frames


class Scanner:
    def __init__(self, iface: str, band: str = "both", channel: Optional[int] = None,
                 dwell: float = 0.35, include_dfs: bool = False):
        self.iface = iface
        self.state = ScanState()
        self.channel = channel
        self._hopper: Optional[ChannelHopper] = None
        self._sniffer = None
        self._band = band
        self._dwell = dwell
        self._include_dfs = include_dfs

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        from scapy.sendrecv import AsyncSniffer

        if self.channel is None:
            plan = build_plan(self._band, self._include_dfs)
            self._hopper = ChannelHopper(self.iface, plan, self._dwell)
            self._hopper.start()
        else:
            from .channels import set_channel
            set_channel(self.iface, self.channel)

        self._sniffer = AsyncSniffer(
            iface=self.iface, prn=self._handle, store=False, monitor=True
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._hopper:
            self._hopper.stop()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    @property
    def current_channel(self) -> Optional[int]:
        if self.channel is not None:
            return self.channel
        return self._hopper.current if self._hopper else None

    # -- frame handling ----------------------------------------------------

    def _handle(self, pkt) -> None:
        from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Deauth,
                                        Dot11Disas, Dot11ProbeReq, Dot11ProbeResp)

        if not pkt.haslayer(Dot11):
            return
        with self.state.lock:
            self.state.frame_count += 1

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._handle_ap(pkt)
        elif pkt.haslayer(Dot11ProbeReq):
            self._handle_probe_req(pkt)
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            self._handle_deauth(pkt)
        else:
            self._handle_data(pkt)

    def _handle_ap(self, pkt) -> None:
        dot11 = pkt.getlayer("Dot11")
        bssid = (dot11.addr3 or "").lower()
        if not bssid or is_broadcast(bssid):
            return
        ssid, hidden = get_ssid(pkt)
        channel, band = get_channel(pkt)
        signal = get_signal(pkt)
        sec = parse_security(pkt)

        with self.state.lock:
            ap = self.state.aps.get(bssid)
            if ap is None:
                ap = AccessPoint(bssid=bssid, vendor=mac_vendor(bssid))
                self.state.aps[bssid] = ap
            ap.beacons += 1
            ap.touch(signal)
            if ssid and not hidden:
                ap.ssid = ssid
                ap.hidden = False
            elif hidden and not ap.ssid:
                ap.hidden = True
            if channel:
                ap.channel = channel
                ap.band = band or band_of(channel)
            ap.encryption = sec.encryption
            ap.ciphers = sec.ciphers
            ap.akms = sec.akms
            ap.pmf = sec.pmf
            ap.wps = sec.wps

    def _handle_probe_req(self, pkt) -> None:
        dot11 = pkt.getlayer("Dot11")
        mac = (dot11.addr2 or "").lower()
        if not mac or is_broadcast(mac):
            return
        ssid, hidden = get_ssid(pkt)
        signal = get_signal(pkt)
        with self.state.lock:
            client = self.state.clients.get(mac)
            if client is None:
                client = Client(mac=mac, vendor=mac_vendor(mac))
                self.state.clients[mac] = client
            client.touch(signal)
            if ssid and not hidden:
                client.probes.add(ssid)

    def _handle_deauth(self, pkt) -> None:
        from scapy.layers.dot11 import Dot11Deauth

        dot11 = pkt.getlayer("Dot11")
        kind = "deauth" if pkt.haslayer(Dot11Deauth) else "disassoc"
        reason = None
        try:
            reason = int(pkt.getlayer(kind == "deauth" and "Dot11Deauth" or "Dot11Disas").reason)
        except Exception:
            reason = None
        evt = DeauthEvent(
            ts=time.time(),
            src=(dot11.addr2 or "?").lower(),
            dst=(dot11.addr1 or "?").lower(),
            bssid=(dot11.addr3 or "?").lower(),
            reason=reason,
            kind=kind,
        )
        with self.state.lock:
            self.state.deauths.append(evt)

    def _handle_data(self, pkt) -> None:
        """Associate stations with APs from data-frame addressing (passive)."""
        dot11 = pkt.getlayer("Dot11")
        try:
            to_ds = dot11.FCfield & 0x1
            from_ds = dot11.FCfield & 0x2
        except Exception:
            return
        signal = get_signal(pkt)

        # Work out which address is the AP (BSSID) and which is the station.
        bssid = station = None
        if to_ds and not from_ds:
            bssid, station = dot11.addr1, dot11.addr2
        elif from_ds and not to_ds:
            bssid, station = dot11.addr2, dot11.addr1
        else:
            return
        if not bssid or not station:
            return
        bssid, station = bssid.lower(), station.lower()
        if is_broadcast(station) or is_broadcast(bssid):
            return

        with self.state.lock:
            client = self.state.clients.get(station)
            if client is None:
                client = Client(mac=station, vendor=mac_vendor(station))
                self.state.clients[station] = client
            client.touch(signal)
            client.bssid = bssid
            ap = self.state.aps.get(bssid)
            if ap is not None:
                ap.clients.add(station)
