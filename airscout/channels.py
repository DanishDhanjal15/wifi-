"""Channel plans and a background channel hopper.

The AWUS036ACH is dual-band, so we hop across both 2.4 GHz and (non-DFS) 5 GHz
channels. DFS channels are skipped by default because many drivers refuse to
tune to them passively, which just produces noise in the logs.
"""

from __future__ import annotations

import threading
import time
from typing import List

from .utils import run

CHANNELS_24: List[int] = list(range(1, 14))          # 1..13

# Common, non-DFS 5 GHz channels (UNII-1 and UNII-3). DFS (52-144) omitted.
CHANNELS_5: List[int] = [36, 40, 44, 48, 149, 153, 157, 161, 165]

# DFS channels, available via --include-dfs for users who know their regulatory
# domain allows passive scanning there.
CHANNELS_5_DFS: List[int] = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]


def build_plan(band: str = "both", include_dfs: bool = False) -> List[int]:
    """Return the ordered list of channels to hop across for a given band choice."""
    plan: List[int] = []
    if band in ("2.4", "both"):
        plan += CHANNELS_24
    if band in ("5", "both"):
        plan += CHANNELS_5
        if include_dfs:
            plan += CHANNELS_5_DFS
    return plan


def set_channel(iface: str, channel: int) -> bool:
    """Tune the interface to a channel via `iw`. Returns False if the driver refuses."""
    res = run(["iw", "dev", iface, "set", "channel", str(channel)])
    return res.returncode == 0


class ChannelHopper(threading.Thread):
    """Cycles the interface through a channel plan on a background thread."""

    def __init__(self, iface: str, plan: List[int], dwell: float = 0.35):
        super().__init__(daemon=True)
        self.iface = iface
        self.plan = plan or CHANNELS_24
        self.dwell = dwell
        self.current: int | None = None
        self._stop = threading.Event()
        self._bad: set[int] = set()      # channels the driver keeps rejecting

    def run(self) -> None:
        idx = 0
        while not self._stop.is_set():
            channel = self.plan[idx % len(self.plan)]
            idx += 1
            if channel in self._bad:
                continue
            if set_channel(self.iface, channel):
                self.current = channel
            else:
                self._bad.add(channel)      # stop retrying a channel that won't tune
            self._stop.wait(self.dwell)

    def stop(self) -> None:
        self._stop.set()
