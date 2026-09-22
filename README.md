# AirScout

**Passive Wi-Fi reconnaissance, 802.11 frame analysis and security auditing — from the command line.**

AirScout listens to the air around you with a monitor-mode adapter and tells you
what's there: nearby access points, their security posture, associated stations,
and whether someone is spraying deauthentication frames. It is built for
**learning 802.11, auditing networks you own, and defending them.**

> AirScout **only receives**. It never transmits a single frame — no deauth, no
> injection, no association. That is a deliberate design choice, not a missing
> feature (see [Scope](#scope--responsible-use)).

---

## Why another Wi-Fi tool?

`aircrack-ng`, `kismet`, `wifite` and friends are powerful but sprawling, and
most of their surface area is offensive. AirScout does the *reconnaissance and
audit* half really well, in one small, readable Python codebase:

| Capability | AirScout |
|---|---|
| Dual-band (2.4 + 5 GHz) channel-hopping scan | ✅ |
| Full RSN/WPA parse: WPA2 / WPA3-SAE / OWE / Enterprise, ciphers, AKMs | ✅ |
| PMF (802.11w) detection | ✅ |
| WPS-enabled detection | ✅ |
| Station discovery + probe-request harvesting (passive) | ✅ |
| Per-network security audit with concrete fixes | ✅ |
| Deauth/disassoc attack **detector** (IDS) | ✅ |
| Clean live UI + JSON/CSV export | ✅ |
| Sending deauth / cracking / WPS attacks / evil-twin | ❌ by design |

---

## Requirements

- **Linux** (Kali, Parrot, Ubuntu…). Monitor mode does not meaningfully work on Windows.
- A monitor-mode + injection capable adapter. Tested target: **Alfa AWUS036ACH (RTL8812AU)**.
- Python 3.9+, `iw`, and libpcap.

### Driver for the Alfa AWUS036ACH on Kali

```bash
sudo apt update
sudo apt install -y realtek-rtl88xxau-dkms iw
# replug the adapter, then confirm it appears:
iw dev
```

---

## Install

```bash
git clone https://github.com/yourname/airscout.git
cd airscout
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# optional: install the `airscout` command
pip install -e .
```

---

## Enable monitor mode

```bash
# find your interface name (e.g. wlan0)
airscout ifaces

# put it into monitor mode (manual method, no extra tools)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# ...or with aircrack-ng's helper (creates wlan0mon and kills interferers)
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

Verify:

```bash
airscout ifaces      # should show [monitor] next to your interface
```

---

## Usage

All capture commands need `sudo` and a monitor-mode interface.

### Scan nearby networks

```bash
sudo airscout scan -i wlan0mon
sudo airscout scan -i wlan0mon --band 2.4 --clients
sudo airscout scan -i wlan0mon -d 60 --json scan.json --csv scan.csv
sudo airscout scan -i wlan0mon -c 6            # lock to channel 6 (no hopping)
```

Live table shows BSSID, SSID (hidden marked), channel, band, RSSI, security
(WPA2/WPA3/…+ciphers), PMF state, WPS, client count and vendor.

### Audit your own network

```bash
# audit everything in range
sudo airscout audit -i wlan0mon -d 20

# audit one network you own
sudo airscout audit -i wlan0mon --ssid "MyHomeWiFi" -d 20 --json audit.json
sudo airscout audit -i wlan0mon --bssid AA:BB:CC:DD:EE:FF
```

You get a severity-ranked findings table — open network, WEP, legacy WPA/TKIP,
WPS enabled, PMF off, hidden-SSID — each with a concrete fix.

### Detect deauth attacks (defensive IDS)

```bash
sudo airscout monitor -i wlan0mon
sudo airscout monitor -i wlan0mon -c 6 --window 10
```

Live panel of deauth/disassociation frames; it flashes an alert when a burst
suggests someone is trying to knock clients off a network near you.

---

## How it works

- `scapy`'s `AsyncSniffer` (with `monitor=True`) receives raw 802.11 frames.
- A background **channel hopper** tunes the radio across the 2.4/5 GHz plans via `iw`.
- `parser.py` walks the information elements: SSID (element 0), DS channel
  (element 3), RSN (element 48) and vendor WPA/WPS (element 221), and reads RSSI
  from the RadioTap header.
- State is kept in thread-safe dictionaries and rendered with `rich`.

Everything is passive decoding of frames the adapter overhears.

---

## Scope & responsible use

AirScout is for:

- **Learning** how 802.11 works.
- **Auditing and defending networks you own or are explicitly authorised to test.**

AirScout deliberately does **not** include, and will not be extended with:
sending deauthentication/disassociation frames, WPS PIN brute-forcing
(Reaver/Bully-style), WPA handshake/PMKID capture-for-cracking, password
cracking, or evil-twin / rogue-AP attacks. Those are for breaking into networks,
not auditing your own.

Attacking, disrupting or intercepting networks you do not own or have written
permission to test is illegal in most jurisdictions — in India, under the
Information Technology Act, 2000 (e.g. §§ 43 & 66). **You are responsible for how
you use this tool.** Use it only against your own equipment or with explicit
authorisation.

---

## License

MIT — see [LICENSE](LICENSE).
