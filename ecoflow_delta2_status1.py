#!/usr/bin/env python3
"""
EcoFlow Delta 2 battery status via the official EcoFlow IoT Open Platform API.

Setup:
    pip install requests
    export ECOFLOW_ACCESS_KEY=...
    export ECOFLOW_SECRET_KEY=...
    export ECOFLOW_SN=R331...          # Delta 2 serial number (optional; else first device)
    export ECOFLOW_HOST=https://api-e.ecoflow.com   # EU account; use https://api.ecoflow.com for US/global

Usage:
    python ecoflow_delta2_status.py          # battery summary
    python ecoflow_delta2_status.py --all    # dump every quota key (to discover names)
    python ecoflow_delta2_status.py --soc    # print only the charge level number (e.g. 87)
"""
import hashlib
import hmac
import json
import os
import random
import re
import sys
import time

import requests

HOST = os.getenv("ECOFLOW_HOST", "https://api-e.ecoflow.com")
ACCESS_KEY = os.environ["ECOFLOW_ACCESS_KEY"]
SECRET_KEY = os.environ["ECOFLOW_SECRET_KEY"]

# Delta 2 quota keys related to the battery
BATTERY_QUOTAS = {
    "bms_emsStatus.lcdShowSoc": ("Battery level (display)", "%"),
    "bms_bmsStatus.soc": ("Main battery SoC", "%"),
    "bms_bmsStatus.f32ShowSoc": ("Main battery SoC (precise)", "%"),
    "pd.soc": ("PD SoC", "%"),
    "bms_bmsStatus.soh": ("State of health", "%"),
    "bms_bmsStatus.cycles": ("Charge cycles", ""),
    "bms_bmsStatus.temp": ("Battery temperature", "°C"),
    "bms_bmsStatus.vol": ("Battery voltage", "mV"),
    "bms_bmsStatus.remainCap": ("Remaining capacity", "mAh"),
    "bms_bmsStatus.fullCap": ("Full capacity", "mAh"),
    "pd.wattsInSum": ("Total input", "W"),
    "pd.wattsOutSum": ("Total output", "W"),
    "bms_emsStatus.chgRemainTime": ("Time to full", "min"),
    "bms_emsStatus.dsgRemainTime": ("Time to empty", "min"),
}


# Charge-level keys in priority order (first one present wins)
SOC_KEYS = ["bms_emsStatus.lcdShowSoc", "bms_bmsStatus.f32ShowSoc", "bms_bmsStatus.soc", "pd.soc"]


def charge_level(data):
    """Return (percent, source_key) for the battery charge level, or (None, None)."""
    for key in SOC_KEYS:
        val = data.get(key)
        if isinstance(val, (int, float)) or (isinstance(val, str) and val.replace(".", "", 1).isdigit()):
            return round(float(val), 1), key
    return None, None


def extra_battery_socs(all_data):
    """Find per-battery SoC values in a full quota dump beyond the main summary keys.

    An add-on / extra battery reports its own SoC under a device-specific key
    (varies by model and firmware), so instead of hardcoding we scan every key
    ending in 'soc' that holds a plausible percentage and isn't already shown in
    the main summary. Returns a list of (key, value) sorted by key.
    """
    found = []
    for key, val in sorted(all_data.items()):
        if key in BATTERY_QUOTAS or key in SOC_KEYS:
            continue
        if re.search(r"soc$", key, re.IGNORECASE) and isinstance(val, (int, float)) and 0 <= val <= 100:
            found.append((key, val))
    return found


def charge_bar(pct, width=20):
    filled = int(round(pct / 100 * width))
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def _flatten(obj, prefix=""):
    """Flatten nested dict/list the way EcoFlow expects: a.b, a.list[0]."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = obj
    return out


def _headers(params=None):
    """Build signed headers: sorted params + accessKey/nonce/timestamp, HMAC-SHA256 hex."""
    nonce = str(random.randint(100000, 999999))
    timestamp = str(int(time.time() * 1000))
    flat = _flatten(params or {})
    parts = [f"{k}={flat[k]}" for k in sorted(flat)]
    parts += [f"accessKey={ACCESS_KEY}", f"nonce={nonce}", f"timestamp={timestamp}"]
    sign = hmac.new(SECRET_KEY.encode(), "&".join(parts).encode(), hashlib.sha256).hexdigest()
    return {
        "accessKey": ACCESS_KEY,
        "nonce": nonce,
        "timestamp": timestamp,
        "sign": sign,
        "Content-Type": "application/json;charset=UTF-8",
    }


def _check(resp):
    resp.raise_for_status()
    body = resp.json()
    if str(body.get("code")) != "0":
        raise RuntimeError(f"EcoFlow API error {body.get('code')}: {body.get('message')}")
    return body.get("data")


def list_devices():
    url = f"{HOST}/iot-open/sign/device/list"
    return _check(requests.get(url, headers=_headers(), timeout=15))


def get_all_quota(sn):
    params = {"sn": sn}
    url = f"{HOST}/iot-open/sign/device/quota/all"
    return _check(requests.get(url, params=params, headers=_headers(params), timeout=15))


def get_quota(sn, quotas):
    body = {"sn": sn, "params": {"quotas": list(quotas)}}
    url = f"{HOST}/iot-open/sign/device/quota"
    return _check(requests.post(url, data=json.dumps(body), headers=_headers(body), timeout=15))


def main():
    sn = os.getenv("ECOFLOW_SN")
    devices = list_devices() or []
    if not sn:
        if not devices:
            sys.exit("No devices bound to this developer account.")
        sn = devices[0]["sn"]
    dev = next((d for d in devices if d.get("sn") == sn), {})
    if "--soc" not in sys.argv:
        print(f"Device: {dev.get('deviceName', '?')}  SN: {sn}  online: {dev.get('online')}")

    if "--all" in sys.argv:
        data = get_all_quota(sn)
        print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))
        return

    data = get_quota(sn, BATTERY_QUOTAS)
    pct, src = charge_level(data)

    if "--soc" in sys.argv:  # machine-friendly: just the number
        print(f"{pct:g}" if pct is not None else "n/a")
        return

    if pct is None:
        print("\nBattery charge: n/a (none of the SoC keys returned — run with --all)")
    else:
        print(f"\nBattery charge: {pct:g}%  {charge_bar(pct)}   (from {src})")
    print()
    for key, (label, unit) in BATTERY_QUOTAS.items():
        val = data.get(key, "n/a")
        print(f"  {label:<28} {val} {unit}".rstrip())

    # Extra / add-on batteries: discover any other SoC values the device reports.
    extras = extra_battery_socs(get_all_quota(sn))
    if extras:
        print("\nOther battery SoC values detected (likely add-on batteries):")
        for key, val in extras:
            print(f"  {key:<32} {val:g} %")


if __name__ == "__main__":
    main()
