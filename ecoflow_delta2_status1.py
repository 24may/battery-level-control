#!/usr/bin/env python3
"""
EcoFlow Delta 2 battery status via the official EcoFlow IoT Open Platform API.

Setup:
    pip install requests
    export ECOFLOW_ACCESS_KEY=...
    export ECOFLOW_SECRET_KEY=...
    export ECOFLOW_SN=R331...          # Delta 2 serial number (optional; else first device)
    export ECOFLOW_HOST=https://api-e.ecoflow.com   # EU account; use https://api.ecoflow.com for US/global

    # Optional: Tuya smart plug that is switched OFF when PD SoC reaches 100%
    export TUYA_CLIENT_ID=...          # Tuya IoT cloud project Access ID
    export TUYA_SECRET=...             # Tuya IoT cloud project Access Secret
    export TUYA_DEVICE_ID=...          # plug device ID
    export TUYA_HOST=https://openapi.tuyaeu.com    # data center of the cloud project
    export TUYA_SWITCH_CODE=switch_1   # DP code of the relay (default switch_1)

Usage:
    python ecoflow_delta2_status1.py          # battery summary
    python ecoflow_delta2_status1.py --all    # dump every quota key (to discover names)
    python ecoflow_delta2_status1.py --soc    # print only the charge level number (e.g. 87)
"""
import hashlib
import hmac
import json
import os
import random
import re
import sys
import time
import uuid

import requests

HOST = os.getenv("ECOFLOW_HOST", "https://api-e.ecoflow.com")
ACCESS_KEY = os.environ["ECOFLOW_ACCESS_KEY"]
SECRET_KEY = os.environ["ECOFLOW_SECRET_KEY"]

# Tuya smart plug (optional). When all three are set, the plug is switched off
# once PD SoC reaches 100%. Leave them unset to disable plug control.
# Values come from GitHub environment secrets in CI (see .github/workflows/battery-status.yml).
# `or` instead of a getenv default: an unset GitHub secret arrives as "" not as missing.
TUYA_HOST = os.getenv("TUYA_HOST") or "https://openapi.tuyaeu.com"  # EU; US: https://openapi.tuyaus.com
TUYA_CLIENT_ID = os.getenv("TUYA_CLIENT_ID")
TUYA_SECRET = os.getenv("TUYA_SECRET")
TUYA_DEVICE_ID = os.getenv("TUYA_DEVICE_ID")
TUYA_SWITCH_CODE = os.getenv("TUYA_SWITCH_CODE") or "switch_1"  # check the plug's instruction set
FULL_SOC = 100

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


def _as_number(val):
    """Return val as float if it is numeric (or a numeric string), else None."""
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)) or (isinstance(val, str) and val.replace(".", "", 1).isdigit()):
        return float(val)
    return None


def charge_level(data):
    """Return (percent, source_key) for the battery charge level, or (None, None)."""
    for key in SOC_KEYS:
        val = _as_number(data.get(key))
        if val is not None:
            return round(val, 1), key
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
    filled = int(pct / 100 * width)  # floor: only a truly full battery shows a full bar
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


# --- Tuya Cloud OpenAPI ---------------------------------------------------------
# Signature (HMAC-SHA256, uppercase hex) over:
#   client_id + [access_token] + t + nonce + stringToSign
#   stringToSign = METHOD \n sha256(body) \n <signature headers, none here> \n path?sorted_query


def _tuya_headers(method, path, body="", access_token=""):
    t = str(int(time.time() * 1000))
    nonce = uuid.uuid4().hex
    content_sha = hashlib.sha256(body.encode()).hexdigest()
    string_to_sign = "\n".join([method, content_sha, "", path])
    msg = TUYA_CLIENT_ID + access_token + t + nonce + string_to_sign
    sign = hmac.new(TUYA_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()
    headers = {
        "client_id": TUYA_CLIENT_ID,
        "sign": sign,
        "sign_method": "HMAC-SHA256",
        "t": t,
        "nonce": nonce,
        "Content-Type": "application/json",
    }
    if access_token:
        headers["access_token"] = access_token
    return headers


def _tuya_check(resp):
    resp.raise_for_status()
    body = resp.json()
    if not body.get("success"):
        raise RuntimeError(f"Tuya API error {body.get('code')}: {body.get('msg')}")
    return body.get("result")


def tuya_token():
    path = "/v1.0/token?grant_type=1"
    resp = requests.get(TUYA_HOST + path, headers=_tuya_headers("GET", path), timeout=15)
    return _tuya_check(resp)["access_token"]


def tuya_set_switch(device_id, on):
    token = tuya_token()
    path = f"/v1.0/iot-03/devices/{device_id}/commands"
    body = json.dumps({"commands": [{"code": TUYA_SWITCH_CODE, "value": bool(on)}]})
    resp = requests.post(TUYA_HOST + path, data=body,
                         headers=_tuya_headers("POST", path, body, token), timeout=15)
    if _tuya_check(resp) is not True:  # success=true but result=false: device rejected it
        raise RuntimeError(f"device did not accept command {TUYA_SWITCH_CODE}={bool(on)}")


def control_plug(data, log):
    """Switch the Tuya plug off when PD SoC is at 100%."""
    soc = _as_number(data.get("pd.soc"))
    if soc is None:
        log(f"PD SoC not reported (pd.soc={data.get('pd.soc')!r}) — plug control skipped.")
        return
    if soc < FULL_SOC:
        return
    if not (TUYA_CLIENT_ID and TUYA_SECRET and TUYA_DEVICE_ID):
        log(f"PD SoC is {soc:g}% but Tuya is not configured (TUYA_CLIENT_ID/TUYA_SECRET/TUYA_DEVICE_ID) — plug left as is.")
        return
    try:
        tuya_set_switch(TUYA_DEVICE_ID, on=False)
        log(f"PD SoC is {soc:g}% — smart plug {TUYA_DEVICE_ID} switched OFF.")
    except Exception as e:  # noqa: BLE001 - plug failure must not hide battery status
        log(f"PD SoC is {soc:g}% — failed to switch plug off: {e}")


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
        control_plug(data, lambda m: print(m, file=sys.stderr))  # keep stdout clean
        return

    if pct is None:
        print("\nBattery charge: n/a (none of the SoC keys returned — run with --all)")
    else:
        print(f"\nBattery charge: {pct:g}%  {charge_bar(pct)}   (from {src})")
    print()
    for key, (label, unit) in BATTERY_QUOTAS.items():
        val = data.get(key, "n/a")
        print(f"  {label:<28} {val} {unit}".rstrip())

    control_plug(data, lambda m: print(f"\n{m}"))

    # Extra / add-on batteries: discover any other SoC values the device reports.
    # This relies on the quota/all endpoint; if it fails (e.g. EcoFlow rejects the
    # request), degrade gracefully rather than losing the main status above.
    try:
        extras = extra_battery_socs(get_all_quota(sn))
    except Exception as e:  # noqa: BLE001 - optional lookup must never crash the run
        print(f"\n(Extra-battery lookup skipped: {e})")
        extras = []
    if extras:
        print("\nOther battery SoC values detected (likely add-on batteries):")
        for key, val in extras:
            print(f"  {key:<32} {val:g} %")


if __name__ == "__main__":
    main()
