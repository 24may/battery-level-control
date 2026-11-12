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

    # Optional: log verbosity (DEBUG, INFO, WARNING, ERROR); default INFO
    export LOG_LEVEL=DEBUG

Usage:
    python ecoflow_delta2_status1.py          # battery summary
    python ecoflow_delta2_status1.py --all    # dump every quota key (to discover names)
    python ecoflow_delta2_status1.py --soc    # print only the charge level number (e.g. 87)
    python ecoflow_delta2_status1.py --debug  # same as LOG_LEVEL=DEBUG (combine with any mode)

Logs go to stderr, so stdout stays clean for --soc / --all. Secrets are masked.
"""
import hashlib
import hmac
import json
import logging
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

HTTP_TIMEOUT = 15
LOG_BODY_LIMIT = 2000  # max chars of a response body shown at DEBUG

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


# --- Logging ---------------------------------------------------------------------

log = logging.getLogger("ecoflow")

# Response fields never written to the log, even at DEBUG
SENSITIVE_KEYS = {"access_token", "refresh_token", "accessKey", "secretKey", "sign"}


# Secret values scrubbed from every log line (URLs, tracebacks included).
# Runtime secrets such as the Tuya access token are added when obtained.
_MIN_SCRUB_LEN = 6  # shorter values would mangle ordinary words; real keys/IDs are far longer
_SECRET_VALUES = {v for v in (ACCESS_KEY, SECRET_KEY, TUYA_CLIENT_ID, TUYA_SECRET, TUYA_DEVICE_ID)
                  if v and len(v) >= _MIN_SCRUB_LEN}


class _ScrubbingFormatter(logging.Formatter):
    def format(self, record):
        text = super().format(record)
        for secret in sorted(_SECRET_VALUES, key=len, reverse=True):
            text = text.replace(secret, mask(secret))
        return text


def setup_logging():
    """Log to stderr; level from --debug, else LOG_LEVEL, else INFO."""
    name = "DEBUG" if "--debug" in sys.argv else (os.getenv("LOG_LEVEL") or "INFO").upper()
    level = getattr(logging, name, None)
    if not isinstance(level, int):
        level = logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_ScrubbingFormatter("%(asctime)s %(levelname)-7s %(message)s",
                                             datefmt="%Y-%m-%d %H:%M:%S"))
    logging.basicConfig(level=level, handlers=[handler], force=True)
    logging.getLogger("urllib3").setLevel(logging.WARNING)  # our own HTTP logs are enough
    if name != logging.getLevelName(level):
        log.warning("Unknown LOG_LEVEL %r, using INFO", name)


def mask(val, keep=4):
    """Show just enough of a secret/ID to recognise it: 'abcd…(32 chars)'."""
    if not val:
        return "<unset>"
    s = str(val)
    return f"{s[:keep]}…({len(s)} chars)" if len(s) > keep * 2 else "***"


def _redact(obj):
    if isinstance(obj, dict):
        return {k: ("***" if k in SENSITIVE_KEYS else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def _http(method, url, **kwargs):
    """requests.request with timing + logging. Headers are never logged (they carry signatures)."""
    log.info("→ %s %s", method, url)
    if kwargs.get("params"):
        log.debug("  query: %s", kwargs["params"])
    if kwargs.get("data"):
        log.debug("  body:  %s", kwargs["data"])
    t0 = time.monotonic()
    try:
        resp = requests.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
    except requests.RequestException as e:
        log.error("✗ %s %s failed after %.2fs: %s", method, url, time.monotonic() - t0, e)
        raise
    log.info("← HTTP %s in %.2fs (%d bytes)", resp.status_code, time.monotonic() - t0, len(resp.content))
    if log.isEnabledFor(logging.DEBUG):
        try:
            shown = json.dumps(_redact(resp.json()), ensure_ascii=False, sort_keys=True)
        except ValueError:
            shown = resp.text
        if len(shown) > LOG_BODY_LIMIT:
            shown = shown[:LOG_BODY_LIMIT] + f"… (+{len(shown) - LOG_BODY_LIMIT} chars)"
        log.debug("  response: %s", shown)
    return resp


def log_config():
    log.info("EcoFlow config: host=%s access_key=%s secret_key=%s sn=%s",
             HOST, mask(ACCESS_KEY), "set" if SECRET_KEY else "<unset>",
             os.getenv("ECOFLOW_SN") or "<auto: first device>")
    log.info("Tuya config: host=%s client_id=%s secret=%s device_id=%s switch_code=%s",
             TUYA_HOST, mask(TUYA_CLIENT_ID), "set" if TUYA_SECRET else "<unset>",
             mask(TUYA_DEVICE_ID), TUYA_SWITCH_CODE)
    if not (TUYA_CLIENT_ID and TUYA_SECRET and TUYA_DEVICE_ID):
        log.info("Tuya plug control disabled (TUYA_CLIENT_ID/TUYA_SECRET/TUYA_DEVICE_ID not all set)")


# --- Battery helpers -------------------------------------------------------------


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
        raw = data.get(key)
        val = _as_number(raw)
        if val is not None:
            log.debug("Charge level from %s = %r", key, raw)
            return round(val, 1), key
        log.debug("Charge level key %s unusable (value=%r), trying next", key, raw)
    log.warning("None of the charge-level keys %s returned a number", SOC_KEYS)
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
    log.info("Extra-battery scan: %d keys checked, %d extra SoC value(s) found", len(all_data), len(found))
    return found


def charge_bar(pct, width=20):
    filled = int(pct / 100 * width)  # floor: only a truly full battery shows a full bar
    return "[" + "█" * filled + "░" * (width - filled) + "]"


# --- EcoFlow IoT Open Platform ---------------------------------------------------


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
    log.debug("EcoFlow string-to-sign: %s", "&".join(parts).replace(ACCESS_KEY, mask(ACCESS_KEY)))
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
        log.error("EcoFlow API error code=%s message=%s", body.get("code"), body.get("message"))
        raise RuntimeError(f"EcoFlow API error {body.get('code')}: {body.get('message')}")
    return body.get("data")


def list_devices():
    log.info("Step: list EcoFlow devices")
    devices = _check(_http("GET", f"{HOST}/iot-open/sign/device/list", headers=_headers())) or []
    log.info("Found %d device(s)", len(devices))
    for d in devices:
        log.info("  device sn=%s name=%s online=%s", d.get("sn"), d.get("deviceName"), d.get("online"))
    return devices


def get_all_quota(sn):
    log.info("Step: fetch all quotas for %s", sn)
    params = {"sn": sn}
    data = _check(_http("GET", f"{HOST}/iot-open/sign/device/quota/all",
                        params=params, headers=_headers(params))) or {}
    log.info("Received %d quota key(s)", len(data))
    return data


def get_quota(sn, quotas):
    log.info("Step: fetch %d battery quotas for %s", len(quotas), sn)
    body = {"sn": sn, "params": {"quotas": list(quotas)}}
    data = _check(_http("POST", f"{HOST}/iot-open/sign/device/quota",
                        data=json.dumps(body), headers=_headers(body))) or {}
    missing = [k for k in quotas if k not in data]
    log.info("Received %d of %d requested quota key(s)", len(quotas) - len(missing), len(quotas))
    if missing:
        log.debug("Missing quota keys (not reported by this model/firmware): %s", missing)
    return data


# --- Tuya Cloud OpenAPI ---------------------------------------------------------
# Signature (HMAC-SHA256, uppercase hex) over:
#   client_id + [access_token] + t + nonce + stringToSign
#   stringToSign = METHOD \n sha256(body) \n <signature headers, none here> \n path?sorted_query


def _tuya_headers(method, path, body="", access_token=""):
    t = str(int(time.time() * 1000))
    nonce = uuid.uuid4().hex
    content_sha = hashlib.sha256(body.encode()).hexdigest()
    string_to_sign = "\n".join([method, content_sha, "", path])
    log.debug("Tuya stringToSign: %r (with access_token: %s)", string_to_sign, bool(access_token))
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
        log.error("Tuya API error code=%s msg=%s", body.get("code"), body.get("msg"))
        raise RuntimeError(f"Tuya API error {body.get('code')}: {body.get('msg')}")
    return body.get("result")


def tuya_token():
    log.info("Step: get Tuya access token")
    path = "/v1.0/token?grant_type=1"
    result = _tuya_check(_http("GET", TUYA_HOST + path, headers=_tuya_headers("GET", path)))
    if not isinstance(result, dict) or not result.get("access_token"):
        raise RuntimeError(f"Tuya token response has no access_token (result keys: "
                           f"{sorted(result) if isinstance(result, dict) else type(result).__name__})")
    if len(result["access_token"]) >= _MIN_SCRUB_LEN:
        _SECRET_VALUES.add(result["access_token"])
    log.info("Tuya token obtained (expires in %ss)", result.get("expire_time", "?"))
    return result["access_token"]


def tuya_set_switch(device_id, on):
    token = tuya_token()
    log.info("Step: send Tuya command %s=%s to device %s", TUYA_SWITCH_CODE, bool(on), mask(device_id))
    path = f"/v1.0/iot-03/devices/{device_id}/commands"
    body = json.dumps({"commands": [{"code": TUYA_SWITCH_CODE, "value": bool(on)}]})
    resp = _http("POST", TUYA_HOST + path, data=body, headers=_tuya_headers("POST", path, body, token))
    result = _tuya_check(resp)
    if result is not True:  # success=true but result=false: device rejected it
        raise RuntimeError(f"device did not accept command {TUYA_SWITCH_CODE}={bool(on)} (result={result!r})")
    log.info("Tuya command accepted")


def control_plug(data):
    """Switch the Tuya plug off when PD SoC is at 100%. Returns a one-line outcome message."""
    log.info("Step: decide plug action")
    raw = data.get("pd.soc")
    soc = _as_number(raw)
    if soc is None:
        msg = f"PD SoC not reported (pd.soc={raw!r}) — plug control skipped."
        log.warning(msg)
        return msg
    if soc < FULL_SOC:
        log.info("PD SoC %g%% < %d%% — plug left as is", soc, FULL_SOC)
        return None
    if not (TUYA_CLIENT_ID and TUYA_SECRET and TUYA_DEVICE_ID):
        msg = f"PD SoC is {soc:g}% but Tuya is not configured (TUYA_CLIENT_ID/TUYA_SECRET/TUYA_DEVICE_ID) — plug left as is."
        log.warning(msg)
        return msg
    log.info("PD SoC %g%% >= %d%% — switching plug OFF", soc, FULL_SOC)
    try:
        tuya_set_switch(TUYA_DEVICE_ID, on=False)
    except Exception as e:  # noqa: BLE001 - plug failure must not hide battery status
        log.error("Failed to switch plug off: %s", e, exc_info=log.isEnabledFor(logging.DEBUG))
        return f"PD SoC is {soc:g}% — failed to switch plug off: {e}"
    msg = f"PD SoC is {soc:g}% — smart plug {mask(TUYA_DEVICE_ID)} switched OFF."
    log.info(msg)
    return msg


# --- Main -----------------------------------------------------------------------


def main():
    setup_logging()
    mode = "all" if "--all" in sys.argv else "soc" if "--soc" in sys.argv else "summary"
    log.info("Start (mode=%s, python=%s)", mode, sys.version.split()[0])
    log_config()

    sn = os.getenv("ECOFLOW_SN")
    devices = list_devices()
    if not sn:
        if not devices:
            log.error("No devices bound to this developer account")
            sys.exit("No devices bound to this developer account.")
        sn = devices[0]["sn"]
        log.info("ECOFLOW_SN not set — using first device %s", sn)
    dev = next((d for d in devices if d.get("sn") == sn), {})
    if not dev:
        log.warning("SN %s is not in the device list — check ECOFLOW_SN", sn)
    elif not dev.get("online"):
        log.warning("Device %s reports online=%s — values may be stale", sn, dev.get("online"))
    if mode != "soc":
        print(f"Device: {dev.get('deviceName', '?')}  SN: {sn}  online: {dev.get('online')}")

    if mode == "all":
        data = get_all_quota(sn)
        print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))
        log.info("Done")
        return

    data = get_quota(sn, BATTERY_QUOTAS)
    pct, src = charge_level(data)
    log.info("Battery charge: %s%% (from %s), PD SoC: %s", pct, src, data.get("pd.soc"))

    if mode == "soc":  # machine-friendly: just the number on stdout; plug outcome is in the log
        print(f"{pct:g}" if pct is not None else "n/a")
        control_plug(data)
        log.info("Done")
        return

    if pct is None:
        print("\nBattery charge: n/a (none of the SoC keys returned — run with --all)")
    else:
        print(f"\nBattery charge: {pct:g}%  {charge_bar(pct)}   (from {src})")
    print()
    for key, (label, unit) in BATTERY_QUOTAS.items():
        val = data.get(key, "n/a")
        print(f"  {label:<28} {val} {unit}".rstrip())

    plug_msg = control_plug(data)
    if plug_msg:
        print(f"\n{plug_msg}")

    # Extra / add-on batteries: discover any other SoC values the device reports.
    # This relies on the quota/all endpoint; if it fails (e.g. EcoFlow rejects the
    # request), degrade gracefully rather than losing the main status above.
    try:
        extras = extra_battery_socs(get_all_quota(sn))
    except Exception as e:  # noqa: BLE001 - optional lookup must never crash the run
        log.warning("Extra-battery lookup skipped: %s", e)
        print(f"\n(Extra-battery lookup skipped: {e})")
        extras = []
    if extras:
        print("\nOther battery SoC values detected (likely add-on batteries):")
        for key, val in extras:
            print(f"  {key:<32} {val:g} %")
    log.info("Done")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.exception("Run failed")  # full traceback in the log (e.g. in the GitHub Actions output)
        sys.exit(1)
