#!/usr/bin/env python3
import os, csv, json
from datetime import datetime, timezone
from typing import List, Dict, Any
from flask import Flask, jsonify, render_template, request

try:
    import yaml
except Exception:
    yaml = None

APP = Flask(__name__, template_folder="templates")

# File locations (override via env)
METRICS_CSV = os.environ.get("METRICS_CSV", "reports/offline_metrics.csv")
ALERTS_JSONL = os.environ.get("ALERTS_JSONL", "data/alerts/offline_alerts.jsonl")
CONFIG_YAML  = os.environ.get("IDS_CONFIG",   "config/config.yaml")


def _load_config() -> Dict[str, Any]:
    defaults = {
        "thresholds": {"deauth_per_sec": 20, "probe_req_per_sec": 50, "beacon_per_sec": 200},
        "windows_sec": {"deauth": 5, "probe_req": 5, "beacon": 5, "stats_interval": 1, "evil_twin_window": 5},
        "evil_twin": {"distinct_bssids_threshold": 3},
        "anomaly": {"use_zscore": True, "z_threshold": 3.0},
    }
    if yaml and os.path.exists(CONFIG_YAML):
        try:
            with open(CONFIG_YAML, "r") as f:
                cfg = yaml.safe_load(f) or {}
            for k, v in cfg.items():
                if isinstance(v, dict) and k in defaults:
                    defaults[k].update(v)
                else:
                    defaults[k] = v
        except Exception:
            pass
    return defaults


def _read_metrics_csv(path: str):
    if not os.path.exists(path):
        return [], []
    with open(path, "r") as f:
        r = csv.DictReader(f)
        rows = list(r)
    series = []
    for row in rows:
        try:
            ts_to = float(row["ts_to"])
        except Exception:
            continue
        series.append({
            "ts_to": ts_to,
            "ts_from": float(row.get("ts_from", ts_to)),
            "deauth": int(row.get("deauth_count", 0)),
            "probe": int(row.get("probe_count", 0)),
            "beacon": int(row.get("beacon_count", 0)),
            "evmx": int(row.get("eviltwin_max_distinct_bssids", 0)),
            "topd": int(row.get("top_sender_deauth", 0)),
            "topp": int(row.get("top_sender_probe", 0)),
            "topb": int(row.get("top_sender_beacon", 0)),
        })
    return series, rows


def _read_alerts_jsonl(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                ts = obj.get("ts_to") or obj.get("ts_end") or obj.get("ts_from")
                if ts is not None:
                    obj["_ts"] = float(ts)
                out.append(obj)
            except Exception:
                continue
    return out


def _epoch_to_iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


@APP.route("/")
def index():
    cfg = _load_config()
    return render_template("index.html",
                           thresholds=cfg.get("thresholds", {}),
                           windows=cfg.get("windows_sec", {}),
                           metrics_csv=METRICS_CSV,
                           alerts_jsonl=ALERTS_JSONL)


@APP.route("/api/metrics")
def api_metrics():
    series, _rows = _read_metrics_csv(METRICS_CSV)
    def to_xy(key: str):
        return [{"x": int(s["ts_to"] * 1000), "y": s[key]} for s in series]
    payload = {
        "count": len(series),
        "x_first": int(series[0]["ts_to"] * 1000) if series else None,
        "x_last": int(series[-1]["ts_to"] * 1000) if series else None,
        "deauth": to_xy("deauth"),
        "probe":  to_xy("probe"),
        "beacon": to_xy("beacon"),
        "evmx":   to_xy("evmx"),
        "topd":   to_xy("topd"),
        "topp":   to_xy("topp"),
        "topb":   to_xy("topb"),
    }
    return jsonify(payload)


@APP.route("/api/alerts")
def api_alerts():
    kind = request.args.get("kind", "").strip()
    alerts = _read_alerts_jsonl(ALERTS_JSONL)
    if kind:
        alerts = [a for a in alerts if kind.upper() in (a.get("kind","").upper())]
    alerts.sort(key=lambda a: a.get("_ts", 0.0))
    for a in alerts:
        if "_ts" in a:
            a["_ts_iso"] = _epoch_to_iso_utc(a["_ts"])
    return jsonify({"count": len(alerts), "alerts": alerts})


@APP.route("/api/summary")
def api_summary():
    metrics, _rows = _read_metrics_csv(METRICS_CSV)
    alerts = _read_alerts_jsonl(ALERTS_JSONL)
    last_ts = metrics[-1]["ts_to"] if metrics else None
    by_kind = {}
    for a in alerts:
        k = a.get("kind", "UNKNOWN")
        by_kind[k] = by_kind.get(k, 0) + 1
    return jsonify({
        "windows": len(metrics),
        "alerts": len(alerts),
        "alerts_by_kind": by_kind,
        "last_window_ts": last_ts,
        "last_window_iso": _epoch_to_iso_utc(last_ts) if last_ts else None
    })


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    APP.run(host=host, port=port, debug=True)


if __name__ == "__main__":
    main()
