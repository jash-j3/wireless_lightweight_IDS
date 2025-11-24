#!/usr/bin/env python3

import argparse
import threading
import time
from dataclasses import asdict
from typing import Optional, List, Dict, Any

import csv
import json
import os

import pyshark
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

from ids_offline import IDS, pkt_to_event, load_config

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

IDS_INSTANCE: Optional[IDS] = None
IDS_LOCK = threading.Lock()
CAPTURE_THREAD: Optional[threading.Thread] = None
RUN_CAPTURE = True
CURRENT_MODE = "learning"  # "learning" or "detection"


def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _open_metrics_writer(path: Optional[str]):
    if not path:
        return None, None
    _ensure_dir(path)
    is_new = not os.path.exists(path) or os.path.getsize(path) == 0
    f = open(path, "a", newline="")
    w = csv.writer(f)
    if is_new:
        w.writerow(
            [
                "ts_from",
                "ts_to",
                "deauth_count",
                "probe_count",
                "beacon_count",
                "eviltwin_max_distinct_bssids",
                "top_sender_deauth",
                "top_sender_probe",
                "top_sender_beacon",
                "top_bssid_deauth_count",
                "top_bssid_deauth_mac",
                "deauth_reason_top",
                "deauth_reason_distinct",
                "top_channel",
                "top_channel_beacon_count",
                "top_channel_deauth_count",
            ]
        )
    return f, w


def _open_alert_file(path: Optional[str]):
    if not path:
        return None
    _ensure_dir(path)
    return open(path, "a", buffering=1)


def _flush_new_metrics_and_alerts(
    ids: IDS,
    metrics_writer,
    alerts_file,
    last_metrics_idx: int,
    last_alert_idx: int,
):
    if metrics_writer:
        while last_metrics_idx < len(ids.metrics):
            m = ids.metrics[last_metrics_idx]
            metrics_writer.writerow(
                [
                    m.ts_from,
                    m.ts_to,
                    m.deauth_count,
                    m.probe_count,
                    m.beacon_count,
                    m.eviltwin_max_distinct_bssids,
                    m.top_sender_deauth,
                    m.top_sender_probe,
                    m.top_sender_beacon,
                    m.top_bssid_deauth_count,
                    m.top_bssid_deauth_mac or "",
                    m.deauth_reason_top if m.deauth_reason_top is not None else "",
                    m.deauth_reason_distinct,
                    m.top_channel if m.top_channel is not None else "",
                    m.top_channel_beacon_count,
                    m.top_channel_deauth_count,
                ]
            )
            last_metrics_idx += 1

    if alerts_file:
        while last_alert_idx < len(ids.alerts):
            a = ids.alerts[last_alert_idx]
            alerts_file.write(json.dumps(asdict(a)) + "\n")
            last_alert_idx += 1

    return last_metrics_idx, last_alert_idx


def capture_loop_live(
    interface: str,
    cfg_path: str,
    display_filter: str,
    reset_baselines: bool,
    alerts_out: Optional[str],
    metrics_out: Optional[str],
):
    global IDS_INSTANCE, RUN_CAPTURE
    cfg = load_config(cfg_path)
    ids = IDS(cfg, reset_baselines=reset_baselines)
    ids.mode = CURRENT_MODE

    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter=display_filter if display_filter else None,
        use_json=True,
    )

    with IDS_LOCK:
        IDS_INSTANCE = ids

    metrics_f, metrics_writer = _open_metrics_writer(metrics_out)
    alerts_f = _open_alert_file(alerts_out)
    last_metrics_idx = 0
    last_alert_idx = 0

    try:
        for pkt in cap.sniff_continuously():
            if not RUN_CAPTURE:
                break
            ev = pkt_to_event(pkt)
            if not ev:
                continue
            with IDS_LOCK:
                ids.ingest(ev)
                last_metrics_idx, last_alert_idx = _flush_new_metrics_and_alerts(
                    ids, metrics_writer, alerts_f, last_metrics_idx, last_alert_idx
                )
    finally:
        cap.close()
        with IDS_LOCK:
            ids.finalize()
            last_metrics_idx, last_alert_idx = _flush_new_metrics_and_alerts(
                ids, metrics_writer, alerts_f, last_metrics_idx, last_alert_idx
            )
        if metrics_f:
            metrics_f.close()
        if alerts_f:
            alerts_f.close()


def capture_loop_pcap(
    pcap_path: str,
    cfg_path: str,
    display_filter: str,
    reset_baselines: bool,
    alerts_out: Optional[str],
    metrics_out: Optional[str],
):
    global IDS_INSTANCE
    cfg = load_config(cfg_path)
    ids = IDS(cfg, reset_baselines=reset_baselines)
    ids.mode = CURRENT_MODE

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=display_filter if display_filter else None,
        keep_packets=False,
        use_json=True,
    )

    with IDS_LOCK:
        IDS_INSTANCE = ids

    metrics_f, metrics_writer = _open_metrics_writer(metrics_out)
    alerts_f = _open_alert_file(alerts_out)
    last_metrics_idx = 0
    last_alert_idx = 0

    try:
        for pkt in cap:
            ev = pkt_to_event(pkt)
            if not ev:
                continue
            with IDS_LOCK:
                ids.ingest(ev)
                last_metrics_idx, last_alert_idx = _flush_new_metrics_and_alerts(
                    ids, metrics_writer, alerts_f, last_metrics_idx, last_alert_idx
                )
    finally:
        cap.close()
        with IDS_LOCK:
            ids.finalize()
            last_metrics_idx, last_alert_idx = _flush_new_metrics_and_alerts(
                ids, metrics_writer, alerts_f, last_metrics_idx, last_alert_idx
            )
        if metrics_f:
            metrics_f.close()
        if alerts_f:
            alerts_f.close()


@app.get("/api/state")
def get_state():
    with IDS_LOCK:
        if IDS_INSTANCE is None:
            return JSONResponse(
                {
                    "ok": False,
                    "message": "IDS not initialized",
                    "now": time.time(),
                    "metrics": None,
                    "alerts": [],
                    "mode": CURRENT_MODE,
                    "learning": None,
                }
            )

        ids = IDS_INSTANCE
        now = time.time()

        if ids.metrics:
            m = ids.metrics[-1]
            metrics = {
                "ts_from": m.ts_from,
                "ts_to": m.ts_to,
                "deauth": m.deauth_count,
                "probe": m.probe_count,
                "beacon": m.beacon_count,
                "top_sender_deauth": m.top_sender_deauth,
                "top_bssid_deauth": m.top_bssid_deauth_count,
                "top_channel": m.top_channel,
                "top_channel_beacon_count": m.top_channel_beacon_count,
                "top_channel_deauth_count": m.top_channel_deauth_count,
            }
        else:
            metrics = None

        recent_alerts: List[dict] = []
        if ids.alerts:
            for a in ids.alerts[-50:]:
                recent_alerts.append(asdict(a))

        def rs_snapshot(rs) -> Dict[str, Any]:
            return {"mean": rs.mean, "std": rs.std, "n": rs.n}

        learning = {
            "mode": getattr(ids, "mode", CURRENT_MODE),
            "safe_z_gate": getattr(ids, "safe_z_gate", None),
            "learn_windows": getattr(ids, "learn_windows", 0),
            "learn_rejected_suspicious": getattr(ids, "learn_rejected_suspicious", 0),
            "baseline": {
                "deauth": rs_snapshot(ids.rs_deauth),
                "probe": rs_snapshot(ids.rs_probe),
                "beacon": rs_snapshot(ids.rs_beacon),
            },
            "learner_baseline": {
                "deauth": rs_snapshot(ids.rs_learn_deauth),
                "probe": rs_snapshot(ids.rs_learn_probe),
                "beacon": rs_snapshot(ids.rs_learn_beacon),
            },
        }

    return JSONResponse(
        {
            "ok": True,
            "now": now,
            "metrics": metrics,
            "alerts": recent_alerts,
            "mode": learning["mode"],
            "learning": learning,
        }
    )


class ModeUpdate(BaseModel):
    mode: str


@app.get("/api/mode")
def get_mode():
    with IDS_LOCK:
        mode = IDS_INSTANCE.mode if IDS_INSTANCE is not None else CURRENT_MODE
    return {"ok": True, "mode": mode}


@app.post("/api/mode")
def set_mode(update: ModeUpdate):
    global CURRENT_MODE
    m = update.mode.lower()
    if m not in ("learning", "detection"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "mode must be 'learning' or 'detection'"},
        )

    CURRENT_MODE = m
    with IDS_LOCK:
        if IDS_INSTANCE is not None:
            IDS_INSTANCE.mode = m

    return {"ok": True, "mode": m}


def _save_learned_baselines_to_config(cfg_path: str, ids: IDS, min_windows: int = 30):
    if yaml is None:
        print("[WARN] pyyaml not available; cannot save learned baselines.")
        return

    learn_windows = getattr(ids, "learn_windows", 0)
    if learn_windows < min_windows:
        print(
            f"[INFO] Not saving baselines: only {learn_windows} safe learning windows "
            f"(need at least {min_windows})."
        )
        return

    try:
        with open(cfg_path, "r") as f:
            cfg_raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        cfg_raw = {}

    if not isinstance(cfg_raw, dict):
        cfg_raw = {}

    b = cfg_raw.get("baselines", {})
    if not isinstance(b, dict):
        b = {}

    def upd(name: str, rs):
        if getattr(rs, "n", 0) <= 0:
            return
        std_val = rs.std if rs.std > 0 else 1.0
        b[name] = {"mean": float(rs.mean), "std": float(std_val)}

    upd("deauth", ids.rs_learn_deauth)
    upd("probe", ids.rs_learn_probe)
    upd("beacon", ids.rs_learn_beacon)

    b["n"] = int(max(learn_windows, b.get("n", 0)))
    cfg_raw["baselines"] = b

    _ensure_dir(cfg_path)
    with open(cfg_path, "w") as f:
        yaml.safe_dump(cfg_raw, f, sort_keys=False)

    print(f"[INFO] Saved learned baselines to {cfg_path} (learn_windows={learn_windows})")


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi IDS dashboard server (live or pcap replay)")
    parser.add_argument("--iface", help="Monitor-mode interface (e.g., wlp0s20f3mon)")
    parser.add_argument("--pcap", help="Replay pcap/pcapng instead of live iface")
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument(
        "--display-filter",
        default="wlan.fc.type==0",
        help="Wireshark display filter (default: management frames)",
    )
    parser.add_argument("--reset-baselines", action="store_true")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--alerts-out",
        default="data/alerts/dashboard_alerts.jsonl",
        help="Path to JSONL alerts output",
    )
    parser.add_argument(
        "--metrics-out",
        default="reports/dashboard_metrics.csv",
        help="Path to CSV metrics output",
    )
    parser.add_argument(
        "--mode",
        choices=["learning", "detection"],
        default="learning",
        help="Initial baseline mode for this run",
    )
    parser.add_argument(
        "--save-learned-baselines",
        action="store_true",
        help="On shutdown, update the given config file with learned baselines",
    )
    args = parser.parse_args()

    if bool(args.iface) == bool(args.pcap):
        raise SystemExit("You must specify exactly one of --iface or --pcap")

    global CAPTURE_THREAD, RUN_CAPTURE, CURRENT_MODE
    RUN_CAPTURE = True
    CURRENT_MODE = args.mode

    if args.iface:
        t = threading.Thread(
            target=capture_loop_live,
            args=(
                args.iface,
                args.config,
                args.display_filter,
                args.reset_baselines,
                args.alerts_out,
                args.metrics_out,
            ),
            daemon=True,
        )
        CAPTURE_THREAD = t
        t.start()
        print(
            f"[INFO] Live capture started on {args.iface}, mode={CURRENT_MODE}, "
            f"API on http://{args.host}:{args.port}"
        )
    else:
        t = threading.Thread(
            target=capture_loop_pcap,
            args=(
                args.pcap,
                args.config,
                args.display_filter,
                args.reset_baselines,
                args.alerts_out,
                args.metrics_out,
            ),
            daemon=True,
        )
        CAPTURE_THREAD = t
        t.start()
        print(
            f"[INFO] Replaying pcap='{args.pcap}', mode={CURRENT_MODE}, "
            f"API on http://{args.host}:{args.port}"
        )

    try:
        uvicorn.run(app, host=args.host, port=args.port)
    finally:
        RUN_CAPTURE = False
        if CAPTURE_THREAD is not None:
            CAPTURE_THREAD.join(timeout=2.0)

        if args.save_learned_baselines:
            with IDS_LOCK:
                ids_ref = IDS_INSTANCE
            if ids_ref is not None:
                _save_learned_baselines_to_config(args.config, ids_ref)
            else:
                print("[INFO] No IDS instance available to save baselines.")


if __name__ == "__main__":
    main()
