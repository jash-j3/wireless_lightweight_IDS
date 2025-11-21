#!/usr/bin/env python3

import argparse
import threading
import time
from dataclasses import asdict
from typing import Optional, List

import pyshark
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from ids_offline import IDS, pkt_to_event, load_config

app = FastAPI()

# CORS so dashboard.html (opened from file:// or another port) can call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

IDS_INSTANCE: Optional[IDS] = None
IDS_LOCK = threading.Lock()
CAPTURE_THREAD: Optional[threading.Thread] = None
RUN_CAPTURE = True  # only used for live capture


def capture_loop_live(interface: str, cfg_path: str, display_filter: str, reset_baselines: bool):
    """
    Live sniffing from a monitor-mode interface, feeding the global IDS_INSTANCE.
    """
    global IDS_INSTANCE, RUN_CAPTURE
    cfg = load_config(cfg_path)
    ids = IDS(cfg, reset_baselines=reset_baselines)

    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter=display_filter if display_filter else None,
        use_json=True,
    )

    with IDS_LOCK:
        IDS_INSTANCE = ids

    try:
        for pkt in cap.sniff_continuously():
            if not RUN_CAPTURE:
                break
            ev = pkt_to_event(pkt)
            if not ev:
                continue
            with IDS_LOCK:
                ids.ingest(ev)
    finally:
        cap.close()


def capture_loop_pcap(pcap_path: str, cfg_path: str, display_filter: str, reset_baselines: bool):
    """
    Offline replay from a pcap/pcapng file, feeding the global IDS_INSTANCE.
    Processes as fast as possible, then finalizes.
    """
    global IDS_INSTANCE
    cfg = load_config(cfg_path)
    ids = IDS(cfg, reset_baselines=reset_baselines)

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=display_filter if display_filter else None,
        keep_packets=False,
        use_json=True,
    )

    with IDS_LOCK:
        IDS_INSTANCE = ids

    try:
        for pkt in cap:
            ev = pkt_to_event(pkt)
            if not ev:
                continue
            with IDS_LOCK:
                ids.ingest(ev)
    finally:
        cap.close()
        with IDS_LOCK:
            ids.finalize()


@app.get("/api/state")
def get_state():
    """
    Returns latest metrics and recent alerts for the dashboard.
    """
    with IDS_LOCK:
        if IDS_INSTANCE is None:
            return JSONResponse(
                {
                    "ok": False,
                    "message": "IDS not initialized",
                    "now": time.time(),
                    "metrics": None,
                    "alerts": [],
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

    return JSONResponse(
        {
            "ok": True,
            "now": now,
            "metrics": metrics,
            "alerts": recent_alerts,
        }
    )


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
    args = parser.parse_args()

    # Require exactly one of --iface or --pcap
    if bool(args.iface) == bool(args.pcap):
        raise SystemExit("You must specify exactly one of --iface or --pcap")

    global CAPTURE_THREAD, RUN_CAPTURE
    RUN_CAPTURE = True

    if args.iface:
        t = threading.Thread(
            target=capture_loop_live,
            args=(args.iface, args.config, args.display_filter, args.reset_baselines),
            daemon=True,
        )
        CAPTURE_THREAD = t
        t.start()
        print(f"[INFO] Live capture started on {args.iface}, API on http://{args.host}:{args.port}")
    else:
        t = threading.Thread(
            target=capture_loop_pcap,
            args=(args.pcap, args.config, args.display_filter, args.reset_baselines),
            daemon=True,
        )
        CAPTURE_THREAD = t
        t.start()
        print(f"[INFO] Replaying pcap='{args.pcap}', API on http://{args.host}:{args.port}")

    try:
        uvicorn.run(app, host=args.host, port=args.port)
    finally:
        RUN_CAPTURE = False
        if CAPTURE_THREAD is not None:
            CAPTURE_THREAD.join(timeout=2.0)


if __name__ == "__main__":
    main()
