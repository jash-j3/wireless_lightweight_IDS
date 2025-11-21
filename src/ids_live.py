#!/usr/bin/env python3
# src/ids_live.py

from dataclasses import asdict
import argparse
import json
import signal
import sys
import pyshark
from typing import Optional

from ids_offline import IDS, pkt_to_event, load_config, PACKET_TYPES

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


def _c(enabled: bool, color: str, text: str) -> str:
    if not enabled:
        return text
    return f"{color}{text}{RESET}"


def format_event(ev, color: bool = True) -> str:
    if ev.ptype == PACKET_TYPES.DEAUTH:
        c = RED
    elif ev.ptype == PACKET_TYPES.PROBE_REQ:
        c = YELLOW
    elif ev.ptype == PACKET_TYPES.BEACON:
        c = CYAN
    else:
        c = DIM

    ptype = ev.ptype.name
    ts = f"{ev.ts:.3f}"
    sa = ev.sender_mac or "-"
    da = ev.receiver_mac or "-"
    bssid = ev.bssid or "-"
    ssid = ev.ssid or "-"
    ch = ev.channel if ev.channel is not None else "-"
    rc = ev.reason_code if ev.reason_code is not None else "-"

    core = f"{ptype:8s} ts={ts} sa={sa} da={da} bssid={bssid} ssid={ssid} ch={ch} rc={rc}"
    return _c(color, c, core)


def format_alert(alert_obj, color: bool = True) -> str:
    kind = alert_obj["kind"]
    if "DEAUTH" in kind and "THRESH" in kind:
        c = RED
    elif "EVIL_TWIN" in kind:
        c = MAGENTA
    elif "PROBE" in kind:
        c = YELLOW
    elif "BEACON" in kind and "SPIKE" in kind:
        c = CYAN
    elif "ANOMALY" in kind:
        c = BLUE
    else:
        c = GREEN

    prefix = _c(color, BOLD + c, "[ALERT]")
    return f"{prefix} {json.dumps(alert_obj)}"


def format_metrics_row(m, color: bool = True) -> str:
    base = (
        f"[STATS] t={m.ts_to:.3f} "
        f"deauth={m.deauth_count} probe={m.probe_count} beacon={m.beacon_count} "
        f"| top_sender_deauth={m.top_sender_deauth} "
        f"top_bssid_deauth={m.top_bssid_deauth_count} "
        f"top_chan={m.top_channel if m.top_channel is not None else '-'} "
        f"chan_beacon={m.top_channel_beacon_count} "
        f"chan_deauth={m.top_channel_deauth_count}"
    )
    return _c(color, DIM, base)


def process_stream(
    pkt_iter,
    ids: IDS,
    alerts_out: Optional[str],
    print_events: bool,
    summary_every: float,
    use_color: bool,
    is_live: bool,
):
    last_alert_idx = 0
    last_summary_ts = 0.0

    alert_file = None
    if alerts_out:
        alert_file = open(alerts_out, "a", buffering=1)

    try:
        for pkt in pkt_iter:
            ev = pkt_to_event(pkt)
            if not ev:
                continue

            if print_events:
                print(format_event(ev, color=use_color))

            ids.ingest(ev)

            # New alerts
            if len(ids.alerts) > last_alert_idx:
                new_alerts = ids.alerts[last_alert_idx:]
                for a in new_alerts:
                    obj = asdict(a)
                    if alert_file:
                        alert_file.write(json.dumps(obj) + "\n")
                    print(format_alert(obj, color=use_color))
                last_alert_idx = len(ids.alerts)

            # Periodic stats from latest metrics row
            if summary_every > 0 and len(ids.metrics) > 0:
                latest = ids.metrics[-1]
                if latest.ts_to >= last_summary_ts + summary_every:
                    print(format_metrics_row(latest, color=use_color))
                    last_summary_ts = latest.ts_to

    finally:
        if alert_file:
            alert_file.close()
        # For offline replay, make sure we flush final windows
        if not is_live:
            ids.finalize()
            if summary_every > 0 and len(ids.metrics) > 0:
                latest = ids.metrics[-1]
                print(format_metrics_row(latest, color=use_color))


def run_live(
    interface: str,
    cfg_path: str,
    display_filter: str,
    reset_baselines: bool = False,
    alerts_out: Optional[str] = None,
    print_events: bool = False,
    summary_every: float = 5.0,
    use_color: bool = True,
):
    cfg = load_config(cfg_path)
    ids = IDS(cfg, reset_baselines=reset_baselines)

    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter=display_filter,
        use_json=True,
    )

    print(
        _c(
            use_color,
            BOLD + GREEN,
            f"[INFO] Starting LIVE IDS on iface={interface}, filter='{display_filter}'",
        )
    )
    print(_c(use_color, GREEN, "[INFO] Press Ctrl+C to stop.\n"))

    def handle_sigint(signum, frame):
        print(_c(use_color, YELLOW, "\n[INFO] Caught Ctrl+C, stopping capture..."))
        cap.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    process_stream(
        pkt_iter=cap.sniff_continuously(),
        ids=ids,
        alerts_out=alerts_out,
        print_events=print_events,
        summary_every=summary_every,
        use_color=use_color,
        is_live=True,
    )


def run_replay_pcap(
    pcap_path: str,
    cfg_path: str,
    display_filter: str,
    reset_baselines: bool = False,
    alerts_out: Optional[str] = None,
    print_events: bool = False,
    summary_every: float = 5.0,
    use_color: bool = True,
):
    cfg = load_config(cfg_path)
    ids = IDS(cfg, reset_baselines=reset_baselines)

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=display_filter if display_filter else None,
        keep_packets=False,
        use_json=True,
    )

    print(
        _c(
            use_color,
            BOLD + GREEN,
            f"[INFO] Replaying PCAP='{pcap_path}' with filter='{display_filter}'",
        )
    )

    process_stream(
        pkt_iter=cap,
        ids=ids,
        alerts_out=alerts_out,
        print_events=print_events,
        summary_every=summary_every,
        use_color=use_color,
        is_live=False,
    )

    cap.close()
    print(_c(use_color, GREEN, "[INFO] Replay finished."))


def main():
    ap = argparse.ArgumentParser(description="Wi-Fi IDS (live or pcap replay)")
    ap.add_argument("--iface", help="Monitor-mode interface (e.g., wlp0s20f3mon)")
    ap.add_argument("--pcap", help="Replay pcap/pcapng instead of live iface")
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument(
        "--display-filter",
        default="wlan.fc.type==0",
        help="Wireshark display filter (management frames by default)",
    )
    ap.add_argument("--alerts-out", default="", help="Optional JSONL file for alerts")
    ap.add_argument("--reset-baselines", action="store_true")
    ap.add_argument("--print-events", action="store_true", help="Print every analyzed packet")
    ap.add_argument(
        "--summary-every",
        type=float,
        default=5.0,
        help="Print aggregated stats every N seconds of trace time (0 to disable)",
    )
    ap.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in output",
    )
    args = ap.parse_args()

    use_color = not args.no_color
    alerts_out = args.alerts_out or None

    # Require exactly one of --iface or --pcap
    if bool(args.iface) == bool(args.pcap):
        print("[ERROR] You must specify exactly one of --iface or --pcap", file=sys.stderr)
        sys.exit(1)

    if args.iface:
        run_live(
            interface=args.iface,
            cfg_path=args.config,
            display_filter=args.display_filter,
            reset_baselines=args.reset_baselines,
            alerts_out=alerts_out,
            print_events=args.print_events,
            summary_every=args.summary_every,
            use_color=use_color,
        )
    else:
        run_replay_pcap(
            pcap_path=args.pcap,
            cfg_path=args.config,
            display_filter=args.display_filter,
            reset_baselines=args.reset_baselines,
            alerts_out=alerts_out,
            print_events=args.print_events,
            summary_every=args.summary_every,
            use_color=use_color,
        )


if __name__ == "__main__":
    main()
