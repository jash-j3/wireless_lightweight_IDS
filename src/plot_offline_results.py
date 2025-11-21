#!/usr/bin/env python3
# src/plot_offline_results.py
import argparse, csv, json, os
from collections import defaultdict, Counter
from datetime import datetime, timezone
import matplotlib.pyplot as plt  # type: ignore


def read_metrics(path):
    X, deauth, probe, beacon, evmx, topd, topp, topb = [], [], [], [], [], [], [], []
    top_bssid_deauth = []
    deauth_reason_top = []

    with open(path, "r") as f:
        r = csv.DictReader(f)
        rows = list(r)
        if not rows:
            return {}, []
        has_top_bssid = "top_bssid_deauth_count" in rows[0]
        has_reason_top = "deauth_reason_top" in rows[0]

        for row in rows:
            # Use window end as the x-axis
            ts_to = float(row["ts_to"])
            X.append(ts_to)
            deauth.append(int(row["deauth_count"]))
            probe.append(int(row["probe_count"]))
            beacon.append(int(row["beacon_count"]))
            evmx.append(int(row["eviltwin_max_distinct_bssids"]))
            topd.append(int(row["top_sender_deauth"]))
            topp.append(int(row["top_sender_probe"]))
            topb.append(int(row["top_sender_beacon"]))

            # New: top BSSID deauth burst
            if has_top_bssid:
                try:
                    top_bssid_deauth.append(int(row["top_bssid_deauth_count"]))
                except Exception:
                    top_bssid_deauth.append(0)
            else:
                top_bssid_deauth.append(0)

            # New: dominant deauth reason-code per window
            if has_reason_top:
                v = row.get("deauth_reason_top", "")
                if v == "":
                    deauth_reason_top.append(None)
                else:
                    try:
                        deauth_reason_top.append(int(v))
                    except Exception:
                        deauth_reason_top.append(None)
            else:
                deauth_reason_top.append(None)

    return {
        "X": X,
        "deauth": deauth,
        "probe": probe,
        "beacon": beacon,
        "evmx": evmx,
        "topd": topd,
        "topp": topp,
        "topb": topb,
        "top_bssid_deauth": top_bssid_deauth,
        "deauth_reason_top": deauth_reason_top,
    }, rows


def read_alerts(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
                out.append(j)
            except Exception:
                pass
    return out


def to_relative_seconds(xs):
    if not xs:
        return [], 0.0
    t0 = xs[0]
    return [x - t0 for x in xs], t0


def to_datetimes(xs):
    return [datetime.fromtimestamp(x, tz=timezone.utc) for x in xs]


def alert_times_by_kind(alerts, kind_contains):
    ts = []
    for a in alerts:
        k = a.get("kind", "")
        if any(sub in k for sub in kind_contains):
            ts.append(float(a.get("ts_to", a.get("ts_end", a.get("ts_from", 0.0)))))
    return sorted(ts)


def plot_series(
    xvals,
    yvals,
    title,
    ylabel,
    outpath,
    alert_times=None,
    x_mode="relative",
    threshold=None,
    extra=None,
):
    """
    extra: optional list of (label, yvals_extra) to overlay on the same axes.
    """
    plt.figure()
    plt.plot(xvals, yvals, label="total")

    if extra:
        for label, ys in extra:
            plt.plot(xvals, ys, linestyle="--", label=label)

    if threshold is not None:
        plt.axhline(threshold, linestyle="--")

    if alert_times:
        for t in alert_times:
            plt.axvline(t, linestyle=":")

    plt.title(title)
    plt.xlabel("time (s)" if x_mode == "relative" else "time (UTC)")
    plt.ylabel(ylabel)

    if extra:
        plt.legend()

    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()


def plot_alert_timeline(xvals, alerts, outpath, x_mode="relative"):
    if not alerts:
        return
    # group by kind
    kinds = sorted({a.get("kind", "") for a in alerts})
    ymap = {k: i for i, k in enumerate(kinds)}
    xs, ys = [], []
    for a in alerts:
        t = float(a.get("ts_to", a.get("ts_end", a.get("ts_from", 0.0))))
        xs.append(t)
        ys.append(ymap[a.get("kind", "")])
    plt.figure()
    plt.scatter(xs, ys, s=12)
    plt.yticks(list(ymap.values()), kinds)
    plt.title("Alerts Timeline")
    plt.xlabel("time (s)" if x_mode == "relative" else "time (UTC)")
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()


def plot_reason_legend(deauth_reason_top, outpath):
    """
    Optional small legend PNG: how often each reason-code was dominant in a window.
    """
    codes = [rc for rc in deauth_reason_top if rc is not None]
    if not codes:
        return

    counts = Counter(codes)

    plt.figure()
    plt.axis("off")

    lines = ["Dominant deauth reason-code per window:"]
    for rc, cnt in sorted(counts.items()):
        lines.append(f"  reason {rc}: {cnt} windows")

    text = "\n".join(lines)
    plt.text(0.01, 0.99, text, va="top", ha="left", fontsize=9)
    plt.title("Deauth reason-code legend")
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()


def main():
    ap = argparse.ArgumentParser(description="Plot offline IDS metrics and alerts")
    ap.add_argument("--metrics", required=True, help="reports/offline_metrics.csv")
    ap.add_argument("--alerts", default="", help="data/alerts/offline_alerts.jsonl")
    ap.add_argument("--out-dir", default="reports/plots")
    ap.add_argument(
        "--x-axis",
        choices=["relative", "utc"],
        default="relative",
        help="relative: seconds from first window end; utc: absolute time",
    )
    ap.add_argument(
        "--deauth-th", type=float, default=None, help="optional horizontal line"
    )
    ap.add_argument(
        "--probe-th", type=float, default=None, help="optional horizontal line"
    )
    ap.add_argument(
        "--beacon-th", type=float, default=None, help="optional horizontal line"
    )
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    metrics, rows = read_metrics(args.metrics)
    if not metrics:
        print("[!] Empty metrics file.")
        return
    alerts = read_alerts(args.alerts)

    X = metrics["X"]
    if args.x_axis == "relative":
        xr, t0 = to_relative_seconds(X)
        xvals = xr
        x_mode = "relative"
    else:
        xvals = to_datetimes(X)
        x_mode = "utc"

    # Alert times per class
    t_deauth_all = alert_times_by_kind(alerts, ["DEAUTH"])
    t_probe = alert_times_by_kind(alerts, ["PROBE"])
    t_beacon = alert_times_by_kind(alerts, ["BEACON"])
    t_evil = alert_times_by_kind(alerts, ["EVIL_TWIN"])
    # Specific markers for BSSID deauth threshold alerts
    t_deauth_bssid = alert_times_by_kind(alerts, ["THRESH_DEAUTH_PER_BSSID"])

    # Convert alert x to chosen axis
    if args.x_axis == "relative":
        if t_deauth_all:
            t_deauth_all = [t - X[0] for t in t_deauth_all]
        if t_probe:
            t_probe = [t - X[0] for t in t_probe]
        if t_beacon:
            t_beacon = [t - X[0] for t in t_beacon]
        if t_evil:
            t_evil = [t - X[0] for t in t_evil]
        if t_deauth_bssid:
            t_deauth_bssid = [t - X[0] for t in t_deauth_bssid]
    else:  # utc
        t_deauth_all = to_datetimes(t_deauth_all)
        t_probe = to_datetimes(t_probe)
        t_beacon = to_datetimes(t_beacon)
        t_evil = to_datetimes(t_evil)
        t_deauth_bssid = to_datetimes(t_deauth_bssid)

    # Deauth plot with overlay: top BSSID deauth burst
    plot_series(
        xvals,
        metrics["deauth"],
        "Deauth per window",
        "count",
        os.path.join(args.out_dir, "deauth.png"),
        alert_times=t_deauth_all,
        x_mode=x_mode,
        threshold=args.deauth_th,
        extra=[("top BSSID deauth", metrics["top_bssid_deauth"])],
    )

    # Optional: separate plot for top-BSSID deauth with BSSID-specific alert markers
    plot_series(
        xvals,
        metrics["top_bssid_deauth"],
        "Top BSSID deauth burst (window)",
        "count",
        os.path.join(args.out_dir, "top_bssid_deauth.png"),
        alert_times=t_deauth_bssid,
        x_mode=x_mode,
    )

    # Probe / beacon / evil-twin plots (unchanged)
    plot_series(
        xvals,
        metrics["probe"],
        "Probe requests per window",
        "count",
        os.path.join(args.out_dir, "probe.png"),
        alert_times=t_probe,
        x_mode=x_mode,
        threshold=args.probe_th,
    )

    plot_series(
        xvals,
        metrics["beacon"],
        "Beacons per window",
        "count",
        os.path.join(args.out_dir, "beacon.png"),
        alert_times=t_beacon,
        x_mode=x_mode,
        threshold=args.beacon_th,
    )

    plot_series(
        xvals,
        metrics["evmx"],
        "Max distinct BSSIDs per SSID (window)",
        "count",
        os.path.join(args.out_dir, "evil_twin_signal.png"),
        alert_times=t_evil,
        x_mode=x_mode,
    )

    # Top-per-sender burst plots (unchanged)
    plot_series(
        xvals,
        metrics["topd"],
        "Top per-sender deauth burst (window)",
        "count",
        os.path.join(args.out_dir, "top_sender_deauth.png"),
        alert_times=t_deauth_all,
        x_mode=x_mode,
    )
    plot_series(
        xvals,
        metrics["topp"],
        "Top per-sender probe burst (window)",
        "count",
        os.path.join(args.out_dir, "top_sender_probe.png"),
        alert_times=t_probe,
        x_mode=x_mode,
    )
    plot_series(
        xvals,
        metrics["topb"],
        "Top per-sender beacon burst (window)",
        "count",
        os.path.join(args.out_dir, "top_sender_beacon.png"),
        alert_times=t_beacon,
        x_mode=x_mode,
    )

    # Alerts timeline (all kinds)
    plot_alert_timeline(
        xvals, alerts, os.path.join(args.out_dir, "alerts_timeline.png"), x_mode=x_mode
    )

    # Optional small legend PNG for dominant deauth reason codes
    plot_reason_legend(
        metrics.get("deauth_reason_top", []),
        os.path.join(args.out_dir, "deauth_reason_legend.png"),
    )

    print(f"[OK] Wrote plots to: {args.out_dir}")


if __name__ == "__main__":
    main()
