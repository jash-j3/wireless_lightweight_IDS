#!/usr/bin/env python3
# src/plot_offline_results.py
import argparse, csv, json, os
from collections import defaultdict
from datetime import datetime, timezone
import matplotlib.pyplot as plt # type: ignore

def read_metrics(path):
    X, deauth, probe, beacon, evmx, topd, topp, topb = [], [], [], [], [], [], [], []
    with open(path, "r") as f:
        r = csv.DictReader(f)
        rows = list(r)
        if not rows:
            return {}, []
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
    return {
        "X": X, "deauth": deauth, "probe": probe, "beacon": beacon, "evmx": evmx,
        "topd": topd, "topp": topp, "topb": topb
    }, rows

def read_alerts(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                j = json.loads(line)
                out.append(j)
            except Exception:
                pass
    return out

def to_relative_seconds(xs):
    if not xs: return []
    t0 = xs[0]
    return [x - t0 for x in xs], t0

def to_datetimes(xs):
    return [datetime.fromtimestamp(x, tz=timezone.utc) for x in xs]

def alert_times_by_kind(alerts, kind_contains):
    ts = []
    for a in alerts:
        k = a.get("kind","")
        if any(sub in k for sub in kind_contains):
            ts.append(float(a.get("ts_to", a.get("ts_end", a.get("ts_from", 0.0)))))
    return sorted(ts)

def plot_series(xvals, yvals, title, ylabel, outpath, alert_times=None, x_mode="relative", threshold=None):
    plt.figure()
    plt.plot(xvals, yvals)
    if threshold is not None:
        plt.axhline(threshold, linestyle="--")
    if alert_times:
        for t in alert_times:
            plt.axvline(t, linestyle=":")
    plt.title(title)
    plt.xlabel("time (s)" if x_mode=="relative" else "time (UTC)")
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()

def plot_alert_timeline(xvals, alerts, outpath, x_mode="relative"):
    if not alerts:
        return
    # group by kind
    kinds = sorted({a.get("kind","") for a in alerts})
    ymap = {k:i for i,k in enumerate(kinds)}
    xs, ys = [], []
    for a in alerts:
        t = float(a.get("ts_to", a.get("ts_end", a.get("ts_from", 0.0))))
        xs.append(t); ys.append(ymap[a.get("kind","")])
    plt.figure()
    plt.scatter(xs, ys, s=12)
    plt.yticks(list(ymap.values()), kinds)
    plt.title("Alerts Timeline")
    plt.xlabel("time (s)" if x_mode=="relative" else "time (UTC)")
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()

def main():
    ap = argparse.ArgumentParser(description="Plot offline IDS metrics and alerts")
    ap.add_argument("--metrics", required=True, help="reports/offline_metrics.csv")
    ap.add_argument("--alerts", default="", help="data/alerts/offline_alerts.jsonl")
    ap.add_argument("--out-dir", default="reports/plots")
    ap.add_argument("--x-axis", choices=["relative","utc"], default="relative",
                    help="relative: seconds from first window end; utc: absolute time")
    ap.add_argument("--deauth-th", type=float, default=None, help="optional horizontal line")
    ap.add_argument("--probe-th", type=float, default=None, help="optional horizontal line")
    ap.add_argument("--beacon-th", type=float, default=None, help="optional horizontal line")
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
    t_deauth = alert_times_by_kind(alerts, ["DEAUTH"])
    t_probe  = alert_times_by_kind(alerts, ["PROBE"])
    t_beacon = alert_times_by_kind(alerts, ["BEACON"])
    t_evil   = alert_times_by_kind(alerts, ["EVIL_TWIN"])

    # Convert alert x to chosen axis
    if args.x_axis == "relative" and t_deauth:
        t_deauth = [t - X[0] for t in t_deauth]
        t_probe  = [t - X[0] for t in t_probe]
        t_beacon = [t - X[0] for t in t_beacon]
        t_evil   = [t - X[0] for t in t_evil]
    elif args.x_axis == "utc":
        t_deauth = to_datetimes(t_deauth)
        t_probe  = to_datetimes(t_probe)
        t_beacon = to_datetimes(t_beacon)
        t_evil   = to_datetimes(t_evil)

    # Plots (one figure per metric)
    plot_series(xvals, metrics["deauth"], "Deauth per window", "count",
                os.path.join(args.out_dir, "deauth.png"),
                alert_times=t_deauth, x_mode=x_mode, threshold=args.deauth_th)

    plot_series(xvals, metrics["probe"], "Probe requests per window", "count",
                os.path.join(args.out_dir, "probe.png"),
                alert_times=t_probe, x_mode=x_mode, threshold=args.probe_th)

    plot_series(xvals, metrics["beacon"], "Beacons per window", "count",
                os.path.join(args.out_dir, "beacon.png"),
                alert_times=t_beacon, x_mode=x_mode, threshold=args.beacon_th)

    plot_series(xvals, metrics["evmx"], "Max distinct BSSIDs per SSID (window)", "count",
                os.path.join(args.out_dir, "evil_twin_signal.png"),
                alert_times=t_evil, x_mode=x_mode)

    # Optional: top-per-sender burst plots
    plot_series(xvals, metrics["topd"], "Top per-sender deauth burst (window)", "count",
                os.path.join(args.out_dir, "top_sender_deauth.png"),
                alert_times=t_deauth, x_mode=x_mode)
    plot_series(xvals, metrics["topp"], "Top per-sender probe burst (window)", "count",
                os.path.join(args.out_dir, "top_sender_probe.png"),
                alert_times=t_probe, x_mode=x_mode)
    plot_series(xvals, metrics["topb"], "Top per-sender beacon burst (window)", "count",
                os.path.join(args.out_dir, "top_sender_beacon.png"),
                alert_times=t_beacon, x_mode=x_mode)

    # Alerts timeline (all kinds)
    plot_alert_timeline(xvals, alerts, os.path.join(args.out_dir, "alerts_timeline.png"), x_mode=x_mode)

    print(f"[OK] Wrote plots to: {args.out_dir}")

if __name__ == "__main__":
    main()
