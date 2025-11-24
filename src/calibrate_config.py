#!/usr/bin/env python3

from __future__ import annotations
import argparse
import math
import statistics
from typing import List, Sequence, Dict, Any, Optional

import csv
import json

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

from ids_offline import run_offline, load_config


def percentile(xs: Sequence[float], q: float) -> float:
    if not xs:
        return 0.0
    xs_sorted = sorted(xs)
    idx = int(round(q * (len(xs_sorted) - 1)))
    idx = max(0, min(idx, len(xs_sorted) - 1))
    return xs_sorted[idx]


def basic_stats(xs: Sequence[float]) -> Dict[str, float]:
    if not xs:
        return {"mean": 0.0, "std": 0.0, "q95": 0.0, "q99": 0.0, "max": 0.0}
    mean = statistics.fmean(xs)
    std = statistics.pstdev(xs)
    q95 = percentile(xs, 0.95)
    q99 = percentile(xs, 0.99)
    mx = max(xs)
    return {"mean": mean, "std": std, "q95": q95, "q99": q99, "max": mx}


def choose_threshold_normal_attack(
    normal_stats: Dict[str, float],
    attack_vals: Sequence[float] | None,
) -> float:
    """
    Choose a per-window threshold given normal-only stats and optional attack values.
    Works on *counts per stats window*, not per second. You may later interpret as per-second
    if stats_interval == 1s (your default).
    """
    mean = normal_stats["mean"]
    std = normal_stats["std"]
    q99 = normal_stats["q99"]
    normal_hi = max(q99, mean + 3.0 * std)

    if not attack_vals:
        return normal_hi

    attack_nonzero = [x for x in attack_vals if x > 0]
    if len(attack_nonzero) < 3:
        return normal_hi

    attack_lo = percentile(attack_nonzero, 0.10)

    if attack_lo > normal_hi:
        thr = 0.5 * (normal_hi + attack_lo)
    else:
        thr = normal_hi * 1.2

    return thr


def choose_global_z_threshold(
    normal_vals: Dict[str, Sequence[float]],
    stats: Dict[str, Dict[str, float]],
    max_fp: float = 0.01,
) -> float:
    """
    Pick a single z_threshold such that in normal data, for each stream (deauth/probe/beacon),
    at most max_fp fraction of windows would cross it.
    """
    candidates = [3.0, 3.5, 4.0, 4.5, 5.0]

    def z_list(xs: Sequence[float], mean: float, std: float) -> List[float]:
        if not xs:
            return []
        s = std if std > 0 else 1.0
        return [(x - mean) / s for x in xs]

    z_deauth = z_list(
        normal_vals["deauth"], stats["deauth"]["mean"], stats["deauth"]["std"]
    )
    z_probe = z_list(
        normal_vals["probe"], stats["probe"]["mean"], stats["probe"]["std"]
    )
    z_beacon = z_list(
        normal_vals["beacon"], stats["beacon"]["mean"], stats["beacon"]["std"]
    )

    streams = [z_deauth, z_probe, z_beacon]

    for thr in candidates:
        ok = True
        for zs in streams:
            if not zs:
                continue
            frac = sum(1 for z in zs if z >= thr) / len(zs)
            if frac > max_fp:
                ok = False
                break
        if ok:
            return thr

    return 5.0


def collect_metrics_from_pcaps(
    pcaps: List[str],
    cfg_base: Dict[str, Any],
    display_filter: str,
) -> List[Dict[str, float]]:
    """
    Run offline IDS on all given pcaps and collect metrics rows as dicts.
    """
    all_rows: List[Dict[str, float]] = []
    for pcap in pcaps:
        alerts, metrics, pkts_seen, evs = run_offline(
            pcap_path=pcap,
            cfg=cfg_base,
            reset_baselines=True,
            display_filter=display_filter,
        )
        for m in metrics:
            all_rows.append(
                {
                    "ts_from": float(m.ts_from),
                    "ts_to": float(m.ts_to),
                    "deauth_count": float(m.deauth_count),
                    "probe_count": float(m.probe_count),
                    "beacon_count": float(m.beacon_count),
                }
            )
    return all_rows


def collect_metrics_from_csv(path: str) -> List[Dict[str, float]]:
    """
    Read metrics CSV (like offline_metrics.csv or dashboard_metrics.csv) and return rows
    with ts_from, ts_to, deauth_count, probe_count, beacon_count.
    Extra columns are ignored.
    """
    rows: List[Dict[str, float]] = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                ts_from = float(r.get("ts_from", "0") or 0)
                ts_to = float(r.get("ts_to", "0") or 0)
                deauth = float(r.get("deauth_count", "0") or 0)
                probe = float(r.get("probe_count", "0") or 0)
                beacon = float(r.get("beacon_count", "0") or 0)
            except ValueError:
                continue
            rows.append(
                {
                    "ts_from": ts_from,
                    "ts_to": ts_to,
                    "deauth_count": deauth,
                    "probe_count": probe,
                    "beacon_count": beacon,
                }
            )
    return rows


def load_alerts_from_jsonl(paths: List[str]) -> List[Dict[str, Any]]:
    """
    Load alerts from JSONL file(s). Each line must be a JSON object with at least kind, ts_from, ts_to.
    """
    alerts: List[Dict[str, Any]] = []
    for p in paths:
        with open(p, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                alerts.append(obj)
    return alerts


def is_metric_row_suspicious(
    row: Dict[str, float],
    alerts: List[Dict[str, Any]],
) -> bool:
    """
    Treat a metrics window as suspicious if there exists a non-INFO, non-ANOMALY alert
    overlapping [ts_from, ts_to].
    """
    if not alerts:
        return False

    r_from = row.get("ts_from", 0.0)
    r_to = row.get("ts_to", r_from)

    for a in alerts:
        kind = str(a.get("kind", ""))
        # Hard alerts only (skip INFO_ and ANOMALY_)
        if kind.startswith("INFO_") or kind.startswith("ANOMALY_"):
            continue
        ats_from = float(a.get("ts_from", 0.0))
        ats_to = float(a.get("ts_to", ats_from))
        # interval overlap
        if ats_from < r_to and ats_to > r_from:
            return True
    return False


def main():
    ap = argparse.ArgumentParser(
        description="Calibrate IDS config from normal and optional attack pcaps/metrics"
    )
    ap.add_argument("--config-in", default="config/config.yaml")
    ap.add_argument("--config-out", default="config/config_calibrated.yaml")
    ap.add_argument(
        "--display-filter",
        default="wlan.fc.type==0",
        help="Wireshark display filter (default: management frames)",
    )

    # Normal data (required: at least one of pcap or metrics)
    ap.add_argument(
        "--normal-pcap",
        action="append",
        help="Normal (benign) traffic pcap/pcapng; can be given multiple times",
    )
    ap.add_argument(
        "--normal-metrics",
        action="append",
        help="CSV metrics file(s) from benign runs (e.g. offline_metrics.csv or dashboard_metrics.csv)",
    )
    ap.add_argument(
        "--normal-alerts-jsonl",
        action="append",
        help="Alerts JSONL file(s) corresponding to normal runs (used to skip suspicious windows)",
    )

    # Attack data (optional)
    ap.add_argument(
        "--deauth-attack-pcap",
        action="append",
        help="Pcap(s) containing deauth attack traffic; optional",
    )
    ap.add_argument(
        "--probe-attack-pcap",
        action="append",
        help="Pcap(s) containing probe-request flood traffic; optional",
    )
    ap.add_argument(
        "--deauth-attack-metrics",
        action="append",
        help="Metrics CSV file(s) from deauth-attack runs; optional",
    )
    ap.add_argument(
        "--probe-attack-metrics",
        action="append",
        help="Metrics CSV file(s) from probe-attack runs; optional",
    )

    args = ap.parse_args()

    if yaml is None:
        raise SystemExit(
            "pyyaml is not installed; install it with 'pip install pyyaml' to use this script."
        )

    cfg = load_config(args.config_in)

    # 1) NORMAL TRAFFIC METRICS (pcaps + metrics CSV)
    normal_metrics: List[Dict[str, float]] = []

    if args.normal_pcap:
        normal_metrics.extend(
            collect_metrics_from_pcaps(args.normal_pcap, cfg, args.display_filter)
        )

    if args.normal_metrics:
        for path in args.normal_metrics:
            normal_metrics.extend(collect_metrics_from_csv(path))

    if not normal_metrics:
        raise SystemExit(
            "No normal data provided. Use --normal-pcap and/or --normal-metrics."
        )

    # 1a) Optional gating: skip windows that overlap hard alerts
    normal_alerts: List[Dict[str, Any]] = []
    if args.normal_alerts_jsonl:
        normal_alerts = load_alerts_from_jsonl(args.normal_alerts_jsonl)

    if normal_alerts:
        filtered = [
            r for r in normal_metrics if not is_metric_row_suspicious(r, normal_alerts)
        ]
        if filtered:
            print(
                f"[INFO] Gating normal windows: {len(normal_metrics)} -> {len(filtered)}"
            )
            normal_metrics = filtered
        else:
            print(
                "[WARN] All normal windows were flagged suspicious by alerts gating; "
                "using original set without gating."
            )

    # Extract normal series
    normal_deauth_counts = [r["deauth_count"] for r in normal_metrics]
    normal_probe_counts = [r["probe_count"] for r in normal_metrics]
    normal_beacon_counts = [r["beacon_count"] for r in normal_metrics]

    stats_deauth = basic_stats(normal_deauth_counts)
    stats_probe = basic_stats(normal_probe_counts)
    stats_beacon = basic_stats(normal_beacon_counts)

    normal_vals = {
        "deauth": normal_deauth_counts,
        "probe": normal_probe_counts,
        "beacon": normal_beacon_counts,
    }
    stats_all = {
        "deauth": stats_deauth,
        "probe": stats_probe,
        "beacon": stats_beacon,
    }

    # 2) OPTIONAL ATTACK METRICS (pcaps + metrics CSV)
    deauth_attack_vals: List[float] = []

    if args.deauth_attack_pcap:
        deauth_metrics = collect_metrics_from_pcaps(
            args.deauth_attack_pcap, cfg, args.display_filter
        )
        deauth_attack_vals.extend(r["deauth_count"] for r in deauth_metrics)

    if args.deauth_attack_metrics:
        for path in args.deauth_attack_metrics:
            m = collect_metrics_from_csv(path)
            deauth_attack_vals.extend(r["deauth_count"] for r in m)

    probe_attack_vals: List[float] = []

    if args.probe_attack_pcap:
        probe_metrics = collect_metrics_from_pcaps(
            args.probe_attack_pcap, cfg, args.display_filter
        )
        probe_attack_vals.extend(r["probe_count"] for r in probe_metrics)

    if args.probe_attack_metrics:
        for path in args.probe_attack_metrics:
            m = collect_metrics_from_csv(path)
            probe_attack_vals.extend(r["probe_count"] for r in m)

    # 3) BASELINES FOR Z-SCORE
    n_windows = len(normal_metrics)
    cfg.setdefault("baselines", {})
    cfg["baselines"]["n"] = max(50, n_windows)

    cfg["baselines"]["deauth"] = {
        "mean": stats_deauth["mean"],
        "std": max(stats_deauth["std"], 1.0),
    }
    cfg["baselines"]["probe"] = {
        "mean": stats_probe["mean"],
        "std": max(stats_probe["std"], 1.0),
    }
    cfg["baselines"]["beacon"] = {
        "mean": stats_beacon["mean"],
        "std": max(stats_beacon["std"], 1.0),
    }

    # 4) STATIC THRESHOLDS (per-window)
    thr_deauth_win = choose_threshold_normal_attack(stats_deauth, deauth_attack_vals)
    thr_probe_win = choose_threshold_normal_attack(stats_probe, probe_attack_vals)
    thr_beacon_win = choose_threshold_normal_attack(stats_beacon, None)

    thr_deauth = int(math.ceil(thr_deauth_win))
    thr_deauth = thr_deauth if thr_deauth > 0 else 1
    thr_probe = int(math.ceil(thr_probe_win))
    thr_probe = thr_probe if thr_probe > 0 else 1
    thr_beacon = int(math.ceil(thr_beacon_win))
    thr_beacon = thr_beacon if thr_beacon > 0 else 1

    cfg.setdefault("thresholds", {})
    cfg["thresholds"]["deauth_per_sec"] = thr_deauth
    cfg["thresholds"]["deauth_per_sec_bssid"] = thr_deauth
    cfg["thresholds"]["probe_req_per_sec"] = thr_probe
    cfg["thresholds"]["beacon_per_sec"] = thr_beacon

    # 5) GLOBAL Z-THRESHOLD FOR ANOMALY MODE
    z_thr = choose_global_z_threshold(normal_vals, stats_all, max_fp=0.01)  # type: ignore
    cfg.setdefault("anomaly", {})
    cfg["anomaly"]["use_zscore"] = True    # ensure anomaly logic is enabled
    cfg["anomaly"]["z_threshold"] = z_thr

    # 6) WRITE OUT NEW CONFIG
    with open(args.config_out, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)

    print(f"[OK] Calibrated config written to {args.config_out}")
    print("     Derived thresholds (per window):")
    print(f"       deauth_per_sec        = {thr_deauth}")
    print(f"       deauth_per_sec_bssid  = {thr_deauth}")
    print(f"       probe_req_per_sec     = {thr_probe}")
    print(f"       beacon_per_sec        = {thr_beacon}")
    print("     Baselines (mean ± std):")
    print(
        f"       deauth  ~ {stats_deauth['mean']:.3f} ± {stats_deauth['std']:.3f}"
    )
    print(
        f"       probe   ~ {stats_probe['mean']:.3f} ± {stats_probe['std']:.3f}"
    )
    print(
        f"       beacon  ~ {stats_beacon['mean']:.3f} ± {stats_beacon['std']:.3f}"
    )
    print(f"     Chosen global z_threshold = {z_thr:.2f}")
    print(f"     Normal windows used       = {n_windows}")
    if deauth_attack_vals:
        print(
            f"     Deauth attack windows     = {len(deauth_attack_vals)} "
            f"(nonzero={sum(1 for x in deauth_attack_vals if x>0)})"
        )
    if probe_attack_vals:
        print(
            f"     Probe attack windows      = {len(probe_attack_vals)} "
            f"(nonzero={sum(1 for x in probe_attack_vals if x>0)})"
        )


if __name__ == "__main__":
    main()
