#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, asdict
from enum import Enum, auto
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple
import argparse, csv, json, math, os

import pyshark
try:
    import yaml  # type: ignore
except Exception:
    yaml = None


class PACKET_TYPES(Enum):
    DEAUTH = auto()
    PROBE_REQ = auto()
    BEACON = auto()
    OTHER = auto()


DEFAULT_CFG = {
    "thresholds": {
        "deauth_per_sec": 20,
        "probe_req_per_sec": 50,
        "beacon_per_sec": 200,
        "deauth_per_sec_bssid": 20,
    },
    "windows_sec": {
        "deauth": 5,
        "probe_req": 5,
        "beacon": 5,
        "stats_interval": 1,
        "evil_twin_window": 5,
    },
    "evil_twin": {
        "distinct_bssids_threshold": 3
    },
    "anomaly": {
        "use_zscore": True,
        "z_threshold": 3.0,
    },
    "deauth_reason": {
        "distinct_threshold": 3,
        "common_whitelist": [1, 4, 8],
    },
    "channel": {
        "beacon_spike_min_count": 50,
        "beacon_spike_dom_ratio": 2.0,
    },
    "alerting": {
        "cooldown_sec": 5.0,
    },
    # NEW: continuous learning / safe gating
    "learning": {
        # windows with |z| >= safe_z_gate OR with hard rule-based alerts
        # are NOT used to update the learner baseline
        "safe_z_gate": 6.0,
    },
}


def load_config(path: Optional[str]) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CFG))
    if path and yaml:
        try:
            with open(path, "r") as f:
                user = yaml.safe_load(f) or {}
            for k, v in user.items():
                if isinstance(v, dict) and k in cfg:
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except FileNotFoundError:
            pass
    return cfg


@dataclass
class PacketEvent:
    ts: float
    ptype: PACKET_TYPES
    sender_mac: Optional[str]
    receiver_mac: Optional[str]
    bssid: Optional[str]
    ssid: Optional[str]
    channel: Optional[int]
    reason_code: Optional[int] = None


@dataclass
class MetricsRow:
    ts_from: float
    ts_to: float
    deauth_count: int
    probe_count: int
    beacon_count: int
    eviltwin_max_distinct_bssids: int
    top_sender_deauth: int
    top_sender_probe: int
    top_sender_beacon: int

    top_bssid_deauth_count: int
    top_bssid_deauth_mac: Optional[str]

    deauth_reason_top: Optional[int]
    deauth_reason_distinct: int

    top_channel: Optional[int]
    top_channel_beacon_count: int
    top_channel_deauth_count: int


@dataclass
class Alert:
    ts_from: float
    ts_to: float
    kind: str
    details: dict


class RunningStats:
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0

    def seed(self, mean: float, std: float, n: int = 50):
        self.n = max(2, int(n))
        self.mean = float(mean)
        self.M2 = (std ** 2) * (self.n - 1)

    def update(self, x: float):
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.M2 += d * (x - self.mean)

    @property
    def var(self):
        return self.M2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self):
        return math.sqrt(self.var) if self.var > 0 else 0.0

    def z(self, x: float) -> float:
        s = self.std or 1.0
        return (x - self.mean) / s

    def copy_from(self, other: "RunningStats"):
        self.n = other.n
        self.mean = other.mean
        self.M2 = other.M2


class IDS:
    def __init__(self, cfg: dict, reset_baselines: bool = False):
        W, T = cfg["windows_sec"], cfg["thresholds"]

        self.win = {
            PACKET_TYPES.DEAUTH: W["deauth"],
            PACKET_TYPES.PROBE_REQ: W["probe_req"],
            PACKET_TYPES.BEACON: W["beacon"],
        }
        self.stats_interval = W["stats_interval"]
        self.thresh = {
            PACKET_TYPES.DEAUTH: T["deauth_per_sec"],
            PACKET_TYPES.PROBE_REQ: T["probe_req_per_sec"],
            PACKET_TYPES.BEACON: T["beacon_per_sec"],
        }
        self.thresh_deauth_bssid = T.get("deauth_per_sec_bssid", T["deauth_per_sec"])

        self.ev_win = W["evil_twin_window"]
        self.ev_thresh = cfg["evil_twin"]["distinct_bssids_threshold"]

        self.use_z = bool(cfg["anomaly"].get("use_zscore", True))
        self.z_thr = float(cfg["anomaly"].get("z_threshold", 3.0))

        # NEW: mode + learning config
        self.mode = str(cfg.get("mode", "detection")).lower()  # "learning" / "detection"
        lcfg = cfg.get("learning", {})
        self.safe_z_gate = float(lcfg.get("safe_z_gate", 6.0))
        self.learn_windows = 0
        self.learn_rejected_suspicious = 0
        self._window_hard_alert = False

        # Per sender stats
        self.sender: Dict[str, Dict] = {}

        # Evil twin
        self.ssid_to_bssid_times: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)

        # Per-BSSID deauth lens
        self.bssid_deauth: Dict[str, Deque[float]] = defaultdict(deque)

        # Reason-code tracking
        self.deauth_reason: Dict[int, Deque[float]] = defaultdict(deque)
        dr_cfg = cfg.get("deauth_reason", {})
        self.reason_div_thresh = int(dr_cfg.get("distinct_threshold", 3))
        self.common_reason_codes = {int(x) for x in dr_cfg.get("common_whitelist", [1, 4, 8])}

        # Channel awareness
        self.chan_beacon: Dict[int, Deque[float]] = defaultdict(deque)
        self.chan_deauth: Dict[int, Deque[float]] = defaultdict(deque)
        ch_cfg = cfg.get("channel", {})
        self.beacon_spike_min = int(ch_cfg.get("beacon_spike_min_count", 50))
        self.beacon_spike_ratio = float(ch_cfg.get("beacon_spike_dom_ratio", 2.0))

        # Alert rate limiting
        alert_cfg = cfg.get("alerting", {})
        self.alert_cooldown = float(alert_cfg.get("cooldown_sec", 5.0))
        self.last_fired: Dict[Tuple[str, str], float] = {}

        # Time bookkeeping
        self.first_ts: Optional[float] = None
        self.next_calc: Optional[float] = None
        self.last_ts: Optional[float] = None

        # Streaming stats (detection baselines)
        self.rs_deauth = RunningStats()
        self.rs_probe = RunningStats()
        self.rs_beacon = RunningStats()
        # Continuous-learning stats (learner baselines)
        self.rs_learn_deauth = RunningStats()
        self.rs_learn_probe = RunningStats()
        self.rs_learn_beacon = RunningStats()

        # Baselines from config
        if not reset_baselines and "baselines" in cfg:
            b = cfg["baselines"]
            n = int(b.get("n", 50))
            if "deauth" in b:
                m = b["deauth"].get("mean", 0.0)
                s = b["deauth"].get("std", 1.0)
                self.rs_deauth.seed(m, s, n)
                self.rs_learn_deauth.seed(m, s, n)
            if "probe" in b:
                m = b["probe"].get("mean", 0.0)
                s = b["probe"].get("std", 1.0)
                self.rs_probe.seed(m, s, n)
                self.rs_learn_probe.seed(m, s, n)
            if "beacon" in b:
                m = b["beacon"].get("mean", 0.0)
                s = b["beacon"].get("std", 1.0)
                self.rs_beacon.seed(m, s, n)
                self.rs_learn_beacon.seed(m, s, n)

        self.alerts: List[Alert] = []
        self.metrics: List[MetricsRow] = []

    # ----------------- internal helpers -----------------

    def _get_or_make(self, sender: str):
        el = self.sender.get(sender)
        if el is None:
            el = {
                PACKET_TYPES.DEAUTH: deque(),
                PACKET_TYPES.PROBE_REQ: deque(),
                PACKET_TYPES.BEACON: deque(),
                "total": 0,
            }
            self.sender[sender] = el
        return el

    @staticmethod
    def _prune(dq: Deque[float], now_ts: float, win: int):
        cut = now_ts - win
        while dq and dq[0] < cut:
            dq.popleft()

    def _add_alert(self, kind: str, ts_from: float, ts_to: float, details: dict, key: Optional[str] = None):
        k = (kind, key or "")
        last = self.last_fired.get(k)
        if last is not None and ts_from < last + self.alert_cooldown:
            return
        self.last_fired[k] = ts_from

        # Mark hard alerts for learning-gating (anything that isn't INFO_* or ANOMALY_*)
        if not kind.startswith("INFO_") and not kind.startswith("ANOMALY_"):
            self._window_hard_alert = True

        self.alerts.append(Alert(ts_from, ts_to, kind, details))

    # ----------------- per-type processors -----------------

    def _proc_deauth(self, ev: PacketEvent):
        if ev.sender_mac:
            el = self._get_or_make(ev.sender_mac)
            dq = el[PACKET_TYPES.DEAUTH]
            dq.append(ev.ts)
            self._prune(dq, ev.ts, self.win[PACKET_TYPES.DEAUTH])
            el["total"] += 1

        if ev.bssid:
            dq_b = self.bssid_deauth[ev.bssid]
            dq_b.append(ev.ts)
            self._prune(dq_b, ev.ts, self.win[PACKET_TYPES.DEAUTH])

        if ev.reason_code is not None:
            dq_r = self.deauth_reason[ev.reason_code]
            dq_r.append(ev.ts)
            self._prune(dq_r, ev.ts, self.win[PACKET_TYPES.DEAUTH])

        if ev.channel is not None:
            dq_c = self.chan_deauth[ev.channel]
            dq_c.append(ev.ts)
            self._prune(dq_c, ev.ts, self.win[PACKET_TYPES.DEAUTH])

    def _proc_probe(self, ev: PacketEvent):
        if not ev.sender_mac:
            return
        el = self._get_or_make(ev.sender_mac)
        dq = el[PACKET_TYPES.PROBE_REQ]
        dq.append(ev.ts)
        self._prune(dq, ev.ts, self.win[PACKET_TYPES.PROBE_REQ])
        el["total"] += 1

    def _proc_beacon(self, ev: PacketEvent):
        if ev.sender_mac:
            el = self._get_or_make(ev.sender_mac)
            dq = el[PACKET_TYPES.BEACON]
            dq.append(ev.ts)
            self._prune(dq, ev.ts, self.win[PACKET_TYPES.BEACON])
            el["total"] += 1

        if ev.ssid and ev.bssid:
            dq2 = self.ssid_to_bssid_times[ev.ssid]
            dq2.append((ev.ts, ev.bssid))
            cut = ev.ts - self.ev_win
            while dq2 and dq2[0][0] < cut:
                dq2.popleft()

        if ev.channel is not None:
            dq_c = self.chan_beacon[ev.channel]
            dq_c.append(ev.ts)
            self._prune(dq_c, ev.ts, self.win[PACKET_TYPES.BEACON])

    # ----------------- public ingest / finalize -----------------

    def ingest(self, ev: PacketEvent):
        if self.first_ts is None:
            self.first_ts = ev.ts
            self.next_calc = self.first_ts + self.stats_interval
        self.last_ts = ev.ts

        if ev.ptype == PACKET_TYPES.DEAUTH:
            self._proc_deauth(ev)
        elif ev.ptype == PACKET_TYPES.PROBE_REQ:
            self._proc_probe(ev)
        elif ev.ptype == PACKET_TYPES.BEACON:
            self._proc_beacon(ev)
        else:
            if ev.sender_mac:
                self._get_or_make(ev.sender_mac)["total"] += 1

        while self.next_calc is not None and ev.ts >= self.next_calc:
            self._compute_and_alert(self.next_calc)
            self.next_calc += self.stats_interval

    def _compute_and_alert(self, window_end: float):
        if self.first_ts is None:
            return

        ws = window_end - self.stats_interval
        self._window_hard_alert = False  # reset for this window

        # Global counts and per-sender maxima
        g: Dict[PACKET_TYPES, int] = defaultdict(int)
        top_d = top_p = top_b = 0

        for sender, el in self.sender.items():
            for t in (PACKET_TYPES.DEAUTH, PACKET_TYPES.PROBE_REQ, PACKET_TYPES.BEACON):
                cnt = len(el[t])
                g[t] += cnt
                if t is PACKET_TYPES.DEAUTH:
                    if cnt > top_d:
                        top_d = cnt
                elif t is PACKET_TYPES.PROBE_REQ:
                    if cnt > top_p:
                        top_p = cnt
                elif t is PACKET_TYPES.BEACON:
                    if cnt > top_b:
                        top_b = cnt

                if cnt > self.thresh[t]:
                    self._add_alert(
                        f"THRESH_{t.name}_PER_SENDER",
                        ws,
                        window_end,
                        {
                            "sender_mac": sender,
                            "count_in_window": cnt,
                            "threshold": self.thresh[t],
                        },
                        key=sender,
                    )

        # Per-BSSID deauth maxima + alerts
        top_bssid_cnt = 0
        top_bssid_mac: Optional[str] = None
        for bssid, dq in self.bssid_deauth.items():
            self._prune(dq, window_end, self.win[PACKET_TYPES.DEAUTH])
            cnt = len(dq)
            if cnt > top_bssid_cnt:
                top_bssid_cnt = cnt
                top_bssid_mac = bssid
            if cnt > self.thresh_deauth_bssid:
                self._add_alert(
                    "THRESH_DEAUTH_PER_BSSID",
                    ws,
                    window_end,
                    {
                        "bssid": bssid,
                        "count_in_window": cnt,
                        "threshold": self.thresh_deauth_bssid,
                    },
                    key=bssid,
                )

        # Evil-twin detection
        ev_max = 0
        for ssid, dq in self.ssid_to_bssid_times.items():
            distinct = len({b for (_, b) in dq})
            ev_max = max(ev_max, distinct)
            if distinct > self.ev_thresh:
                self._add_alert(
                    "EVIL_TWIN_SUSPECT",
                    ws,
                    window_end,
                    {
                        "ssid": ssid,
                        "distinct_bssids_in_window": distinct,
                        "threshold": self.ev_thresh,
                    },
                    key=ssid,
                )

        # Reason-code metrics and INFO note
        deauth_reason_top: Optional[int] = None
        deauth_reason_top_cnt = 0
        deauth_reason_distinct = 0
        uncommon_reasons = set()

        for rc, dq in self.deauth_reason.items():
            self._prune(dq, window_end, self.win[PACKET_TYPES.DEAUTH])
            cnt = len(dq)
            if cnt > 0:
                deauth_reason_distinct += 1
                if cnt > deauth_reason_top_cnt:
                    deauth_reason_top_cnt = cnt
                    deauth_reason_top = rc
                if rc not in self.common_reason_codes:
                    uncommon_reasons.add(rc)

        if deauth_reason_distinct >= self.reason_div_thresh:
            self._add_alert(
                "INFO_DEAUTH_REASON_DIVERSITY",
                ws,
                window_end,
                {
                    "distinct_reasons": deauth_reason_distinct,
                    "top_reason": deauth_reason_top,
                    "uncommon_reasons": sorted(uncommon_reasons),
                },
                key="GLOBAL_DEAUTH_REASON",
            )

        # Channel-level metrics + optional INFO on beacon spike
        top_channel: Optional[int] = None
        top_channel_beacon_count = 0
        second_best_beacon = 0

        for ch, dq in self.chan_beacon.items():
            self._prune(dq, window_end, self.win[PACKET_TYPES.BEACON])
            cnt = len(dq)
            if cnt > top_channel_beacon_count:
                second_best_beacon = top_channel_beacon_count
                top_channel_beacon_count = cnt
                top_channel = ch
            elif cnt > second_best_beacon:
                second_best_beacon = cnt

        top_channel_deauth_count = 0
        for ch, dq in self.chan_deauth.items():
            self._prune(dq, window_end, self.win[PACKET_TYPES.DEAUTH])
            cnt = len(dq)
            if cnt > top_channel_deauth_count:
                top_channel_deauth_count = cnt

        if (
            top_channel is not None
            and top_channel_beacon_count >= self.beacon_spike_min
            and top_channel_beacon_count >= self.beacon_spike_ratio * max(second_best_beacon, 1)
        ):
            self._add_alert(
                "INFO_BEACON_SPIKE_ON_CHANNEL",
                ws,
                window_end,
                {
                    "channel": top_channel,
                    "top_count": top_channel_beacon_count,
                    "second_best": second_best_beacon,
                    "min_count": self.beacon_spike_min,
                    "dom_ratio": self.beacon_spike_ratio,
                },
                key=str(top_channel),
            )

        # Z-scores using detection baseline (rs_deauth/probe/beacon)
        z_d = z_p = z_b = 0.0
        if self.use_z:
            z_d = self.rs_deauth.z(g[PACKET_TYPES.DEAUTH])
            z_p = self.rs_probe.z(g[PACKET_TYPES.PROBE_REQ])
            z_b = self.rs_beacon.z(g[PACKET_TYPES.BEACON])

        max_abs_z = max(abs(z_d), abs(z_p), abs(z_b)) if self.use_z else 0.0
        suspicious = self._window_hard_alert or (self.use_z and max_abs_z >= self.safe_z_gate)

        # Anomaly alerts (global z-score)
        if self.use_z:
            if z_d >= self.z_thr:
                self._add_alert(
                    "ANOMALY_DEAUTH_GLOBAL_Z",
                    ws,
                    window_end,
                    {
                        "z": z_d,
                        "count": g[PACKET_TYPES.DEAUTH],
                        "z_threshold": self.z_thr,
                    },
                    key="DEAUTH",
                )
            if z_p >= self.z_thr:
                self._add_alert(
                    "ANOMALY_PROBE_REQ_GLOBAL_Z",
                    ws,
                    window_end,
                    {
                        "z": z_p,
                        "count": g[PACKET_TYPES.PROBE_REQ],
                        "z_threshold": self.z_thr,
                    },
                    key="PROBE_REQ",
                )
            if z_b >= self.z_thr:
                self._add_alert(
                    "ANOMALY_BEACON_GLOBAL_Z",
                    ws,
                    window_end,
                    {
                        "z": z_b,
                        "count": g[PACKET_TYPES.BEACON],
                        "z_threshold": self.z_thr,
                    },
                    key="BEACON",
                )

        # Continuous learner: only update with safe windows
        if self.use_z:
            if not suspicious:
                self.rs_learn_deauth.update(g[PACKET_TYPES.DEAUTH])
                self.rs_learn_probe.update(g[PACKET_TYPES.PROBE_REQ])
                self.rs_learn_beacon.update(g[PACKET_TYPES.BEACON])
                self.learn_windows += 1
            else:
                self.learn_rejected_suspicious += 1

            # If in learning mode, sync detection baseline from learner
            if self.mode == "learning" and self.rs_learn_deauth.n > 0:
                self.rs_deauth.copy_from(self.rs_learn_deauth)
                self.rs_probe.copy_from(self.rs_learn_probe)
                self.rs_beacon.copy_from(self.rs_learn_beacon)

        # Metrics row
        self.metrics.append(
            MetricsRow(
                ws,
                window_end,
                g[PACKET_TYPES.DEAUTH],
                g[PACKET_TYPES.PROBE_REQ],
                g[PACKET_TYPES.BEACON],
                ev_max,
                top_d,
                top_p,
                top_b,
                top_bssid_cnt,
                top_bssid_mac,
                deauth_reason_top,
                deauth_reason_distinct,
                top_channel,
                top_channel_beacon_count,
                top_channel_deauth_count,
            )
        )

    def finalize(self):
        if self.first_ts is None or self.next_calc is None:
            return
        end = self.last_ts if self.last_ts is not None else self.next_calc
        while self.next_calc is not None and self.next_calc <= end:
            self._compute_and_alert(self.next_calc)
            self.next_calc += self.stats_interval
        if not self.metrics and end is not None:
            self._compute_and_alert(end)


# ---- robust field access helpers ----

def _iter_layers(pkt):
    for ly in getattr(pkt, "layers", []):
        yield ly


def _first_field_attr(pkt, layer_candidates, field_candidates):
    for ly in _iter_layers(pkt):
        lname = (ly.layer_name or "").lower()
        if lname not in layer_candidates:
            continue
        names = set(getattr(ly, "field_names", []) or [])
        for f in field_candidates:
            if f in names:
                try:
                    v = getattr(ly, f)
                    if v not in (None, ""):
                        return v
                except Exception:
                    pass
    return None


def _first_field_any(pkt, layer_candidates, dotted_candidates, underscore_candidates):
    for ly in _iter_layers(pkt):
        lname = (ly.layer_name or "").lower()
        if lname not in layer_candidates:
            continue
        for f in dotted_candidates:
            try:
                v = ly.get_field_value(f)
                if v not in (None, ""):
                    return v
            except Exception:
                pass
    return _first_field_attr(pkt, layer_candidates, underscore_candidates)


def _to_int(x) -> Optional[int]:
    if x is None:
        return None
    s = str(x).strip()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s)
    except Exception:
        acc = ""
        for ch in s:
            if ch.isdigit():
                acc += ch
            else:
                break
        try:
            return int(acc) if acc else None
        except Exception:
            return None


SUBTYPE_TO_TYPE_INT = {
    4: PACKET_TYPES.PROBE_REQ,
    8: PACKET_TYPES.BEACON,
    12: PACKET_TYPES.DEAUTH,
}

def pkt_to_event(pkt) -> Optional[PacketEvent]:
    try:
        ts = float(pkt.sniff_timestamp)
    except Exception:
        return None

    L_WLAN = {"wlan", "ieee802_11", "ieee802-11"}

    st_raw = _first_field_any(
        pkt,
        layer_candidates=L_WLAN,
        dotted_candidates=[
            "wlan.fc.type_subtype",
            "wlan.fc.subtype",
            "wlan.subtype",
        ],
        underscore_candidates=[
            "fc_type_subtype",
            "fc_subtype",
            "subtype",
            "wlan_fc_type_subtype",
            "wlan_fc_subtype",
            "type_subtype",
        ],
    )
    st_i = _to_int(st_raw)
    ptype = SUBTYPE_TO_TYPE_INT.get(st_i, PACKET_TYPES.OTHER)  # type: ignore

    sa = _first_field_any(pkt, L_WLAN, ["wlan.sa", "wlan.ta"], ["sa", "ta"])
    da = _first_field_any(pkt, L_WLAN, ["wlan.da", "wlan.ra"], ["da", "ra"])
    bssid = _first_field_any(pkt, L_WLAN, ["wlan.bssid"], ["bssid"])

    L_MGT = {"wlan_mgt"} | L_WLAN
    ssid = _first_field_any(pkt, L_MGT, ["wlan_mgt.ssid", "wlan.ssid"], ["ssid"])
    if ssid == "":
        ssid = None

    chan_s = _first_field_any(
        pkt,
        {"wlan_radio", "radiotap", "wlan"},
        ["wlan_radio.channel"],
        ["channel"],
    )
    try:
        chan = int(chan_s) if chan_s is not None and str(chan_s).isdigit() else None
    except Exception:
        chan = None

    reason_raw = _first_field_any(
        pkt,
        L_MGT,
        ["wlan_mgt.fixed.reason_code", "wlan.fixed.reason_code"],
        ["fixed_reason_code", "reason_code"],
    )
    reason_code = _to_int(reason_raw)

    return PacketEvent(ts, ptype, sa, da, bssid, ssid, chan, reason_code)


def _process_with_filter(pcap_path: str, ids: IDS, display_filter: Optional[str]):
    pkts_seen = 0
    evs = 0
    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=display_filter,
        keep_packets=False,
        use_json=True,
    )
    try:
        for pkt in cap:
            pkts_seen += 1
            ev = pkt_to_event(pkt)
            if ev:
                ids.ingest(ev)
                evs += 1
    finally:
        cap.close()
    ids.finalize()
    return pkts_seen, evs


def run_offline(
    pcap_path: str,
    cfg: dict,
    reset_baselines: bool = False,
    display_filter: Optional[str] = "wlan.fc.type==0",
):
    ids = IDS(cfg, reset_baselines=reset_baselines)
    pkts_seen, evs = _process_with_filter(pcap_path, ids, display_filter)
    if evs == 0:
        ids = IDS(cfg, reset_baselines=reset_baselines)
        pkts_seen, evs = _process_with_filter(pcap_path, ids, None)
    return ids.alerts, ids.metrics, pkts_seen, evs


def main():
    ap = argparse.ArgumentParser(description="Offline Wi-Fi IDS (pcap/pcapng)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument(
        "--debug-fields",
        type=int,
        default=0,
        help="Print layer names and field_names for the first N packets (no filter).",
    )
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--alerts-out", default="data/alerts/offline_alerts.jsonl")
    ap.add_argument("--metrics-out", default="reports/offline_metrics.csv")
    ap.add_argument("--reset-baselines", action="store_true")
    ap.add_argument("--print-metrics-head", type=int, default=0)
    ap.add_argument("--display-filter", default="wlan.fc.type==0")
    args = ap.parse_args()

    cfg = load_config(args.config)
    alerts, metrics, pkts_seen, evs = run_offline(
        args.pcap,
        cfg,
        reset_baselines=args.reset_baselines,
        display_filter=args.display_filter,
    )

    os.makedirs(os.path.dirname(args.alerts_out), exist_ok=True)
    with open(args.alerts_out, "w") as f:
        for a in alerts:
            f.write(json.dumps(asdict(a)) + "\n")

    os.makedirs(os.path.dirname(args.metrics_out), exist_ok=True)

    if args.debug_fields > 0:
        cap_dbg = pyshark.FileCapture(args.pcap, keep_packets=False, use_json=True)
        try:
            for i, p in enumerate(cap_dbg):
                print(f"\n--- DEBUG packet #{i} ---")
                for ly in getattr(p, "layers", []):
                    print(
                        f"  LAYER: {ly.layer_name}  fields={getattr(ly,'field_names', [])}"
                    )
                if i + 1 >= args.debug_fields:
                    break
        finally:
            cap_dbg.close()

    with open(args.metrics_out, "w", newline="") as f:
        w = csv.writer(f)
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
        for m in metrics:
            w.writerow(
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

    if args.print_metrics_head > 0:
        from itertools import islice

        print("\n[Metrics head]")
        with open(args.metrics_out) as f:
            for line in islice(f, args.print_metrics_head + 1):
                print(line.rstrip())

    print(
        f"\n[Ingest] packets_read={pkts_seen}  "
        f"events_parsed={evs}  windows={len(metrics)}  alerts={len(alerts)}"
    )


if __name__ == "__main__":
    main()
