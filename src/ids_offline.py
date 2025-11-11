from __future__ import annotations
from dataclasses import dataclass, asdict
from enum import Enum, auto
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple
import argparse, csv, json, math, os

import pyshark
try:
    import yaml # type: ignore
except Exception:
    yaml = None

class PACKET_TYPES(Enum):
    DEAUTH = auto()
    PROBE_REQ = auto()
    BEACON = auto()
    OTHER = auto()

DEFAULT_CFG = {
    "thresholds": {"deauth_per_sec": 20, "probe_req_per_sec": 50, "beacon_per_sec": 200},
    "windows_sec": {"deauth": 5, "probe_req": 5, "beacon": 5, "stats_interval": 1, "evil_twin_window": 5},
    "evil_twin": {"distinct_bssids_threshold": 3},
    "anomaly": {"use_zscore": True, "z_threshold": 3.0},
}

def load_config(path: Optional[str]) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CFG))
    if path and yaml:
        try:
            with open(path, "r") as f:
                user = yaml.safe_load(f) or {}
            for k, v in user.items():
                if isinstance(v, dict) and k in cfg: cfg[k].update(v)
                else: cfg[k] = v
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

@dataclass
class Alert:
    ts_from: float
    ts_to: float
    kind: str
    details: dict

class RunningStats:
    def __init__(self): self.n, self.mean, self.M2 = 0, 0.0, 0.0
    def seed(self, mean: float, std: float, n: int = 50):
        self.n = max(2, int(n)); self.mean = float(mean); self.M2 = (std**2)*(self.n-1)
    def update(self, x: float):
        self.n += 1; d = x - self.mean; self.mean += d/self.n; self.M2 += d*(x - self.mean)
    @property
    def var(self): return self.M2/(self.n-1) if self.n>1 else 0.0
    @property
    def std(self): return math.sqrt(self.var) if self.var>0 else 0.0
    def z(self, x: float) -> float: s = self.std or 1.0; return (x - self.mean)/s

class IDS:
    def __init__(self, cfg: dict, reset_baselines: bool = False):
        W, T = cfg["windows_sec"], cfg["thresholds"]
        self.win = {PACKET_TYPES.DEAUTH: W["deauth"], PACKET_TYPES.PROBE_REQ: W["probe_req"], PACKET_TYPES.BEACON: W["beacon"]}
        self.stats_interval = W["stats_interval"]
        self.thresh = {PACKET_TYPES.DEAUTH: T["deauth_per_sec"], PACKET_TYPES.PROBE_REQ: T["probe_req_per_sec"], PACKET_TYPES.BEACON: T["beacon_per_sec"]}
        self.ev_win = W["evil_twin_window"]; self.ev_thresh = cfg["evil_twin"]["distinct_bssids_threshold"]
        self.use_z = bool(cfg["anomaly"].get("use_zscore", True)); self.z_thr = float(cfg["anomaly"].get("z_threshold", 3.0))
        self.sender: Dict[str, Dict] = {}
        self.ssid_to_bssid_times: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self.first_ts = None; self.next_calc = None; self.last_ts = None
        self.rs_deauth, self.rs_probe, self.rs_beacon = RunningStats(), RunningStats(), RunningStats()
        if not reset_baselines and "baselines" in cfg:
            b = cfg["baselines"]; n = int(b.get("n", 50))
            if "deauth" in b: self.rs_deauth.seed(b["deauth"].get("mean", 0.0), b["deauth"].get("std", 1.0), n)
            if "probe"  in b: self.rs_probe .seed(b["probe"] .get("mean", 0.0), b["probe"] .get("std", 1.0), n)
            if "beacon" in b: self.rs_beacon.seed(b["beacon"].get("mean", 0.0), b["beacon"].get("std", 1.0), n)
        self.alerts: List[Alert] = []; self.metrics: List[MetricsRow] = []

    def _get_or_make(self, sender: str):
        el = self.sender.get(sender)
        if el is None:
            el = {PACKET_TYPES.DEAUTH: deque(), PACKET_TYPES.PROBE_REQ: deque(), PACKET_TYPES.BEACON: deque(), "total": 0}
            self.sender[sender] = el
        return el

    def _prune(self, dq: Deque[float], now_ts: float, win: int):
        cut = now_ts - win
        while dq and dq[0] < cut: dq.popleft()

    def _proc_deauth(self, ev: PacketEvent):
        if not ev.sender_mac: return
        el = self._get_or_make(ev.sender_mac); dq = el[PACKET_TYPES.DEAUTH]
        dq.append(ev.ts); self._prune(dq, ev.ts, self.win[PACKET_TYPES.DEAUTH]); el["total"] += 1

    def _proc_probe(self, ev: PacketEvent):
        if not ev.sender_mac: return
        el = self._get_or_make(ev.sender_mac); dq = el[PACKET_TYPES.PROBE_REQ]
        dq.append(ev.ts); self._prune(dq, ev.ts, self.win[PACKET_TYPES.PROBE_REQ]); el["total"] += 1

    def _proc_beacon(self, ev: PacketEvent):
        if ev.sender_mac:
            el = self._get_or_make(ev.sender_mac); dq = el[PACKET_TYPES.BEACON]
            dq.append(ev.ts); self._prune(dq, ev.ts, self.win[PACKET_TYPES.BEACON]); el["total"] += 1
        if ev.ssid and ev.bssid:
            dq2 = self.ssid_to_bssid_times[ev.ssid]; dq2.append((ev.ts, ev.bssid))
            cut = ev.ts - self.ev_win
            while dq2 and dq2[0][0] < cut: dq2.popleft()

    def ingest(self, ev: PacketEvent):
        # print(ev)
        if self.first_ts is None:
            self.first_ts = ev.ts; self.next_calc = self.first_ts + self.stats_interval
        self.last_ts = ev.ts
        if ev.ptype == PACKET_TYPES.DEAUTH: self._proc_deauth(ev)
        elif ev.ptype == PACKET_TYPES.PROBE_REQ: self._proc_probe(ev)
        elif ev.ptype == PACKET_TYPES.BEACON: self._proc_beacon(ev)
        else:
            if ev.sender_mac: self._get_or_make(ev.sender_mac)["total"] += 1
        while self.next_calc is not None and ev.ts >= self.next_calc:
            self._compute_and_alert(self.next_calc); self.next_calc += self.stats_interval

    def _compute_and_alert(self, window_end: float):
        if self.first_ts is None: return
        ws = window_end - self.stats_interval
        g = defaultdict(int); top_d = top_p = top_b = 0
        for sender, el in self.sender.items():
            for t in (PACKET_TYPES.DEAUTH, PACKET_TYPES.PROBE_REQ, PACKET_TYPES.BEACON):
                cnt = len(el[t]); g[t] += cnt
                if t is PACKET_TYPES.DEAUTH: top_d = max(top_d, cnt)
                elif t is PACKET_TYPES.PROBE_REQ: top_p = max(top_p, cnt)
                elif t is PACKET_TYPES.BEACON: top_b = max(top_b, cnt)
                if cnt > self.thresh[t]:
                    self.alerts.append(Alert(ws, window_end, f"THRESH_{t.name}_PER_SENDER",
                                             {"sender_mac": sender, "count_in_window": cnt, "threshold": self.thresh[t]}))
        if self.use_z:
            z_d = self.rs_deauth.z(g[PACKET_TYPES.DEAUTH]); self.rs_deauth.update(g[PACKET_TYPES.DEAUTH])
            z_p = self.rs_probe .z(g[PACKET_TYPES.PROBE_REQ]); self.rs_probe .update(g[PACKET_TYPES.PROBE_REQ])
            z_b = self.rs_beacon.z(g[PACKET_TYPES.BEACON]);  self.rs_beacon.update(g[PACKET_TYPES.BEACON])
            if z_d >= self.z_thr: self.alerts.append(Alert(ws, window_end, "ANOMALY_DEAUTH_GLOBAL_Z", {"z": z_d, "count": g[PACKET_TYPES.DEAUTH], "z_threshold": self.z_thr}))
            if z_p >= self.z_thr: self.alerts.append(Alert(ws, window_end, "ANOMALY_PROBE_REQ_GLOBAL_Z", {"z": z_p, "count": g[PACKET_TYPES.PROBE_REQ], "z_threshold": self.z_thr}))
            if z_b >= self.z_thr: self.alerts.append(Alert(ws, window_end, "ANOMALY_BEACON_GLOBAL_Z", {"z": z_b, "count": g[PACKET_TYPES.BEACON], "z_threshold": self.z_thr}))
        ev_max = 0
        for ssid, dq in self.ssid_to_bssid_times.items():
            distinct = len({b for (_, b) in dq}); ev_max = max(ev_max, distinct)
            if distinct > self.ev_thresh:
                self.alerts.append(Alert(ws, window_end, "EVIL_TWIN_SUSPECT",
                                         {"ssid": ssid, "distinct_bssids_in_window": distinct, "threshold": self.ev_thresh}))
        self.metrics.append(MetricsRow(ws, window_end, g[PACKET_TYPES.DEAUTH], g[PACKET_TYPES.PROBE_REQ],
                                       g[PACKET_TYPES.BEACON], ev_max, top_d, top_p, top_b))

    def finalize(self):
        if self.first_ts is None or self.next_calc is None: return
        end = self.last_ts if self.last_ts is not None else self.next_calc
        while self.next_calc is not None and self.next_calc <= end:
            self._compute_and_alert(self.next_calc); self.next_calc += self.stats_interval
        if not self.metrics and end is not None:
            self._compute_and_alert(end)

# ---- robust field access ----
# def _iter_layers(pkt):
#     for ly in getattr(pkt, "layers", []):
#         yield ly

# def _gv(layer, field):
#     try:
#         print(layer.field_names)
#         print("Getting field:", field, " from layer:", layer.layer_name, " of type:", type(layer))
#         print(" from layer: ", layer.fc_subtype)
#         return layer.get_field_value(field)
#     except Exception as e:
#         print(f"Error getting field '{field}' from layer: {e}")
#         return None

# def _first_field(pkt, candidates: List[str]) -> Optional[str]:
#     for ly in _iter_layers(pkt):
#         # print("Layer:", ly)
#         for f in candidates:
#             v = _gv(ly, f)
#             if v not in (None, ""):
#                 return v
#     return None

# def _to_int(x) -> Optional[int]:
#     if x is None: return None
#     s = str(x).strip()
#     try:
#         if s.startswith("0x"): return int(s, 16)
#         return int(s)
#     except Exception:
#         acc = ""
#         for ch in s:
#             if ch.isdigit(): acc += ch
#             else: break
#         try: return int(acc) if acc else None
#         except Exception: return None

# SUBTYPE_TO_TYPE_INT = {4: PACKET_TYPES.PROBE_REQ, 8: PACKET_TYPES.BEACON, 12: PACKET_TYPES.DEAUTH}

# def pkt_to_event(pkt) -> Optional[PacketEvent]:
#     try: ts = float(pkt.sniff_timestamp)
#     except Exception: return None
#     st_raw = _first_field(pkt, ["fc.type_subtype","fc.subtype","subtype","fc_type_subtype"])
#     print("raw subtype:", st_raw)
#     st_i = _to_int(st_raw)
#     ptype = SUBTYPE_TO_TYPE_INT.get(st_i, PACKET_TYPES.OTHER)
#     print(f"Packet ts={ts} subtype={st_raw} ptype={ptype.name}")
#     sa = _first_field(pkt, ["wlan.sa","wlan.ta"])
#     da = _first_field(pkt, ["wlan.da","wlan.ra"])
#     bssid = _first_field(pkt, ["wlan.bssid"])
#     ssid = _first_field(pkt, ["wlan_mgt.ssid","wlan.ssid"])
#     if ssid == "": ssid = None
#     chan_s = _first_field(pkt, ["wlan_radio.channel"])
#     chan = int(chan_s) if chan_s and str(chan_s).isdigit() else None
#     return PacketEvent(ts, ptype, sa, da, bssid, ssid, chan)
# ---- helpers for robust field access (underscore-style) ----
def _iter_layers(pkt):
    for ly in getattr(pkt, "layers", []):
        yield ly

def _first_field_attr(pkt, layer_candidates, field_candidates):
    """
    Try attribute names that appear in `layer.field_names`, e.g. 'fc_type_subtype'.
    Returns the first non-empty value.
    """
    # print("field candidates:", field_candidates)
    for ly in _iter_layers(pkt):
        lname = (ly.layer_name or "").lower()
        # print("Layer:", lname, " fields=", getattr(ly, "field_names", []))
        # try:
        #     print("bssid:", getattr(ly, "fc.type_subtype"))
        # except Exception as e:
        #     print(f"Error getting bssid from layer {lname}: {e}")
        if lname not in layer_candidates:
            continue
        names = set(getattr(ly, "field_names", []) or [])
        for f in field_candidates:
            if f in names:
                try:
                    v = getattr(ly, f)
                    if v not in (None, ""):
                        # print("finished here")
                        # print("got value:", v, " from field:", f, " in layer:", lname)
                        return v
                except Exception:
                    pass
    return None

def _first_field_any(pkt, layer_candidates, dotted_candidates, underscore_candidates):
    """
    Try dotted names via get_field_value(), then underscore attributes via getattr().
    """
    # 1) get_field_value on dotted names across all layers
    for ly in _iter_layers(pkt):
        lname = (ly.layer_name or "").lower()
        if lname not in layer_candidates:
            continue
        for f in dotted_candidates:
            try:
                v = ly.get_field_value(f)
                if v not in (None, ""):
                    # print("finished")
                    return v
            except Exception:
                pass
    # print("reaching here")
    # 2) attribute access on underscore names
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
        # e.g., "8 (Beacon frame)"
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

# ---- map subtype int -> our type ----
SUBTYPE_TO_TYPE_INT = {4: PACKET_TYPES.PROBE_REQ, 8: PACKET_TYPES.BEACON, 12: PACKET_TYPES.DEAUTH}

def pkt_to_event(pkt) -> Optional[PacketEvent]:
    try:
        ts = float(pkt.sniff_timestamp)
    except Exception:
        return None

    # Layers to consider (PyShark may expose 802.11 as 'wlan' or 'ieee802_11')
    L_WLAN = {"wlan", "ieee802_11", "ieee802-11"}

    # Robust subtype: try dotted, then underscore variants
    st_raw = _first_field_any(
        pkt,
        layer_candidates=L_WLAN,
        dotted_candidates=[
            "wlan.fc.type_subtype", "wlan.fc.subtype", "wlan.subtype"
        ],
        underscore_candidates=[
            "fc_type_subtype", "fc_subtype", "subtype", "wlan_fc_type_subtype", "wlan_fc_subtype", "type_subtype"
        ],
    )
    # print("raw subtype:", st_raw)
    st_i = _to_int(st_raw)
    ptype = SUBTYPE_TO_TYPE_INT.get(st_i, PACKET_TYPES.OTHER) # type: ignore

    # Addresses / SSID / channel (use same robust strategy)
    sa = _first_field_any(pkt, L_WLAN, ["wlan.sa", "wlan.ta"], ["sa", "ta"])
    da = _first_field_any(pkt, L_WLAN, ["wlan.da", "wlan.ra"], ["da", "ra"])
    bssid = _first_field_any(pkt, L_WLAN, ["wlan.bssid"], ["bssid"])

    # SSID usually sits in wlan_mgt; try both layers just in case
    L_MGT = {"wlan_mgt"} | L_WLAN
    ssid = _first_field_any(pkt, L_MGT, ["wlan_mgt.ssid", "wlan.ssid"], ["ssid"])
    if ssid == "":
        ssid = None

    chan_s = _first_field_any(pkt, {"wlan_radio", "radiotap", "wlan"}, ["wlan_radio.channel"], ["channel"])
    try:
        chan = int(chan_s) if chan_s is not None and str(chan_s).isdigit() else None
    except Exception:
        chan = None

    return PacketEvent(ts, ptype, sa, da, bssid, ssid, chan)

def _process_with_filter(pcap_path: str, ids: IDS, display_filter: Optional[str]):
    pkts_seen = evs = 0
    cap = pyshark.FileCapture(pcap_path, display_filter=display_filter, keep_packets=False, use_json=True)
    try:
        for pkt in cap:
            pkts_seen += 1
            # print(pkt)
            ev = pkt_to_event(pkt)
            if ev: 
                ids.ingest(ev); evs += 1
    finally:
        cap.close()
    ids.finalize()
    return pkts_seen, evs

def run_offline(pcap_path: str, cfg: dict, reset_baselines: bool=False, display_filter: Optional[str]="wlan.fc.type==0"):
    ids = IDS(cfg, reset_baselines=reset_baselines)
    pkts_seen, evs = _process_with_filter(pcap_path, ids, display_filter)
    if evs == 0:
        ids = IDS(cfg, reset_baselines=reset_baselines)
        pkts_seen, evs = _process_with_filter(pcap_path, ids, None)
    return ids.alerts, ids.metrics, pkts_seen, evs

def main():
    ap = argparse.ArgumentParser(description="Offline Wi-Fi IDS (pcap/pcapng)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--debug-fields", type=int, default=0,
                help="Print layer names and field_names for the first N packets (no filter).")
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--alerts-out", default="data/alerts/offline_alerts.jsonl")
    ap.add_argument("--metrics-out", default="reports/offline_metrics.csv")
    ap.add_argument("--reset-baselines", action="store_true")
    ap.add_argument("--print-metrics-head", type=int, default=0)
    ap.add_argument("--display-filter", default="wlan.fc.type==0")
    args = ap.parse_args()

    cfg = load_config(args.config)
    alerts, metrics, pkts_seen, evs = run_offline(args.pcap, cfg, reset_baselines=args.reset_baselines, display_filter=args.display_filter)

    os.makedirs(os.path.dirname(args.alerts_out), exist_ok=True)
    with open(args.alerts_out, "w") as f:
        for a in alerts: f.write(json.dumps(asdict(a)) + "\n")

    os.makedirs(os.path.dirname(args.metrics_out), exist_ok=True)
    if args.debug_fields > 0:
        cap_dbg = pyshark.FileCapture(args.pcap, keep_packets=False, use_json=True)
        try:
            for i, p in enumerate(cap_dbg):
                print(f"\n--- DEBUG packet #{i} ---")
                for ly in getattr(p, "layers", []):
                    print(f"  LAYER: {ly.layer_name}  fields={getattr(ly,'field_names', [])}")
                if i+1 >= args.debug_fields:
                    break
        finally:
            cap_dbg.close()

    with open(args.metrics_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts_from","ts_to","deauth_count","probe_count","beacon_count",
                    "eviltwin_max_distinct_bssids","top_sender_deauth","top_sender_probe","top_sender_beacon"])
        for m in metrics:
            w.writerow([m.ts_from,m.ts_to,m.deauth_count,m.probe_count,m.beacon_count,
                        m.eviltwin_max_distinct_bssids,m.top_sender_deauth,m.top_sender_probe,m.top_sender_beacon])

    if args.print_metrics_head > 0:
        from itertools import islice
        print("\n[Metrics head]")
        with open(args.metrics_out) as f:
            for line in islice(f, args.print_metrics_head + 1): print(line.rstrip())
    print(f"\n[Ingest] packets_read={pkts_seen}  events_parsed={evs}  windows={len(metrics)}  alerts={len(alerts)}")

if __name__ == "__main__":
    main()
