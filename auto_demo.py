#!/usr/bin/env python3
"""
Shadow Guard 2.0 — Controllable Demo Traffic Simulator Service
==============================================================
Refactored from the original auto_demo.py generator.

By default, starts in IDLE state and exposes an HTTP Control API
(default port 8010) so the SOC Dashboard or operators can explicitly
Start, Pause, Resume, Stop, and Reset synthetic traffic simulations.

Does NOT generate traffic automatically on startup.
`ground_truth` is kept strictly isolated inside this simulator's session
store for post-session evaluation and is NEVER sent to ML inference.
"""

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import random
import sys
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CAPTURE_URL = os.getenv("CAPTURE_URL", "http://localhost:3001/capture")
SIMULATOR_HOST = os.getenv("SIMULATOR_HOST", "0.0.0.0")
SIMULATOR_PORT = int(os.getenv("SIMULATOR_PORT", "8010"))

SPEED_INTERVALS = {
    "low": 1.0,      # ~1 event/sec
    "medium": 0.4,   # ~2.5 events/sec
    "high": 0.125,   # ~8 events/sec
}

SCENARIO_ALIASES = {
    "brute_force": "ssh_brute_force",
    "malware_command_control": "c2_beaconing",
    "zero_day": "stealth_anomaly",
    "normal": "normal_traffic",
}

VALID_SCENARIOS = [
    "normal_traffic",
    "port_scan",
    "ssh_brute_force",
    "service_enumeration",
    "ddos",
    "data_exfiltration",
    "c2_beaconing",
    "multi_vector",
    "stealth_anomaly",
    "mixed",
]

MALICIOUS_SCENARIOS = [
    "port_scan",
    "ssh_brute_force",
    "service_enumeration",
    "ddos",
    "data_exfiltration",
    "c2_beaconing",
    "multi_vector",
    "stealth_anomaly",
]

INTERNAL_HOSTS = [f"192.168.1.{i}" for i in range(10, 220)]
EXTERNAL_BENIGN_HOSTS = ["8.8.8.8", "1.1.1.1", "13.107.42.14", "151.101.1.69", "140.82.112.4"]
EXTERNAL_ATTACKER_HOSTS = [f"203.0.113.{i}" for i in range(10, 90)] + [f"198.51.100.{i}" for i in range(10, 90)]
C2_HOSTS = ["104.21.45.67", "185.220.101.42", "45.155.205.91", "198.18.0.77"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_scenario(name: str) -> str:
    key = (name or "mixed").strip().lower()
    key = SCENARIO_ALIASES.get(key, key)
    if key not in VALID_SCENARIOS:
        raise ValueError(f"Unsupported scenario '{name}'. Valid scenarios: {', '.join(VALID_SCENARIOS)}")
    return key


def _rand_ephemeral_port() -> int:
    return random.randint(32768, 60999)


def build_synthetic_flow(scenario: str) -> tuple[dict, dict]:
    """
    Build a synthetic network flow payload compatible with traffic-capture-service
    `/capture` alongside an isolated ground-truth record for post-session evaluation.

    NOTE: `ground_truth` is returned separately and is NOT included in `capture_payload`.
    """
    if scenario == "normal_traffic":
        proto = random.choice(["TCP", "UDP"])
        dst_port = random.choice([80, 443, 53, 123]) if proto == "UDP" else random.choice([80, 443, 8443])
        packets = random.randint(12, 650)
        bytes_sent = packets * random.randint(250, 1200)
        duration = round(random.uniform(0.15, 18.0), 3)
        src_ip = random.choice(INTERNAL_HOSTS)
        dst_ip = random.choice(EXTERNAL_BENIGN_HOSTS)
        attack_type = "normal_traffic"
        flow_type = "normal"

    elif scenario == "port_scan":
        proto = "TCP"
        dst_port = random.choice([21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432, 8080])
        packets = random.randint(1, 3)
        bytes_sent = packets * random.randint(48, 74)
        duration = round(random.uniform(0.01, 0.15), 3)
        src_ip = random.choice(["10.0.0.50", "10.0.0.51", "203.0.113.45"])
        dst_ip = random.choice(INTERNAL_HOSTS)
        attack_type = "port_scan"
        flow_type = "anomaly"

    elif scenario == "ssh_brute_force":
        proto = "TCP"
        dst_port = 22
        packets = random.randint(2, 8)
        bytes_sent = packets * random.randint(96, 180)
        duration = round(random.uniform(0.05, 0.35), 3)
        src_ip = random.choice(["10.20.30.40", "185.220.101.14", "203.0.113.77"])
        dst_ip = random.choice(["192.168.1.200", "192.168.1.201", "192.168.1.100"])
        attack_type = "brute_force"
        flow_type = "anomaly"

    elif scenario == "service_enumeration":
        proto = "TCP"
        dst_port = random.choice([21, 22, 80, 135, 139, 443, 445, 1433, 3306, 5432, 6379, 8080])
        packets = random.randint(4, 18)
        bytes_sent = packets * random.randint(120, 420)
        duration = round(random.uniform(0.08, 0.75), 3)
        src_ip = random.choice(EXTERNAL_ATTACKER_HOSTS)
        dst_ip = random.choice(INTERNAL_HOSTS)
        attack_type = "service_enumeration"
        flow_type = "anomaly"

    elif scenario == "ddos":
        proto = random.choice(["UDP", "TCP"])
        dst_port = random.choice([80, 443, 53])
        packets = random.randint(3500, 12000)
        bytes_sent = packets * random.randint(450, 900)
        duration = round(random.uniform(0.2, 1.2), 3)
        src_ip = random.choice(EXTERNAL_ATTACKER_HOSTS)
        dst_ip = random.choice(["192.168.1.100", "192.168.1.101"])
        attack_type = "ddos"
        flow_type = "anomaly"

    elif scenario == "data_exfiltration":
        proto = "TCP"
        dst_port = random.choice([443, 8443, 22, 9001])
        packets = random.randint(150, 900)
        bytes_sent = random.randint(15_000_000, 85_000_000)
        duration = round(random.uniform(4.0, 22.0), 3)
        src_ip = random.choice(["192.168.1.50", "192.168.1.80", "192.168.1.95"])
        dst_ip = random.choice(EXTERNAL_ATTACKER_HOSTS)
        attack_type = "data_exfiltration"
        flow_type = "anomaly"

    elif scenario == "c2_beaconing":
        proto = "TCP"
        dst_port = random.choice([443, 8080, 8443, 4444])
        packets = random.randint(30, 180)
        bytes_sent = random.randint(8_000, 320_000)
        duration = round(random.uniform(0.8, 4.5), 3)
        src_ip = random.choice(["192.168.1.75", "192.168.1.76", "192.168.1.112"])
        dst_ip = random.choice(C2_HOSTS)
        attack_type = "malware_command_control"
        flow_type = "anomaly"

    elif scenario == "multi_vector":
        sub_scenario = random.choice(["port_scan", "ddos", "data_exfiltration", "ssh_brute_force"])
        payload, gt = build_synthetic_flow(sub_scenario)
        gt["parent_scenario"] = "multi_vector"
        return payload, gt

    elif scenario == "stealth_anomaly":
        proto = "TCP"
        dst_port = random.choice([443, 4444, 9443, 5555])
        packets = random.randint(15, 110)
        bytes_sent = random.randint(140_000, 3_800_000)
        duration = round(random.uniform(0.08, 0.45), 3)
        src_ip = random.choice(["198.18.0.77", "198.18.0.88", "10.99.0.14"])
        dst_ip = random.choice(["192.168.1.210", "192.168.1.215"])
        attack_type = "zero_day"
        flow_type = "anomaly"

    else:
        raise ValueError(f"Cannot build flow for scenario '{scenario}'")

    capture_payload = {
        "packets": packets,
        "bytes": bytes_sent,
        "duration": duration,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": _rand_ephemeral_port(),
        "dst_port": dst_port,
        "protocol": proto,
        "attack_type": attack_type,
        "packet_count": packets,
        "bytes_sent": bytes_sent,
        "bytes_received": max(64, bytes_sent // 2),
        "flow_type": flow_type,
        "event_source": "demo_simulator",
        "timestamp": utc_now_iso(),
    }

    ground_truth_record = {
        "scenario": scenario,
        "canonical_category": scenario,
        "attack_type": attack_type,
        "is_malicious": flow_type != "normal",
        "label": "malicious" if flow_type != "normal" else "benign",
    }
    return capture_payload, ground_truth_record


class DemoTrafficSimulator:
    """Thread-safe controllable synthetic traffic simulator."""

    def __init__(self, default_capture_url: str = CAPTURE_URL, max_history: int = 500):
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()  # set = running, clear = paused
        self._pause_event.set()
        self._worker: threading.Thread | None = None
        self.default_capture_url = default_capture_url
        self.max_history = max_history
        self._init_session_state()

    def _init_session_state(self):
        self.state = "Idle"
        self.session_id = None
        self.scenario = "mixed"
        self.mode = "mixed"
        self.speed = "medium"
        self.events_per_sec = round(1.0 / SPEED_INTERVALS["medium"], 2)
        self.interval_sec = SPEED_INTERVALS["medium"]
        self.duration_seconds = None
        self.capture_url = self.default_capture_url
        self.started_at = None
        self.ended_at = None
        self._start_mono = None
        self._seq = 0
        self.counters = {
            "events_generated": 0,
            "benign_events": 0,
            "malicious_events": 0,
            "delivered_events": 0,
            "failed_events": 0,
            "category_counts": {},
        }
        self.events_log = []

    def start(self, config: dict | None = None) -> tuple[int, dict]:
        cfg = config or {}
        with self._lock:
            if self.state in ("Running", "Paused"):
                return 409, {
                    "status": "error",
                    "code": "ALREADY_RUNNING",
                    "message": f"Simulation is already {self.state}. Stop or reset it first.",
                    "data": self.get_status(),
                }

            scenario = normalize_scenario(cfg.get("scenario", "mixed"))
            mode = (cfg.get("mode") or ("mixed" if scenario == "mixed" else "single")).strip().lower()
            if mode not in ("single", "mixed"):
                raise ValueError("mode must be 'single' or 'mixed'")
            if scenario == "mixed":
                mode = "mixed"

            speed = (cfg.get("speed") or "medium").strip().lower()
            if speed not in SPEED_INTERVALS:
                raise ValueError("speed must be 'low', 'medium', or 'high'")

            eps = cfg.get("events_per_sec")
            if eps is not None:
                eps_val = max(0.2, min(20.0, float(eps)))
                interval = 1.0 / eps_val
            else:
                interval = SPEED_INTERVALS[speed]
                eps_val = round(1.0 / interval, 2)

            dur = cfg.get("duration_seconds")
            duration_seconds = int(dur) if dur not in (None, "", 0, "0") else None
            if duration_seconds is not None and duration_seconds < 1:
                raise ValueError("duration_seconds must be >= 1 or null")

            capture_url = cfg.get("capture_url") or self.default_capture_url

            self._init_session_state()
            self.state = "Running"
            self.session_id = f"demo-sess-{uuid.uuid4().hex[:10]}"
            self.scenario = scenario
            self.mode = mode
            self.speed = speed
            self.events_per_sec = eps_val
            self.interval_sec = interval
            self.duration_seconds = duration_seconds
            self.capture_url = capture_url
            self.started_at = utc_now_iso()
            self._start_mono = time.monotonic()

            self._stop_event.clear()
            self._pause_event.set()
            self._worker = threading.Thread(target=self._run_loop, name="demo-sim-worker", daemon=True)
            self._worker.start()

            return 200, {"status": "success", "message": "Demo simulation started", "data": self.get_status()}

    def pause(self) -> tuple[int, dict]:
        with self._lock:
            if self.state != "Running":
                return 409, {
                    "status": "error",
                    "code": "INVALID_STATE",
                    "message": f"Cannot pause when state is {self.state}",
                    "data": self.get_status(),
                }
            self.state = "Paused"
            self._pause_event.clear()
            return 200, {"status": "success", "message": "Demo simulation paused", "data": self.get_status()}

    def resume(self) -> tuple[int, dict]:
        with self._lock:
            if self.state != "Paused":
                return 409, {
                    "status": "error",
                    "code": "INVALID_STATE",
                    "message": f"Cannot resume when state is {self.state}",
                    "data": self.get_status(),
                }
            self.state = "Running"
            self._pause_event.set()
            return 200, {"status": "success", "message": "Demo simulation resumed", "data": self.get_status()}

    def stop(self) -> tuple[int, dict]:
        worker = None
        with self._lock:
            if self.state in ("Idle", "Stopped", "Completed"):
                return 200, {"status": "success", "message": f"Simulation already {self.state}", "data": self.get_status()}
            self._stop_event.set()
            self._pause_event.set()
            self.state = "Stopped"
            self.ended_at = utc_now_iso()
            worker = self._worker
        if worker and worker.is_alive() and worker is not threading.current_thread():
            worker.join(timeout=3.0)
        return 200, {"status": "success", "message": "Demo simulation stopped", "data": self.get_status()}

    def reset(self) -> tuple[int, dict]:
        self.stop()
        with self._lock:
            self._init_session_state()
            return 200, {"status": "success", "message": "Demo simulation reset to Idle", "data": self.get_status()}

    def _pick_step_scenario(self) -> str:
        with self._lock:
            mode = self.mode
            scenario = self.scenario
        if mode == "mixed" or scenario == "mixed":
            # ~35% normal traffic, ~65% distributed across malicious categories
            if random.random() < 0.35:
                return "normal_traffic"
            if scenario != "mixed" and scenario != "normal_traffic":
                return scenario if random.random() < 0.65 else random.choice(MALICIOUS_SCENARIOS)
            return random.choice(MALICIOUS_SCENARIOS)
        return scenario

    def _deliver_to_capture(self, capture_url: str, payload: dict) -> tuple[bool, int | None, dict | str]:
        try:
            body = json.dumps(payload).encode("utf-8")
            req = Request(capture_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=5) as resp:
                raw = resp.read().decode("utf-8", "replace")
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = raw
                return True, resp.status, parsed
        except HTTPError as err:
            return False, err.code, str(err)
        except (URLError, Exception) as err:
            return False, None, str(err)

    def _run_loop(self):
        while not self._stop_event.is_set():
            # Wait while paused
            if not self._pause_event.wait(timeout=0.2):
                continue
            if self._stop_event.is_set():
                break

            with self._lock:
                if self.duration_seconds is not None and self._start_mono is not None:
                    if (time.monotonic() - self._start_mono) >= self.duration_seconds:
                        self.state = "Completed"
                        self.ended_at = utc_now_iso()
                        break
                session_id = self.session_id
                capture_url = self.capture_url
                interval = self.interval_sec

            step_scenario = self._pick_step_scenario()
            payload, gt = build_synthetic_flow(step_scenario)

            with self._lock:
                self._seq += 1
                flow_id = f"demo-{session_id[-6:]}-{self._seq:05d}-{uuid.uuid4().hex[:4]}"

            # Attach demo session metadata without exposing `ground_truth` to ML inference
            payload["flow_id"] = flow_id
            payload["session_id"] = session_id
            payload["event_source"] = "demo_simulator"

            ok, status_code, resp_body = self._deliver_to_capture(capture_url, payload)

            with self._lock:
                self.counters["events_generated"] += 1
                if gt["is_malicious"]:
                    self.counters["malicious_events"] += 1
                else:
                    self.counters["benign_events"] += 1
                if ok:
                    self.counters["delivered_events"] += 1
                else:
                    self.counters["failed_events"] += 1
                cat = gt["canonical_category"]
                self.counters["category_counts"][cat] = self.counters["category_counts"].get(cat, 0) + 1

                self.events_log.append({
                    "flow_id": flow_id,
                    "session_id": session_id,
                    "timestamp": payload["timestamp"],
                    "src_ip": payload["src_ip"],
                    "dst_ip": payload["dst_ip"],
                    "src_port": payload["src_port"],
                    "dst_port": payload["dst_port"],
                    "protocol": payload["protocol"],
                    "packets": payload["packets"],
                    "bytes": payload["bytes"],
                    "duration": payload["duration"],
                    "attack_type": payload["attack_type"],
                    "event_source": "demo_simulator",
                    "delivered": ok,
                    "capture_status": status_code,
                    "capture_response": resp_body if ok else {"error": resp_body},
                    "ground_truth": gt,
                })
                if len(self.events_log) > self.max_history:
                    self.events_log = self.events_log[-self.max_history:]

            self._stop_event.wait(timeout=interval)

    def get_status(self) -> dict:
        with self._lock:
            elapsed = 0.0
            if self._start_mono is not None:
                if self.state in ("Running", "Paused"):
                    elapsed = round(time.monotonic() - self._start_mono, 2)
                elif self.started_at and self.ended_at:
                    try:
                        t0 = datetime.fromisoformat(self.started_at)
                        t1 = datetime.fromisoformat(self.ended_at)
                        elapsed = round(max(0.0, (t1 - t0).total_seconds()), 2)
                    except Exception:
                        elapsed = 0.0
            return {
                "state": self.state,
                "session_id": self.session_id,
                "scenario": self.scenario,
                "mode": self.mode,
                "speed": self.speed,
                "events_per_sec": self.events_per_sec,
                "duration_seconds": self.duration_seconds,
                "elapsed_seconds": elapsed,
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "capture_url": self.capture_url,
                "counters": {
                    "events_generated": self.counters["events_generated"],
                    "benign_events": self.counters["benign_events"],
                    "malicious_events": self.counters["malicious_events"],
                    "delivered_events": self.counters["delivered_events"],
                    "failed_events": self.counters["failed_events"],
                    "category_counts": dict(self.counters["category_counts"]),
                },
                "available_scenarios": VALID_SCENARIOS,
            }

    def get_summary(self) -> dict:
        with self._lock:
            st = self.get_status()
            return {
                "synthetic_demo_evaluation": True,
                "note": "Synthetic demo-session metrics only; ground_truth is isolated from ML inference.",
                "session_id": st["session_id"],
                "state": st["state"],
                "scenario": st["scenario"],
                "mode": st["mode"],
                "started_at": st["started_at"],
                "ended_at": st["ended_at"],
                "elapsed_seconds": st["elapsed_seconds"],
                "total_events_generated": st["counters"]["events_generated"],
                "benign_events": st["counters"]["benign_events"],
                "malicious_events": st["counters"]["malicious_events"],
                "delivered_events": st["counters"]["delivered_events"],
                "failed_events": st["counters"]["failed_events"],
                "category_breakdown": st["counters"]["category_counts"],
            }

    def get_events(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self.events_log[-max(1, min(limit, self.max_history)):])


def create_http_server(simulator: DemoTrafficSimulator, host: str = SIMULATOR_HOST, port: int = SIMULATOR_PORT) -> ThreadingHTTPServer:
    class SimulatorHandler(BaseHTTPRequestHandler):
        def _send_json(self, status_code: int, payload: dict):
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}

        def log_message(self, format, *args):
            return

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.end_headers()

        def do_GET(self):
            path_only = self.path.split("?", 1)[0]
            if path_only == "/health":
                st = simulator.get_status()
                self._send_json(200, {"status": "healthy", "state": st["state"], "session_id": st["session_id"]})
            elif path_only == "/status":
                self._send_json(200, {"status": "success", "data": simulator.get_status()})
            elif path_only == "/summary":
                self._send_json(200, {"status": "success", "data": simulator.get_summary()})
            elif path_only == "/events":
                limit_val = 500
                if "?" in self.path:
                    for part in self.path.split("?", 1)[1].split("&"):
                        if part.startswith("limit="):
                            try:
                                limit_val = int(part.split("=", 1)[1])
                            except ValueError:
                                limit_val = 500
                self._send_json(200, {"status": "success", "data": simulator.get_events(limit=limit_val)})
            else:
                self._send_json(404, {"status": "error", "message": "Not found"})

        def do_POST(self):
            path_only = self.path.split("?", 1)[0]
            try:
                body = self._read_json()
            except Exception as exc:
                self._send_json(400, {"status": "error", "message": f"Invalid JSON: {exc}"})
                return

            try:
                if path_only == "/start":
                    code, resp = simulator.start(body)
                elif path_only == "/pause":
                    code, resp = simulator.pause()
                elif path_only == "/resume":
                    code, resp = simulator.resume()
                elif path_only == "/stop":
                    code, resp = simulator.stop()
                elif path_only == "/reset":
                    code, resp = simulator.reset()
                else:
                    code, resp = 404, {"status": "error", "message": "Not found"}
            except ValueError as exc:
                code, resp = 400, {"status": "error", "message": str(exc)}
            self._send_json(code, resp)

    return ThreadingHTTPServer((host, port), SimulatorHandler)


def main():
    parser = argparse.ArgumentParser(description="Shadow Guard 2.0 Demo Traffic Simulator")
    parser.add_argument("--host", default=SIMULATOR_HOST)
    parser.add_argument("--port", type=int, default=SIMULATOR_PORT)
    parser.add_argument("--cli", action="store_true", help="Run a one-off mixed demo in CLI mode (explicit opt-in only)")
    args = parser.parse_args()

    simulator = DemoTrafficSimulator()

    if args.cli:
        print("[DemoSimulator] Starting explicit CLI mixed simulation (Ctrl+C to stop)...", flush=True)
        simulator.start({"scenario": "mixed", "mode": "mixed", "speed": "medium"})
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            simulator.stop()
            print(json.dumps(simulator.get_summary(), indent=2), flush=True)
        return

    server = create_http_server(simulator, host=args.host, port=args.port)
    print(f"[DemoSimulator] Listening on http://{args.host}:{args.port} (initial state: Idle)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        simulator.stop()
        server.shutdown()


if __name__ == "__main__":
    main()
