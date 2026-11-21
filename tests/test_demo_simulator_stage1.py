import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import auto_demo


class _CaptureSink:
    def __init__(self):
        self.received = []
        self.lock = threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw = self.rfile.read(length).decode("utf-8")
                payload = json.loads(raw)
                with sink.lock:
                    sink.received.append(payload)
                resp = json.dumps({"message": "ok", "event_id": payload.get("flow_id")}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/capture"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _http_json(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


class TestDemoSimulatorStage1(unittest.TestCase):
    def setUp(self):
        self.sink = _CaptureSink()
        self.sim = auto_demo.DemoTrafficSimulator(default_capture_url=self.sink.url)
        self.http = auto_demo.create_http_server(self.sim, host="127.0.0.1", port=0)
        self.port = self.http.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.sim.stop()
        self.http.shutdown()
        self.http.server_close()
        self.sink.close()

    def test_01_starts_idle_with_zero_traffic(self):
        time.sleep(0.3)
        code, st = _http_json("GET", f"{self.base}/status")
        self.assertEqual(code, 200)
        self.assertEqual(st["data"]["state"], "Idle")
        self.assertEqual(st["data"]["counters"]["events_generated"], 0)
        self.assertEqual(len(self.sink.received), 0)

    def test_02_start_pause_resume_stop_reset_and_duplicate_guard(self):
        # Start
        code, res = _http_json("POST", f"{self.base}/start", {"scenario": "mixed", "speed": "high"})
        self.assertEqual(code, 200)
        self.assertEqual(res["data"]["state"], "Running")

        # Duplicate start rejected with 409
        code_dup, res_dup = _http_json("POST", f"{self.base}/start", {"scenario": "port_scan"})
        self.assertEqual(code_dup, 409)
        self.assertEqual(res_dup["code"], "ALREADY_RUNNING")

        time.sleep(0.45)
        self.assertGreaterEqual(len(self.sink.received), 2)

        # Verify schema + strict isolation of ground_truth from /capture payload
        for ev in self.sink.received:
            self.assertEqual(ev["event_source"], "demo_simulator")
            self.assertIn("flow_id", ev)
            self.assertIn("session_id", ev)
            self.assertIn("src_port", ev)
            self.assertIn("dst_port", ev)
            self.assertNotIn("ground_truth", ev)

        # Pause
        code_p, res_p = _http_json("POST", f"{self.base}/pause", {})
        self.assertEqual(code_p, 200)
        self.assertEqual(res_p["data"]["state"], "Paused")
        count_at_pause = len(self.sink.received)
        time.sleep(0.35)
        self.assertEqual(len(self.sink.received), count_at_pause)

        # Duplicate start while Paused also rejected
        code_dup2, _ = _http_json("POST", f"{self.base}/start", {"scenario": "ddos"})
        self.assertEqual(code_dup2, 409)

        # Resume
        code_r, res_r = _http_json("POST", f"{self.base}/resume", {})
        self.assertEqual(code_r, 200)
        self.assertEqual(res_r["data"]["state"], "Running")
        time.sleep(0.35)
        self.assertGreater(len(self.sink.received), count_at_pause)

        # Stop
        code_s, res_s = _http_json("POST", f"{self.base}/stop", {})
        self.assertEqual(code_s, 200)
        self.assertEqual(res_s["data"]["state"], "Stopped")

        # Summary available after stop
        code_sum, res_sum = _http_json("GET", f"{self.base}/summary")
        self.assertEqual(code_sum, 200)
        self.assertTrue(res_sum["data"]["synthetic_demo_evaluation"])
        self.assertGreater(res_sum["data"]["total_events_generated"], 0)

        # Reset
        code_rst, res_rst = _http_json("POST", f"{self.base}/reset", {})
        self.assertEqual(code_rst, 200)
        self.assertEqual(res_rst["data"]["state"], "Idle")
        self.assertEqual(res_rst["data"]["counters"]["events_generated"], 0)

    def test_03_duration_auto_completes(self):
        code, _ = _http_json("POST", f"{self.base}/start", {
            "scenario": "port_scan",
            "mode": "single",
            "speed": "high",
            "duration_seconds": 1,
        })
        self.assertEqual(code, 200)
        time.sleep(1.35)
        _, st = _http_json("GET", f"{self.base}/status")
        self.assertEqual(st["data"]["state"], "Completed")

    def test_04_all_scenarios_generate_valid_isolated_flows(self):
        for scen in auto_demo.VALID_SCENARIOS:
            if scen == "mixed":
                continue
            payload, gt = auto_demo.build_synthetic_flow(scen)
            self.assertNotIn("ground_truth", payload)
            self.assertEqual(payload["event_source"], "demo_simulator")
            self.assertIn("is_malicious", gt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
