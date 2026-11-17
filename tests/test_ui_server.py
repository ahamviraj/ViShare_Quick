import http.client
import json
import threading
import unittest
from unittest.mock import patch
from urllib.parse import quote

from vishare_quick.desktop import WindowUnavailable
from vishare_quick.ui_server import create_server, run_ui


class FakeService:
    def __init__(self):
        self.phase = "idle"
        self.calls = []

    def snapshot(self):
        return {
            "version": "alpha_0.8",
            "phase": self.phase,
            "active": self.phase == "advertising",
            "advertising": self.phase == "advertising",
            "device_name": "ViShare Quick",
            "download_dir": "C:/Downloads",
            "endpoint": None,
            "pin": None,
            "request": None,
            "progress": None,
            "result": None,
            "error": None,
            "events": [],
        }

    def start(self):
        self.calls.append(("start",))
        self.phase = "advertising"
        return True

    def stop(self):
        self.calls.append(("stop",))
        self.phase = "idle"
        return True

    def resolve_pin(self, match):
        self.calls.append(("pin", match))
        return True

    def resolve_consent(self, accept):
        self.calls.append(("consent", accept))
        return True

    def cancel_transfer(self):
        self.calls.append(("cancel",))
        return True

    def dismiss_result(self):
        self.calls.append(("dismiss",))

    def set_device_name(self, name):
        self.calls.append(("name", name))
        return True

    def open_download_folder(self):
        self.calls.append(("open",))
        return True


class FakeSendService:
    def __init__(self):
        self.calls = []
        self.uploads = []
        self.phase = "idle"

    def snapshot(self):
        return {
            "version": "alpha_0.8",
            "phase": self.phase,
            "active": False,
            "discovering": False,
            "device_name": "ViShare Quick",
            "files": [],
            "total_size": 0,
            "peers": [],
            "peer": None,
            "pin": None,
            "progress": None,
            "result": None,
            "error": None,
            "events": [],
        }

    def add_upload(self, source, filename, length):
        data = source.read(length)
        self.uploads.append((filename, length, len(data)))
        if filename == "bad":
            raise ValueError("That file name cannot be used.")
        return {"id": 1, "name": filename, "size": length}

    def start_discovery(self):
        self.calls.append(("discover",))
        return True

    def start_send(self, peer_key=None):
        self.calls.append(("start", peer_key))
        return True

    def resolve_pin(self, match):
        self.calls.append(("pin", match))
        return True

    def cancel(self):
        self.calls.append(("cancel",))
        return True

    def clear_files(self):
        self.calls.append(("clear",))
        return True

    def dismiss_result(self):
        self.calls.append(("dismiss",))

    def reset(self):
        self.calls.append(("reset",))
        return True

    def stop(self):
        self.calls.append(("stop",))

    def set_device_name(self, name):
        self.calls.append(("name", name))
        return True


class TestUiServer(unittest.TestCase):
    def setUp(self):
        self.fake = FakeService()
        self.server = create_server(self.fake, port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)

    def request(
        self, method, path, body=None, token=True, host=None, token_value=None
    ):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5.0
        )
        headers = {}
        if token:
            headers["X-ViShare-Token"] = (
                self.server.token if token_value is None else token_value
            )
        if host is not None:
            headers["Host"] = host
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        data = response.read()
        status = response.status
        response_headers = dict(response.getheaders())
        connection.close()
        return status, response_headers, data

    def test_index_is_token_stamped_and_locked_down(self):
        status, headers, body = self.request("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        text = body.decode("utf-8")
        self.assertIn(self.server.token, text)
        self.assertNotIn("__VISHARE_TOKEN__", text)
        self.assertIn("alpha_0.8", text)

    def test_state_requires_token_and_allows_loopback_hosts(self):
        status, _, _ = self.request("GET", "/api/state", token=False)
        self.assertEqual(status, 401)

        status, _, body = self.request(
            "GET", "/api/state", token=True, host=f"localhost:{self.port}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["phase"], "idle")

        status, _, _ = self.request(
            "GET", "/api/state", token=True, host="attacker.example"
        )
        self.assertEqual(status, 403)

    def test_post_actions_are_token_protected_and_dispatched(self):
        status, headers, _ = self.request("POST", "/api/start", {}, token=False)
        self.assertEqual(status, 401)
        self.assertEqual(headers.get("Connection"), "close")
        self.assertEqual(self.fake.calls, [])

        cases = (
            ("/api/start", {}, ("start",)),
            ("/api/stop", {}, ("stop",)),
            ("/api/pin", {"match": True}, ("pin", True)),
            ("/api/consent", {"accept": False}, ("consent", False)),
            ("/api/cancel", {}, ("cancel",)),
            ("/api/dismiss", {}, ("dismiss",)),
            ("/api/device-name", {"name": "Desk"}, ("name", "Desk")),
            ("/api/open-downloads", {}, ("open",)),
        )
        for path, body, expected in cases:
            with self.subTest(path=path):
                self.fake.calls.clear()
                status, _, payload = self.request("POST", path, body)
                self.assertEqual(status, 200)
                self.assertEqual(self.fake.calls, [expected])
                self.assertTrue(json.loads(payload)["ok"])
                self.assertIn("state", json.loads(payload))

    def test_invalid_boolean_is_rejected_without_dispatch(self):
        status, _, _ = self.request("POST", "/api/pin", {"match": "yes"})
        self.assertEqual(status, 400)
        self.assertEqual(self.fake.calls, [])

    def test_non_ascii_token_is_rejected_without_an_error(self):
        status, _, _ = self.request(
            "GET", "/api/state", token_value="t\u00e9st"
        )
        self.assertEqual(status, 401)

    def test_static_assets_are_served_without_token(self):
        status, headers, body = self.request(
            "GET", "/styles/common.css", token=False
        )
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers["Content-Type"])
        self.assertIn(b"--accent", body)

        status, headers, body = self.request("GET", "/app.js", token=False)
        self.assertEqual(status, 200)
        self.assertIn("text/javascript", headers["Content-Type"])
        self.assertIn(b"vishare-token", body)

        status, headers, body = self.request(
            "GET", "/assets/VarelaRound-Regular.ttf", token=False
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "font/ttf")
        self.assertGreater(len(body), 1000)

    def test_every_interface_page_is_token_stamped(self):
        for name in (
            "index.html",
            "receive-main.html",
            "receive-request.html",
            "receive-receiving.html",
            "receive-received.html",
            "send-send.html",
            "send-sending.html",
            "send-failed.html",
            "settings.html",
            "under-construction.html",
        ):
            with self.subTest(page=name):
                status, headers, body = self.request("GET", f"/{name}", token=False)
                self.assertEqual(status, 200)
                self.assertIn("text/html", headers["Content-Type"])
                text = body.decode("utf-8")
                self.assertIn(self.server.token, text)
                self.assertNotIn("__VISHARE_TOKEN__", text)
                self.assertIn("alpha_0.8", text)

    def test_path_traversal_is_not_served(self):
        for path in (
            "/assets/../app.js",
            "/assets/%2e%2e%2fapp.js",
            "/assets/sub/app.js",
            "/styles/../app.js",
            "/styles/sub/page.css",
            "/assets/sub/app.exe",
        ):
            with self.subTest(path=path):
                status, _, _ = self.request("GET", path, token=False)
                self.assertEqual(status, 404)

    def test_shutdown_stops_the_service(self):
        status, _, _ = self.request("POST", "/api/shutdown", {})
        self.assertEqual(status, 200)
        self.thread.join(timeout=3.0)
        self.assertFalse(self.thread.is_alive())
        self.assertTrue(self.server.stop_event.wait(timeout=3.0))
        self.assertEqual(self.fake.calls, [("stop",)])


class TestSendUiServer(unittest.TestCase):
    def setUp(self):
        self.receive = FakeService()
        self.send = FakeSendService()
        self.server = create_server(
            self.receive, send_service=self.send, port=0
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)

    def request(self, path, body=None, token=True):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5.0
        )
        headers = {}
        if token:
            headers["X-ViShare-Token"] = self.server.token
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request("POST", path, body=payload, headers=headers)
        response = connection.getresponse()
        data = response.read()
        status = response.status
        response_headers = dict(response.getheaders())
        connection.close()
        return status, response_headers, data

    def upload(self, name, data, *, token=True, content_type="application/octet-stream"):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5.0
        )
        headers = {
            "X-ViShare-Filename": quote(name, safe=""),
            "Content-Type": content_type,
        }
        if token:
            headers["X-ViShare-Token"] = self.server.token
        connection.request("POST", "/api/send/add-file", body=data, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        response_headers = dict(response.getheaders())
        connection.close()
        return status, response_headers, payload

    def test_state_includes_send_snapshot(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5.0
        )
        connection.request(
            "GET",
            "/api/state",
            headers={"X-ViShare-Token": self.server.token},
        )
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertEqual(body["send"]["phase"], "idle")

    def test_upload_streams_to_send_service(self):
        status, _, payload = self.upload("hello world.txt", b"abc")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["ok"])
        self.assertEqual(self.send.uploads, [("hello world.txt", 3, 3)])

    def test_upload_rejections_are_closed_and_token_protected(self):
        status, _, _ = self.upload("hello.txt", b"abc", token=False)
        self.assertEqual(status, 401)
        self.assertEqual(self.send.uploads, [])

        status, _, _ = self.upload(
            "hello.txt", b"abc", content_type="application/json"
        )
        self.assertEqual(status, 415)
        self.assertEqual(self.send.uploads, [])

        status, headers, payload = self.upload("bad", b"abc")
        self.assertEqual(status, 409)
        self.assertEqual(headers.get("Connection"), "close")
        self.assertIn("file name", json.loads(payload)["error"])

    def test_send_actions_are_dispatched(self):
        cases = (
            ("/api/send/discover", {}, ("discover",)),
            ("/api/send/start", {"peer": "10.0.0.2:1234"}, ("start", "10.0.0.2:1234")),
            ("/api/send/pin", {"match": True}, ("pin", True)),
            ("/api/send/cancel", {}, ("cancel",)),
            ("/api/send/clear-files", {}, ("clear",)),
            ("/api/send/dismiss", {}, ("dismiss",)),
            ("/api/send/reset", {}, ("reset",)),
        )
        for path, body, expected in cases:
            with self.subTest(path=path):
                self.send.calls.clear()
                status, _, payload = self.request(path, body)
                self.assertEqual(status, 200)
                self.assertEqual(self.send.calls, [expected])
                self.assertTrue(json.loads(payload)["ok"])

    def test_send_start_rejects_non_string_peer(self):
        status, _, _ = self.request("/api/send/start", {"peer": 5})
        self.assertEqual(status, 400)
        self.assertEqual(self.send.calls, [])


class FakeRunReceiveService:
    def __init__(self, download_dir, device_name):
        self.download_dir = download_dir
        self.device_name = device_name
        self.stopped = False

    def stop(self):
        self.stopped = True


class FakeRunSendService:
    def __init__(self, device_name):
        self.device_name = device_name
        self.stopped = False

    def stop(self):
        self.stopped = True


class FakeRunServer:
    last = None

    def __init__(self, service, send_service, port):
        self.server_address = ("127.0.0.1", 12345)
        self.shutdown_called = False
        self.closed = False
        FakeRunServer.last = self

    def serve_forever(self, poll_interval=0.5):
        return None

    def shutdown(self):
        self.shutdown_called = True

    def server_close(self):
        self.closed = True


class TestRunUiLifecycle(unittest.TestCase):
    @patch("vishare_quick.ui_server.create_server", FakeRunServer)
    @patch("vishare_quick.ui_server.SendService", FakeRunSendService)
    @patch("vishare_quick.ui_server.ReceiveService", FakeRunReceiveService)
    @patch("vishare_quick.desktop.run_app_window")
    def test_defaults_to_the_app_window_and_cleans_up(self, window):
        result = run_ui(download_dir="C:/Downloads")

        self.assertEqual(result, 0)
        window.assert_called_once()
        self.assertEqual(window.call_args.args[1], "http://127.0.0.1:12345/")
        self.assertTrue(FakeRunServer.last.shutdown_called)
        self.assertTrue(FakeRunServer.last.closed)

    @patch("vishare_quick.ui_server.create_server", FakeRunServer)
    @patch("vishare_quick.ui_server.SendService", FakeRunSendService)
    @patch("vishare_quick.ui_server.ReceiveService", FakeRunReceiveService)
    @patch("vishare_quick.ui_server.webbrowser.open")
    @patch(
        "vishare_quick.desktop.run_app_window",
        side_effect=WindowUnavailable("no backend"),
    )
    def test_falls_back_to_the_browser_when_no_window_is_available(
        self, window, browser_open
    ):
        result = run_ui(download_dir="C:/Downloads")

        self.assertEqual(result, 0)
        browser_open.assert_called_once_with("http://127.0.0.1:12345/")
        self.assertTrue(FakeRunServer.last.shutdown_called)


if __name__ == "__main__":
    unittest.main()
