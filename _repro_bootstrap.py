"""Temporary reproduction harness for the signup/signin credential mismatch."""
import json
import logging
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

logging.basicConfig(level=logging.INFO, format="%(message)s")

USERS = {}
SEEN = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode()
        if self.path.rstrip("/") == "/api/v1/users":
            payload = json.loads(raw or "{}")
            SEEN.append(("signup", payload))
            username = payload.get("username")
            USERS[username] = payload.get("password")
            return self._send(201, {
                "id": str(uuid.uuid4()), "username": username, "profile_image": None,
                "store_api_key": None, "is_active": False, "is_superuser": False,
                "create_at": "2026-09-06T00:00:00", "updated_at": "2026-09-06T00:00:00",
                "last_login_at": None, "optins": payload.get("optins"),
            })
        if self.path == "/api/v1/login":
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            SEEN.append(("login", form))
            if form.get("username") not in USERS:
                return self._send(401, {"detail": "Incorrect username or password"})
            return self._send(400, {"detail": "Waiting for approval"})
        return self._send(404, {"detail": "not found"})

    def do_GET(self):
        return self._send(401, {"detail": "Not authenticated"})


def main():
    server = HTTPServer(("127.0.0.1", 7861), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    from spec_parser import SpecParser
    from llm_planner import LLMPlanner
    from runtime_executor import RequestExecutor
    from actor_bootstrapper import ActorBootstrapper

    parser = SpecParser("_repro_spec.json", overlay_path="langflow_bola_overlay.json")
    operations = parser.extract_operations()
    planner = LLMPlanner()
    executor = RequestExecutor("http://127.0.0.1:7861", planner)
    bootstrapper = ActorBootstrapper(operations, executor,
                                     identity_config=parser.get_bola_config())
    signup, login = bootstrapper.discover_auth_operations()
    print("DISCOVERED signup:", signup and signup["id"])
    print("DISCOVERED login :", login and login["id"])
    print("LOGIN INPUTS     :", json.dumps(login.get("inputs", {}), ensure_ascii=False))

    result = bootstrapper.bootstrap(base_state={
        "actor_id": "owner_a", "actor_role": "user",
        "auth_header_name": "Authorization", "auth_header_prefix": "",
        "email": "seed@example.test", "password": "SeedPass@123",
    })
    print("\nBOOTSTRAP success:", result.success, "errors:", result.errors)
    for stage, payload in SEEN:
        print(f"WIRE {stage}: {json.dumps(payload, ensure_ascii=False)}")
    server.shutdown()


if __name__ == "__main__":
    main()
