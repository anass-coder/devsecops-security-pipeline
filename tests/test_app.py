import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app as app_module


class AppTests(unittest.TestCase):
    def setUp(self):
        database_dir = tempfile.TemporaryDirectory()
        self.addCleanup(database_dir.cleanup)
        database_patch = patch.object(
            app_module, "DB_PATH", str(Path(database_dir.name) / "users.db")
        )
        database_patch.start()
        self.addCleanup(database_patch.stop)
        config_patch = patch.dict(
            app_module.app.config, {"TESTING": True, "DEBUG": False}
        )
        config_patch.start()
        self.addCleanup(config_patch.stop)
        app_module.init_db()
        self.client = app_module.app.test_client()

    def test_index(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["service"], "soc-test-app")

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_security_headers_on_success_and_errors(self):
        for path in ("/health", "/users/99999", "/missing-page"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
                policy = response.headers.get("Content-Security-Policy", "")
                self.assertIn("default-src 'none'", policy)
                self.assertIn("frame-ancestors 'none'", policy)

    def test_existing_user(self):
        response = self.client.get("/users/1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(), {"id": 1, "username": "alice", "role": "admin"}
        )

    def test_missing_user(self):
        response = self.client.get("/users/99999")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json(), {"error": "not found"})

    def test_valid_login(self):
        response = self.client.post(
            "/login", json={"username": "alice", "password": "password123"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "login ok")
        self.assertEqual(response.get_json()["user"]["username"], "alice")

    def test_invalid_login(self):
        response = self.client.post(
            "/login", json={"username": "alice", "password": "wrong"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"error": "invalid credentials"})

    def test_missing_credentials(self):
        response = self.client.post("/login", json={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(), {"error": "username and password required"}
        )


if __name__ == "__main__":
    unittest.main()
