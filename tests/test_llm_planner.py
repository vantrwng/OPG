"""
tests/test_llm_planner.py
=========================
Unit tests cho LLMPlanner (Ollama-only backend).
Không còn OpenAI/GitHub Models — tất cả mock qua OllamaClient.
"""
import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from llm_planner import LLMPlanner
from state_store import StateStore


# ── Fixture helper ─────────────────────────────────────────────────────────────

def make_planner_no_ollama() -> LLMPlanner:
    """Tạo LLMPlanner mà không kết nối Ollama (heuristic-only)."""
    with patch("llm_planner.OLLAMA_ENABLED", False):
        return LLMPlanner()


def make_planner_with_mock_ollama() -> tuple:
    """Tạo LLMPlanner với OllamaClient đã mock. Returns (planner, mock_client)."""
    mock_client = MagicMock()
    mock_client.ping.return_value = True
    with (
        patch("llm_planner.OLLAMA_ENABLED", True),
        patch("llm_planner.get_ollama_client", return_value=mock_client),
    ):
        planner = LLMPlanner()
    planner._ollama = mock_client
    return planner, mock_client


# ── TestInit ───────────────────────────────────────────────────────────────────

class TestLLMPlannerInit:

    def test_init_heuristic_only_when_ollama_disabled(self):
        """Khi OLLAMA_ENABLED=false → _ollama là None."""
        planner = make_planner_no_ollama()
        assert planner._ollama is None

    def test_init_with_ollama_connected(self):
        """Khi Ollama ping OK → _ollama được gán."""
        planner, mock_client = make_planner_with_mock_ollama()
        assert planner._ollama is mock_client

    def test_init_ollama_not_reachable(self):
        """Khi Ollama ping FAIL → _ollama là None, fallback heuristic."""
        mock_client = MagicMock()
        mock_client.ping.return_value = False
        with (
            patch("llm_planner.OLLAMA_ENABLED", True),
            patch("llm_planner.get_ollama_client", return_value=mock_client),
        ):
            planner = LLMPlanner()
        assert planner._ollama is None


# ── TestClassifyUnknownFields ──────────────────────────────────────────────────

class TestClassifyUnknownFields:

    def test_classify_success(self):
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = {
            "user_id":      "identity",
            "balance":      "finance",
            "session_key":  "auth/workflow",
            "metadata":     "unknown",
        }

        result = planner.classify_unknown_fields(
            ["user_id", "balance", "session_key", "metadata"]
        )

        assert result["user_id"]     == "identity"
        assert result["balance"]     == "finance"
        assert result["session_key"] == "auth/workflow"
        # Cache phải được cập nhật (trừ "unknown")
        assert planner._llm_cache["user_id"]    == "identity"
        assert "metadata" not in planner._llm_cache

    def test_classify_empty_list(self):
        planner = make_planner_no_ollama()
        assert planner.classify_unknown_fields([]) == {}

    def test_classify_no_ollama(self):
        planner = make_planner_no_ollama()
        assert planner.classify_unknown_fields(["user_id"]) == {}

    def test_classify_ollama_error_graceful(self):
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.side_effect = Exception("Timeout")
        result = planner.classify_unknown_fields(["user_id"])
        assert result == {}

    def test_classify_filters_invalid_categories(self):
        """LLM trả về category không hợp lệ phải bị lọc bỏ."""
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = {
            "user_id": "identity",
            "foo":     "invalid_category",  # ← không hợp lệ
        }
        result = planner.classify_unknown_fields(["user_id", "foo"])
        assert "user_id" in result
        assert "foo" not in result


# ── TestClusterIdentities ──────────────────────────────────────────────────────

class TestClusterIdentities:

    def test_cluster_success(self):
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = {
            "clusters": [
                ["user_id", "userId", "account_id"],
                ["vehicle_id"],
                ["order_id"],
            ]
        }

        result = planner.cluster_identities(
            ["user_id", "userId", "vehicle_id", "order_id"]
        )

        assert planner._identity_cluster_map["user_id"]    == 0
        assert planner._identity_cluster_map["userId"]     == 0
        assert planner._identity_cluster_map["vehicle_id"] == 1

    def test_cluster_no_ollama_fallback(self):
        """Khi không có Ollama → mỗi field thành 1 cluster riêng."""
        planner = make_planner_no_ollama()
        result = planner.cluster_identities(["user_id", "vehicle_id"])
        assert len(result) == 2
        assert result["user_id"] != result["vehicle_id"]

    def test_cluster_invalid_response_fallback(self):
        """LLM trả về dict không có 'clusters' → fallback 1-field."""
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = {"wrong_key": []}
        result = planner.cluster_identities(["user_id", "vehicle_id"])
        assert len(result) == 2


# ── TestGeneratePayload ────────────────────────────────────────────────────────

class TestGeneratePayload:

    def test_get_method_returns_empty(self):
        planner = make_planner_no_ollama()
        api_node = {"id": "getUser", "method": "GET", "path": "/users/{id}", "inputs": {}}
        payload, source = planner.generate_payload(api_node, StateStore())
        assert payload == {}
        assert source == "NONE"

    def test_delete_method_returns_empty(self):
        planner = make_planner_no_ollama()
        api_node = {"id": "deleteUser", "method": "DELETE", "path": "/users/{id}", "inputs": {}}
        payload, source = planner.generate_payload(api_node, StateStore())
        assert payload == {}
        assert source == "NONE"

    def test_post_with_ollama(self):
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = {
            "email":    "fuzz_abc123@test.com",
            "password": "Fuzz@Test1!",
            "name":     "Fuzzer Test",
        }

        api_node = {
            "id": "signupUser",
            "method": "POST",
            "path": "/identity/api/auth/signup",
            "inputs": {
                "email":    {"type": "string"},
                "password": {"type": "string"},
                "name":     {"type": "string"},
            },
        }
        payload, source = planner.generate_payload(api_node, StateStore())

        assert source == "OLLAMA_ARCHITECT"
        assert "email" in payload
        assert "password" in payload
        # CREATE endpoint → email phải được randomize bởi _randomize_volatile_fields
        assert "fuzz_" in payload["email"]

    def test_post_fallback_heuristic(self):
        planner = make_planner_no_ollama()
        api_node = {
            "id": "createUser",
            "method": "POST",
            "path": "/users",
            "inputs": {
                "email": {"type": "string"},
                "name":  {"type": "string"},
            },
        }
        payload, source = planner.generate_payload(api_node, StateStore())
        assert source == "HEURISTIC"
        assert "email" in payload
        assert "@" in payload["email"]

    def test_ollama_fail_falls_to_heuristic(self):
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = None  # Ollama fails

        api_node = {
            "id": "createItem",
            "method": "POST",
            "path": "/items",
            "inputs": {"title": {"type": "string"}},
        }
        payload, source = planner.generate_payload(api_node, StateStore())
        assert source == "HEURISTIC"
        assert "title" in payload

    def test_payload_cache_hit(self):
        """Cùng prompt → CACHE HIT, Ollama không được gọi lại."""
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = {"email": "fuzz_abc@test.com"}

        api_node = {
            "id": "createUser",
            "method": "POST",
            "path": "/users",
            "inputs": {"email": {"type": "string"}},
        }
        state = StateStore()

        planner.generate_payload(api_node, state)
        planner.generate_payload(api_node, state)  # 2nd call

        # Ollama chỉ được gọi 1 lần (lần 2 dùng cache)
        assert mock_ollama.architect.call_count == 1


# ── TestRepairPayload ──────────────────────────────────────────────────────────

class TestRepairPayload:

    def test_repair_success(self):
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = {"email": "new_unique@test.com"}

        api_node = {
            "id": "createUser",
            "method": "POST",
            "path": "/users",
            "inputs": {"email": {"type": "string"}},
        }
        result = planner.repair_payload(
            api_node, StateStore(),
            bad_payload={"email": "old@test.com"},
            error_response="Email already registered",
        )

        assert result is not None
        assert result["email"] == "new_unique@test.com"

    def test_repair_no_ollama_returns_none(self):
        planner = make_planner_no_ollama()
        result = planner.repair_payload(
            {"id": "x", "method": "POST", "inputs": {}},
            StateStore(), {}, "error"
        )
        assert result is None

    def test_repair_ollama_returns_none_graceful(self):
        planner, mock_ollama = make_planner_with_mock_ollama()
        mock_ollama.architect.return_value = None
        result = planner.repair_payload(
            {"id": "x", "method": "POST", "inputs": {}},
            StateStore(), {}, "error"
        )
        assert result is None


# ── TestHeuristicGenerate ──────────────────────────────────────────────────────

class TestHeuristicGenerate:

    def test_edge_deps_resolved(self):
        planner = make_planner_no_ollama()
        api_node = {
            "id": "updateVehicle",
            "method": "PUT",
            "path": "/vehicles/{vehicleId}",
            "inputs": {
                "vehicleId": {"type": "string", "original": "vehicleId"},
                "name":      {"type": "string", "original": "name"},
            },
        }
        state = StateStore()
        state.update("vehicleId", "veh_abc123")

        edge_deps = [{"producer_field": "vehicleId", "consumer_field": "vehicleId"}]
        payload = planner._heuristic_generate(api_node, state, edge_deps)

        assert payload["vehicleId"] == "veh_abc123"
        assert "name" in payload

    def test_state_match(self):
        planner = make_planner_no_ollama()
        api_node = {
            "id": "getOrders",
            "method": "POST",
            "path": "/orders",
            "inputs": {"userId": {"type": "string", "original": "userId"}},
        }
        state = StateStore()
        state.update("userId", "usr_42")

        payload = planner._heuristic_generate(api_node, state)
        assert payload["userId"] == "usr_42"

    def test_default_values(self):
        planner = make_planner_no_ollama()
        api_node = {
            "id": "createProduct",
            "method": "POST",
            "path": "/products",
            "inputs": {
                "price":  {"type": "number", "original": "price"},
                "active": {"type": "boolean", "original": "active"},
                "count":  {"type": "integer", "original": "count"},
            },
        }
        payload = planner._heuristic_generate(api_node, StateStore())
        assert payload["price"]  == 0.01
        assert payload["active"] is True
        assert payload["count"]  == 1


# ── TestRandomizeVolatileFields ────────────────────────────────────────────────

class TestRandomizeVolatileFields:

    def _make_node(self, path: str, op_id: str) -> dict:
        return {"id": op_id, "path": path, "method": "POST"}

    def test_create_always_fresh_email(self):
        node  = self._make_node("/auth/signup", "signupUser")
        state = StateStore()
        state.update("email", "old@example.com")
        payload = {"email": "any@example.com", "password": "Pass123!"}

        result = LLMPlanner._randomize_volatile_fields(payload, node, state)
        assert "fuzz_" in result["email"]
        assert result["email"] != "old@example.com"

    def test_auth_reuses_state_email(self):
        node  = self._make_node("/auth/login", "loginUser")
        state = StateStore()
        state.update("email", "user@example.com")
        state.update("password", "SecurePass!")
        payload = {"email": "wrong@example.com", "password": "wrong"}

        result = LLMPlanner._randomize_volatile_fields(payload, node, state)
        assert result["email"]    == "user@example.com"
        assert result["password"] == "SecurePass!"

    def test_nested_dict(self):
        node  = self._make_node("/orders", "createOrder")
        state = StateStore()
        payload = {"customer": {"email": "test@example.com"}}

        result = LLMPlanner._randomize_volatile_fields(payload, node, state)
        assert "fuzz_" in result["customer"]["email"]

    def test_nested_list_of_objects(self):
        node  = self._make_node("/bulk", "createBulk")
        state = StateStore()
        payload = {
            "items": [
                {"email": "a@example.com", "qty": 1},
                {"email": "b@example.com", "qty": 2},
            ]
        }
        result = LLMPlanner._randomize_volatile_fields(payload, node, state)
        for item in result["items"]:
            assert "fuzz_" in item["email"]
            assert item["qty"] in (1, 2)  # non-volatile giữ nguyên

    def test_non_volatile_fields_unchanged(self):
        node  = self._make_node("/items", "createItem")
        state = StateStore()
        payload = {"title": "My Product", "price": 9.99, "stock": 100}
        result = LLMPlanner._randomize_volatile_fields(payload, node, state)
        assert result["title"] == "My Product"
        assert result["price"] == 9.99
        assert result["stock"] == 100


# ── TestDefaultFuzzValue ───────────────────────────────────────────────────────

class TestDefaultFuzzValue:

    def test_integer(self):
        assert LLMPlanner._default_fuzz_value("integer", "count") == 1

    def test_number(self):
        assert LLMPlanner._default_fuzz_value("number", "price") == 0.01

    def test_boolean(self):
        assert LLMPlanner._default_fuzz_value("boolean", "active") is True

    def test_email_field(self):
        v = LLMPlanner._default_fuzz_value("string", "email_address")
        assert "@" in v and "test.com" in v

    def test_password_field(self):
        v = LLMPlanner._default_fuzz_value("string", "password")
        assert "Fuzz" in v or "@" in v

    def test_generic_string(self):
        assert LLMPlanner._default_fuzz_value("string", "title") == "fuzz_test_value"


# ── TestNorm ───────────────────────────────────────────────────────────────────

class TestNorm:
    def test_underscore(self):
        assert LLMPlanner._norm("user_id") == "userid"

    def test_camel_case(self):
        assert LLMPlanner._norm("userId") == "userid"

    def test_dot_notation(self):
        assert LLMPlanner._norm("auth.token") == "authtoken"

    def test_lowercase(self):
        assert LLMPlanner._norm("email") == "email"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
