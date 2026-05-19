"""
Unit tests cho LLMPlanner class
"""
import pytest
import json
import os
from unittest.mock import MagicMock, patch, Mock
from llm_planner import LLMPlanner
from state_store import StateStore


class TestLLMPlannerInit:
    """Test LLMPlanner initialization"""
    
    def test_init_with_openai_key(self):
        """Test initialization với OpenAI API key"""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-123"}):
            planner = LLMPlanner()
            assert planner.model == "gpt-5.5"
            assert planner.endpoint == "https://codex.xirothedev.io.vn/v1"
            assert planner._client is not None
    
    def test_init_with_github_token(self):
        """Test initialization với GitHub token fallback"""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp-test-123"}, clear=True):
            with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
                planner = LLMPlanner()
                assert planner.model == "gpt-4o-mini"
                assert planner.endpoint == "https://models.github.ai/inference"
    
    def test_init_without_api_key(self):
        """Test initialization mà không có API key"""
        with patch.dict(os.environ, {}, clear=True):
            with patch("llm_planner.load_dotenv"):
                planner = LLMPlanner()
                assert planner._client is None
                assert planner.endpoint == ""
                assert planner.model == ""


class TestClassifyUnknownFields:
    """Test LLM field classification"""
    
    def test_classify_unknown_fields_success(self):
        """Test phân loại field thành công"""
        planner = LLMPlanner()
        
        # Mock LLM response
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "user_id": "identity",
            "balance": "finance",
            "session_token": "auth/workflow",
            "metadata": "unknown"
        })
        
        with patch.object(planner, '_client') as mock_client:
            mock_client.chat.completions.create.return_value = mock_response
            planner._client = mock_client
            
            result = planner.classify_unknown_fields(
                ["user_id", "balance", "session_token", "metadata"]
            )
            
            assert result["user_id"] == "identity"
            assert result["balance"] == "finance"
            assert result["session_token"] == "auth/workflow"
            # Check cache
            assert planner._llm_cache["user_id"] == "identity"
    
    def test_classify_unknown_fields_empty_list(self):
        """Test với empty list"""
        planner = LLMPlanner()
        result = planner.classify_unknown_fields([])
        assert result == {}
    
    def test_classify_unknown_fields_no_client(self):
        """Test khi không có LLM client"""
        planner = LLMPlanner()
        planner._client = None
        result = planner.classify_unknown_fields(["user_id"])
        assert result == {}
    
    def test_classify_unknown_fields_rate_limit(self):
        """Test xử lý rate limit gracefully"""
        planner = LLMPlanner()
        
        with patch.object(planner, '_client') as mock_client:
            mock_client.chat.completions.create.side_effect = Exception("429 rate limit")
            planner._client = mock_client
            
            result = planner.classify_unknown_fields(["user_id"])
            # Phải fallback, không crash
            assert isinstance(result, dict)


class TestClusterIdentities:
    """Test identity clustering"""
    
    def test_cluster_identities_success(self):
        """Test gom nhóm identity field thành công"""
        planner = LLMPlanner()
        
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "clusters": [
                ["user_id", "userId", "account_id"],
                ["vehicle_id", "car_id"],
                ["order_id", "order_no"]
            ]
        })
        
        with patch.object(planner, '_client') as mock_client:
            mock_client.chat.completions.create.return_value = mock_response
            planner._client = mock_client
            
            result = planner.cluster_identities(
                ["user_id", "userId", "vehicle_id", "order_id"]
            )
            
            # Verify clusters
            assert planner._identity_cluster_map["user_id"] == 0
            assert planner._identity_cluster_map["userid"] == 0  # normalized
            assert planner._identity_cluster_map["vehicle_id"] == 1
    
    def test_cluster_identities_no_client(self):
        """Test clustering khi không có LLM client"""
        planner = LLMPlanner()
        planner._client = None
        
        result = planner.cluster_identities(["user_id", "vehicle_id"])
        assert result == {}


class TestGeneratePayload:
    """Test payload generation"""
    
    def test_generate_payload_get_method_returns_empty(self):
        """Test GET/DELETE method trả về empty payload"""
        planner = LLMPlanner()
        
        api_node = {
            "id": "get_user",
            "method": "GET",
            "path": "/users/{user_id}",
            "inputs": {"user_id": {"type": "string"}}
        }
        state = StateStore()
        
        payload, source = planner.generate_payload(api_node, state)
        assert payload == {}
        assert source == "NONE"
    
    def test_generate_payload_post_with_llm(self):
        """Test POST method với LLM generation"""
        planner = LLMPlanner()
        
        api_node = {
            "id": "create_user",
            "method": "POST",
            "path": "/users",
            "inputs": {
                "email": {"type": "string"},
                "name": {"type": "string"},
                "password": {"type": "string"}
            }
        }
        state = StateStore()
        
        # Mock LLM response
        expected_payload = {"email": "test@example.com", "name": "John", "password": "Pass123!"}
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps(expected_payload)
        
        with patch.object(planner, '_client') as mock_client:
            mock_client.chat.completions.create.return_value = mock_response
            planner._client = mock_client
            
            payload, source = planner.generate_payload(api_node, state)
            
            assert source == "LLM"
            assert "email" in payload
            # Email should be randomized to avoid duplicates
            assert payload["email"] != "test@example.com"
    
    def test_generate_payload_fallback_to_heuristic(self):
        """Test fallback to heuristic khi LLM fail"""
        planner = LLMPlanner()
        planner._client = None  # Simulate no API key
        
        api_node = {
            "id": "create_user",
            "method": "POST",
            "path": "/users",
            "inputs": {
                "email": {"type": "string"},
                "name": {"type": "string"}
            }
        }
        state = StateStore()
        
        payload, source = planner.generate_payload(api_node, state)
        
        assert source == "HEURISTIC"
        assert payload is not None
        assert "email" in payload
        assert "name" in payload
        assert "@" in payload["email"]  # Valid email format


class TestHeuristicGenerate:
    """Test heuristic payload generation"""
    
    def test_heuristic_generate_with_edge_deps(self):
        """Test heuristic generation với edge dependencies"""
        planner = LLMPlanner()
        
        api_node = {
            "id": "update_vehicle",
            "method": "PUT",
            "inputs": {
                "vehicle_id": {"type": "string"},
                "name": {"type": "string"}
            }
        }
        
        state = StateStore()
        state.update("vehicle_id", "veh_123")
        
        edge_deps = [
            {
                "producer_field": "vehicle_id",
                "consumer_field": "vehicle_id"
            }
        ]
        
        payload = planner._heuristic_generate(api_node, state, edge_deps)
        
        assert payload["vehicle_id"] == "veh_123"  # From state via edge dep
        assert "name" in payload
    
    def test_heuristic_generate_without_deps(self):
        """Test heuristic generation mà không có dependencies"""
        planner = LLMPlanner()
        
        api_node = {
            "id": "create_product",
            "method": "POST",
            "inputs": {
                "title": {"type": "string"},
                "price": {"type": "number"}
            }
        }
        
        state = StateStore()
        payload = planner._heuristic_generate(api_node, state)
        
        assert "title" in payload
        assert "price" in payload


class TestRandomizeVolatileFields:
    """Test volatile field randomization"""
    
    def test_randomize_volatile_fields_create_api(self):
        """Test CREATE API - luôn sinh mới"""
        api_node = {
            "id": "register_user",
            "path": "/auth/register",
            "method": "POST"
        }
        state = StateStore()
        state.update("email", "old_email@example.com")
        
        payload = {
            "email": "test@example.com",
            "password": "Pass123!",
            "name": "John Doe"
        }
        
        result = LLMPlanner._randomize_volatile_fields(payload, api_node, state)
        
        # CREATE API should generate new email, không reuse
        assert result["email"] != "old_email@example.com"
        assert result["email"] != "test@example.com"
        assert "fuzz_" in result["email"]
    
    def test_randomize_volatile_fields_auth_api(self):
        """Test AUTH API - ưu tiên reuse từ state"""
        api_node = {
            "id": "login_user",
            "path": "/auth/login",
            "method": "POST"
        }
        state = StateStore()
        state.update("email", "user@example.com")
        state.update("password", "SecurePass123!")
        
        payload = {
            "email": "fake@example.com",
            "password": "FakePass123!"
        }
        
        result = LLMPlanner._randomize_volatile_fields(payload, api_node, state)
        
        # AUTH API should reuse từ state
        assert result["email"] == "user@example.com"
        assert result["password"] == "SecurePass123!"
    
    def test_randomize_volatile_fields_nested_dict(self):
        """Test xử lý nested dictionary"""
        api_node = {
            "id": "create_order",
            "path": "/orders",
            "method": "POST"
        }
        state = StateStore()
        
        payload = {
            "customer": {
                "email": "test@example.com",
                "phone": "0987654321"
            },
            "items": [
                {"name": "Item 1"},
                {"name": "Item 2"}
            ]
        }
        
        result = LLMPlanner._randomize_volatile_fields(payload, api_node, state)
        
        assert isinstance(result["customer"], dict)
        assert "email" in result["customer"]
        assert "fuzz_" in result["customer"]["email"]
    
    def test_randomize_volatile_fields_nested_list_of_objects(self):
        """✅ Test xử lý nested list chứa objects với email"""
        api_node = {
            "id": "create_order",
            "path": "/orders",
            "method": "POST"
        }
        state = StateStore()
        
        payload = {
            "items": [
                {"email": "test@example.com", "quantity": 2},
                {"email": "test2@example.com", "quantity": 3}
            ],
            "shipping": {
                "email": "ship@example.com"
            }
        }
        
        result = LLMPlanner._randomize_volatile_fields(payload, api_node, state)
        
        # Verify nested list is processed
        assert isinstance(result["items"], list)
        assert len(result["items"]) == 2
        
        # Email trong list phải được randomize
        for item in result["items"]:
            assert isinstance(item, dict)
            assert "email" in item
            assert "fuzz_" in item["email"]  # ← KEY: Email được randomize!
            assert item["email"] != "test@example.com"
            assert item["email"] != "test2@example.com"
        
        # Shipping email cũng được randomize
        assert "fuzz_" in result["shipping"]["email"]



class TestRepairPayload:
    """Test payload repair functionality"""
    
    def test_repair_payload_duplicate_error(self):
        """Test fix payload khi server trả về duplicate error"""
        planner = LLMPlanner()
        
        api_node = {
            "id": "create_user",
            "method": "POST",
            "path": "/users",
            "inputs": {"email": {"type": "string"}}
        }
        state = StateStore()
        
        bad_payload = {"email": "user@example.com"}
        error_response = "Error: Email already registered"
        
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "email": "new_unique@example.com"
        })
        
        with patch.object(planner, '_client') as mock_client:
            mock_client.chat.completions.create.return_value = mock_response
            planner._client = mock_client
            
            fixed = planner.repair_payload(api_node, state, bad_payload, error_response)
            
            assert fixed is not None
            assert fixed["email"] == "new_unique@example.com"
    
    def test_repair_payload_no_client(self):
        """Test repair khi không có LLM client"""
        planner = LLMPlanner()
        planner._client = None
        
        api_node = {"id": "test", "method": "POST", "inputs": {}}
        state = StateStore()
        
        result = planner.repair_payload(api_node, state, {}, "error")
        assert result is None


class TestNormFunction:
    """Test _norm() field normalization"""
    
    def test_norm_underscore_case(self):
        """Test normalization của underscore_case"""
        assert LLMPlanner._norm("user_id") == "userid"
        assert LLMPlanner._norm("vehicle_id") == "vehicleid"
    
    def test_norm_lowercase_already(self):
        """Test normalization của lowercase"""
        assert LLMPlanner._norm("email") == "email"
        assert LLMPlanner._norm("password") == "password"
    
    def test_norm_camel_case(self):
        """Test normalization của camelCase"""
        # Note: Current implementation might have issues with this
        # This test documents the expected behavior
        result = LLMPlanner._norm("userId")
        # After fix, should be same as user_id
        assert "userid" in result.lower()
    
    def test_norm_dot_notation(self):
        """Test normalization của dot.notation"""
        assert LLMPlanner._norm("user.id") == "userid"
        assert LLMPlanner._norm("auth.token") == "authtoken"


class TestGetSemanticCache:
    """Test semantic cache lookup"""
    
    def test_get_semantic_cache_hit(self):
        """Test cache hit"""
        planner = LLMPlanner()
        planner._llm_cache["user_id"] = "identity"
        
        result = planner.get_semantic_cache("user_id")
        assert result == "identity"
    
    def test_get_semantic_cache_miss(self):
        """Test cache miss"""
        planner = LLMPlanner()
        result = planner.get_semantic_cache("unknown_field")
        assert result is None


class TestGetClusterMap:
    """Test identity cluster map retrieval"""
    
    def test_get_cluster_map_empty(self):
        """Test empty cluster map"""
        planner = LLMPlanner()
        result = planner.get_cluster_map()
        assert result == {}
    
    def test_get_cluster_map_with_data(self):
        """Test cluster map with data"""
        planner = LLMPlanner()
        planner._identity_cluster_map = {
            "user_id": 0,
            "userid": 0,
            "vehicle_id": 1
        }
        
        result = planner.get_cluster_map()
        assert result["user_id"] == 0
        assert result["vehicle_id"] == 1


class TestBuildPrompt:
    """Test prompt building"""
    
    def test_build_prompt_basic(self):
        """Test building basic prompt"""
        planner = LLMPlanner()
        
        api_node = {
            "id": "create_user",
            "path": "/users",
            "method": "POST",
            "inputs": {
                "email": {"type": "string", "format": "email"},
                "name": {"type": "string"}
            }
        }
        state = StateStore()
        
        prompt = planner._build_prompt(api_node, state)
        
        assert "POST" in prompt
        assert "/users" in prompt
        assert "email" in prompt
        assert "string" in prompt
    
    def test_build_prompt_with_context(self):
        """Test prompt building với state context"""
        planner = LLMPlanner()
        
        api_node = {
            "id": "update_vehicle",
            "path": "/vehicles/{vehicle_id}",
            "method": "PUT",
            "inputs": {
                "vehicle_id": {"type": "string"},
                "name": {"type": "string"}
            }
        }
        state = StateStore()
        state.update("vehicle_id", "veh_123")
        state.update("auth_token", "token_xyz")
        
        prompt = planner._build_prompt(api_node, state)
        
        assert "veh_123" in prompt
        assert "token_xyz" in prompt


class TestDefaultFuzzValue:
    """Test default fuzz value generation"""
    
    def test_default_fuzz_value_integer(self):
        """Test integer default"""
        result = LLMPlanner._default_fuzz_value("integer", "count")
        assert result == 1
    
    def test_default_fuzz_value_number(self):
        """Test number default"""
        result = LLMPlanner._default_fuzz_value("number", "price")
        assert result == 0.01
    
    def test_default_fuzz_value_boolean(self):
        """Test boolean default"""
        result = LLMPlanner._default_fuzz_value("boolean", "active")
        assert result is True
    
    def test_default_fuzz_value_email(self):
        """Test email field"""
        result = LLMPlanner._default_fuzz_value("string", "email_address")
        assert "@" in result
        assert "test.com" in result
    
    def test_default_fuzz_value_password(self):
        """Test password field"""
        result = LLMPlanner._default_fuzz_value("string", "password")
        assert "Fuzz" in result or "@" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
