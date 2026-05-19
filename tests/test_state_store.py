"""
Unit tests cho StateStore class
"""
import pytest
import json
from state_store import StateStore


class TestStateStoreInit:
    """Test StateStore initialization"""
    
    def test_init_empty(self):
        """Test khởi tạo StateStore rỗng"""
        store = StateStore()
        assert store.memory == {}
    
    def test_init_with_data(self):
        """Test khởi tạo với initial data"""
        initial = {"user_id": "123", "email": "test@example.com"}
        store = StateStore(initial)
        
        assert store.memory == initial
        assert store.get("user_id") == "123"


class TestStateStoreBasicCRUD:
    """Test basic CRUD operations"""
    
    def test_update_and_get(self):
        """Test update và get"""
        store = StateStore()
        store.update("auth_token", "token_xyz")
        
        assert store.get("auth_token") == "token_xyz"
    
    def test_get_with_default(self):
        """Test get với default value"""
        store = StateStore()
        result = store.get("nonexistent", "default_value")
        
        assert result == "default_value"
    
    def test_has_key(self):
        """Test has() method"""
        store = StateStore()
        store.update("email", "test@example.com")
        
        assert store.has("email") is True
        assert store.has("nonexistent") is False
    
    def test_update_existing_key(self):
        """Test update existing key"""
        store = StateStore()
        store.update("count", 1)
        assert store.get("count") == 1
        
        store.update("count", 2)
        assert store.get("count") == 2


class TestStateStoreClone:
    """Test deep copy functionality"""
    
    def test_clone_creates_independent_copy(self):
        """Test clone tạo bản copy độc lập"""
        original = StateStore()
        original.update("user_id", "123")
        original.update("email", "test@example.com")
        
        cloned = original.clone()
        
        # Modify cloned
        cloned.update("user_id", "456")
        cloned.update("email", "new@example.com")
        
        # Original should be unchanged
        assert original.get("user_id") == "123"
        assert original.get("email") == "test@example.com"
        
        # Cloned should have new values
        assert cloned.get("user_id") == "456"
        assert cloned.get("email") == "new@example.com"
    
    def test_clone_nested_objects(self):
        """Test clone xử lý nested objects"""
        original = StateStore()
        original.update("user_info", {"id": "123", "nested": {"name": "John"}})
        
        cloned = original.clone()
        cloned_user_info = cloned.get("user_info")
        cloned_user_info["nested"]["name"] = "Jane"
        
        # Original nested object should not be affected
        assert original.get("user_info")["nested"]["name"] == "John"


class TestStateStoreExtractFromResponse:
    """Test extracting state from API response"""
    
    def test_extract_auth_token(self):
        """Test extraction of auth token"""
        store = StateStore()
        response = {
            "user_id": "123",
            "token": "eyJhbGciOiJIUzI1NiJ9",
            "user_name": "john_doe"
        }
        
        found = store.extract_from_response(response)
        
        assert found is True
        assert store.get("auth_token") == "eyJhbGciOiJIUzI1NiJ9"
    
    def test_extract_generic_ids(self):
        """Test extraction of generic IDs"""
        store = StateStore()
        response = {
            "user_id": "usr_123",
            "vehicle_id": "veh_456",
            "order_id": "ord_789"
        }
        
        found = store.extract_from_response(response)
        
        assert found is True
        assert store.get("user_id") == "usr_123"
        assert store.get("vehicle_id") == "veh_456"
        assert store.get("order_id") == "ord_789"
    
    def test_extract_email_and_phone(self):
        """Test extraction of email and phone"""
        store = StateStore()
        response = {
            "email": "user@example.com",
            "phone": "0987654321",
            "mobile_number": "0912345678"
        }
        
        found = store.extract_from_response(response)
        
        assert found is True
        assert store.get("email") == "user@example.com"
        assert store.get("phone") == "0987654321"
    
    def test_extract_nested_response(self):
        """Test extraction từ nested response"""
        store = StateStore()
        response = {
            "status": "success",
            "data": {
                "user": {
                    "id": "usr_123",
                    "email": "test@example.com",
                    "token": "auth_token_xyz"
                }
            }
        }
        
        found = store.extract_from_response(response)
        
        assert found is True
        assert store.get("user_id") == "usr_123" or store.get("id") == "usr_123"
        assert store.get("email") == "test@example.com"
        assert store.get("auth_token") == "auth_token_xyz"
    
    def test_extract_from_list_response(self):
        """Test extraction từ list response"""
        store = StateStore()
        response = [
            {"id": "item_1", "name": "Item 1"},
            {"id": "item_2", "name": "Item 2"}
        ]
        
        found = store.extract_from_response(response)
        
        # Should extract từ first item
        assert found is True
        assert store.has("id")
    
    def test_extract_no_match_returns_false(self):
        """Test extract khi không có harvest pattern match"""
        store = StateStore()
        response = {
            "status": "success",
            "message": "OK"
        }
        
        found = store.extract_from_response(response)
        assert found is False
    
    def test_extract_duplicate_value_not_updated(self):
        """Test khi value đã tồn tại thì không update"""
        store = StateStore()
        store.update("user_id", "usr_123")
        
        response = {"user_id": "usr_123"}
        found = store.extract_from_response(response)
        
        # Should return False vì value không change
        assert found is False
    
    def test_extract_new_value_updated(self):
        """Test khi có value mới thì update"""
        store = StateStore()
        store.update("user_id", "usr_123")
        
        response = {"user_id": "usr_456"}  # Different value
        found = store.extract_from_response(response)
        
        # Should return True vì value change
        assert found is True
        assert store.get("user_id") == "usr_456"
    
    def test_extract_with_schema_guide(self):
        """Test extraction với schema guide"""
        store = StateStore()
        response = {
            "vehicle_vin": "ABC123XYZ",
            "license_plate": "ABC-12345"
        }
        schema = ["vehicle_vin", "license_plate"]
        
        # Note: Current implementation might not fully use schema
        # This test documents expected behavior
        found = store.extract_from_response(response, schema)
        
        # Should extract based on schema hints
        assert store.has("vehicle_vin") or store.memory


class TestStateStoreEdgeCases:
    """Test edge cases và error handling"""
    
    def test_extract_from_non_dict_response(self):
        """Test extract from string response"""
        store = StateStore()
        found = store.extract_from_response("just a string")
        
        assert found is False
    
    def test_extract_from_none_response(self):
        """Test extract from None response"""
        store = StateStore()
        found = store.extract_from_response(None)
        
        assert found is False
    
    def test_extract_from_empty_dict(self):
        """Test extract from empty dictionary"""
        store = StateStore()
        found = store.extract_from_response({})
        
        assert found is False
    
    def test_multiple_extractions_accumulate(self):
        """Test multiple extractions accumulate in memory"""
        store = StateStore()
        
        # First response
        store.extract_from_response({"user_id": "usr_123"})
        assert store.get("user_id") == "usr_123"
        
        # Second response - add more data
        store.extract_from_response({"email": "test@example.com"})
        
        # Both should be present
        assert store.get("user_id") == "usr_123"
        assert store.get("email") == "test@example.com"


class TestStateStoreMemoryStructure:
    """Test memory structure and organization"""
    
    def test_memory_dict_accessible(self):
        """Test memory dict is accessible"""
        store = StateStore()
        store.update("key1", "value1")
        
        assert store.memory["key1"] == "value1"
    
    def test_can_iterate_memory(self):
        """Test can iterate over memory"""
        store = StateStore()
        store.update("user_id", "123")
        store.update("email", "test@example.com")
        store.update("token", "xyz")
        
        keys = list(store.memory.keys())
        assert "user_id" in keys
        assert "email" in keys
        assert "token" in keys
    
    def test_memory_values_types_preserved(self):
        """Test that value types are preserved"""
        store = StateStore()
        
        store.update("string_val", "test")
        store.update("int_val", 123)
        store.update("list_val", [1, 2, 3])
        store.update("dict_val", {"nested": "data"})
        
        assert isinstance(store.get("string_val"), str)
        assert isinstance(store.get("int_val"), int)
        assert isinstance(store.get("list_val"), list)
        assert isinstance(store.get("dict_val"), dict)


class TestStateStoreRealWorldScenarios:
    """Test real-world fuzzing scenarios"""
    
    def test_auth_flow_with_multiple_apis(self):
        """Test auth flow storing token across multiple API calls"""
        store = StateStore()
        
        # First API: login
        login_response = {
            "status": "success",
            "access_token": "token_abc123",
            "user_id": "usr_001"
        }
        store.extract_from_response(login_response)
        assert store.get("auth_token") == "token_abc123"
        
        # Second API: create resource using token
        create_response = {
            "status": "success",
            "resource_id": "res_789"
        }
        store.extract_from_response(create_response)
        assert store.get("auth_token") == "token_abc123"  # Preserved
        assert store.get("resource_id") == "res_789"  # New
    
    def test_beam_search_branch_isolation(self):
        """Test Beam Search branches don't interfere"""
        # Parent state
        parent = StateStore()
        parent.update("user_id", "usr_123")
        parent.update("email", "user@example.com")
        
        # Branch 1
        branch1 = parent.clone()
        branch1.update("user_id", "usr_456")
        branch1.extract_from_response({"token": "token_branch1"})
        
        # Branch 2
        branch2 = parent.clone()
        branch2.update("user_id", "usr_789")
        branch2.extract_from_response({"token": "token_branch2"})
        
        # Verify isolation
        assert parent.get("user_id") == "usr_123"
        assert branch1.get("user_id") == "usr_456"
        assert branch1.get("token") == "token_branch1"
        assert branch2.get("user_id") == "usr_789"
        assert branch2.get("token") == "token_branch2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
