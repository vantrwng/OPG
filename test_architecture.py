import json
from unittest.mock import MagicMock
from state_store import StateStore
from llm_planner import LLMPlanner
from auditor_agent import AuditorAgent

def run_tests():
    print("=== RUNNING ARCHITECTURE REFACTOR TESTS ===\n")
    
    # Giả lập Ollama Client để trả về JSON cứng
    mock_ollama_client = MagicMock()
    
    # ---------------------------------------------------------
    # TEST 1: Validation error về string length
    # ---------------------------------------------------------
    print("TEST 1: Validation length repair")
    mock_ollama_client.architect.return_value = {
        "action": "MODIFY",
        "vulnerability_type": "VALIDATION",
        "evidence": ["size must be between 4 and 8"],
        "changes": {"pincode": "12345"},
        "reason": "Shortened pincode to 5 chars to meet 4-8 constraint"
    }
    planner = LLMPlanner()
    planner._ollama = mock_ollama_client
    
    state = StateStore()
    bad_payload = {"pincode": "fuzz_1234567890abcdef@test.com", "vin": "123"}
    error_response = '{"message": "Validation failed", "details": "field pincode size must be between 4 and 8"}'
    
    fixed_payload = planner.repair_payload(
        {"id": "addVehicle"}, state, bad_payload, error_response
    )
    
    assert fixed_payload["pincode"] == "12345", "Failed Test 1: Pincode not fixed"
    assert fixed_payload["vin"] == "123", "Failed Test 1: Other fields modified"
    print("✅ Passed Test 1")

    # ---------------------------------------------------------
    # TEST 2: Validation error về required field
    # ---------------------------------------------------------
    print("TEST 2: Required field repair")
    mock_ollama_client.architect.return_value = {
        "action": "MODIFY",
        "vulnerability_type": "VALIDATION",
        "evidence": ["email must not be null"],
        "changes": {"email": "test@test.com"},
        "reason": "Added missing required email field"
    }
    
    bad_payload = {"name": "test"}
    error_response = '{"message": "email must not be null"}'
    
    fixed_payload = planner.repair_payload(
        {"id": "addUser"}, state, bad_payload, error_response
    )
    
    assert "email" in fixed_payload, "Failed Test 2: Missing field not added"
    assert fixed_payload["email"] == "test@test.com", "Failed Test 2: Wrong value added"
    print("✅ Passed Test 2")

    # ---------------------------------------------------------
    # TEST 3: Duplicate/conflict error
    # ---------------------------------------------------------
    print("TEST 3: Duplicate entry repair")
    mock_ollama_client.architect.return_value = {
        "action": "MODIFY",
        "vulnerability_type": "CONFLICT",
        "evidence": ["Duplicate entry 'admin@test.com'"],
        "changes": {"email": "random99@test.com"},
        "reason": "Generated new random email to avoid collision"
    }
    
    bad_payload = {"email": "admin@test.com"}
    error_response = '{"message": "Duplicate entry admin@test.com"}'
    
    fixed_payload = planner.repair_payload(
        {"id": "addUser"}, state, bad_payload, error_response
    )
    
    assert fixed_payload["email"] == "random99@test.com", "Failed Test 3: Email not randomized"
    print("✅ Passed Test 3")

    # ---------------------------------------------------------
    # TEST 4 & 5: Authentication / Authorization failure
    # ---------------------------------------------------------
    print("TEST 4: Auth failure (NO CHANGE)")
    mock_ollama_client.architect.return_value = {
        "action": "NO_CHANGE",
        "vulnerability_type": "AUTHENTICATION",
        "evidence": ["Invalid token"],
        "reason": "Payload data cannot fix an invalid auth token."
    }
    
    bad_payload = {"data": "test"}
    error_response = '{"message": "Invalid token"}'
    
    fixed_payload = planner.repair_payload(
        {"id": "getData"}, state, bad_payload, error_response
    )
    assert fixed_payload is None, "Failed Test 4: Should return None for NO_CHANGE"
    print("✅ Passed Test 4")

    # ---------------------------------------------------------
    # TEST 6: HTTP 200 nhưng không có evidence BOLA
    # ---------------------------------------------------------
    print("TEST 6: HTTP 200 without BOLA evidence")
    auditor = AuditorAgent(client=mock_ollama_client)
    mock_ollama_client.auditor.return_value = {
        "classification": "INCONCLUSIVE",
        "confidence": 0.2,
        "vulnerability_type": "NONE",
        "evidence": ["HTTP 200"],
        "reason": "No ownership info available."
    }
    
    state = StateStore()
    state.memory["user_id"] = "1"
    
    attack_resp = {"status": 200, "raw_response": {"data": "public"}}
    result = auditor.audit({"strategy": "test"}, attack_resp, None, state, {"method": "GET"})
    
    assert result.is_bola is False, "Failed Test 6: Falsely flagged as BOLA"
    assert result.classification == "INCONCLUSIVE", "Failed Test 6: Wrong classification"
    print("✅ Passed Test 6")

    # ---------------------------------------------------------
    # TEST 7: Cross-user object access với owner khác current user
    # ---------------------------------------------------------
    print("TEST 7: Confirmed BOLA")
    mock_ollama_client.auditor.return_value = {
        "classification": "CONFIRMED",
        "confidence": 0.9,
        "vulnerability_type": "BOLA",
        "evidence": ["owner_id is 2, but current user is 1"],
        "reason": "Strong evidence of foreign ownership."
    }
    
    attack_resp = {"status": 200, "raw_response": {"id": 100, "owner_id": 2}}
    result = auditor.audit({"strategy": "BOLA_ID"}, attack_resp, None, state, {"method": "GET"})
    
    assert result.is_bola is True, "Failed Test 7: BOLA not detected"
    assert result.classification == "CONFIRMED", "Failed Test 7: Wrong classification"
    print("✅ Passed Test 7")

    print("\n🎉 ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
