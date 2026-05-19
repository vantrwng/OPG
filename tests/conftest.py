"""
Pytest configuration và fixtures
"""
import pytest
import os
import sys
from unittest.mock import MagicMock, patch

# Add parent directory to path để import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client fixture"""
    with patch('llm_planner.OpenAI') as mock:
        client = MagicMock()
        mock.return_value = client
        yield client


@pytest.fixture
def sample_api_node():
    """Sample API node for testing"""
    return {
        "id": "create_user",
        "method": "POST",
        "path": "/users",
        "inputs": {
            "email": {"type": "string", "format": "email"},
            "name": {"type": "string"},
            "password": {"type": "string"}
        },
        "outputs": {
            "user_id": {"type": "string"},
            "access_token": {"type": "string"}
        }
    }


@pytest.fixture
def sample_api_response():
    """Sample API response for testing"""
    return {
        "user_id": "usr_12345",
        "email": "test@example.com",
        "access_token": "token_xyz_abc",
        "created_at": "2026-05-18T10:00:00Z"
    }


@pytest.fixture
def sample_state():
    """Sample StateStore with initial data"""
    from state_store import StateStore
    store = StateStore()
    store.update("auth_token", "initial_token")
    store.update("user_id", "usr_001")
    return store


@pytest.fixture(autouse=True)
def mock_dotenv():
    """Mock dotenv loading to avoid real .env file"""
    with patch('llm_planner.load_dotenv'):
        yield


@pytest.fixture
def cleanup_cache():
    """Cleanup LLMPlanner cache after test"""
    yield
    # Cleanup could be done here if needed


def pytest_configure(config):
    """Configure pytest with markers"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests based on file location"""
    for item in items:
        if "test_" in str(item.fspath):
            # Mark all tests as unit by default
            if "integration" not in str(item.fspath):
                item.add_marker(pytest.mark.unit)
