# Unit Tests for AI-Driven API Fuzzer

## Overview

This directory contains comprehensive unit tests for the AI-Driven API Fuzzer system.

### Test Files

- **test_llm_planner.py**: Tests for LLMPlanner class
  - Field classification (semantic tagging)
  - Identity clustering
  - Payload generation (LLM + heuristic)
  - Payload repair (error handling)
  - Volatile field randomization
  
- **test_state_store.py**: Tests for StateStore class
  - CRUD operations
  - Deep cloning (Beam Search isolation)
  - Response extraction and harvesting
  - Real-world fuzzing scenarios

## Installation

### 1. Install test dependencies
```bash
pip install -r requirements-test.txt
```

### 2. Ensure main dependencies are installed
```bash
pip install -r ../requirements.txt
```

## Running Tests

### Run all tests
```bash
pytest
```

### Run specific test file
```bash
pytest tests/test_llm_planner.py -v
```

### Run specific test class
```bash
pytest tests/test_llm_planner.py::TestGeneratePayload -v
```

### Run specific test function
```bash
pytest tests/test_llm_planner.py::TestGeneratePayload::test_generate_payload_post_with_llm -v
```

### Run with coverage report
```bash
pytest --cov=. --cov-report=html
```

### Run only unit tests
```bash
pytest -m unit
```

### Run with parallel execution (faster)
```bash
pytest -n auto
```

### Run with timeout (prevent hanging tests)
```bash
pytest --timeout=30
```

## Test Organization

Tests are organized by component:

```
tests/
├── __init__.py
├── conftest.py                 # pytest fixtures and configuration
├── test_llm_planner.py         # LLMPlanner unit tests (20+ tests)
├── test_state_store.py         # StateStore unit tests (25+ tests)
├── pytest.ini                  # pytest configuration
├── requirements-test.txt       # test dependencies
└── README.md                   # this file
```

## Key Testing Patterns

### 1. Mocking LLM API Calls
```python
from unittest.mock import MagicMock, patch

@patch.object(planner, '_client')
def test_with_llm_mock(mock_client):
    mock_response = MagicMock()
    mock_response.choices[0].message.content = json.dumps({...})
    mock_client.chat.completions.create.return_value = mock_response
    ...
```

### 2. Testing StateStore Cloning (Beam Search)
```python
original = StateStore()
original.update("user_id", "123")

cloned = original.clone()
cloned.update("user_id", "456")

# Original unchanged, cloned changed
assert original.get("user_id") == "123"
assert cloned.get("user_id") == "456"
```

### 3. Testing Payload Generation Flow
```python
# LLM generation → Fallback to heuristic → Randomize volatile fields
payload, source = planner.generate_payload(api_node, state)
assert payload is not None
assert source in ["LLM", "HEURISTIC", "NONE"]
```

## Coverage Goals

Target coverage by component:
- **llm_planner.py**: 85%+ (core fuzzing logic)
- **state_store.py**: 90%+ (critical for beam search)
- **graph_builder.py**: 70%+ (complex graph algorithms)

Current coverage report generated in: `tests/coverage/index.html`

## Continuous Integration

To run tests as part of CI/CD pipeline:

```bash
# Run tests with coverage and exit code
pytest --cov=. --cov-fail-under=75 -v

# Only fail if tests error, not if coverage is low
pytest --tb=short -v
```

## Debugging Tests

### Increase logging verbosity
```bash
pytest -v --log-cli-level=DEBUG
```

### Run single test with print statements
```bash
pytest tests/test_llm_planner.py::test_name -s
```

### Use pytest debugger
```bash
pytest --pdb tests/test_llm_planner.py::test_name
```

### Run with IPython debugger
```bash
pytest --pdbcls=IPython.terminal.debugger:TerminalPdb
```

## Common Issues

### Issue: "ModuleNotFoundError: No module named 'llm_planner'"
**Solution**: Ensure you're running pytest from the root project directory
```bash
cd /path/to/OPG
pytest
```

### Issue: Tests timeout
**Solution**: Increase timeout in pytest.ini or use --timeout flag
```bash
pytest --timeout=60
```

### Issue: LLM API rate limiting in tests
**Solution**: Tests use mocks by default. To test with real API:
```python
# In conftest.py, set environment variable
os.environ["RUN_LIVE_API_TESTS"] = "1"
```

## Adding New Tests

1. **Create test file** following pattern `test_<module>.py`
2. **Use clear naming**: `TestClassName` and `test_method_description`
3. **Use fixtures** from conftest.py for common setup
4. **Add docstrings** to explain what's being tested
5. **Use assertions** with clear error messages

Example:
```python
class TestNewFeature:
    """Test description"""
    
    def test_specific_behavior(self, sample_api_node):
        """Test that feature does X when given Y"""
        # Arrange
        expected = "value"
        
        # Act
        result = function_under_test(sample_api_node)
        
        # Assert
        assert result == expected, "Clear error message"
```

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [unittest.mock documentation](https://docs.python.org/3/library/unittest.mock.html)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [pytest-xdist for parallel execution](https://pytest-xdist.readthedocs.io/)

## Contributing

When adding new code to the project:
1. Write tests first (TDD approach)
2. Ensure tests pass: `pytest`
3. Ensure coverage: `pytest --cov=. --cov-report=term-missing`
4. Ensure code quality: Add type hints, docstrings
