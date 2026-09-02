.PHONY: test test-unit test-coverage test-fast test-llm test-state test-watch test-debug help

# Default target
help:
	@echo "╔════════════════════════════════════════╗"
	@echo "║   AI-Driven API Fuzzer - Make Targets  ║"
	@echo "╚════════════════════════════════════════╝"
	@echo ""
	@echo "Testing targets:"
	@echo "  make test              - Run all tests"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-coverage     - Run with coverage report"
	@echo "  make test-fast         - Run tests in parallel"
	@echo "  make test-llm          - Run llm_planner tests"
	@echo "  make test-state        - Run state_store tests"
	@echo "  make test-watch        - Watch mode (auto-run on change)"
	@echo "  make test-debug        - Run with debugger"
	@echo ""
	@echo "Code quality targets:"
	@echo "  make format            - Format code with black/isort"
	@echo "  make lint              - Run pylint and mypy"
	@echo "  make type-check        - Run mypy type checking"
	@echo ""
	@echo "Setup targets:"
	@echo "  make install-deps      - Install all dependencies"
	@echo "  make install-test-deps - Install test dependencies only"
	@echo ""

# Testing targets
test:
	@echo "▶ Running all tests..."
	pytest tests/ --tb=short

test-unit:
	@echo "▶ Running unit tests only..."
	pytest tests/ -m unit -v --tb=short

test-coverage:
	@echo "▶ Running tests with coverage..."
	pytest tests/ -v --cov=. --cov-config=.coveragerc --cov-report=html:tests/coverage --cov-report=term-missing
	@echo "✓ Coverage report: tests/coverage/index.html"

test-fast:
	@echo "▶ Running tests in parallel..."
	pytest tests/ -n auto -v

test-llm:
	@echo "▶ Running llm_planner tests..."
	pytest tests/test_llm_planner.py -v --tb=short

test-state:
	@echo "▶ Running state_store tests..."
	pytest tests/test_state_store.py -v --tb=short

test-watch:
	@echo "▶ Starting watch mode..."
	ptw tests/ -- --tb=short

test-debug:
	@echo "▶ Running with debugger..."
	pytest tests/ -v --pdb --tb=short

# Code quality targets
format:
	@echo "▶ Formatting code..."
	black llm_planner.py graph_builder.py state_store.py runtime_executor.py spec_parser.py main.py
	isort llm_planner.py graph_builder.py state_store.py runtime_executor.py spec_parser.py main.py

lint:
	@echo "▶ Running pylint..."
	pylint llm_planner.py graph_builder.py state_store.py runtime_executor.py --disable=C0301

type-check:
	@echo "▶ Running mypy type checking..."
	mypy llm_planner.py --ignore-missing-imports

# Dependency management
install-deps:
	@echo "▶ Installing main dependencies..."
	pip install -r requirements.txt

install-test-deps:
	@echo "▶ Installing test dependencies..."
	pip install -r tests/requirements-test.txt

install-all: install-deps install-test-deps
	@echo "✓ All dependencies installed"

# Cleanup
clean:
	@echo "▶ Cleaning up..."
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".coverage" -delete
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	@echo "✓ Cleanup complete"

clean-tests:
	@echo "▶ Cleaning test artifacts..."
	rm -rf tests/coverage/
	rm -f tests/pytest.log
	@echo "✓ Test artifacts removed"

# CI/CD targets
ci: test-coverage lint type-check
	@echo "✓ CI checks passed"

# Default
.DEFAULT_GOAL := help
