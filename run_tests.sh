#!/bin/bash
# Test runner script for AI-Driven API Fuzzer

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AI-Driven API Fuzzer - Test Runner   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}❌ pytest not found. Installing test dependencies...${NC}"
    pip install -r tests/requirements-test.txt
fi

# Parse command line arguments
TEST_MODE="${1:-all}"
VERBOSE="${2:-false}"

case "$TEST_MODE" in
    "all")
        echo -e "${YELLOW}▶ Running all tests...${NC}"
        if [ "$VERBOSE" = "-v" ]; then
            pytest tests/ -v --tb=short
        else
            pytest tests/ --tb=short
        fi
        ;;
    
    "unit")
        echo -e "${YELLOW}▶ Running unit tests only...${NC}"
        pytest tests/ -m unit -v --tb=short
        ;;
    
    "coverage")
        echo -e "${YELLOW}▶ Running tests with coverage report...${NC}"
        pytest tests/ -v --cov=. --cov-report=html --cov-report=term-missing
        echo -e "${GREEN}✓ Coverage report generated: tests/coverage/index.html${NC}"
        ;;
    
    "fast")
        echo -e "${YELLOW}▶ Running tests in parallel (fast mode)...${NC}"
        pytest tests/ -n auto -v
        ;;
    
    "llm_planner")
        echo -e "${YELLOW}▶ Running llm_planner tests only...${NC}"
        pytest tests/test_llm_planner.py -v --tb=short
        ;;
    
    "state_store")
        echo -e "${YELLOW}▶ Running state_store tests only...${NC}"
        pytest tests/test_state_store.py -v --tb=short
        ;;
    
    "watch")
        echo -e "${YELLOW}▶ Running tests in watch mode (requires ptw)...${NC}"
        pip install pytest-watch &> /dev/null
        ptw tests/
        ;;
    
    "debug")
        echo -e "${YELLOW}▶ Running tests with debugger...${NC}"
        pytest tests/ -v --pdb --tb=short
        ;;
    
    *)
        echo -e "${RED}Unknown test mode: $TEST_MODE${NC}"
        echo ""
        echo "Usage: ./run_tests.sh [MODE] [-v]"
        echo ""
        echo "Modes:"
        echo "  all        - Run all tests (default)"
        echo "  unit       - Run unit tests only"
        echo "  coverage   - Run with coverage report"
        echo "  fast       - Run tests in parallel"
        echo "  llm_planner- Run llm_planner tests only"
        echo "  state_store- Run state_store tests only"
        echo "  watch      - Watch mode (auto-run on file change)"
        echo "  debug      - Run with debugger"
        echo ""
        echo "Options:"
        echo "  -v         - Verbose output"
        exit 1
        ;;
esac

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
else
    echo -e "${RED}✗ Some tests failed!${NC}"
    exit 1
fi
