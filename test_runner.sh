#!/bin/bash

# Test runner script for Django OpenID Connect project
# This script provides various testing options

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Change to project directory
cd "$(dirname "$0")/odic"

# Function to run Django tests
run_django_tests() {
    print_status "Running Django tests..."
    python manage.py test --settings=odic.test_settings --verbosity=2
}

# Function to run specific test
run_specific_test() {
    print_status "Running specific test: $1"
    python manage.py test "$1" --settings=odic.test_settings --verbosity=2
}

# Function to run tests with coverage
run_tests_with_coverage() {
    print_status "Running tests with coverage..."
    
    # Check if coverage is installed
    if ! command -v coverage &> /dev/null; then
        print_warning "Coverage not installed. Installing..."
        pip install coverage
    fi
    
    coverage erase
    coverage run --source='.' manage.py test --settings=odic.test_settings
    coverage report
    coverage html
    
    print_success "Coverage report generated in htmlcov/"
}

# Function to run linting
run_linting() {
    print_status "Running code linting..."
    
    # Check if flake8 is installed
    if ! command -v flake8 &> /dev/null; then
        print_warning "flake8 not installed. Installing..."
        pip install flake8
    fi
    
    flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
    flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
}

# Function to run security checks
run_security_checks() {
    print_status "Running security checks..."
    
    # Check if bandit is installed
    if ! command -v bandit &> /dev/null; then
        print_warning "bandit not installed. Installing..."
        pip install bandit
    fi
    
    bandit -r . -x tests/,test_*.py
}

# Function to check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check if pip-audit is installed
    if ! command -v pip-audit &> /dev/null; then
        print_warning "pip-audit not installed. Installing..."
        pip install pip-audit
    fi
    
    pip-audit
}

# Function to run performance tests
run_performance_tests() {
    print_status "Running performance tests..."
    python manage.py test custom_protected_resource.tests.PerformanceTestCase --settings=odic.test_settings --verbosity=2
}

# Function to run integration tests
run_integration_tests() {
    print_status "Running integration tests..."
    python manage.py test custom_protected_resource.tests.CompleteOAuth2FlowTestCase --settings=odic.test_settings --verbosity=2
    python manage.py test tests.test_oauth2_flow --settings=odic.test_settings --verbosity=2
}

# Function to run security tests
run_security_tests() {
    print_status "Running security tests..."
    python manage.py test custom_protected_resource.tests.SecurityTestCase --settings=odic.test_settings --verbosity=2
}

# Function to run all tests
run_all_tests() {
    print_status "Running all tests..."
    run_django_tests
    print_success "All tests completed!"
}

# Function to setup test environment
setup_test_env() {
    print_status "Setting up test environment..."
    
    # Install test dependencies
    pip install coverage flake8 bandit pip-audit pytest pytest-django
    
    # Run migrations for test database
    python manage.py migrate --settings=odic.test_settings
    
    print_success "Test environment setup complete!"
}

# Function to clean test artifacts
clean_test_artifacts() {
    print_status "Cleaning test artifacts..."
    
    # Remove coverage files
    rm -f .coverage
    rm -rf htmlcov/
    
    # Remove pytest cache
    rm -rf .pytest_cache/
    
    # Remove Python cache
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete
    
    print_success "Test artifacts cleaned!"
}

# Main script logic
case "${1:-all}" in
    "all")
        run_all_tests
        ;;
    "coverage")
        run_tests_with_coverage
        ;;
    "lint")
        run_linting
        ;;
    "security")
        run_security_checks
        ;;
    "security-tests")
        run_security_tests
        ;;
    "performance")
        run_performance_tests
        ;;
    "integration")
        run_integration_tests
        ;;
    "deps")
        check_dependencies
        ;;
    "setup")
        setup_test_env
        ;;
    "clean")
        clean_test_artifacts
        ;;
    "help")
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  all           Run all tests (default)"
        echo "  coverage      Run tests with coverage report"
        echo "  lint          Run code linting"
        echo "  security      Run security checks"
        echo "  security-tests Run security-focused tests"
        echo "  performance   Run performance tests"
        echo "  integration   Run integration tests"
        echo "  deps          Check dependencies for vulnerabilities"
        echo "  setup         Setup test environment"
        echo "  clean         Clean test artifacts"
        echo "  help          Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0                    # Run all tests"
        echo "  $0 coverage          # Run tests with coverage"
        echo "  $0 security-tests    # Run only security tests"
        ;;
    *)
        # Treat as specific test
        run_specific_test "$1"
        ;;
esac