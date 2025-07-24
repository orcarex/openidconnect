#!/usr/bin/env python
"""
Test runner script for Django OpenID Connect project
"""
import os
import sys
import django
from django.conf import settings
from django.test.utils import get_runner

def run_basic_tests():
    """Run basic functionality tests only"""
    print("🧪 Running Basic Functionality Tests...")
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=2)
    
    failures = test_runner.run_tests([
        "tests.test_basic_functionality"
    ])
    
    return failures

def run_all_working_tests():
    """Run all currently working tests"""
    print("🧪 Running All Working Tests...")
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=2)
    
    failures = test_runner.run_tests([
        "tests.test_basic_functionality",
        "tests.test_models",
    ])
    
    return failures

def run_all_tests():
    """Run all tests (including potentially failing ones)"""
    print("🧪 Running All Tests (including experimental)...")
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=2)
    
    failures = test_runner.run_tests([
        "tests.test_basic_functionality",
        "tests.test_models",
        "tests.test_oauth2_flow",
        "tests.test_api_endpoints", 
        "tests.test_security",
        "tests.test_settings"
    ])
    
    return failures

def main():
    """Main test runner"""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'odic.settings')
    django.setup()
    
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
    else:
        test_type = "basic"
    
    print(f"🚀 Django OpenID Connect Test Runner")
    print(f"📁 Working directory: {os.getcwd()}")
    print(f"🐍 Python version: {sys.version}")
    print(f"🔧 Django version: {django.get_version()}")
    print("-" * 50)
    
    if test_type == "basic":
        failures = run_basic_tests()
    elif test_type == "working":
        failures = run_all_working_tests()
    elif test_type == "all":
        failures = run_all_tests()
    else:
        print(f"❌ Unknown test type: {test_type}")
        print("Available options: basic, working, all")
        sys.exit(1)
    
    print("-" * 50)
    if failures:
        print(f"❌ {failures} test(s) failed!")
        sys.exit(1)
    else:
        print("✅ All tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()