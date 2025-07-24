#!/usr/bin/env python
"""
Test runner script for Django OpenID Connect project
"""
import os
import sys
import django
from django.conf import settings
from django.test.utils import get_runner


def run_tests():
    """Run all tests for the project"""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'odic.settings')
    django.setup()
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    
    # Run all tests
    failures = test_runner.run_tests([])
    
    if failures:
        sys.exit(1)
    else:
        print("\n✅ All tests passed!")


def run_specific_tests(test_labels):
    """Run specific tests"""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'odic.settings')
    django.setup()
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=2)
    
    failures = test_runner.run_tests(test_labels)
    
    if failures:
        sys.exit(1)
    else:
        print(f"\n✅ Tests {test_labels} passed!")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Run specific tests
        test_labels = sys.argv[1:]
        run_specific_tests(test_labels)
    else:
        # Run all tests
        run_tests()