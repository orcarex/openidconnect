# Testing Guide for Django OpenID Connect Project

This document provides comprehensive information about testing the Django OpenID Connect project.

## Test Structure

The project includes several test suites covering different aspects of the application:

### 📁 Test Files

```
odic/
├── custom_protected_resource/
│   └── tests.py                    # App-specific tests
├── tests/
│   ├── __init__.py
│   ├── test_basic_functionality.py # Core functionality tests
│   ├── test_oauth2_flow.py        # OAuth2 flow tests
│   ├── test_api_endpoints.py      # API endpoint tests
│   ├── test_models.py             # Model tests
│   ├── test_security.py           # Security tests
│   └── test_settings.py           # Settings configuration tests
└── run_tests.py                   # Test runner script
```

## 🚀 Running Tests

### Quick Start

```bash
# Navigate to project directory
cd odic

# Run all basic functionality tests (recommended for quick verification)
python manage.py test tests.test_basic_functionality -v 2

# Run specific app tests
python manage.py test custom_protected_resource.tests -v 2

# Run all tests in a specific test file
python manage.py test tests.test_models -v 2
```

### Comprehensive Testing

```bash
# Run all tests
python manage.py test -v 2

# Run tests with coverage (if coverage is installed)
coverage run --source='.' manage.py test
coverage report
coverage html
```

### Test Categories

#### 1. Basic Functionality Tests (`test_basic_functionality.py`)
- ✅ **Core Features**: UserInfo endpoint, OAuth2 application creation
- ✅ **Database Operations**: User creation, token management
- ✅ **URL Configuration**: Endpoint accessibility
- ✅ **Settings Validation**: Required settings verification
- ✅ **Security Basics**: Authentication requirements

**Run with:**
```bash
python manage.py test tests.test_basic_functionality
```

#### 2. OAuth2 Flow Tests (`test_oauth2_flow.py`)
- 🔄 **Authorization Code Flow**: Complete OAuth2 flow testing
- 🔄 **Token Management**: Access tokens, refresh tokens
- 🔄 **Token Introspection**: Token validation endpoints
- 🔄 **Token Revocation**: Token cleanup functionality

**Run with:**
```bash
python manage.py test tests.test_oauth2_flow
```

#### 3. API Endpoint Tests (`test_api_endpoints.py`)
- 🌐 **UserInfo Endpoint**: Response structure and content
- 🌐 **Admin Interface**: Admin panel accessibility
- 🌐 **OAuth2 Endpoints**: Provider endpoint functionality
- 🌐 **Error Handling**: Proper error responses

**Run with:**
```bash
python manage.py test tests.test_api_endpoints
```

#### 4. Model Tests (`test_models.py`)
- 📊 **User Model**: User creation and methods
- 📊 **OAuth2 Models**: Application, AccessToken, RefreshToken, Grant
- 📊 **Model Relationships**: Foreign key relationships
- 📊 **Model Validation**: Field validation and constraints

**Run with:**
```bash
python manage.py test tests.test_models
```

#### 5. Security Tests (`test_security.py`)
- 🔒 **Token Security**: Token validation and expiration
- 🔒 **Authentication**: Bearer token authentication
- 🔒 **Input Validation**: SQL injection and XSS protection
- 🔒 **Security Headers**: HTTP security headers
- 🔒 **Rate Limiting**: Request rate limiting (if implemented)

**Run with:**
```bash
python manage.py test tests.test_security
```

#### 6. Settings Tests (`test_settings.py`)
- ⚙️ **Django Settings**: Core Django configuration
- ⚙️ **OAuth2 Settings**: OAuth2 provider configuration
- ⚙️ **REST Framework**: DRF configuration
- ⚙️ **JWT Settings**: JWT token configuration
- ⚙️ **Environment Variables**: Environment-based configuration

**Run with:**
```bash
python manage.py test tests.test_settings
```

## 📋 Test Coverage

### Current Test Coverage

| Component | Tests | Status |
|-----------|-------|--------|
| UserInfo Endpoint | ✅ | Fully tested |
| OAuth2 Application | ✅ | Fully tested |
| User Management | ✅ | Fully tested |
| Database Models | ✅ | Fully tested |
| URL Configuration | ✅ | Fully tested |
| Settings Validation | ✅ | Fully tested |
| Basic Security | ✅ | Fully tested |
| OAuth2 Flow | 🔄 | Partially tested |
| Token Management | 🔄 | Partially tested |
| API Endpoints | 🔄 | Partially tested |

### Key Test Scenarios

#### ✅ Working Tests
- **UserInfo with valid token**: Returns correct user data
- **UserInfo without token**: Returns 401/403 unauthorized
- **UserInfo with invalid token**: Returns 401/403 unauthorized
- **OAuth2 application creation**: Creates applications correctly
- **User model functionality**: User creation and methods work
- **Database operations**: All CRUD operations work
- **Settings configuration**: All required settings present
- **URL routing**: All endpoints accessible

#### 🔄 Partially Working Tests
- **OAuth2 authorization flow**: Some flow steps work, others need adjustment
- **Token introspection**: Endpoint exists but may need authentication fixes
- **Token revocation**: Endpoint exists but may need authentication fixes
- **Security headers**: Basic security works, headers may need implementation

## 🛠️ Test Configuration

### Test Database
Tests use an in-memory SQLite database for speed:
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}
```

### Test Settings
Key test configurations:
- **Fast password hashing**: MD5 for test speed
- **Disabled migrations**: For faster test setup
- **Test-specific OAuth2 settings**: Simplified scopes and timeouts

### Environment Variables for Testing
```env
DEBUG=True
SECRET_KEY=test-secret-key-for-testing-only
DATABASE_URL=sqlite:///:memory:
ALLOWED_HOSTS=localhost,127.0.0.1,testserver
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Import Errors
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

#### 2. Database Issues
```bash
# Solution: Reset test database
python manage.py migrate
```

#### 3. OAuth2 401/403 Errors
The OAuth2 protected resource decorator returns 403 instead of 401 for some unauthorized requests. This is expected behavior and tests account for both status codes.

#### 4. Concurrent Test Failures
SQLite in-memory database may have locking issues with concurrent tests. This is expected in test environment.

### Test Debugging

#### Verbose Output
```bash
python manage.py test -v 3  # Maximum verbosity
```

#### Specific Test Debugging
```bash
python manage.py test tests.test_basic_functionality.BasicFunctionalityTestCase.test_userinfo_endpoint_with_valid_token -v 2
```

#### Test with PDB
```python
import pdb; pdb.set_trace()  # Add to test method
```

## 📊 Test Metrics

### Performance Benchmarks
- **Basic functionality tests**: ~2.6 seconds (20 tests)
- **Single test execution**: ~0.3 seconds average
- **Database setup**: ~1.5 seconds (migrations)

### Test Statistics
- **Total test files**: 6
- **Basic functionality tests**: 20 tests ✅
- **Model tests**: 15+ tests ✅
- **Security tests**: 10+ tests ✅
- **OAuth2 flow tests**: 10+ tests 🔄
- **API endpoint tests**: 15+ tests 🔄

## 🎯 Best Practices

### Writing New Tests

1. **Follow naming conventions**:
   ```python
   def test_specific_functionality_description(self):
       """Clear description of what is being tested"""
   ```

2. **Use descriptive assertions**:
   ```python
   self.assertEqual(response.status_code, 200, "UserInfo should return 200 for valid token")
   ```

3. **Clean test data**:
   ```python
   def setUp(self):
       """Set up test data"""
       # Create minimal required data
   
   def tearDown(self):
       """Clean up if needed"""
       # Usually not needed with Django's test database rollback
   ```

4. **Test edge cases**:
   - Valid inputs
   - Invalid inputs
   - Empty inputs
   - Boundary conditions

### Test Organization

- **Group related tests** in the same test class
- **Use descriptive test class names** ending with `TestCase`
- **Keep tests independent** - each test should work in isolation
- **Use setUp/tearDown** for common test data

## 🚀 Continuous Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.12
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    - name: Run tests
      run: |
        cd odic
        python manage.py test
```

## 📈 Future Testing Improvements

### Planned Enhancements
1. **Integration Tests**: End-to-end OAuth2 flow testing
2. **Performance Tests**: Load testing for high concurrency
3. **Security Tests**: Comprehensive security vulnerability testing
4. **Browser Tests**: Selenium-based UI testing
5. **API Tests**: Complete REST API testing with different clients

### Test Coverage Goals
- **90%+ code coverage** across all modules
- **100% critical path coverage** for OAuth2 flows
- **Comprehensive error handling** testing
- **Security vulnerability** testing

---

## 📞 Support

If you encounter issues with tests:

1. **Check this documentation** for common solutions
2. **Run basic functionality tests** first to verify setup
3. **Check test output** for specific error messages
4. **Verify environment setup** and dependencies
5. **Create an issue** with detailed error information

**Happy Testing! 🧪✨**