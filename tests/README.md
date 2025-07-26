# Test Suite Documentation

This directory contains comprehensive integration tests for the Nabla binary analysis service.

## Test Files

### `integration_tests.rs`
Main integration test file covering:
- Server startup/shutdown testing
- Debug routes testing (`/debug/multipart`)
- CLI tools testing (`mint_license`, `jwt_validation_test`, `generate_hmac`)
- HTTP provider mocking with external services
- Middleware error paths and rate limiting
- Route error handling and edge cases
- API key extraction methods
- Concurrent request handling

### `binary_analysis_edge_cases.rs`
Dedicated tests for binary analysis edge cases:
- Empty files
- Corrupted binaries (ELF, Mach-O, PE)
- Very large files
- Unsupported file types
- Unicode and special character filenames
- Null byte handling
- Performance testing
- Metadata extraction edge cases

### `cli_tools_tests.rs`
Comprehensive CLI tool testing:
- All mint_license expiry options
- JWT validation with valid/invalid tokens
- HMAC generation with various inputs
- Error handling for missing arguments
- Environment variable handling
- Help and version commands
- File output testing
- Concurrent execution testing

### `http_provider_mocking_tests.rs`
HTTP provider testing with mocked external services:
- OpenAI-compatible API mocking
- Llama.cpp API mocking
- Authentication testing
- Server error responses
- Network error handling
- Timeout scenarios
- Malformed response handling
- Rate limiting simulation
- Concurrent request testing

### `error_paths_tests.rs`
Error path testing for middleware and routes:
- Missing API keys
- Invalid JWT formats
- Expired tokens
- Rate limiting scenarios
- Invalid multipart data
- Large payload handling
- Malformed JSON
- Unsupported content types
- Missing headers
- Concurrent request handling

### `test_config.rs`
Test configuration and utilities:
- Test environment setup
- Test license key generation
- Test binary data creation
- Multipart data helpers

## Running Tests

### Prerequisites
1. Set the `LICENSE_SIGNING_KEY` environment variable:
   ```bash
   export LICENSE_SIGNING_KEY="your-base64-encoded-32-byte-key"
   ```

2. Ensure all dependencies are installed:
   ```bash
   cargo build
   ```

### Running All Tests
```bash
cargo test
```

### Running Specific Test Categories
```bash
# Integration tests
cargo test integration_tests

# Binary analysis edge cases
cargo test binary_analysis_edge_cases

# CLI tools tests
cargo test cli_tools_tests

# HTTP provider mocking tests
cargo test http_provider_mocking_tests

# Error paths tests
cargo test error_paths_tests
```

### Running Tests with Output
```bash
cargo test -- --nocapture
```

### Running Tests in Parallel
```bash
cargo test -- --test-threads=4
```

## Test Coverage

### Server Integration Tests
- ✅ Server startup/shutdown
- ✅ Health endpoint
- ✅ Route registration
- ✅ Middleware integration

### Debug Routes
- ✅ Multipart data parsing
- ✅ Field extraction
- ✅ Content preview generation
- ✅ Large file handling
- ✅ Multiple field support

### CLI Tools
- ✅ License token generation
- ✅ JWT validation
- ✅ HMAC generation
- ✅ Error handling
- ✅ Argument parsing
- ✅ Environment variable handling

### HTTP Provider Mocking
- ✅ OpenAI-compatible API
- ✅ Llama.cpp API
- ✅ Authentication
- ✅ Error responses
- ✅ Network failures
- ✅ Rate limiting

### Binary Analysis Edge Cases
- ✅ Empty files
- ✅ Corrupted binaries
- ✅ Large files
- ✅ Unsupported types
- ✅ Unicode filenames
- ✅ Performance testing

### Error Paths
- ✅ Missing authentication
- ✅ Invalid tokens
- ✅ Rate limiting
- ✅ Invalid data
- ✅ Large payloads
- ✅ Malformed requests

## Test Utilities

### JWT Token Creation
```rust
use crate::test_config::get_test_license_key;

let token = create_test_jwt("test-user", 60);
```

### Test Binary Data
```rust
use crate::test_config::create_test_binary_data;

let binary_data = create_test_binary_data();
```

### Multipart Data
```rust
use crate::test_config::create_test_multipart_data;

let multipart = create_test_multipart_data("test.bin", &binary_data);
```

## Mock Server Setup

The tests use WireMock for HTTP provider testing:

```rust
use wiremock::{Mock, MockServer, ResponseTemplate};

let mock_server = MockServer::start().await;
Mock::given(method("POST"))
    .and(path("/v1/chat/completions"))
    .respond_with(ResponseTemplate::new(200))
    .mount(&mock_server)
    .await;
```

## Test Environment

Tests automatically set up:
- Test license signing key
- Logging configuration
- Temporary directories
- Mock servers

## Continuous Integration

These tests are designed to run in CI environments:
- No external dependencies (except for mocked services)
- Deterministic test data
- Proper cleanup of resources
- Parallel execution support

## Debugging Tests

To debug failing tests:

1. Run with verbose output:
   ```bash
   cargo test -- --nocapture --test-threads=1
   ```

2. Run specific test:
   ```bash
   cargo test test_name -- --nocapture
   ```

3. Check test logs:
   ```bash
   RUST_LOG=debug cargo test
   ```

## Adding New Tests

When adding new tests:

1. Follow the existing naming conventions
2. Use the test utilities from `test_config.rs`
3. Add appropriate error handling
4. Include both success and failure cases
5. Test edge cases and error conditions
6. Document any new test utilities

## Test Dependencies

The tests require these additional dependencies:
- `wiremock` - HTTP mocking
- `axum-test` - Axum testing utilities
- `futures` - Async utilities
- `tempfile` - Temporary file handling 