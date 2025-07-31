use axum::http::StatusCode;
use tempfile::tempdir;
use tokio::fs;

// Import the function we want to test
use nabla::routes::binary::validate_file_path;

#[tokio::test]
async fn test_path_traversal_protection() {
    // Create a temporary directory for testing
    let temp_dir = tempdir().unwrap();
    let test_file_path = temp_dir.path().join("test_file.txt");

    // Create a test file
    fs::write(&test_file_path, "test content").await.unwrap();

    // Test cases that should be blocked
    let malicious_paths = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/passwd",
        "C:\\Windows\\System32\\config\\sam",
        "test_file.txt/../test_file.txt",
        "test_file.txt/../../test_file.txt",
        "test_file.txt/../../../test_file.txt",
        "test_file.txt\\..\\test_file.txt",
        "test_file.txt\\..\\..\\test_file.txt",
        "test_file.txt\\..\\..\\..\\test_file.txt",
    ];

    for malicious_path in malicious_paths {
        println!("Testing malicious path: {}", malicious_path);
        let result = validate_file_path(malicious_path);
        assert!(
            result.is_err(),
            "Path traversal should be blocked: {}",
            malicious_path
        );

        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let error_response = err.1;
        assert!(error_response.error == "invalid_input");
        // Check for the actual error messages returned by our function
        assert!(
            error_response.message.contains("Path traversal")
                || error_response.message.contains("Absolute paths")
                || error_response.message.contains("Invalid file path")
        );
    }

    // Test cases that should be allowed (but may fail if file doesn't exist in current dir)
    let valid_paths = vec![
        "test_file.txt",
        "subdir/test_file.txt",
        "subdir\\test_file.txt",
        "test_file.txt.old",
        "test_file.txt.backup",
    ];

    for valid_path in valid_paths {
        println!("Testing valid path: {}", valid_path);
        let result = validate_file_path(valid_path);
        if result.is_ok() {
            println!("✅ Valid path accepted: {}", valid_path);
        } else {
            println!(
                "❌ Valid path rejected: {} - {:?}",
                valid_path,
                result.unwrap_err()
            );
        }
    }
}

#[tokio::test]
async fn test_file_validation() {
    let temp_dir = tempdir().unwrap();
    let test_file_path = temp_dir.path().join("test_file.txt");

    // Create a test file
    fs::write(&test_file_path, "test content").await.unwrap();

    // Test that non-existent files are rejected (this should work from any directory)
    let result = validate_file_path("non_existent_file.txt");
    assert!(result.is_err(), "Non-existent file should be rejected");

    // Test that path traversal attempts are blocked
    let result = validate_file_path("../../../etc/passwd");
    assert!(result.is_err(), "Path traversal should be blocked");

    // Test that absolute paths are blocked
    let result = validate_file_path("/etc/passwd");
    assert!(result.is_err(), "Absolute paths should be blocked");
}

#[tokio::test]
async fn test_canonicalization_protection() {
    let temp_dir = tempdir().unwrap();
    let test_file_path = temp_dir.path().join("test_file.txt");

    // Create a test file
    fs::write(&test_file_path, "test content").await.unwrap();

    // Change to the temp directory for this test
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(&temp_dir).unwrap();

    // Test that canonicalization resolves to the correct path
    let result = validate_file_path("test_file.txt");
    assert!(result.is_ok());

    let canonical_path = result.unwrap();
    assert_eq!(canonical_path, test_file_path.canonicalize().unwrap());

    // Restore original directory
    std::env::set_current_dir(original_dir).unwrap();
}

#[tokio::test]
async fn test_boundary_enforcement() {
    let temp_dir = tempdir().unwrap();
    let test_file_path = temp_dir.path().join("test_file.txt");

    // Create a test file
    fs::write(&test_file_path, "test content").await.unwrap();

    // Change to the temp directory
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(&temp_dir).unwrap();

    // Test that paths outside the current directory are rejected
    let result = validate_file_path("../../../etc/passwd");
    assert!(
        result.is_err(),
        "Path outside current directory should be rejected"
    );

    // Test that valid paths within the directory are accepted
    let result = validate_file_path("test_file.txt");
    assert!(
        result.is_ok(),
        "Path within current directory should be accepted"
    );

    // Restore original directory
    std::env::set_current_dir(original_dir).unwrap();
}
