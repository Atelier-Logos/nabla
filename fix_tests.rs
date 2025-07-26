use std::fs;
use std::path::Path;

fn main() {
    let content = fs::read_to_string("tests/middleware_tests.rs").unwrap();
    
    // Fix all validate_license_jwt calls to wrap state in State
    let content = content.replace(
        "validate_license_jwt(state, req, Next::new",
        "validate_license_jwt(State(state), req, Next::new"
    );
    
    // Fix the wrong_secret type issue
    let content = content.replace(
        "let wrong_secret = [2; 32]; // Different secret",
        "let wrong_secret = Arc::new([2; 32]); // Different secret"
    );
    
    // Fix the req.clone() issue by removing it
    let content = content.replace(
        "validate_license_jwt(State(state.clone()), req.clone(), Next::new",
        "validate_license_jwt(State(state.clone()), req, Next::new"
    );
    
    fs::write("tests/middleware_tests.rs", content).unwrap();
    println!("Fixed middleware tests");
} 