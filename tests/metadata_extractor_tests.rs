// tests/metadata_extractor_tests.rs

use nabla::binary::metadata_extractor::{
    is_valid_version, normalize_license_name, infer_license_from_text,
    extract_company_name, extract_product_name,
    calculate_version_confidence, calculate_license_confidence,
};
use std::collections::HashSet;

#[test]
fn test_is_valid_version() {
    assert!(is_valid_version("1.2.3"));
    assert!(is_valid_version("0.0.1"));
    assert!(!is_valid_version("abc"));
    assert!(!is_valid_version("1"));
}

#[test]
fn test_normalize_license_name() {
    assert_eq!(normalize_license_name("mit"), "MIT");
    assert_eq!(normalize_license_name("gpl3"), "gpl3"); // accept untouched
    assert_eq!(normalize_license_name("unknown"), "unknown");
}

#[test]
fn test_infer_license_from_text() {
    let mit_text = "Permission is hereby granted, free of charge, to any person obtaining a copy ... MIT";
    assert_eq!(infer_license_from_text(mit_text).as_deref(), Some("MIT"));

    let apache_text = "Licensed under the Apache License, Version 2.0 (the \"License\")";
    assert_eq!(infer_license_from_text(apache_text).as_deref(), Some("Apache-2.0"));
}

#[test]
fn test_extract_company_product_name() {
    let sample = "Company: ExampleCorp Product: SuperApp";
    assert!(extract_company_name(sample).is_some());
    assert!(extract_product_name(sample).is_some());
}

#[test]
fn test_calculate_confidences() {
    let mut versions = HashSet::new();
    versions.insert("1.0.0".to_string());
    let cv = calculate_version_confidence(&versions, &Some("1.0.0".to_string()));
    assert!(cv > 0.5);

    let licenses: HashSet<String> = ["MIT".to_string()].iter().cloned().collect();
    let spdx: HashSet<String> = ["MIT".to_string()].iter().cloned().collect();
    let texts = vec!["Permission is hereby granted".to_string()];
    let lc = calculate_license_confidence(&licenses, &spdx, &texts);
    assert!(lc > 0.5);
} 