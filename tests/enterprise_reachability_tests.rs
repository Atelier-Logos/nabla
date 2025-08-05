// tests/enterprise_reachability_tests.rs

use nabla_cli::binary::BinaryAnalysis;
use nabla_cli::enterprise::secure::reachability::{
    ControlFlowGraph, NodeType, ExploitabilityAnalysis
};

#[test]
fn test_control_flow_graph_creation() {
    let mut cfg = ControlFlowGraph::new();
    
    // Test basic graph creation
    assert_eq!(cfg.graph.node_count(), 0);
    assert_eq!(cfg.graph.edge_count(), 0);
}

#[test]
fn test_node_addition() {
    let mut cfg = ControlFlowGraph::new();
    
    // Add different types of nodes
    let entry_node = cfg.get_or_add_node(NodeType::EntryPoint);
    let func_node = cfg.get_or_add_node(NodeType::InternalFunction("test_func".to_string()));
    let import_node = cfg.get_or_add_node(NodeType::ImportedFunction("malloc".to_string()));
    let vuln_node = cfg.get_or_add_node(NodeType::VulnerableFunction("strcpy".to_string()));
    
    assert_eq!(cfg.graph.node_count(), 4);
    
    // Test that adding the same node returns the same index
    let entry_node2 = cfg.get_or_add_node(NodeType::EntryPoint);
    assert_eq!(entry_node, entry_node2);
    assert_eq!(cfg.graph.node_count(), 4); // Should not increase
}

#[test]
fn test_build_from_analysis() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec!["main".to_string(), "process_data".to_string()],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec!["malloc".to_string(), "strcpy".to_string(), "recv".to_string()],
        exports: vec![],
        hash_sha256: String::new(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
        binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
        entry_point: Some(0x1000),
        code_sections: vec![],
    };

    let cfg = ControlFlowGraph::build_from_analysis(&analysis);
    
    // Should have: 1 entry point + 2 internal functions + 3 imported functions = 6 nodes
    assert_eq!(cfg.graph.node_count(), 6);
    
    // Should have edges from entry point to internal functions (2 edges)
    // + edges from each internal function to each imported function (2 * 3 = 6 edges)
    // Total: 8 edges
    assert_eq!(cfg.graph.edge_count(), 8);
}

#[test]
fn test_exploitability_analysis_reachable() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec!["main".to_string()],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec!["recv".to_string(), "strcpy".to_string()],
        exports: vec![],
        hash_sha256: String::new(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
        binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
        entry_point: Some(0x1000),
        code_sections: vec![],
    };

    let mut cfg = ControlFlowGraph::build_from_analysis(&analysis);
    
    // Test exploitability analysis with recv as source and strcpy as sink
    let sources = vec!["recv".to_string()];
    let result = cfg.analyze_exploitability(&sources, "strcpy");
    
    assert_eq!(result.sink, "strcpy");
    assert!(result.is_reachable); // Should be reachable through the constructed CFG
    assert!(result.path.is_some());
}

#[test]
fn test_exploitability_analysis_unreachable() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec!["main".to_string()],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec!["malloc".to_string()],
        exports: vec![],
        hash_sha256: String::new(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
        binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
        entry_point: Some(0x1000),
        code_sections: vec![],
    };

    let mut cfg = ControlFlowGraph::build_from_analysis(&analysis);
    
    // Test with non-existent source function
    let sources = vec!["nonexistent_function".to_string()];
    let result = cfg.analyze_exploitability(&sources, "malloc");
    
    assert_eq!(result.sink, "malloc");
    assert!(!result.is_reachable); // Should not be reachable
    assert!(result.path.is_none());
}

#[test]
fn test_exploitability_analysis_empty_sources() {
    let analysis = BinaryAnalysis {
        id: uuid::Uuid::nil(),
        file_name: "test.bin".to_string(),
        format: "application/x-elf".to_string(),
        architecture: "x86_64".to_string(),
        languages: vec![],
        detected_symbols: vec!["main".to_string()],
        embedded_strings: vec![],
        suspected_secrets: vec![],
        imports: vec!["malloc".to_string()],
        exports: vec![],
        hash_sha256: String::new(),
        hash_blake3: None,
        size_bytes: 0,
        linked_libraries: vec![],
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        sbom: None,
        binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]),
        entry_point: Some(0x1000),
        code_sections: vec![],
    };

    let mut cfg = ControlFlowGraph::build_from_analysis(&analysis);
    
    // Test with empty sources
    let sources = vec![];
    let result = cfg.analyze_exploitability(&sources, "malloc");
    
    assert_eq!(result.sink, "malloc");
    assert!(!result.is_reachable); // Should not be reachable with no sources
    assert!(result.path.is_none());
}

#[test]
fn test_node_type_equality() {
    // Test NodeType equality and hashing
    let node1 = NodeType::EntryPoint;
    let node2 = NodeType::EntryPoint;
    let node3 = NodeType::InternalFunction("test".to_string());
    let node4 = NodeType::InternalFunction("test".to_string());
    let node5 = NodeType::InternalFunction("other".to_string());
    
    assert_eq!(node1, node2);
    assert_eq!(node3, node4);
    assert_ne!(node3, node5);
    assert_ne!(node1, node3);
}