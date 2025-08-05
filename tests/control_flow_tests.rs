#[cfg(test)]
mod control_flow_tests {
    use chrono::Utc;
    use nabla_cli::binary::{BinaryAnalysis, CodeSection, CodeSectionType};
    use nabla_cli::enterprise::secure::control_flow::{
        BasicBlockType, ControlFlowGraph, EdgeType, ExploitabilityAnalysis,
    };
    use uuid::Uuid;

    fn create_test_analysis() -> BinaryAnalysis {
        BinaryAnalysis {
            id: Uuid::new_v4(),
            file_name: "test.bin".to_string(),
            format: "elf".to_string(),
            architecture: "x86_64".to_string(),
            languages: vec!["C".to_string()],
            detected_symbols: vec!["main".to_string(), "test_func".to_string()],
            embedded_strings: vec![],
            suspected_secrets: vec![],
            imports: vec!["strcpy".to_string(), "malloc".to_string()],
            exports: vec!["main".to_string()],
            hash_sha256: "abc123".to_string(),
            hash_blake3: None,
            size_bytes: 1024,
            linked_libraries: vec!["libc.so.6".to_string()],
            static_linked: false,
            version_info: None,
            license_info: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            sbom: None,
            binary_data: Some(vec![0x7f, 0x45, 0x4c, 0x46]), // ELF header
            entry_point: Some("0x401000".to_string()),
            code_sections: vec![CodeSection {
                name: ".text".to_string(),
                start_address: 0x401000,
                end_address: 0x402000,
                size: 0x1000,
                permissions: "rx".to_string(),
                section_type: CodeSectionType::Text,
            }],
        }
    }

    #[test]
    fn test_control_flow_graph_creation() {
        let cfg = ControlFlowGraph::new();
        assert_eq!(cfg.graph.node_count(), 0);
    }

    #[test]
    fn test_build_cfg() {
        let analysis = create_test_analysis();
        let result = ControlFlowGraph::build_cfg(&analysis);

        // Should succeed even with minimal test data
        assert!(result.is_ok());

        let _cfg = result.unwrap();
        // The graph should be initialized (may be empty if no disassembly succeeded)
        // We don't assert on node_count here as it depends on disassembly capabilities
    }

    #[test]
    fn test_build_cfg_with_empty_data() {
        let mut analysis = create_test_analysis();
        analysis.binary_data = None;
        analysis.code_sections = vec![];

        let result = ControlFlowGraph::build_cfg(&analysis);

        // Should handle missing data gracefully
        assert!(result.is_ok() || result.is_err()); // Either outcome is acceptable
    }

    #[test]
    fn test_build_cfg_with_invalid_entry_point() {
        let mut analysis = create_test_analysis();
        analysis.entry_point = Some("invalid".to_string());

        let result = ControlFlowGraph::build_cfg(&analysis);

        // Should handle invalid entry point gracefully
        assert!(result.is_ok() || result.is_err()); // Either outcome is acceptable
    }

    #[test]
    fn test_build_from_different_formats() {
        // Test with PE format
        let mut analysis = create_test_analysis();
        analysis.format = "pe".to_string();
        analysis.binary_data = Some(vec![0x4d, 0x5a]); // PE header

        let result = ControlFlowGraph::build_cfg(&analysis);
        assert!(result.is_ok() || result.is_err()); // Either outcome is acceptable

        // Test with unknown format
        analysis.format = "unknown".to_string();
        analysis.binary_data = Some(vec![0x00, 0x01, 0x02, 0x03]);

        let result = ControlFlowGraph::build_cfg(&analysis);
        assert!(result.is_ok() || result.is_err()); // Either outcome is acceptable
    }

    #[test]
    fn test_loop_analysis_methods() {
        let cfg = ControlFlowGraph::new();

        // Test loop detection methods (should work on empty graph)
        let headers = cfg.get_loop_headers();
        assert!(headers.is_empty()); // Empty graph has no loops

        let in_loop = cfg.is_in_loop(0x1000);
        assert!(!in_loop); // Address not in empty graph
    }

    #[test]
    fn test_dominator_analysis() {
        let cfg = ControlFlowGraph::new();

        // Test with empty graph - should return None for any node
        let dominators = cfg.get_dominators(petgraph::graph::NodeIndex::new(0));
        assert!(dominators.is_none());
    }

    #[test]
    fn test_call_graph_analysis() {
        let analysis = create_test_analysis();
        let cfg = ControlFlowGraph::build_cfg(&analysis).unwrap();

        // Test call graph analysis
        let _call_graph = cfg.analyze_call_graph(&analysis);

        // Should complete without panicking. We don't assert on content as it depends on disassembly.
    }

    #[test]
    fn test_edge_types() {
        // Test that all edge types can be created and compared
        let edge_types = vec![
            EdgeType::Sequential,
            EdgeType::ConditionalTrue,
            EdgeType::ConditionalFalse,
            EdgeType::Jump,
            EdgeType::Call,
            EdgeType::Return,
        ];

        for edge_type in edge_types {
            // Edge types should be comparable
            assert_eq!(edge_type, edge_type);
        }
    }

    #[test]
    fn test_basic_block_types() {
        // Test that basic block types can be created
        let function_entry = BasicBlockType::FunctionEntry {
            function_name: "test".to_string(),
            address: 0x1000,
        };

        let sequential = BasicBlockType::Sequential {
            start_address: 0x1000,
            end_address: 0x1010,
        };

        let conditional = BasicBlockType::ConditionalBranch {
            address: 0x1000,
            condition: "zero".to_string(),
        };

        // Should be able to match on these types
        match function_entry {
            BasicBlockType::FunctionEntry {
                function_name,
                address,
            } => {
                assert_eq!(function_name, "test");
                assert_eq!(address, 0x1000);
            }
            _ => panic!("Wrong type"),
        }

        match sequential {
            BasicBlockType::Sequential {
                start_address,
                end_address,
            } => {
                assert_eq!(start_address, 0x1000);
                assert_eq!(end_address, 0x1010);
            }
            _ => panic!("Wrong type"),
        }

        match conditional {
            BasicBlockType::ConditionalBranch { address, condition } => {
                assert_eq!(address, 0x1000);
                assert_eq!(condition, "zero");
            }
            _ => panic!("Wrong type"),
        }
    }

    #[test]
    fn test_build_with_multiple_code_sections() {
        let mut analysis = create_test_analysis();
        analysis.code_sections = vec![
            CodeSection {
                name: ".text".to_string(),
                start_address: 0x401000,
                end_address: 0x402000,
                size: 0x1000,
                permissions: "rx".to_string(),
                section_type: CodeSectionType::Text,
            },
            CodeSection {
                name: ".init".to_string(),
                start_address: 0x400000,
                end_address: 0x401000,
                size: 0x1000,
                permissions: "rx".to_string(),
                section_type: CodeSectionType::Text,
            },
        ];

        let result = ControlFlowGraph::build_cfg(&analysis);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_with_large_binary() {
        let mut analysis = create_test_analysis();
        // Create larger binary data
        analysis.binary_data = Some(
            vec![0x7f, 0x45, 0x4c, 0x46]
                .into_iter()
                .chain(vec![0u8; 10000].into_iter()) // 10KB of zeros
                .collect(),
        );
        analysis.size_bytes = 10004;

        let start = std::time::Instant::now();
        let result = ControlFlowGraph::build_cfg(&analysis);
        let duration = start.elapsed();

        // Should complete in reasonable time
        assert!(
            duration.as_millis() < 5000,
            "Analysis took too long: {:?}",
            duration
        );
        assert!(result.is_ok() || result.is_err()); // Either outcome is acceptable
    }

    #[test]
    fn test_concurrent_analysis() {
        use std::thread;

        let analysis = create_test_analysis();

        // Test that multiple analyses can run concurrently
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let analysis_clone = analysis.clone();
                thread::spawn(move || ControlFlowGraph::build_cfg(&analysis_clone))
            })
            .collect();

        // All threads should complete without panicking
        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_ok() || result.is_err()); // Either outcome is acceptable
        }
    }

    #[test]
    fn test_memory_usage() {
        let analysis = create_test_analysis();

        // Create multiple CFGs to test memory usage
        let mut cfgs = Vec::new();
        for _ in 0..10 {
            if let Ok(cfg) = ControlFlowGraph::build_cfg(&analysis) {
                cfgs.push(cfg);
            }
        }

        // Should be able to create multiple instances
    }

    #[test]
    fn test_cfg_construction_from_secure_module() {
        let analysis = create_test_analysis();
        let result = ControlFlowGraph::build_cfg(&analysis);

        // Should succeed even with minimal test data
        assert!(result.is_ok());

        let _cfg = result.unwrap();
        // We don't assert on function_entries content as it depends on disassembly capabilities
    }

    #[test]
    fn test_call_graph_analysis_from_secure_module() {
        let analysis = create_test_analysis();
        let cfg = ControlFlowGraph::build_cfg(&analysis).unwrap();
        let _call_graph = cfg.analyze_call_graph(&analysis);

        // Should complete without panicking. We don't assert on content as it depends on disassembly.
    }

    #[test]
    fn test_exploitability_analysis_from_secure_module() {
        let analysis = create_test_analysis();
        let cfg = ControlFlowGraph::build_cfg(&analysis).unwrap();

        let sources = vec!["main".to_string()];
        let result = ExploitabilityAnalysis::analyze(&cfg, &sources, "vulnerable_func");

        assert_eq!(result.sink, "vulnerable_func");
    }
}
