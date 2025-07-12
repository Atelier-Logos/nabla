use anyhow::Result;
use serde_json::Value as JsonValue;
use std::path::Path;
use syn::{visit::Visit, ItemFn, Block, ExprUnsafe};
use walkdir::WalkDir;
use serde_json::json;

pub struct UnsafeAnalysis {
    pub uses_unsafe: bool,
    pub locations: JsonValue,
}

#[derive(Debug, Clone)]
struct UnsafeBlockInfo {
    location: String,
    function: Option<String>,
    line: Option<usize>,
    reason: String,
}

pub async fn analyze(package_path: &Path) -> Result<UnsafeAnalysis> {
    tracing::debug!("Running unsafe detection analysis on {:?}", package_path);

    let mut unsafe_locations = Vec::new();
    let mut uses_unsafe = false;

    // Walk through all Rust source files
    for entry in WalkDir::new(package_path) {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                let locations = find_unsafe_in_file(&content, path)?;
                if !locations.is_empty() {
                    uses_unsafe = true;
                    unsafe_locations.extend(locations);
                }
            }
        }
    }

    Ok(UnsafeAnalysis {
        uses_unsafe,
        locations: JsonValue::Array(unsafe_locations),
    })
}

fn find_unsafe_in_file(content: &str, file_path: &Path) -> Result<Vec<JsonValue>> {
    let mut locations = Vec::new();

    // Try to parse the file
    match syn::parse_file(content) {
        Ok(file) => {
            let mut visitor = UnsafeVisitor::new();
            visitor.visit_file(&file);
            
            // Convert visitor results to JSON
            for unsafe_block in visitor.unsafe_blocks {
                locations.push(json!({
                    "file": file_path.to_string_lossy(),
                    "location": unsafe_block.location,
                    "function": unsafe_block.function,
                    "line": unsafe_block.line,
                    "reason": unsafe_block.reason
                }));
            }
        }
        Err(_) => {
            // If parsing fails, use regex as fallback
            locations.extend(find_unsafe_with_regex(content, file_path));
        }
    }

    Ok(locations)
}

struct UnsafeVisitor {
    unsafe_blocks: Vec<UnsafeBlockInfo>,
    current_function: Option<String>,
}

impl UnsafeVisitor {
    fn new() -> Self {
        Self {
            unsafe_blocks: Vec::new(),
            current_function: None,
        }
    }

    fn record_unsafe_block(&mut self, location: String) {
        let unsafe_info = UnsafeBlockInfo {
            location,
            function: self.current_function.clone(),
            line: None, // We'll leave line numbers as None since span info is complex
            reason: "Unsafe block detected".to_string(),
        };
        self.unsafe_blocks.push(unsafe_info);
    }
}

impl<'ast> Visit<'ast> for UnsafeVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let old_function = self.current_function.clone();
        self.current_function = Some(node.sig.ident.to_string());
        
        // Check if function is marked unsafe
        if node.sig.unsafety.is_some() {
            self.record_unsafe_block("unsafe function".to_string());
        }
        
        syn::visit::visit_item_fn(self, node);
        
        self.current_function = old_function;
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.record_unsafe_block("unsafe block".to_string());
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_block(&mut self, node: &'ast Block) {
        syn::visit::visit_block(self, node);
    }
}

fn find_unsafe_with_regex(content: &str, file_path: &Path) -> Vec<JsonValue> {
    let mut locations = Vec::new();
    
    for (line_num, line) in content.lines().enumerate() {
        if line.contains("unsafe") {
            locations.push(json!({
                "file": file_path.to_string_lossy(),
                "line": line_num + 1,
                "column": 0,
                "type": "unsafe (regex match)",
                "context": line.trim()
            }));
        }
    }

    locations
} 