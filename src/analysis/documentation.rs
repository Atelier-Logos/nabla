use anyhow::Result;
use serde_json::Value as JsonValue;
use std::path::Path;
use syn::{visit::Visit, ItemFn, ItemStruct, ItemTrait, ItemMod, Visibility};
use walkdir::WalkDir;
use tokio::process::Command;
use std::collections::HashMap;
use quote::ToTokens;

pub struct DocsAnalysis {
    pub quality_score: JsonValue,
}

pub async fn analyze(package_path: &Path) -> Result<DocsAnalysis> {
    tracing::debug!("Running documentation analysis on {:?}", package_path);

    // Try to generate docs and capture output
    let rustdoc_result = run_rustdoc_analysis(package_path).await;
    
    // Analyze source code for documentation coverage
    let coverage_analysis = analyze_doc_coverage(package_path).await?;
    
    let quality_score = serde_json::json!({
        "coverage_percentage": coverage_analysis.coverage_percentage,
        "total_items": coverage_analysis.total_items,
        "documented_items": coverage_analysis.documented_items,
        "missing_docs": coverage_analysis.missing_docs,
        "doc_comments_count": coverage_analysis.doc_comments_count,
        "rustdoc_success": rustdoc_result.is_ok(),
        "rustdoc_output": rustdoc_result.unwrap_or_else(|e| format!("Error: {}", e))
    });

    Ok(DocsAnalysis {
        quality_score,
    })
}

async fn run_rustdoc_analysis(package_path: &Path) -> Result<String> {
    // Try to run rustdoc with JSON output
    let output = Command::new("rustdoc")
        .args([
            "--output-format", "json",
            "--document-private-items",
            "--", 
            "src/lib.rs"
        ])
        .current_dir(package_path)
        .output()
        .await?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        // Fall back to cargo doc
        let cargo_output = Command::new("cargo")
            .args(["doc", "--no-deps", "--quiet"])
            .current_dir(package_path)
            .output()
            .await?;
            
        if cargo_output.status.success() {
            Ok("Documentation generated successfully".to_string())
        } else {
            anyhow::bail!("Failed to generate documentation: {}", 
                String::from_utf8_lossy(&cargo_output.stderr))
        }
    }
}

#[derive(Default)]
struct DocCoverageAnalysis {
    coverage_percentage: f64,
    total_items: usize,
    documented_items: usize,
    missing_docs: Vec<String>,
    doc_comments_count: usize,
}

async fn analyze_doc_coverage(package_path: &Path) -> Result<DocCoverageAnalysis> {
    let mut analysis = DocCoverageAnalysis::default();
    
    // Walk through all Rust source files
    for entry in WalkDir::new(package_path) {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                analyze_file_docs(&content, path, &mut analysis)?;
            }
        }
    }

    // Calculate coverage percentage
    if analysis.total_items > 0 {
        analysis.coverage_percentage = 
            (analysis.documented_items as f64 / analysis.total_items as f64) * 100.0;
    }

    Ok(analysis)
}

fn analyze_file_docs(content: &str, file_path: &Path, analysis: &mut DocCoverageAnalysis) -> Result<()> {
    // Count total doc comments
    analysis.doc_comments_count += content.lines()
        .filter(|line| line.trim_start().starts_with("///") || line.trim_start().starts_with("//!"))
        .count();

    // Parse the file and analyze documentation coverage
    match syn::parse_file(content) {
        Ok(file) => {
            let mut visitor = DocVisitor {
                analysis,
                file_path,
            };
            visitor.visit_file(&file);
        }
        Err(_) => {
            tracing::warn!("Failed to parse file for doc analysis: {:?}", file_path);
        }
    }

    Ok(())
}

struct DocVisitor<'a> {
    analysis: &'a mut DocCoverageAnalysis,
    file_path: &'a Path,
}

impl<'a> Visit<'a> for DocVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'a ItemFn) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.analysis.total_items += 1;
            
            let has_docs = has_doc_comments(&node.attrs);
            if has_docs {
                self.analysis.documented_items += 1;
            } else {
                self.analysis.missing_docs.push(
                    format!("Function '{}' in {}", node.sig.ident, self.file_path.display())
                );
            }
        }
        
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'a ItemStruct) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.analysis.total_items += 1;
            
            let has_docs = has_doc_comments(&node.attrs);
            if has_docs {
                self.analysis.documented_items += 1;
            } else {
                self.analysis.missing_docs.push(
                    format!("Struct '{}' in {}", node.ident, self.file_path.display())
                );
            }
        }
        
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_trait(&mut self, node: &'a ItemTrait) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.analysis.total_items += 1;
            
            let has_docs = has_doc_comments(&node.attrs);
            if has_docs {
                self.analysis.documented_items += 1;
            } else {
                self.analysis.missing_docs.push(
                    format!("Trait '{}' in {}", node.ident, self.file_path.display())
                );
            }
        }
        
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_mod(&mut self, node: &'a ItemMod) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.analysis.total_items += 1;
            
            let has_docs = has_doc_comments(&node.attrs);
            if has_docs {
                self.analysis.documented_items += 1;
            } else {
                self.analysis.missing_docs.push(
                    format!("Module '{}' in {}", node.ident, self.file_path.display())
                );
            }
        }
        
        syn::visit::visit_item_mod(self, node);
    }
}

fn has_doc_comments(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("doc") || 
        attr.to_token_stream().to_string().contains("///") ||
        attr.to_token_stream().to_string().contains("//!")
    })
} 