use anyhow::Result;
use serde_json::Value as JsonValue;
use std::path::Path;
use syn::{visit::Visit, File, ItemStruct, ItemFn, ItemTrait, ItemMod, ItemMacro, ItemExternCrate, Visibility, Attribute};
use walkdir::WalkDir;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use quote::ToTokens;

pub struct SourceAnalysis {
    pub key_modules: JsonValue,
    pub important_structs: JsonValue,
    pub notable_functions: JsonValue,
    pub traits: JsonValue,
    pub api_examples: JsonValue,
    pub source_stats: JsonValue,
    pub macro_usage: JsonValue,
    pub build_rs_present: bool,
    pub public_api_surface: i64,
    pub external_crates: Vec<String>,
}

pub async fn analyze(package_path: &Path) -> Result<SourceAnalysis> {
    tracing::debug!("Running source analysis on {:?}", package_path);

    let mut analyzer = SourceCodeAnalyzer::new();
    
    // Walk through all Rust source files
    for entry in WalkDir::new(package_path) {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                analyzer.analyze_file(&content, path)?;
            }
        }
    }

    // Check for build.rs
    let build_rs_present = package_path.join("build.rs").exists();

    Ok(SourceAnalysis {
        key_modules: analyzer.get_key_modules(),
        important_structs: analyzer.get_important_structs(),
        notable_functions: analyzer.get_notable_functions(),
        traits: analyzer.get_traits(),
        api_examples: analyzer.get_api_examples(),
        source_stats: analyzer.get_source_stats(),
        macro_usage: analyzer.get_macro_usage(),
        build_rs_present,
        public_api_surface: analyzer.public_api_count,
        external_crates: analyzer.external_crates.into_iter().collect(),
    })
}

struct SourceCodeAnalyzer {
    
    _file_contents: HashMap<String, String>,
    _analysis: SourceAnalysis,
    modules: Vec<ModuleInfo>,
    structs: Vec<StructInfo>,
    functions: Vec<FunctionInfo>,
    traits: Vec<TraitInfo>,
    macros: std::collections::HashMap<String, usize>,
    external_crates: std::collections::HashSet<String>,
    public_api_count: i64,
    total_lines: usize,
    total_files: usize,
}

#[derive(Debug)]
struct ModuleInfo {
    name: String,
    path: String,
    is_public: bool,
    item_count: usize,
}

#[derive(Debug)]
struct StructInfo {
    name: String,
    path: String,
    is_public: bool,
    field_count: usize,
    derives: Vec<String>,
}

#[derive(Debug)]
struct FunctionInfo {
    name: String,
    path: String,
    is_public: bool,
    is_async: bool,
    param_count: usize,
    has_docs: bool,
}

#[derive(Debug)]
struct TraitInfo {
    name: String,
    path: String,
    is_public: bool,
    method_count: usize,
    has_docs: bool,
}

impl SourceCodeAnalyzer {
    fn new() -> Self {
        Self {
                        _file_contents: HashMap::new(),
            _analysis: SourceAnalysis {
                key_modules: JsonValue::Null,
                important_structs: JsonValue::Null,
                notable_functions: JsonValue::Null,
                traits: JsonValue::Null,
                api_examples: JsonValue::Null,
                source_stats: JsonValue::Null,
                macro_usage: JsonValue::Null,
                build_rs_present: false,
                public_api_surface: 0,
                external_crates: Vec::new(),
            },
            modules: Vec::new(),
            structs: Vec::new(),
            functions: Vec::new(),
            traits: Vec::new(),
            macros: std::collections::HashMap::new(),
            external_crates: std::collections::HashSet::new(),
            public_api_count: 0,
            total_lines: 0,
            total_files: 0,
        }
    }

    fn analyze_file(&mut self, content: &str, file_path: &Path) -> Result<()> {
        self.total_files += 1;
        self.total_lines += content.lines().count();

        match syn::parse_file(content) {
            Ok(file) => {
                let mut visitor = SourceVisitor {
                    analyzer: self,
                    current_file: file_path.to_string_lossy().to_string(),
                    _content: content,
                };
                visitor.visit_file(&file);
            }
            Err(_) => {
                tracing::warn!("Failed to parse file: {:?}", file_path);
            }
        }

        Ok(())
    }

    fn get_key_modules(&self) -> JsonValue {
        let mut modules: Vec<_> = self.modules.iter()
            .filter(|m| m.is_public || m.item_count > 5)
            .map(|m| serde_json::json!({
                "name": m.name,
                "path": m.path,
                "is_public": m.is_public,
                "item_count": m.item_count
            }))
            .collect();

        modules.sort_by(|a, b| {
            b.get("item_count").unwrap().as_u64().unwrap()
                .cmp(&a.get("item_count").unwrap().as_u64().unwrap())
        });

        JsonValue::Array(modules.into_iter().take(10).collect())
    }

    fn get_important_structs(&self) -> JsonValue {
        let mut structs: Vec<_> = self.structs.iter()
            .filter(|s| s.is_public || s.field_count > 3)
            .map(|s| serde_json::json!({
                "name": s.name,
                "path": s.path,
                "is_public": s.is_public,
                "field_count": s.field_count,
                "derives": s.derives
            }))
            .collect();

        structs.sort_by(|a, b| {
            b.get("field_count").unwrap().as_u64().unwrap()
                .cmp(&a.get("field_count").unwrap().as_u64().unwrap())
        });

        JsonValue::Array(structs.into_iter().take(20).collect())
    }

    fn get_notable_functions(&self) -> JsonValue {
        let mut functions: Vec<_> = self.functions.iter()
            .filter(|f| f.is_public || f.has_docs)
            .map(|f| serde_json::json!({
                "name": f.name,
                "path": f.path,
                "is_public": f.is_public,
                "is_async": f.is_async,
                "param_count": f.param_count,
                "has_docs": f.has_docs
            }))
            .collect();

        functions.sort_by(|a, b| {
            let a_score = if a.get("is_public").unwrap().as_bool().unwrap() { 2 } else { 0 } +
                          if a.get("has_docs").unwrap().as_bool().unwrap() { 1 } else { 0 };
            let b_score = if b.get("is_public").unwrap().as_bool().unwrap() { 2 } else { 0 } +
                          if b.get("has_docs").unwrap().as_bool().unwrap() { 1 } else { 0 };
            b_score.cmp(&a_score)
        });

        JsonValue::Array(functions.into_iter().take(30).collect())
    }

    fn get_traits(&self) -> JsonValue {
        let traits: Vec<_> = self.traits.iter()
            .map(|t| serde_json::json!({
                "name": t.name,
                "path": t.path,
                "is_public": t.is_public,
                "method_count": t.method_count,
                "has_docs": t.has_docs
            }))
            .collect();

        JsonValue::Array(traits)
    }

    fn get_api_examples(&self) -> JsonValue {
        // For now, return empty - would need more sophisticated analysis
        // to extract actual usage examples
        JsonValue::Array(vec![])
    }

    fn get_source_stats(&self) -> JsonValue {
        serde_json::json!({
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "modules_count": self.modules.len(),
            "structs_count": self.structs.len(),
            "functions_count": self.functions.len(),
            "traits_count": self.traits.len(),
            "public_api_surface": self.public_api_count
        })
    }

    fn get_macro_usage(&self) -> JsonValue {
        let macro_usage: Vec<_> = self.macros.iter()
            .map(|(name, count)| serde_json::json!({
                "macro_name": name,
                "usage_count": count
            }))
            .collect();

        JsonValue::Array(macro_usage)
    }
}

struct SourceVisitor<'a> {
    analyzer: &'a mut SourceCodeAnalyzer,
    current_file: String,
    _content: &'a str,
}

impl<'a> Visit<'a> for SourceVisitor<'a> {
    fn visit_item_mod(&mut self, node: &'a ItemMod) {
        let is_public = matches!(node.vis, Visibility::Public(_));
        
        if is_public {
            self.analyzer.public_api_count += 1;
        }

        self.analyzer.modules.push(ModuleInfo {
            name: node.ident.to_string(),
            path: self.current_file.to_string(),
            is_public,
            item_count: node.content.as_ref().map(|(_, items)| items.len()).unwrap_or(0),
        });

        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_struct(&mut self, node: &'a ItemStruct) {
        let is_public = matches!(node.vis, Visibility::Public(_));
        
        if is_public {
            self.analyzer.public_api_count += 1;
        }

        let field_count = match &node.fields {
            syn::Fields::Named(fields) => fields.named.len(),
            syn::Fields::Unnamed(fields) => fields.unnamed.len(),
            syn::Fields::Unit => 0,
        };

        let derives = node.attrs.iter()
            .filter_map(|attr| {
                if attr.path().is_ident("derive") {
                    Some("derive".to_string())
                } else {
                    None
                }
            })
            .collect();

        self.analyzer.structs.push(StructInfo {
            name: node.ident.to_string(),
            path: self.current_file.to_string(),
            is_public,
            field_count,
            derives,
        });

        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_fn(&mut self, node: &'a ItemFn) {
        let is_public = matches!(node.vis, Visibility::Public(_));
        
        if is_public {
            self.analyzer.public_api_count += 1;
        }

        let has_docs = node.attrs.iter().any(|attr| 
            attr.path().is_ident("doc") || attr.to_token_stream().to_string().starts_with("///")
        );

        self.analyzer.functions.push(FunctionInfo {
            name: node.sig.ident.to_string(),
            path: self.current_file.to_string(),
            is_public,
            is_async: node.sig.asyncness.is_some(),
            param_count: node.sig.inputs.len(),
            has_docs,
        });

        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_trait(&mut self, node: &'a ItemTrait) {
        let is_public = matches!(node.vis, Visibility::Public(_));
        
        if is_public {
            self.analyzer.public_api_count += 1;
        }

        let has_docs = node.attrs.iter().any(|attr| 
            attr.path().is_ident("doc") || attr.to_token_stream().to_string().starts_with("///")
        );

        self.analyzer.traits.push(TraitInfo {
            name: node.ident.to_string(),
            path: self.current_file.to_string(),
            is_public,
            method_count: node.items.len(),
            has_docs,
        });

        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_extern_crate(&mut self, node: &'a ItemExternCrate) {
        let crate_name = node.ident.to_string();
        self.analyzer.external_crates.insert(crate_name);
        
        syn::visit::visit_item_extern_crate(self, node);
    }

    fn visit_item_macro(&mut self, node: &'a ItemMacro) {
        if let Some(ident) = &node.ident {
            let macro_name = ident.to_string();
            *self.analyzer.macros.entry(macro_name).or_insert(0) += 1;
        }
        
        syn::visit::visit_item_macro(self, node);
    }
} 