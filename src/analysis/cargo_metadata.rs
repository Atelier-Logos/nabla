use anyhow::Result;
use cargo_metadata::{MetadataCommand, Metadata};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct MetadataResult {
    pub description: Option<String>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
    pub features: JsonValue,
    pub dependencies: JsonValue,
}

pub async fn analyze(package_path: &Path) -> Result<MetadataResult> {
    tracing::debug!("Running cargo metadata analysis on {:?}", package_path);

    let metadata = MetadataCommand::new()
        .manifest_path(package_path.join("Cargo.toml"))
        .no_deps()
        .exec()?;

    let package = metadata
        .packages
        .iter()
        .find(|p| metadata.workspace_members.contains(&p.id))
        .or_else(|| metadata.packages.first())
        .ok_or_else(|| anyhow::anyhow!("No package found in metadata"))?;

    // Extract features
    let features = serde_json::to_value(&package.features)?;

    // Build dependency graph
    let dependencies = build_dependency_graph(&metadata)?;

    Ok(MetadataResult {
        description: package.description.clone(),
        repository: package.repository.clone(),
        homepage: package.homepage.clone(),
        documentation: package.documentation.clone(),
        features,
        dependencies,
    })
}

fn build_dependency_graph(metadata: &Metadata) -> Result<JsonValue> {
    let mut dependency_graph = serde_json::Map::new();

    for package in &metadata.packages {
        let mut deps = Vec::new();
        
        for dependency in &package.dependencies {
            deps.push(serde_json::json!({
                "name": dependency.name,
                "version_req": dependency.req.to_string(),
                "kind": format!("{:?}", dependency.kind),
                "optional": dependency.optional,
                "features": dependency.features
            }));
        }

        dependency_graph.insert(
            format!("{}:{}", package.name, package.version),
            JsonValue::Array(deps.into_iter().collect())
        );
    }

    Ok(JsonValue::Object(dependency_graph))
} 