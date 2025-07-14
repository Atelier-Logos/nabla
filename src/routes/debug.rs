// Debug route for multipart analysis
use axum::{
    extract::{Multipart, State},
    response::Json,
    http::StatusCode,
};
use serde::Serialize;
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct MultipartDebugInfo {
    pub fields: Vec<FieldInfo>,
    pub total_fields: usize,
}

#[derive(Debug, Serialize)]
pub struct FieldInfo {
    pub field_name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub size_bytes: usize,
    pub content_preview: String,
}

pub async fn debug_multipart(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<MultipartDebugInfo>, StatusCode> {
    let mut fields = Vec::new();
    
    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        let field_name = field.name().unwrap_or("unknown").to_string();
        let filename = field.file_name().map(|s| s.to_string());
        let content_type = field.content_type().map(|s| s.to_string());
        
        let contents = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
        let size_bytes = contents.len();
        
        // Create a safe preview of the content
        let content_preview = if contents.len() <= 100 {
            String::from_utf8_lossy(&contents).to_string()
        } else {
            format!("{}... (truncated)", String::from_utf8_lossy(&contents[..100]))
        };
        
        fields.push(FieldInfo {
            field_name,
            filename,
            content_type,
            size_bytes,
            content_preview,
        });
    }
    
    Ok(Json(MultipartDebugInfo {
        total_fields: fields.len(),
        fields,
    }))
}
