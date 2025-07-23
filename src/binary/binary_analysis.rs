use super::{BinaryAnalysis, extract_version_info, extract_license_info};
use chrono::Utc;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use blake3;
use goblin::{Object as GoblinObject, pe::PE, elf::Elf, mach::{Mach, MachO, load_command::CommandVariant}};
use object::{Object, ObjectSymbol};
use wasmparser::{Parser, Payload};
use infer;
use std::collections::HashSet;

pub async fn analyze_binary(file_name: &str, contents: &[u8]) -> anyhow::Result<BinaryAnalysis> {
    tracing::info!("Starting binary analysis for '{}' ({} bytes)", file_name, contents.len());
    
    // Early validation for very small files
    if contents.len() < 50 {
        tracing::warn!("File is very small ({} bytes), likely not a binary executable", contents.len());
        return analyze_small_file(file_name, contents);
    }
    
    let sha256_hash = Sha256::digest(contents);
    let blake3_hash = blake3::hash(contents);
    
    // Detect file type with more detailed logging
    let detected_type = infer::get(contents);
    let file_type = if let Some(kind) = detected_type {
        tracing::info!("Detected file type: {} ({})", kind.mime_type(), kind.extension());
        kind.mime_type().to_string()
    } else {
        tracing::debug!("Could not detect file type, using fallback");
        detect_file_type_fallback(file_name, contents)
    };
    
    let mut analysis = BinaryAnalysis {
        id: Uuid::new_v4(),
        file_name: file_name.to_string(),
        format: file_type.clone(),
        architecture: "unknown".to_string(),
        languages: Vec::new(),
        detected_symbols: Vec::new(),
        embedded_strings: extract_strings(contents),
        suspected_secrets: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        hash_sha256: format!("{:x}", sha256_hash),
        hash_blake3: Some(blake3_hash.to_hex().to_string()),
        size_bytes: contents.len() as u64,
        linked_libraries: Vec::new(),
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        sbom: None,
    };

    // Try different parsing strategies based on file type and magic bytes
    let mut parsed_successfully = false;
    
    if contents.len() >= 4 {
        match &contents[0..4] {
            [0x7f, b'E', b'L', b'F'] => {
                tracing::info!("ELF magic detected, using goblin ELF parser");
                if let Ok(GoblinObject::Elf(elf)) = GoblinObject::parse(contents) {
                    analyze_elf(&mut analysis, &elf, contents)?;
                    parsed_successfully = true;
                }
            }
            [b'M', b'Z', _, _] => {
                tracing::info!("PE magic detected, using goblin PE parser");
                if let Ok(GoblinObject::PE(pe)) = GoblinObject::parse(contents) {
                    analyze_pe(&mut analysis, &pe, contents)?;
                    parsed_successfully = true;
                }
            }
            [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => {
                tracing::info!("Mach-O magic detected, using goblin Mach-O parser");
                if let Ok(GoblinObject::Mach(mach)) = GoblinObject::parse(contents) {
                    match mach {
                        goblin::mach::Mach::Fat(_) => {
                            analysis.format = "macho-fat".to_string();
                            analysis.architecture = "multi".to_string();
                        }
                        goblin::mach::Mach::Binary(macho) => analyze_macho(&mut analysis, &macho, contents)?,
                    }
                    parsed_successfully = true;
                }
            }
            [0x00, 0x61, 0x73, 0x6d] => {
                tracing::info!("WASM magic detected, using wasmparser");
                if analyze_wasm(&mut analysis, contents).is_ok() {
                    parsed_successfully = true;
                }
            }
            _ => {}
        }
    }
    
    if !parsed_successfully {
        tracing::debug!("No specific magic bytes found, attempting generic goblin parsing...");
        match GoblinObject::parse(contents) {
            Ok(obj) => {
                tracing::info!("Successfully parsed with goblin (generic)");
                match obj {
                    GoblinObject::Elf(elf) => {
                        tracing::info!("Detected ELF binary (generic)");
                        analyze_elf(&mut analysis, &elf, contents)?;
                        parsed_successfully = true;
                    }
                    GoblinObject::PE(pe) => {
                        tracing::info!("Detected PE binary (generic)");
                        analyze_pe(&mut analysis, &pe, contents)?;
                        parsed_successfully = true;
                    }
                    GoblinObject::Mach(mach) => {
                        tracing::info!("Detected Mach-O binary (generic)");
                        match mach {
                            goblin::mach::Mach::Fat(_) => {
                                analysis.format = "macho-fat".to_string();
                                analysis.architecture = "multi".to_string();
                            }
                            goblin::mach::Mach::Binary(macho) => analyze_macho(&mut analysis, &macho, contents)?,
                        }
                        parsed_successfully = true;
                    }
                    GoblinObject::Archive(_) => {
                        tracing::info!("Detected archive");
                        analysis.format = "archive".to_string();
                        parsed_successfully = true;
                    }
                    _ => {
                        tracing::debug!("Unknown goblin object type");
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Goblin parsing failed: {}, trying WebAssembly", e);
                if analyze_wasm(&mut analysis, contents).is_ok() {
                    tracing::info!("Successfully parsed as WebAssembly");
                    parsed_successfully = true;
                }
            }
        }
    }
    
    if !parsed_successfully {
        tracing::info!("All specialized parsers failed, using generic analysis");
        analyze_unknown_binary(&mut analysis, contents)?;
    } else {
        tracing::info!("Successfully analyzed {} as {}", file_name, analysis.format);
    }

    // Extract version and license information
    tracing::debug!("Extracting version and license metadata");
    analysis.version_info = Some(extract_version_info(contents, &analysis.embedded_strings, &analysis.format));
    analysis.license_info = Some(extract_license_info(&analysis.embedded_strings));
    
    tracing::info!("Metadata extraction complete: version_confidence={:.2}, license_confidence={:.2}", 
                   analysis.version_info.as_ref().map(|v| v.confidence).unwrap_or(0.0),
                   analysis.license_info.as_ref().map(|l| l.confidence).unwrap_or(0.0));

    Ok(analysis)
}

fn analyze_macho(analysis: &mut BinaryAnalysis, macho: &MachO, contents: &[u8]) -> anyhow::Result<()> {
    analysis.format = "macho".to_string();

    // Determine architecture
    analysis.architecture = match macho.header.cputype() {
        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => "x86_64".to_string(),
        goblin::mach::constants::cputype::CPU_TYPE_ARM64 => "aarch64".to_string(),
        goblin::mach::constants::cputype::CPU_TYPE_X86 => "i386".to_string(),
        _ => format!("unknown({})", macho.header.cputype()),
    };

    // Extract symbols (both regular and dynamic)
    let mut symbol_set = HashSet::new();
    if let Some(symbols) = &macho.symbols {
        for symbol in symbols.iter() {
            if let Ok((name, _)) = symbol {
                if !name.is_empty() {
                    symbol_set.insert(name.to_string());
                    analysis.detected_symbols.push(name.to_string());
                }
            }
        }
    }

    // Extract libraries and frameworks
    for lib in &macho.libs {
        let lib_name = lib.to_string();
        analysis.linked_libraries.push(lib_name.clone());
        // Add to embedded strings for version extraction
        analysis.embedded_strings.push(lib_name.clone());
        // Extract potential version info from library name (e.g., libcrypto.1.1.dylib)
        if let Some(version) = extract_version_from_lib_name(&lib_name) {
            analysis.embedded_strings.push(version);
        }
    }

    // Use object crate for detailed import/export analysis
    if let Ok(obj_file) = object::File::parse(contents) {
        for symbol in obj_file.symbols() {
            if let Ok(name) = symbol.name() {
                if !name.is_empty() {
                    if symbol.is_undefined() {
                        analysis.imports.push(name.to_string());
                        analysis.embedded_strings.push(name.to_string());
                    } else if symbol.is_global() {
                        analysis.exports.push(name.to_string());
                    }
                    symbol_set.insert(name.to_string());
                }
            }
        }
    }

    // Extract additional metadata from load commands
    let mut metadata = serde_json::json!({
        "analysis_type": "macho",
        "load_commands": [],
        "frameworks": [],
        "min_os_version": null,
    });

    // Process load commands for frameworks and version info
    for lc in macho.load_commands.iter() {
        match lc.command {
            CommandVariant::LoadDylib(ref dylib) => {
                let offset = dylib.dylib.name as usize;
                if offset < contents.len() {
                    let name_bytes = &contents[offset..];
                    if let Some(end) = name_bytes.iter().position(|&b| b == 0) {
                        if let Ok(name_str) = std::str::from_utf8(&name_bytes[..end]) {
                            if name_str.contains(".framework") {
                                metadata["frameworks"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(serde_json::Value::String(name_str.to_string()));
                                analysis.embedded_strings.push(name_str.to_string());
                            }
                        }
                    }
                }
            }
            CommandVariant::VersionMinMacosx(ref ver) => {
                let (major, minor) = unpack_version(ver.version);
                metadata["min_os_version"] = serde_json::Value::String(format!("{}.{}", major, minor));
            }
            CommandVariant::BuildVersion(ref build) => {
                let (major, minor) = unpack_version(build.minos);
                metadata["min_os_version"] = serde_json::Value::String(format!("{}.{}", major, minor));
            }
            _ => {}
        }
        metadata["load_commands"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String(format!("{:?}", lc.command)));
    }

    // Detect static linking
    analysis.static_linked = macho.libs.is_empty() && symbol_set.iter().any(|s| s.contains("main"));

    // Extract potential CPE identifiers for CVE matching
    let cpe_candidates = extract_cpe_candidates(&analysis.linked_libraries, &analysis.imports, &analysis.detected_symbols);
    analysis.metadata = serde_json::json!({
        "macho_metadata": metadata,
        "cpe_candidates": cpe_candidates,
    });

    tracing::info!(
        "Mach-O analysis complete: {} symbols, {} libraries, {} imports, {} exports",
        analysis.detected_symbols.len(),
        analysis.linked_libraries.len(),
        analysis.imports.len(),
        analysis.exports.len()
    );

    Ok(())
}

// Helper function to extract version from library names
fn extract_version_from_lib_name(lib_name: &str) -> Option<String> {
    let parts: Vec<&str> = lib_name.split('.').collect();
    for part in parts {
        if part.chars().all(|c| c.is_digit(10) || c == '.') {
            return Some(part.to_string());
        }
    }
    None
}

// Helper function to unpack Mach-O version numbers (u32) into major and minor components
fn unpack_version(version: u32) -> (u32, u32) {
    let major = (version >> 16) & 0xFFFF;
    let minor = (version >> 8) & 0xFF;
    (major, minor)
}

// Helper function to generate CPE-like identifiers
fn extract_cpe_candidates(libs: &[String], imports: &[String], symbols: &[String]) -> Vec<String> {
    let mut cpes = HashSet::new();
    for item in libs.iter().chain(imports.iter()).chain(symbols.iter()) {
        let item_lower = item.to_lowercase();
        // Example: Convert "libcrypto.1.1.dylib" to "cpe:2.3:a:openssl:openssl:1.1:*:*:*:*:*:*:*"
        if item_lower.contains("openssl") || item_lower.contains("libcrypto") || item_lower.contains("libssl") {
            if let Some(version) = extract_version_from_lib_name(&item_lower) {
                cpes.insert(format!("cpe:2.3:a:openssl:openssl:{}:*:*:*:*:*:*:*", version));
            } else {
                cpes.insert("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*".to_string());
            }
        }
        // Add more CPE patterns for common libraries (e.g., zlib, curl)
        if item_lower.contains("zlib") {
            if let Some(version) = extract_version_from_lib_name(&item_lower) {
                cpes.insert(format!("cpe:2.3:a:zlib:zlib:{}:*:*:*:*:*:*:*", version));
            }
        }
        if item_lower.contains("curl") || item_lower.contains("libcurl") {
            if let Some(version) = extract_version_from_lib_name(&item_lower) {
                cpes.insert(format!("cpe:2.3:a:curl:curl:{}:*:*:*:*:*:*:*", version));
            }
        }
    }
    cpes.into_iter().collect()
}

fn analyze_elf(analysis: &mut BinaryAnalysis, elf: &Elf, contents: &[u8]) -> anyhow::Result<()> {
    analysis.format = "elf".to_string();
    
    // Determine architecture
    analysis.architecture = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
        goblin::elf::header::EM_386 => "i386".to_string(),
        goblin::elf::header::EM_ARM => "arm".to_string(),
        goblin::elf::header::EM_AARCH64 => "aarch64".to_string(),
        goblin::elf::header::EM_RISCV => "riscv".to_string(),
        _ => format!("unknown({})", elf.header.e_machine),
    };

    // Extract symbols
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                analysis.detected_symbols.push(name.to_string());
            }
        }
    }

    // Extract dynamic symbols
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if !name.is_empty() {
                analysis.detected_symbols.push(name.to_string());
            }
        }
    }

    // Extract libraries
    for lib in &elf.libraries {
        analysis.linked_libraries.push(lib.to_string());
        // Store library name for regex-based version extraction later
        analysis.embedded_strings.push(lib.to_string());
    }

    // Determine if statically linked
    analysis.static_linked = elf.libraries.is_empty() && elf.header.e_type == goblin::elf::header::ET_EXEC;

    // Extract imports/exports using object crate for more detailed analysis
    if let Ok(obj_file) = object::File::parse(contents) {
        for symbol in obj_file.symbols() {
            if let Ok(name) = symbol.name() {
                if symbol.is_undefined() {
                    analysis.imports.push(name.to_string());
                } else if symbol.is_global() {
                    analysis.exports.push(name.to_string());
                }
            }
        }
    }

    Ok(())
}

fn analyze_pe(analysis: &mut BinaryAnalysis, pe: &PE, _contents: &[u8]) -> anyhow::Result<()> {
    analysis.format = "pe".to_string();
    
    // Determine architecture
    analysis.architecture = match pe.header.coff_header.machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => "x86_64".to_string(),
        goblin::pe::header::COFF_MACHINE_X86 => "i386".to_string(),
        goblin::pe::header::COFF_MACHINE_ARM64 => "aarch64".to_string(),
        _ => format!("unknown({})", pe.header.coff_header.machine),
    };

    // Extract exports
    for export in &pe.exports {
        if let Some(name) = &export.name {
            analysis.exports.push(name.to_string());
        }
    }

    // Extract imports
    for import in &pe.imports {
        analysis.imports.push(import.name.to_string());
        // Add import name to embedded strings for version extraction heuristics
        analysis.embedded_strings.push(import.name.to_string());
        if !analysis.linked_libraries.contains(&import.dll.to_string()) {
            analysis.linked_libraries.push(import.dll.to_string());
            // Include DLL name in embedded strings so version like "vcruntime140.dll" can be parsed
            analysis.embedded_strings.push(import.dll.to_string());
        }
    }

    // PE files are typically dynamically linked if they have imports
    analysis.static_linked = pe.imports.is_empty();

    Ok(())
}

fn analyze_wasm(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    tracing::info!("Starting WASM analysis");
    analysis.format = "application/wasm".to_string();
    analysis.architecture = "wasm32".to_string();
    analysis.languages.push("WebAssembly".to_string());
    
    let parser = Parser::new(0);
    let mut imports = HashSet::new();
    let mut exports = HashSet::new();
    let mut function_count = 0;
    let mut memory_info = Vec::new();
    let mut table_info = Vec::new();
    
    for payload in parser.parse_all(contents) {
        use wasmparser::Payload as WasmPayload;
        match payload {
            Ok(payload) => {
                match payload {
                    Payload::Version { num, .. } => {
                        tracing::debug!("WASM version: {}", num);
                    }
                    Payload::ImportSection(reader) => {
                        for import in reader {
                            match import {
                                Ok(import) => {
                                    let import_name = format!("{}::{}", import.module, import.name);
                                    imports.insert(import_name);
                                    tracing::debug!("Found import: {}::{}", import.module, import.name);
                                }
                                Err(e) => tracing::warn!("Failed to parse import: {}", e),
                            }
                        }
                    }
                    Payload::ExportSection(reader) => {
                        for export in reader {
                            match export {
                                Ok(export) => {
                                    exports.insert(export.name.to_string());
                                    tracing::debug!("Found export: {}", export.name);
                                }
                                Err(e) => tracing::warn!("Failed to parse export: {}", e),
                            }
                        }
                    }
                    Payload::FunctionSection(reader) => {
                        function_count = reader.count();
                        tracing::debug!("Function count: {}", function_count);
                    }
                    Payload::MemorySection(reader) => {
                        for memory in reader {
                            match memory {
                                Ok(memory) => {
                                    memory_info.push(format!("initial: {}, maximum: {:?}", 
                                                           memory.initial, memory.maximum));
                                }
                                Err(e) => tracing::warn!("Failed to parse memory: {}", e),
                            }
                        }
                    }
                    Payload::TableSection(reader) => {
                        for table in reader {
                            match table {
                                Ok(table) => {
                                    table_info.push(format!("element_type: {:?}, initial: {}, maximum: {:?}", 
                                                           table.ty.element_type, table.ty.initial, table.ty.maximum));
                                }
                                Err(e) => tracing::warn!("Failed to parse table: {}", e),
                            }
                        }
                    }
                    WasmPayload::CustomSection(custom) => {
                        if let Ok(bytes_str) = std::str::from_utf8(custom.data()) {
                            for s in extract_strings(bytes_str.as_bytes()) {
                                analysis.embedded_strings.push(s);
                            }
                        }
                    }
                    Payload::TypeSection(reader) => {
                        tracing::debug!("Type section with {} types", reader.count());
                    }
                    _ => {
                        // tracing::debug!("Skipping WASM section: {:?}", payload);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("WASM parsing error: {}", e);
                break;
            }
        }
    }
    
    analysis.imports = imports.into_iter().collect();
    analysis.exports = exports.into_iter().collect();
    analysis.static_linked = true; // WASM modules are self-contained
    
    // Add WASM-specific metadata
    analysis.metadata = serde_json::json!({
        "wasm_version": "1.0",
        "function_count": function_count,
        "memory_sections": memory_info,
        "table_sections": table_info,
        "import_count": analysis.imports.len(),
        "export_count": analysis.exports.len(),
        "analysis_type": "wasm"
    });
    
    tracing::info!("WASM analysis complete: {} imports, {} exports, {} functions", 
                   analysis.imports.len(), analysis.exports.len(), function_count);
    
    Ok(())
}

fn analyze_unknown_binary(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    tracing::debug!("Performing generic binary analysis");
    
    // Try to determine if it's a text file
    let text_ratio = contents.iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f64 / contents.len() as f64;
    
    if text_ratio > 0.7 {
        analysis.format = "text".to_string();
        tracing::debug!("Detected text file ({}% ASCII)", (text_ratio * 100.0) as u32);
        
        // Try to extract more information from text files
        let text = String::from_utf8_lossy(contents);
        {
            // Look for shebang
            if text.starts_with("#!") {
                analysis.format = "script".to_string();
                analysis.languages.push("script".to_string());
            }
            
            // Look for common programming patterns
            if text.contains("function") || text.contains("def ") {
                analysis.languages.push("script".to_string());
            }
            if text.contains("#include") || text.contains("int main") {
                analysis.languages.push("C/C++".to_string());
            }
            if text.contains("pub fn") || text.contains("fn main") {
                analysis.languages.push("Rust".to_string());
            }
        }
    } else {
        analysis.format = "binary".to_string();
        tracing::debug!("Detected binary file ({}% ASCII)", (text_ratio * 100.0) as u32);
    }
    
    analysis.architecture = "unknown".to_string();
    
    // Add some basic metadata
    analysis.metadata = serde_json::json!({
        "ascii_ratio": text_ratio,
        "analysis_type": "generic"
    });
    
    Ok(())
}

fn analyze_small_file(file_name: &str, contents: &[u8]) -> anyhow::Result<BinaryAnalysis> {
    tracing::info!("Analyzing small file '{}' ({} bytes)", file_name, contents.len());
    
    let sha256_hash = Sha256::digest(contents);
    let blake3_hash = blake3::hash(contents);
    
    // For small files, just extract strings and basic info
    let strings = extract_strings(contents);
    let text_content = String::from_utf8_lossy(contents);
    
    // Check if it's mostly text
    let text_ratio = contents.iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f64 / contents.len() as f64;
    
    let format = if text_ratio > 0.8 {
        "text/plain"
    } else {
        "application/octet-stream"
    }.to_string();
    
    // Try to determine what kind of small file this is
    let mut languages = Vec::new();
    let mut analysis_notes = Vec::new();
    
    if strings.iter().any(|s| s.ends_with(".wasm")) {
        analysis_notes.push("Contains WASM module reference".to_string());
        languages.push("WebAssembly".to_string());
    }
    
    if strings.iter().any(|s| s.ends_with(".dll") || s.ends_with(".exe")) {
        analysis_notes.push("Contains Windows executable reference".to_string());
    }
    
    if text_content.starts_with("#!") {
        languages.push("Script".to_string());
        analysis_notes.push("Shell script or executable script".to_string());
    }
    
    let metadata = serde_json::json!({
        "ascii_ratio": text_ratio,
        "analysis_type": "small_file",
        "notes": analysis_notes,
        "content_preview": text_content.chars().take(50).collect::<String>()
    });
    
    let version_info = extract_version_info(contents, &strings, &format);
    let license_info = extract_license_info(&strings);
    
    Ok(BinaryAnalysis {
        id: Uuid::new_v4(),
        file_name: file_name.to_string(),
        format,
        architecture: "n/a".to_string(),
        languages,
        detected_symbols: Vec::new(),
        embedded_strings: strings,
        suspected_secrets: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        hash_sha256: format!("{:x}", sha256_hash),
        hash_blake3: Some(blake3_hash.to_hex().to_string()),
        size_bytes: contents.len() as u64,
        linked_libraries: Vec::new(),
        static_linked: false,
        version_info: Some(version_info),
        license_info: Some(license_info),
        metadata,
        created_at: Utc::now(),
        sbom: None,
    })
}

fn detect_file_type_fallback(file_name: &str, contents: &[u8]) -> String {
    // Check for common magic bytes
    if contents.len() >= 4 {
        match &contents[0..4] {
            [0x7f, b'E', b'L', b'F'] => return "application/x-elf".to_string(),
            [b'M', b'Z', _, _] => return "application/x-msdownload".to_string(), // PE
            [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => return "application/x-mach-binary".to_string(),
            [0x00, 0x61, 0x73, 0x6d] => return "application/wasm".to_string(), // WASM
            _ => {}
        }
    }
    
    // Check file extension
    if let Some(ext) = file_name.split('.').last() {
        match ext.to_lowercase().as_str() {
            "exe" | "dll" => return "application/x-msdownload".to_string(),
            "so" | "a" => return "application/x-sharedlib".to_string(),
            "wasm" => return "application/wasm".to_string(),
            "bin" => return "application/octet-stream".to_string(),
            _ => {}
        }
    }
    
    "application/octet-stream".to_string()
}

fn extract_strings(contents: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    
    tracing::debug!("Extracting strings from {} bytes", contents.len());
    
    for &byte in contents {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            current_string.push(byte);
        } else {
            if current_string.len() >= 3 { // Reduced minimum for small files
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    // Filter out very common/useless strings
                    if !s.trim().is_empty() && !is_junk_string(&s) {
                        strings.push(s.trim().to_string());
                    }
                }
            }
            current_string.clear();
        }
    }
    
    // Process any remaining string
    if current_string.len() >= 3 {
        if let Ok(s) = String::from_utf8(current_string) {
            if !s.trim().is_empty() && !is_junk_string(&s) {
                strings.push(s.trim().to_string());
            }
        }
    }
    
    // Deduplicate and limit
    strings.sort();
    strings.dedup();
    strings.truncate(50);
    
    tracing::debug!("Extracted {} strings", strings.len());
    strings
}

fn is_junk_string(s: &str) -> bool {
    // Filter out strings that are likely padding or noise
    s.chars().all(|c| c == '\0' || c == ' ') ||
    s.len() > 200 || // Very long strings are often noise
    s.chars().all(|c| c.is_ascii_punctuation())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_empty() {
        let result = analyze_binary("test.bin", &[]).await;
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.file_name, "test.bin");
        assert_eq!(analysis.size_bytes, 0);
    }
}
