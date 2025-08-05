use super::{BinaryAnalysis, extract_license_info, extract_version_info};
use blake3::Hasher;
use chrono::Utc;
use goblin::{
    Object as GoblinObject,
    elf::Elf,
    mach::{MachO, load_command::CommandVariant},
    pe::PE,
};
use infer;
use object::{Object, ObjectSymbol};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use uuid::Uuid;
use wasmparser::{Parser, Payload};

// Import specialized format parsers
// DICOM parsing done manually to avoid complex API
use capstone::prelude::*;

pub async fn analyze_binary(
    file_name: &str,
    contents: &[u8],
) -> anyhow::Result<BinaryAnalysis> {
    tracing::info!(
        "Starting binary analysis for '{}' ({} bytes)",
        file_name,
        contents.len()
    );

    // Early validation for very small files
    if contents.len() < 50 {
        tracing::warn!(
            "File is very small ({} bytes), analyzing as raw firmware blob",
            contents.len()
        );
        let sha256_hash = Sha256::digest(contents);
        let mut hasher = Hasher::new();
        hasher.update(contents);
        let alternative_hash = hasher.finalize();
        
        let mut analysis = BinaryAnalysis {
            id: Uuid::new_v4(),
            file_name: file_name.to_string(),
            format: "unknown".to_string(),
            architecture: "unknown".to_string(),
            languages: Vec::new(),
            detected_symbols: Vec::new(),
            embedded_strings: Vec::new(),
            suspected_secrets: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            hash_sha256: format!("{:x}", sha256_hash),
            hash_blake3: Some(hex::encode(alternative_hash.as_bytes())),
            size_bytes: contents.len() as u64,
            linked_libraries: Vec::new(),
            static_linked: false,
            version_info: None,
            license_info: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            sbom: None,
            binary_data: Some(contents.to_vec()),
            entry_point: None,
            code_sections: Vec::new(),
        };
        
        analyze_raw_firmware_blob(&mut analysis, contents)?;
        
        // Extract version and license information
        analysis.version_info = Some(extract_version_info(
            contents,
            &analysis.embedded_strings,
            &analysis.format,
        ));
        analysis.license_info = Some(extract_license_info(&analysis.embedded_strings));
        
        return Ok(analysis);
    }

    let sha256_hash = Sha256::digest(contents);
    let mut hasher = Hasher::new();
        hasher.update(contents);
        let alternative_hash = hasher.finalize();

    // Detect file type with more detailed logging
    let detected_type = infer::get(contents);
    let file_type = if let Some(kind) = detected_type {
        tracing::info!(
            "Detected file type: {} ({})",
            kind.mime_type(),
            kind.extension()
        );
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
        hash_blake3: Some(hex::encode(alternative_hash.as_bytes())),
        size_bytes: contents.len() as u64,
        linked_libraries: Vec::new(),
        static_linked: false,
        version_info: None,
        license_info: None,
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        sbom: None,
        binary_data: Some(contents.to_vec()),
        entry_point: None,
        code_sections: Vec::new(),
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
                        goblin::mach::Mach::Binary(macho) => {
                            analyze_macho(&mut analysis, &macho, contents)?
                        }
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
            _ => {
                // Check for DICOM files (DICM at offset 128)
                if contents.len() >= 132 && &contents[128..132] == b"DICM" {
                    tracing::info!("DICOM magic detected, using DICOM parser");
                    if analyze_dicom_medical_imaging(&mut analysis, contents).is_ok() {
                        parsed_successfully = true;
                    }
                }
            }
        }
    }

    // Check for firmware file formats before goblin parsing
    if !parsed_successfully {
        let text_content = String::from_utf8_lossy(contents);
        let first_few_lines: Vec<&str> = text_content.lines().take(5).collect();
        
        // Check for Intel HEX format (starts with :)
        if first_few_lines.iter().any(|line| line.trim().starts_with(':')) &&
           first_few_lines.iter().all(|line| {
               let trimmed = line.trim();
               trimmed.is_empty() || trimmed.starts_with(':') || trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
           }) {
            tracing::info!("Detected Intel HEX format, using Intel HEX parser");
            if analyze_intel_hex(&mut analysis, contents).is_ok() {
                parsed_successfully = true;
            }
        }
        
        // Check for Motorola S-Record format (starts with S)
        if !parsed_successfully && first_few_lines.iter().any(|line| line.trim().starts_with('S')) &&
           first_few_lines.iter().all(|line| {
               let trimmed = line.trim();
               trimmed.is_empty() || (trimmed.starts_with('S') && trimmed.len() >= 4 && 
                                     trimmed.chars().skip(1).all(|c| c.is_ascii_hexdigit()))
           }) {
            tracing::info!("Detected Motorola S-Record format, using S-Record parser");
            if analyze_srec(&mut analysis, contents).is_ok() {
                parsed_successfully = true;
            }
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
                            goblin::mach::Mach::Binary(macho) => {
                                analyze_macho(&mut analysis, &macho, contents)?
                            }
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

    // Check for raw firmware blobs before giving up
    if !parsed_successfully {
        // Try ARM Cortex-M firmware detection (look for vector table patterns)
        if contents.len() >= 8 {
            let sp_bytes = [contents[0], contents[1], contents[2], contents[3]];
            let reset_bytes = [contents[4], contents[5], contents[6], contents[7]];
            let sp_value = u32::from_le_bytes(sp_bytes);
            let reset_value = u32::from_le_bytes(reset_bytes);
            
            // Check if this looks like ARM Cortex-M vector table
            if sp_value >= 0x20000000 && sp_value <= 0x20100000 && // Stack in SRAM
               reset_value >= 0x08000000 && reset_value <= 0x08100000 && // Reset in Flash
               (reset_value & 1) == 1 { // Thumb mode bit set
                tracing::info!("Detected ARM Cortex-M firmware blob, using ARM Cortex-M parser");
                if analyze_arm_cortex_m(&mut analysis, contents).is_ok() {
                    parsed_successfully = true;
                }
            }
        }
    }

    if !parsed_successfully {
        tracing::info!("All specialized parsers failed, using raw firmware blob analysis");
        analyze_raw_firmware_blob(&mut analysis, contents)?;
    } else {
        tracing::info!("Successfully analyzed {} as {}", file_name, analysis.format);
    }

    // Extract version and license information
    tracing::debug!("Extracting version and license metadata");
    analysis.version_info = Some(extract_version_info(
        contents,
        &analysis.embedded_strings,
        &analysis.format,
    ));
    analysis.license_info = Some(extract_license_info(&analysis.embedded_strings));

    tracing::info!(
        "Metadata extraction complete: version_confidence={:.2}, license_confidence={:.2}",
        analysis
            .version_info
            .as_ref()
            .map(|v| v.confidence)
            .unwrap_or(0.0),
        analysis
            .license_info
            .as_ref()
            .map(|l| l.confidence)
            .unwrap_or(0.0)
    );

    Ok(analysis)
}

fn analyze_macho(
    analysis: &mut BinaryAnalysis,
    macho: &MachO,
    contents: &[u8],
) -> anyhow::Result<()> {
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
                metadata["min_os_version"] =
                    serde_json::Value::String(format!("{}.{}", major, minor));
            }
            CommandVariant::BuildVersion(ref build) => {
                let (major, minor) = unpack_version(build.minos);
                metadata["min_os_version"] =
                    serde_json::Value::String(format!("{}.{}", major, minor));
            }
            _ => {}
        }
        metadata["load_commands"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String(format!("{:?}", lc.command)));
    }

    // Extract entry point from Mach-O header
    if macho.entry != 0 {
        analysis.entry_point = Some(format!("0x{:08X}", macho.entry));
        tracing::debug!("Mach-O entry point: 0x{:08X}", macho.entry);
    }

    // Detect static linking
    analysis.static_linked = macho.libs.is_empty() && symbol_set.iter().any(|s| s.contains("main"));

    // Extract potential CPE identifiers for CVE matching
    let cpe_candidates = extract_cpe_candidates(
        &analysis.linked_libraries,
        &analysis.imports,
        &analysis.detected_symbols,
    );
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
        if item_lower.contains("openssl")
            || item_lower.contains("libcrypto")
            || item_lower.contains("libssl")
        {
            if let Some(version) = extract_version_from_lib_name(&item_lower) {
                cpes.insert(format!(
                    "cpe:2.3:a:openssl:openssl:{}:*:*:*:*:*:*:*",
                    version
                ));
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

    // Extract entry point
    if elf.header.e_entry != 0 {
        analysis.entry_point = Some(format!("0x{:08X}", elf.header.e_entry));
        tracing::debug!("ELF entry point: 0x{:08X}", elf.header.e_entry);
    }

    // Determine if statically linked
    analysis.static_linked =
        elf.libraries.is_empty() && elf.header.e_type == goblin::elf::header::ET_EXEC;

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

    // Extract entry point
    if let Some(optional_header) = &pe.header.optional_header {
        let entry_point = optional_header.standard_fields.address_of_entry_point;
        if entry_point != 0 {
            // Add image base to get virtual address  
            let image_base = optional_header.windows_fields.image_base;
            let virtual_entry_point = image_base + entry_point as u64;
            analysis.entry_point = Some(format!("0x{:08X}", virtual_entry_point));
            tracing::debug!("PE entry point: 0x{:08X} (RVA: 0x{:08X})", virtual_entry_point, entry_point);
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
                                    tracing::debug!(
                                        "Found import: {}::{}",
                                        import.module,
                                        import.name
                                    );
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
                                    memory_info.push(format!(
                                        "initial: {}, maximum: {:?}",
                                        memory.initial, memory.maximum
                                    ));
                                }
                                Err(e) => tracing::warn!("Failed to parse memory: {}", e),
                            }
                        }
                    }
                    Payload::TableSection(reader) => {
                        for table in reader {
                            match table {
                                Ok(table) => {
                                    table_info.push(format!(
                                        "element_type: {:?}, initial: {}, maximum: {:?}",
                                        table.ty.element_type, table.ty.initial, table.ty.maximum
                                    ));
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

    tracing::info!(
        "WASM analysis complete: {} imports, {} exports, {} functions",
        analysis.imports.len(),
        analysis.exports.len(),
        function_count
    );

    Ok(())
}

fn analyze_intel_hex(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    tracing::info!("Starting Intel HEX analysis using manual parsing");
    analysis.format = "intel-hex".to_string();
    analysis.architecture = "embedded".to_string();
    analysis.languages.push("Firmware".to_string());
    
    let hex_content = String::from_utf8_lossy(contents);
    let mut memory_segments = Vec::new();
    let mut entry_points = Vec::new();
    let mut total_data_bytes = 0;
    let mut start_address = None;
    let mut firmware_data = Vec::new();
    let mut min_address = None;
    let mut max_address = None;
    let mut extended_linear_address = 0u32;
    let mut extended_segment_address = 0u32;
    
    // Parse Intel HEX manually for better control
    for (line_num, line) in hex_content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with(':') {
            continue;
        }
        
        if line.len() < 11 {
            tracing::warn!("Invalid Intel HEX record at line {}: too short", line_num + 1);
            continue;
        }
        
        // Parse Intel HEX: :LLAAAATT[DD...]CC
        // LL = byte count, AAAA = address, TT = type, DD = data, CC = checksum
        
        let byte_count = match u8::from_str_radix(&line[1..3], 16) {
            Ok(count) => count,
            Err(_) => continue,
        };
        
        let address = match u16::from_str_radix(&line[3..7], 16) {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        
        let record_type = match u8::from_str_radix(&line[7..9], 16) {
            Ok(rt) => rt,
            Err(_) => continue,
        };
        
        // Calculate expected line length
        let expected_len = 11 + (byte_count as usize * 2);
        if line.len() != expected_len {
            tracing::warn!("Invalid Intel HEX record at line {}: wrong length", line_num + 1);
            continue;
        }
        
        // Extract data bytes
        let mut data_bytes = Vec::new();
        for i in 0..byte_count {
            let start_idx = 9 + (i as usize * 2);
            let end_idx = start_idx + 2;
            if let Ok(byte) = u8::from_str_radix(&line[start_idx..end_idx], 16) {
                data_bytes.push(byte);
            }
        }
        
        match record_type {
            0x00 => {
                // Data record
                let full_address = extended_linear_address + extended_segment_address + (address as u32);
                total_data_bytes += data_bytes.len() as u32;
                firmware_data.extend_from_slice(&data_bytes);
                
                min_address = Some(min_address.map_or(full_address, |min: u32| min.min(full_address)));
                max_address = Some(max_address.map_or(full_address + data_bytes.len() as u32, |max: u32| max.max(full_address + data_bytes.len() as u32)));
                
                memory_segments.push(serde_json::json!({
                    "address": format!("0x{:08X}", full_address),
                    "size": data_bytes.len(),
                    "type": "data"
                }));
            }
            0x01 => {
                // End of file record
                tracing::debug!("Found end of file record");
                break;
            }
            0x02 => {
                // Extended segment address
                if data_bytes.len() >= 2 {
                    extended_segment_address = ((data_bytes[0] as u32) << 12) | ((data_bytes[1] as u32) << 4);
                    tracing::debug!("Extended segment address: 0x{:08X}", extended_segment_address);
                }
            }
            0x03 => {
                // Start segment address (CS:IP)
                if data_bytes.len() >= 4 {
                    let cs = ((data_bytes[0] as u32) << 8) | (data_bytes[1] as u32);
                    let ip = ((data_bytes[2] as u32) << 8) | (data_bytes[3] as u32);
                    let start_addr = (cs << 4) + ip;
                    start_address = Some(start_addr);
                    entry_points.push(format!("0x{:08X}", start_addr));
                    analysis.entry_point = Some(format!("0x{:08X}", start_addr));
                    tracing::debug!("Start segment address: CS=0x{:04X}, IP=0x{:04X}", cs, ip);
                }
            }
            0x04 => {
                // Extended linear address
                if data_bytes.len() >= 2 {
                    extended_linear_address = ((data_bytes[0] as u32) << 24) | ((data_bytes[1] as u32) << 16);
                    tracing::debug!("Extended linear address: 0x{:08X}", extended_linear_address);
                }
            }
            0x05 => {
                // Start linear address
                if data_bytes.len() >= 4 {
                    let start_addr = ((data_bytes[0] as u32) << 24) | ((data_bytes[1] as u32) << 16) | 
                                    ((data_bytes[2] as u32) << 8) | (data_bytes[3] as u32);
                    start_address = Some(start_addr);
                    entry_points.push(format!("0x{:08X}", start_addr));
                    analysis.entry_point = Some(format!("0x{:08X}", start_addr));
                    tracing::debug!("Start linear address: 0x{:08X}", start_addr);
                }
            }
            _ => {
                tracing::debug!("Unknown Intel HEX record type: 0x{:02X}", record_type);
            }
        }
    }
    
    // Extract strings from firmware data
    let firmware_strings = extract_strings(&firmware_data);
    analysis.embedded_strings.extend(firmware_strings);
    
    // Detect potential microcontroller/bootloader patterns
    let mut device_hints = Vec::new();
    for string in &analysis.embedded_strings {
        let lower = string.to_lowercase();
        if lower.contains("bootloader") || lower.contains("boot") {
            device_hints.push("bootloader");
        }
        if lower.contains("interrupt") || lower.contains("isr") {
            device_hints.push("interrupt_handler");
        }
        if lower.contains("uart") || lower.contains("spi") || lower.contains("i2c") {
            device_hints.push("peripheral_driver");
        }
        if lower.contains("atmega") || lower.contains("avr") {
            analysis.architecture = "avr".to_string();
            device_hints.push("avr_microcontroller");
        }
        if lower.contains("stm32") || lower.contains("cortex") {
            analysis.architecture = "arm_cortex_m".to_string();
            device_hints.push("arm_cortex_m");
        }
        if lower.contains("pic") && (lower.contains("16") || lower.contains("18")) {
            analysis.architecture = "pic".to_string();
            device_hints.push("pic_microcontroller");
        }
    }
    
    analysis.static_linked = true; // Firmware is typically self-contained
    
    // Calculate memory utilization
    let memory_span = if let (Some(min), Some(max)) = (min_address, max_address) {
        max - min
    } else {
        0
    };
    
    // Add Intel HEX specific metadata
    analysis.metadata = serde_json::json!({
        "hex_format": "intel_hex",
        "total_data_bytes": total_data_bytes,
        "memory_segments": memory_segments,
        "entry_points": entry_points,
        "start_address": start_address.map(|addr| format!("0x{:08X}", addr)),
        "memory_range": {
            "min_address": min_address.map(|addr| format!("0x{:08X}", addr)),
            "max_address": max_address.map(|addr| format!("0x{:08X}", addr)),
            "span_bytes": memory_span
        },
        "device_hints": device_hints,
        "analysis_type": "intel_hex_firmware"
    });
    
    tracing::info!(
        "Intel HEX analysis complete: {} data bytes, {} memory segments, memory span: {} bytes",
        total_data_bytes,
        memory_segments.len(),
        memory_span
    );
    
    Ok(())
}

fn analyze_srec(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    tracing::info!("Starting Motorola S-Record analysis using srec library");
    analysis.format = "motorola-srec".to_string();
    analysis.architecture = "embedded".to_string();
    analysis.languages.push("Firmware".to_string());
    
    let srec_content = String::from_utf8_lossy(contents);
    let mut memory_segments = Vec::new();
    let mut entry_points = Vec::new();
    let mut total_data_bytes = 0;
    let mut start_address = None;
    let mut firmware_data = Vec::new();
    let mut min_address = None;
    let mut max_address = None;
    let mut header_info = None;
    
    // Parse S-Record manually for better control
    for (line_num, line) in srec_content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('S') {
            continue;
        }
        
        if line.len() < 4 {
            tracing::warn!("Invalid S-Record at line {}: too short", line_num + 1);
            continue;
        }
        
        // Parse S-Record: STYCC[AAAA...][DD...]CC
        let record_type = match line.chars().nth(1) {
            Some(c) => c,
            None => continue,
        };
        
        let byte_count = match u8::from_str_radix(&line[2..4], 16) {
            Ok(count) => count,
            Err(_) => continue,
        };
        
        match record_type {
            '0' => {
                // Header record
                if line.len() >= 8 {
                    let data_start = 8;
                    let data_end = line.len().saturating_sub(2);
                    if data_end > data_start {
                        let data_hex = &line[data_start..data_end];
                        let mut header_data = Vec::new();
                        for i in (0..data_hex.len()).step_by(2) {
                            if i + 1 < data_hex.len() {
                                if let Ok(byte_val) = u8::from_str_radix(&data_hex[i..i + 2], 16) {
                                    header_data.push(byte_val);
                                }
                            }
                        }
                        let header_string = String::from_utf8_lossy(&header_data);
                        if !header_string.trim().is_empty() {
                            header_info = Some(header_string.trim().to_string());
                        }
                    }
                }
            }
            '1' => {
                // 16-bit address data record
                if line.len() >= 8 {
                    if let Ok(address) = u16::from_str_radix(&line[4..8], 16) {
                        let data_bytes = byte_count.saturating_sub(3);
                        total_data_bytes += data_bytes as u32;
                        
                        let addr32 = address as u32;
                        min_address = Some(min_address.map_or(addr32, |min: u32| min.min(addr32)));
                        max_address = Some(max_address.map_or(addr32 + data_bytes as u32, |max: u32| max.max(addr32 + data_bytes as u32)));
                        
                        // Extract actual data bytes
                        if line.len() >= 8 + (data_bytes as usize * 2) {
                            let data_hex = &line[8..8 + (data_bytes as usize * 2)];
                            for i in (0..data_hex.len()).step_by(2) {
                                if i + 1 < data_hex.len() {
                                    if let Ok(byte_val) = u8::from_str_radix(&data_hex[i..i + 2], 16) {
                                        firmware_data.push(byte_val);
                                    }
                                }
                            }
                        }
                        
                        memory_segments.push(serde_json::json!({
                            "address": format!("0x{:04X}", address),
                            "size": data_bytes,
                            "type": "data_16bit"
                        }));
                    }
                }
            }
            '7' => {
                // 32-bit start address
                if line.len() >= 12 {
                    if let Ok(address) = u32::from_str_radix(&line[4..12], 16) {
                        start_address = Some(address);
                        entry_points.push(format!("0x{:08X}", address));
                        analysis.entry_point = Some(format!("0x{:08X}", address));
                    }
                }
            }
            '8' => {
                // 24-bit start address  
                if line.len() >= 10 {
                    if let Ok(address) = u32::from_str_radix(&line[4..10], 16) {
                        start_address = Some(address & 0x00FFFFFF);
                        entry_points.push(format!("0x{:06X}", address & 0x00FFFFFF));
                        analysis.entry_point = Some(format!("0x{:06X}", address & 0x00FFFFFF));
                    }
                }
            }
            '9' => {
                // 16-bit start address
                if line.len() >= 8 {
                    if let Ok(address) = u16::from_str_radix(&line[4..8], 16) {
                        start_address = Some(address as u32);
                        entry_points.push(format!("0x{:04X}", address));
                        analysis.entry_point = Some(format!("0x{:04X}", address));
                    }
                }
            }
            _ => {}
        }
    }
    
    // Extract strings from firmware data
    let firmware_strings = extract_strings(&firmware_data);
    analysis.embedded_strings.extend(firmware_strings);
    
    // Add header info if available
    if let Some(header) = header_info {
        analysis.embedded_strings.push(header);
    }
    
    // Detect potential microcontroller/bootloader patterns
    let mut device_hints = Vec::new();
    for string in &analysis.embedded_strings {
        let lower = string.to_lowercase();
        if lower.contains("bootloader") || lower.contains("boot") {
            device_hints.push("bootloader");
        }
        if lower.contains("interrupt") || lower.contains("isr") {
            device_hints.push("interrupt_handler");
        }
        if lower.contains("can") || lower.contains("ecu") || lower.contains("automotive") {
            device_hints.push("automotive_ecu");
            analysis.architecture = "automotive".to_string();
        }
        if lower.contains("motorola") || lower.contains("freescale") || lower.contains("nxp") {
            device_hints.push("motorola_mcu");
        }
        if lower.contains("68k") || lower.contains("68000") {
            analysis.architecture = "m68k".to_string();
            device_hints.push("motorola_68k");
        }
        if lower.contains("coldfire") {
            analysis.architecture = "coldfire".to_string();
            device_hints.push("coldfire_mcu");
        }
        if lower.contains("powerpc") || lower.contains("ppc") {
            analysis.architecture = "powerpc".to_string();
            device_hints.push("powerpc_mcu");
        }
    }
    
    analysis.static_linked = true; // Firmware is typically self-contained
    
    // Calculate memory utilization
    let memory_span = if let (Some(min), Some(max)) = (min_address, max_address) {
        max - min
    } else {
        0
    };
    
    // Add S-Record specific metadata
    analysis.metadata = serde_json::json!({
        "record_format": "motorola_srec",
        "total_data_bytes": total_data_bytes,
        "memory_segments": memory_segments,
        "entry_points": entry_points,
        "start_address": start_address.map(|addr| format!("0x{:08X}", addr)),
        "memory_range": {
            "min_address": min_address.map(|addr| format!("0x{:08X}", addr)),
            "max_address": max_address.map(|addr| format!("0x{:08X}", addr)),
            "span_bytes": memory_span
        },
        "device_hints": device_hints,
        "analysis_type": "srec_firmware"
    });
    
    tracing::info!(
        "S-Record analysis complete: {} data bytes, {} memory segments, memory span: {} bytes",
        total_data_bytes,
        memory_segments.len(),
        memory_span
    );
    
    Ok(())
}

fn analyze_arm_cortex_m(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    tracing::info!("Starting ARM Cortex-M firmware analysis with Capstone disassembly");
    analysis.format = "arm-cortex-m-firmware".to_string();
    analysis.architecture = "arm_cortex_m".to_string();
    analysis.languages.push("ARM Assembly".to_string());
    analysis.languages.push("C/C++".to_string());
    
    let mut vector_table = Vec::new();
    let mut interrupt_handlers = Vec::new();
    let mut rtos_indicators = Vec::new();
    let mut memory_regions = Vec::new();
    let mut stack_pointer = None;
    let mut reset_handler = None;
    let mut disassembly_info = Vec::new();
    
    // Initialize Capstone disassembler for ARM Thumb
    let cs = match Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build() 
    {
        Ok(cs) => Some(cs),
        Err(e) => {
            tracing::warn!("Failed to initialize Capstone disassembler: {}", e);
            None
        }
    };
    
    // Parse ARM Cortex-M vector table (first 1KB typically)
    if contents.len() >= 256 {
        // Vector table starts at offset 0x00000000
        // First entry: Initial Stack Pointer (MSP)
        // Second entry: Reset Handler
        
        // Extract initial stack pointer (first 4 bytes, little endian)
        if contents.len() >= 4 {
            let sp_bytes = [contents[0], contents[1], contents[2], contents[3]];
            let sp_value = u32::from_le_bytes(sp_bytes);
            stack_pointer = Some(sp_value);
            
            // Validate that stack pointer looks reasonable (usually in RAM region)
            if sp_value >= 0x20000000 && sp_value <= 0x20100000 {
                tracing::debug!("Valid ARM Cortex-M stack pointer found: 0x{:08X}", sp_value);
                memory_regions.push(serde_json::json!({
                    "type": "RAM",
                    "start_address": "0x20000000",
                    "size_estimate": format!("{}KB", (sp_value - 0x20000000) / 1024),
                    "purpose": "SRAM"
                }));
            }
        }
        
        // Extract reset handler (second 4 bytes, little endian)
        if contents.len() >= 8 {
            let reset_bytes = [contents[4], contents[5], contents[6], contents[7]];
            let reset_addr = u32::from_le_bytes(reset_bytes);
            
            // ARM Cortex-M addresses have LSB set for Thumb mode
            let actual_reset_addr = reset_addr & 0xFFFFFFFE;
            
            if actual_reset_addr > 0 && actual_reset_addr < 0x08100000 {
                reset_handler = Some(actual_reset_addr);
                analysis.entry_point = Some(format!("0x{:08X}", actual_reset_addr));
                
                // Try to disassemble first few instructions at reset handler
                let mut reset_analysis = serde_json::json!({
                    "name": "Reset_Handler",
                    "address": format!("0x{:08X}", actual_reset_addr),
                    "thumb_mode": (reset_addr & 1) == 1
                });
                
                if let Some(ref cs) = cs {
                    // Try to find the reset handler code in the binary
                    // Assume it's near the beginning for now
                    let code_start = if actual_reset_addr >= 0x08000000 && actual_reset_addr < 0x08000000 + contents.len() as u32 {
                        (actual_reset_addr - 0x08000000) as usize
                    } else {
                        0x200 // Common offset after vector table
                    };
                    
                    if code_start < contents.len() && contents.len() > code_start + 32 {
                        let code_slice = &contents[code_start..code_start.min(contents.len()).min(code_start + 32)];
                        match cs.disasm_all(code_slice, actual_reset_addr as u64) {
                            Ok(insns) => {
                                let mut reset_instructions = Vec::new();
                                for insn in insns.iter().take(8) { // First 8 instructions
                                    reset_instructions.push(serde_json::json!({
                                        "address": format!("0x{:08X}", insn.address()),
                                        "mnemonic": insn.mnemonic().unwrap_or(""),
                                        "op_str": insn.op_str().unwrap_or("")
                                    }));
                                }
                                reset_analysis["disassembly"] = serde_json::json!(reset_instructions);
                                disassembly_info.push("Reset handler disassembled");
                            }
                            Err(e) => {
                                tracing::debug!("Failed to disassemble reset handler: {}", e);
                            }
                        }
                    }
                }
                
                interrupt_handlers.push(reset_analysis);
                tracing::debug!("Reset handler found at: 0x{:08X}", actual_reset_addr);
            }
        }
        
        // Parse standard ARM Cortex-M vector table entries
        let vector_names = [
            "Initial_SP", "Reset_Handler", "NMI_Handler", "HardFault_Handler",
            "MemManage_Handler", "BusFault_Handler", "UsageFault_Handler", "Reserved",
            "Reserved", "Reserved", "Reserved", "SVC_Handler",
            "DebugMon_Handler", "Reserved", "PendSV_Handler", "SysTick_Handler"
        ];
        
        for (i, &name) in vector_names.iter().enumerate() {
            let offset = i * 4;
            if offset + 4 <= contents.len() && offset + 4 <= 64 { // Standard vectors are first 16 entries
                let addr_bytes = [
                    contents[offset], contents[offset + 1], 
                    contents[offset + 2], contents[offset + 3]
                ];
                let addr_value = u32::from_le_bytes(addr_bytes);
                
                vector_table.push(serde_json::json!({
                    "index": i,
                    "name": name,
                    "address": format!("0x{:08X}", addr_value),
                    "raw_value": format!("0x{:08X}", addr_value)
                }));
                
                // Check for valid interrupt handler addresses
                if i > 0 && addr_value > 0 && addr_value != 0xFFFFFFFF {
                    let actual_addr = addr_value & 0xFFFFFFFE;
                    if actual_addr < 0x08100000 && actual_addr > 0x08000000 {
                        interrupt_handlers.push(serde_json::json!({
                            "name": name,
                            "address": format!("0x{:08X}", actual_addr),
                            "thumb_mode": (addr_value & 1) == 1,
                            "vector_index": i
                        }));
                    }
                }
            }
        }
    }
    
    // Look for RTOS patterns in the firmware
    let firmware_strings = extract_strings(contents);
    for string in &firmware_strings {
        let lower = string.to_lowercase();
        
        // FreeRTOS indicators
        if lower.contains("freertos") || lower.contains("xTaskCreate") || 
           lower.contains("vTaskDelay") || lower.contains("xQueueCreate") {
            rtos_indicators.push("FreeRTOS");
        }
        
        // RTX indicators
        if lower.contains("rtx") || lower.contains("osKernelStart") || 
           lower.contains("osThreadCreate") {
            rtos_indicators.push("ARM RTX");
        }
        
        // ThreadX indicators
        if lower.contains("threadx") || lower.contains("tx_thread_create") {
            rtos_indicators.push("ThreadX");
        }
        
        // Zephyr indicators
        if lower.contains("zephyr") || lower.contains("k_thread_create") {
            rtos_indicators.push("Zephyr RTOS");
        }
        
        // CMSIS indicators
        if lower.contains("cmsis") || lower.contains("__main") || 
           lower.contains("SystemInit") {
            rtos_indicators.push("CMSIS");
        }
        
        // Hardware abstraction layer indicators
        if lower.contains("hal_") || lower.contains("stm32") {
            rtos_indicators.push("STM32 HAL");
        }
    }
    
    // Add firmware strings to analysis
    analysis.embedded_strings.extend(firmware_strings);
    
    // Identify common ARM Cortex-M memory regions
    memory_regions.push(serde_json::json!({
        "type": "Flash",
        "start_address": "0x08000000",
        "purpose": "Program Flash Memory",
        "typical_size": "64KB-2MB"
    }));
    
    memory_regions.push(serde_json::json!({
        "type": "System",
        "start_address": "0xE0000000",
        "purpose": "System Control Space",
        "contains": ["SysTick", "NVIC", "SCB", "MPU", "FPU"]
    }));
    
    // Look for peripheral register access patterns
    let mut peripheral_indicators = Vec::new();
    
    // Check for common STM32 peripheral base addresses in the binary
    let peripheral_bases: &[(u32, &str)] = &[
        (0x40000000, "APB1 Peripherals"),
        (0x40010000, "APB2 Peripherals"), 
        (0x40020000, "AHB1 Peripherals"),
        (0x50000000, "AHB2 Peripherals"),
        (0xE0000000, "Cortex-M System"),
    ];
    
    for (base_addr, name) in peripheral_bases {
        // Look for this address in the binary (little endian)
        let addr_bytes = base_addr.to_le_bytes();
        if contents.windows(4).any(|window| window == addr_bytes) {
            peripheral_indicators.push(serde_json::json!({
                "base_address": format!("0x{:08X}", base_addr),
                "name": name
            }));
        }
    }
    
    // Remove duplicates from RTOS indicators
    rtos_indicators.sort();
    rtos_indicators.dedup();
    
    analysis.static_linked = true; // Firmware is self-contained
    
    // Calculate useful statistics
    let vector_table_size = vector_table.len() * 4;
    let total_handlers = interrupt_handlers.len();
    
    // Add ARM Cortex-M specific metadata
    analysis.metadata = serde_json::json!({
        "firmware_type": "arm_cortex_m",
        "vector_table": {
            "entries": vector_table,
            "size_bytes": vector_table_size,
            "total_vectors": vector_table.len()
        },
        "interrupt_handlers": interrupt_handlers,
        "stack_pointer": stack_pointer.map(|sp| format!("0x{:08X}", sp)),
        "reset_handler": reset_handler.map(|rh| format!("0x{:08X}", rh)),
        "rtos_detected": rtos_indicators,
        "memory_regions": memory_regions,
        "peripheral_indicators": peripheral_indicators,
        "analysis_type": "arm_cortex_m_firmware",
        "disassembly": {
            "capstone_available": cs.is_some(),
            "analysis_info": disassembly_info
        },
        "statistics": {
            "total_interrupt_handlers": total_handlers,
            "has_rtos": !rtos_indicators.is_empty(),
            "has_hal": rtos_indicators.iter().any(|s| s.contains("HAL")),
            "disassembly_performed": !disassembly_info.is_empty()
        }
    });
    
    tracing::info!(
        "ARM Cortex-M analysis complete: {} interrupt handlers, {} RTOS indicators, stack at 0x{:08X}",
        total_handlers,
        rtos_indicators.len(),
        stack_pointer.unwrap_or(0)
    );
    
    Ok(())
}

fn analyze_raw_firmware_blob(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    tracing::info!("Starting raw firmware blob analysis ({} bytes)", contents.len());
    
    let text_ratio = contents
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f64
        / contents.len() as f64;
    
    let mut architecture_hints = Vec::new();
    let mut firmware_indicators = Vec::new();
    let mut compression_detected = Vec::new();
    let mut crypto_indicators = Vec::new();
    
    // Check for various firmware signatures and patterns
    
    // 1. Architecture detection by instruction patterns
    if contents.len() >= 4 {
        // ARM Thumb instructions (common in Cortex-M)
        let thumb_patterns = [
            [0x00, 0xBF], // NOP (Thumb)
            [0x70, 0x47], // BX LR (Thumb)
            [0x08, 0x68], // LDR r0, [r1] (Thumb)
        ];
        
        for pattern in &thumb_patterns {
            if contents.windows(2).any(|w| w == pattern) {
                architecture_hints.push("ARM Thumb");
                break;
            }
        }
        
        // x86 patterns
        let x86_patterns: &[&[u8]] = &[
            &[0x55u8, 0x89, 0xE5], // push ebp; mov ebp, esp
            &[0x48u8, 0x89, 0xE5], // mov rbp, rsp (x86-64)
            &[0xEBu8, 0xFE],       // jmp $ (infinite loop)
        ];
        
        for pattern in x86_patterns {
            if contents.windows(pattern.len()).any(|w| w == *pattern) {
                architecture_hints.push("x86");
                break;
            }
        }
        
        // MIPS patterns
        if contents.windows(4).any(|w| matches!(w, [0x27, 0xBD, _, _] | [_, _, 0xBD, 0x27])) {
            architecture_hints.push("MIPS");
        }
        
        // PowerPC patterns
        if contents.windows(4).any(|w| matches!(w, [0x94, 0x21, _, _] | [_, _, 0x21, 0x94])) {
            architecture_hints.push("PowerPC");
        }
    }
    
    // 2. Bootloader detection
    let bootloader_strings = [
        "U-Boot", "GRUB", "bootloader", "BOOT", "loader",
        "SPL", "MLO", "bootstrap", "uboot"
    ];
    
    for &pattern in &bootloader_strings {
        if contents.windows(pattern.len()).any(|w| 
            String::from_utf8_lossy(w).to_lowercase().contains(&pattern.to_lowercase())
        ) {
            firmware_indicators.push("bootloader");
            break;
        }
    }
    
    // 3. Compression detection
    if contents.len() >= 4 {
        match &contents[0..4.min(contents.len())] {
            [0x1F, 0x8B, _, _] => compression_detected.push("gzip"),
            [0x42, 0x5A, 0x68, _] => compression_detected.push("bzip2"),
            [0xFD, 0x37, 0x7A, 0x58] => compression_detected.push("xz"),
            [0x28, 0xB5, 0x2F, 0xFD] => compression_detected.push("zstd"),
            [0x04, 0x22, 0x4D, 0x18] => compression_detected.push("lz4"),
            _ => {}
        }
    }
    
    // 4. Cryptographic signatures
    let crypto_patterns: &[(&str, &[u8])] = &[
        ("AES", b"AES"),
        ("RSA", b"RSA"),
        ("SHA", b"SHA"),
        ("OpenSSL", b"OpenSSL"),
        ("mbedtls", b"mbedtls"),
        ("WolfSSL", b"wolfSSL"),
    ];
    
    for (name, pattern) in crypto_patterns {
        if contents.windows(pattern.len()).any(|w| w == *pattern) {
            crypto_indicators.push(*name);
        }
    }
    
    // 5. Device-specific patterns
    let device_patterns = [
        ("ESP32", b"ESP32" as &[u8]),
        ("Arduino", b"Arduino"),
        ("Raspberry Pi", b"Raspberry Pi"),
        ("STM32", b"STM32"),
        ("Nordic", b"Nordic"),
        ("Qualcomm", b"Qualcomm"),
        ("Broadcom", b"Broadcom"),
    ];
    
    for (device, pattern) in &device_patterns {
        if contents.windows(pattern.len()).any(|w| w == *pattern) {
            firmware_indicators.push(*device);
        }
    }
    
    // Determine format based on analysis
    if text_ratio > 0.8 {
        analysis.format = if contents.len() < 1024 { "text/small" } else { "text" }.to_string();
        
        let text = String::from_utf8_lossy(contents);
        if text.starts_with("#!") {
            analysis.format = "script".to_string();
            analysis.languages.push("script".to_string());
        }
        
        // Look for programming language patterns
        if text.contains("function") || text.contains("def ") {
            analysis.languages.push("script".to_string());
        }
        if text.contains("#include") || text.contains("int main") {
            analysis.languages.push("C/C++".to_string());
        }
        if text.contains("pub fn") || text.contains("fn main") {
            analysis.languages.push("Rust".to_string());
        }
    } else if !compression_detected.is_empty() {
        analysis.format = "compressed-firmware".to_string();
        analysis.languages.push("Compressed Binary".to_string());
    } else if !firmware_indicators.is_empty() {
        analysis.format = "firmware-blob".to_string();
        analysis.languages.push("Firmware".to_string());
    } else if contents.len() < 50 {
        analysis.format = "micro-binary".to_string();
    } else {
        analysis.format = "raw-binary".to_string();
    }
    
    // Set architecture based on hints
    analysis.architecture = if architecture_hints.is_empty() {
        "unknown".to_string()
    } else {
        architecture_hints.join(", ")
    };
    
    // Extract strings for further analysis
    let extracted_strings = extract_strings(contents);
    analysis.embedded_strings.extend(extracted_strings);
    
    // Look for version patterns in strings
    let mut version_hints = Vec::new();
    for string in &analysis.embedded_strings {
        if string.len() > 2 && string.len() < 20 {
            // Look for version-like patterns (e.g., "1.2.3", "v2.0", "Rev 1.0")
            if string.chars().any(|c| c.is_ascii_digit()) && 
               (string.contains('.') || string.to_lowercase().contains('v') || 
                string.to_lowercase().contains("rev")) {
                version_hints.push(string.clone());
            }
        }
    }
    
    // Firmware-specific analysis
    analysis.static_linked = !firmware_indicators.is_empty() || text_ratio < 0.1;
    
    // Calculate entropy to detect encryption/compression
    let entropy = calculate_entropy(contents);
    let is_likely_encrypted = entropy > 7.5;
    let is_likely_compressed = entropy > 7.0 && compression_detected.is_empty();
    
    // Build comprehensive metadata
    analysis.metadata = serde_json::json!({
        "analysis_type": "raw_firmware_blob",
        "file_characteristics": {
            "size_bytes": contents.len(),
            "ascii_ratio": text_ratio,
            "entropy": entropy,
            "likely_encrypted": is_likely_encrypted,
            "likely_compressed": is_likely_compressed
        },
        "architecture_hints": architecture_hints,
        "firmware_indicators": firmware_indicators,
        "compression_detected": compression_detected,
        "crypto_indicators": crypto_indicators,
        "version_hints": version_hints,
        "detection_confidence": {
            "architecture": if architecture_hints.is_empty() { "low" } else { "medium" },
            "firmware_type": if firmware_indicators.is_empty() { "low" } else { "high" },
            "format": if text_ratio > 0.8 { "high" } else if !firmware_indicators.is_empty() { "medium" } else { "low" }
        }
    });
    
    tracing::info!(
        "Raw firmware blob analysis complete: format={}, arch={}, {} indicators, entropy={:.2}",
        analysis.format,
        analysis.architecture,
        firmware_indicators.len(),
        entropy
    );
    
    Ok(())
}

// Helper function to calculate Shannon entropy
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

fn analyze_dicom_medical_imaging(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    tracing::info!("Starting DICOM medical imaging analysis using dicom library");
    analysis.format = "dicom-medical-imaging".to_string();
    analysis.architecture = "medical-device".to_string();
    analysis.languages.push("Medical Software".to_string());
    
    let mut dicom_tags = Vec::new();
    let mut fda_compliance_indicators = Vec::new();
    let mut medical_protocols = Vec::new();
    let mut embedded_software_components = Vec::new();
    let mut security_features = Vec::new();
    let mut patient_data_detected = false;
    
    // Check for DICOM file format manually since API is complex
    let has_dicom_preamble = contents.len() >= 132 && &contents[128..132] == b"DICM";
    let dicom_obj = if has_dicom_preamble {
        Some(())  // Just indicate we found DICOM format
    } else {
        None
    };
    
    if dicom_obj.is_some() {
        analysis.format = "dicom-file".to_string();
        
        // Basic DICOM tag parsing - look for common patterns in the data after preamble
        if contents.len() > 132 {
            let dicom_data = &contents[132..];
            
            // Look for common DICOM tags manually
            for i in (0..dicom_data.len().saturating_sub(8)).step_by(2) {
                if i + 8 <= dicom_data.len() {
                    let group = u16::from_le_bytes([dicom_data[i], dicom_data[i + 1]]);
                    let element = u16::from_le_bytes([dicom_data[i + 2], dicom_data[i + 3]]);
                    
                    // Check for patient data tags
                    if group == 0x0010 && (element == 0x0010 || element == 0x0020) {
                        patient_data_detected = true;
                        medical_protocols.push("Patient Data");
                    }
                    
                    // Check for manufacturer info
                    if group == 0x0008 && element == 0x0070 {
                        medical_protocols.push("Manufacturer");
                    }
                    
                    // Limit our search to avoid performance issues
                    if dicom_tags.len() > 20 {
                        break;
                    }
                    
                    dicom_tags.push(serde_json::json!({
                        "group": format!("0x{:04X}", group),
                        "element": format!("0x{:04X}", element),
                        "tag": format!("({:04X},{:04X})", group, element)
                    }));
                }
            }
        }
    } else {
        // Not a DICOM file, analyze as medical imaging software
        analysis.format = "medical-imaging-software".to_string();
    }
    
    // Look for medical device software indicators in strings
    let medical_strings = extract_strings(contents);
    analysis.embedded_strings.extend(medical_strings);
    
    // Analyze embedded strings for medical software patterns
    for string in &analysis.embedded_strings {
        let lower = string.to_lowercase();
        
        // FDA compliance indicators
        if lower.contains("fda") || lower.contains("510k") || lower.contains("pma") {
            fda_compliance_indicators.push("FDA Regulatory");
        }
        if lower.contains("ce mark") || lower.contains("ce marked") {
            fda_compliance_indicators.push("CE Marking");
        }
        if lower.contains("iso 13485") || lower.contains("iso13485") {
            fda_compliance_indicators.push("ISO 13485");
        }
        if lower.contains("iec 62304") || lower.contains("iec62304") {
            fda_compliance_indicators.push("IEC 62304");
        }
        if lower.contains("hipaa") {
            fda_compliance_indicators.push("HIPAA Compliance");
        }
        
        // Medical protocols and standards
        if lower.contains("dicom") {
            medical_protocols.push("DICOM Protocol");
        }
        if lower.contains("hl7") || lower.contains("fhir") {
            medical_protocols.push("HL7/FHIR");
        }
        if lower.contains("pacs") {
            medical_protocols.push("PACS System");
        }
        if lower.contains("modality") || lower.contains("worklist") {
            medical_protocols.push("Modality Worklist");
        }
        if lower.contains("mpps") {
            medical_protocols.push("MPPS Protocol");
        }
        
        // Embedded software components
        if lower.contains("qt") || lower.contains("qtcore") {
            embedded_software_components.push("Qt Framework");
        }
        if lower.contains("opencv") {
            embedded_software_components.push("OpenCV");
        }
        if lower.contains("vtk") {
            embedded_software_components.push("VTK Visualization");
        }
        if lower.contains("itk") {
            embedded_software_components.push("ITK Medical Imaging");
        }
        if lower.contains("gdcm") {
            embedded_software_components.push("GDCM DICOM Library");
        }
        if lower.contains("dcmtk") {
            embedded_software_components.push("DCMTK DICOM Toolkit");
        }
        if lower.contains("cornerstone") {
            embedded_software_components.push("Cornerstone Medical Imaging");
        }
        
        // Security features
        if lower.contains("encryption") || lower.contains("encrypt") {
            security_features.push("Data Encryption");
        }
        if lower.contains("digital signature") || lower.contains("signature") {
            security_features.push("Digital Signatures");
        }
        if lower.contains("audit log") || lower.contains("audit trail") {
            security_features.push("Audit Logging");
        }
        if lower.contains("access control") || lower.contains("authentication") {
            security_features.push("Access Control");
        }
        if lower.contains("tls") || lower.contains("ssl") {
            security_features.push("TLS/SSL");
        }
    }
    
    // Look for medical device identifiers
    let mut device_identifiers = Vec::new();
    let manufacturers = [
        ("GE Healthcare", b"GE Medical" as &[u8]),
        ("Siemens", b"Siemens"),
        ("Philips", b"Philips"),
        ("Canon Medical", b"Canon"),
        ("Fujifilm", b"Fujifilm"),
        ("Hologic", b"Hologic"),
        ("Carestream", b"Carestream"),
        ("Agfa", b"Agfa"),
    ];
    
    for (name, pattern) in &manufacturers {
        if contents.windows(pattern.len()).any(|w| 
            w.to_ascii_lowercase() == pattern.to_ascii_lowercase()
        ) {
            device_identifiers.push(*name);
        }
    }
    
    // Remove duplicates
    fda_compliance_indicators.sort();
    fda_compliance_indicators.dedup();
    medical_protocols.sort();
    medical_protocols.dedup();
    embedded_software_components.sort();
    embedded_software_components.dedup();
    security_features.sort();
    security_features.dedup();
    
    analysis.static_linked = false; // Medical software often uses shared libraries
    
    // Risk assessment based on found indicators
    let risk_level = if fda_compliance_indicators.len() >= 2 && security_features.len() >= 2 {
        "Low" // Has compliance and security features
    } else if fda_compliance_indicators.len() >= 1 {
        "Medium" // Has some compliance indicators
    } else if patient_data_detected {
        "High" // Has patient data but lacks compliance indicators
    } else {
        "Medium" // General medical software
    };
    
    // Add DICOM medical imaging specific metadata
    analysis.metadata = serde_json::json!({
        "medical_device_type": "dicom_medical_imaging",
        "dicom_analysis": {
            "is_dicom_file": dicom_obj.is_some(),
            "dicom_tags_found": dicom_tags.len(),
            "sample_tags": dicom_tags.into_iter().take(10).collect::<Vec<_>>(),
            "patient_data_detected": patient_data_detected
        },
        "compliance_indicators": {
            "fda_compliance": fda_compliance_indicators,
            "medical_protocols": medical_protocols,
            "risk_assessment": risk_level
        },
        "embedded_components": embedded_software_components,
        "security_features": security_features,
        "device_identifiers": device_identifiers,
        "analysis_type": "dicom_medical_imaging",
        "regulatory_notes": {
            "requires_fda_clearance": fda_compliance_indicators.is_empty(),
            "hipaa_relevant": patient_data_detected || security_features.iter().any(|s| s.contains("Encryption") || s.contains("Access Control")),
            "dicom_compliant": medical_protocols.iter().any(|p| p.contains("DICOM"))
        }
    });
    
    tracing::info!(
        "DICOM medical imaging analysis complete: {} compliance indicators, {} protocols, {} security features",
        fda_compliance_indicators.len(),
        medical_protocols.len(),
        security_features.len()
    );
    
    Ok(())
}


fn detect_file_type_fallback(file_name: &str, contents: &[u8]) -> String {
    // Check for common magic bytes
    if contents.len() >= 4 {
        match &contents[0..4] {
            [0x7f, b'E', b'L', b'F'] => return "application/x-elf".to_string(),
            [b'M', b'Z', _, _] => return "application/x-msdownload".to_string(), // PE
            [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => {
                return "application/x-mach-binary".to_string();
            }
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
            if current_string.len() >= 3 {
                // Reduced minimum for small files
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
