use super::BinaryAnalysis;
use chrono::Utc;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use blake3;
use goblin::{Object, pe::PE, elf::Elf, mach::MachO};
use object::{Object as ObjectFile, ObjectSection, ObjectSymbol};
use wasmparser::{Parser, Payload};
use infer;
use std::collections::HashSet;

pub async fn analyze_binary(file_name: &str, contents: &[u8]) -> anyhow::Result<BinaryAnalysis> {
    let sha256_hash = Sha256::digest(contents);
    let blake3_hash = blake3::hash(contents);
    
    // Detect file type
    let file_type = infer::get(contents)
        .map(|t| t.mime_type().to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());
    
    let mut analysis = BinaryAnalysis {
        id: Uuid::new_v4(),
        file_name: file_name.to_string(),
        format: file_type.clone(),
        architecture: "unknown".to_string(),
        languages: Vec::new(),
        detected_symbols: Vec::new(),
        embedded_strings: extract_strings(contents),
        suspected_secrets: Vec::new(), // Will be filled by separate endpoint
        imports: Vec::new(),
        exports: Vec::new(),
        hash_sha256: format!("{:x}", sha256_hash),
        hash_blake3: Some(blake3_hash.to_hex().to_string()),
        size_bytes: contents.len() as u64,
        linked_libraries: Vec::new(),
        static_linked: false,
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        sbom: None,
    };

    // Parse with goblin
    match Object::parse(contents) {
        Ok(obj) => {
            match obj {
                Object::Elf(elf) => analyze_elf(&mut analysis, &elf, contents)?,
                Object::PE(pe) => analyze_pe(&mut analysis, &pe, contents)?,
                Object::Mach(mach) => {
                    match mach {
                        goblin::mach::Mach::Fat(_) => {
                            analysis.format = "macho-fat".to_string();
                            analysis.architecture = "multi".to_string();
                        }
                        goblin::mach::Mach::Binary(macho) => analyze_macho(&mut analysis, &macho)?,
                    }
                }
                Object::Archive(_) => {
                    analysis.format = "archive".to_string();
                }
                _ => {}
            }
        }
        Err(_) => {
            // Try WebAssembly parsing
            if let Ok(_) = analyze_wasm(&mut analysis, contents) {
                // WASM analysis succeeded
            } else {
                // Fall back to generic binary analysis
                analyze_unknown_binary(&mut analysis, contents)?;
            }
        }
    }

    Ok(analysis)
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
        if !analysis.linked_libraries.contains(&import.dll.to_string()) {
            analysis.linked_libraries.push(import.dll.to_string());
        }
    }

    // PE files are typically dynamically linked if they have imports
    analysis.static_linked = pe.imports.is_empty();

    Ok(())
}

fn analyze_macho(analysis: &mut BinaryAnalysis, macho: &MachO) -> anyhow::Result<()> {
    analysis.format = "macho".to_string();
    
    // Determine architecture
    analysis.architecture = match macho.header.cputype() {
        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => "x86_64".to_string(),
        goblin::mach::constants::cputype::CPU_TYPE_ARM64 => "aarch64".to_string(),
        goblin::mach::constants::cputype::CPU_TYPE_X86 => "i386".to_string(),
        _ => format!("unknown({})", macho.header.cputype()),
    };

    // Extract symbols
    if let Some(symbols) = &macho.symbols {
        for symbol in symbols.iter() {
            if let Ok((name, _)) = symbol {
                analysis.detected_symbols.push(name.to_string());
            }
        }
    }

    // Extract libraries
    for lib in &macho.libs {
        analysis.linked_libraries.push(lib.to_string());
    }

    analysis.static_linked = macho.libs.is_empty();

    Ok(())
}

fn analyze_wasm(analysis: &mut BinaryAnalysis, contents: &[u8]) -> anyhow::Result<()> {
    analysis.format = "wasm".to_string();
    analysis.architecture = "wasm32".to_string();
    
    let parser = Parser::new(0);
    let mut imports = HashSet::new();
    let mut exports = HashSet::new();
    
    for payload in parser.parse_all(contents) {
        match payload? {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import?;
                    imports.insert(format!("{}::{}", import.module, import.name));
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export?;
                    exports.insert(export.name.to_string());
                }
            }
            _ => {}
        }
    }
    
    analysis.imports = imports.into_iter().collect();
    analysis.exports = exports.into_iter().collect();
    analysis.static_linked = true; // WASM modules are self-contained
    
    Ok(())
}

fn analyze_unknown_binary(analysis: &mut BinaryAnalysis, _contents: &[u8]) -> anyhow::Result<()> {
    analysis.format = "unknown".to_string();
    analysis.architecture = "unknown".to_string();
    
    // Could add more heuristics here for unknown formats
    
    Ok(())
}

fn extract_strings(contents: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    
    for &byte in contents {
        if byte.is_ascii_graphic() || byte == b' ' {
            current_string.push(byte);
        } else {
            if current_string.len() >= 4 { // Minimum string length
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push(s);
                }
            }
            current_string.clear();
        }
    }
    
    // Don't return too many strings
    strings.truncate(100);
    strings
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
