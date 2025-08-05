use crate::binary::{BinaryAnalysis, CodeSection};
use capstone::prelude::*;
use petgraph::Direction;
use petgraph::algo::{dijkstra, dominators};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents different types of basic blocks in the Control Flow Graph
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BasicBlockType {
    /// Entry point of a function
    FunctionEntry { function_name: String, address: u64 },
    /// Regular basic block with sequential instructions
    Sequential {
        start_address: u64,
        end_address: u64,
    },
    /// Conditional branch block
    ConditionalBranch { address: u64, condition: String },
    /// Unconditional jump
    UnconditionalJump { address: u64, target: u64 },
    /// Function call site
    FunctionCall { address: u64, target: String },
    /// Return statement
    Return { address: u64 },
    /// Exception handler
    ExceptionHandler { address: u64, handler_type: String },
}

/// Represents edge types in the CFG
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeType {
    /// Sequential execution (fall-through)
    Sequential,
    /// Conditional branch taken
    ConditionalTrue,
    /// Conditional branch not taken
    ConditionalFalse,
    /// Unconditional jump
    Jump,
    /// Function call
    Call,
    /// Function return
    Return,
    /// Exception flow
    Exception,
}

/// Basic block containing instructions and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub block_type: BasicBlockType,
    pub instructions: Vec<Instruction>,
    pub size_bytes: usize,
    pub execution_count: Option<u64>, // For profiling integration
}

/// Disassembled instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
    pub size: u32,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_return: bool,
    pub branch_target: Option<u64>,
}

/// Control Flow Graph with proper basic block analysis
#[derive(Debug)]
pub struct ControlFlowGraph {
    pub graph: DiGraph<BasicBlock, EdgeType>,
    /// Maps addresses to node indices for quick lookup
    address_to_node: HashMap<u64, NodeIndex>,
    /// Maps function names to their entry blocks
    function_entries: HashMap<String, NodeIndex>,
    /// Detected loops in the CFG
    pub loops: Vec<LoopInfo>,
    /// Dominator tree information
    pub dominators: Option<dominators::Dominators<NodeIndex>>,
}

/// Information about detected loops
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopInfo {
    pub header: u64,
    pub back_edges: Vec<(u64, u64)>,
    pub loop_blocks: HashSet<u64>,
    pub nesting_level: usize,
    pub loop_type: LoopType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoopType {
    Natural,
    Irreducible,
    Infinite,
}

/// Results of inter-procedural analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphAnalysis {
    pub call_sites: Vec<CallSite>,
    pub function_summaries: HashMap<String, FunctionSummary>,
    pub recursive_functions: Vec<String>,
    pub dead_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub caller_address: u64,
    pub callee: String,
    pub call_type: CallType,
    pub arguments: Vec<String>, // Detected argument patterns
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallType {
    Direct,
    Indirect,
    Virtual,
    Tail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub entry_address: u64,
    pub size_bytes: usize,
    pub basic_blocks: usize,
    pub cyclomatic_complexity: usize,
    pub calls_made: Vec<String>,
    pub calls_received: Vec<String>,
    pub has_loops: bool,
    pub max_call_depth: usize,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            address_to_node: HashMap::new(),
            function_entries: HashMap::new(),
            loops: Vec::new(),
            dominators: None,
        }
    }

    /// Build CFG from binary analysis with Capstone disassembly
    pub fn build_cfg(analysis: &BinaryAnalysis) -> Result<Self, String> {
        let mut cfg = Self::new();

        // Initialize Capstone based on architecture
        let cs = cfg.init_capstone(&analysis.architecture)?;

        // Use binary data for advanced analysis if available
        if let Some(binary_data) = &analysis.binary_data {
            cfg.build_basic_blocks_from_binary(analysis, &cs, binary_data)?;
        } else {
            // Fallback to symbol-based analysis
            cfg.build_basic_blocks_from_symbols(analysis, &cs)?;
        }

        // Detect loops
        cfg.detect_loops();

        // Build dominator tree
        cfg.build_dominators();

        Ok(cfg)
    }

    pub fn init_capstone(&self, architecture: &str) -> Result<Capstone, String> {
        match architecture.to_lowercase().as_str() {
            "x86_64" | "amd64" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| format!("Failed to initialize Capstone for x86_64: {}", e)),
            "i386" | "x86" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| format!("Failed to initialize Capstone for x86: {}", e)),
            "arm" => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| format!("Failed to initialize Capstone for ARM: {}", e)),
            "aarch64" | "arm64" => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| format!("Failed to initialize Capstone for ARM64: {}", e)),
            "arm_cortex_m" => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Thumb)
                .detail(true)
                .build()
                .map_err(|e| format!("Failed to initialize Capstone for ARM Cortex-M: {}", e)),
            _ => Err(format!("Unsupported architecture: {}", architecture)),
        }
    }

    pub fn build_basic_blocks_from_symbols(
        &mut self,
        analysis: &BinaryAnalysis,
        _cs: &Capstone,
    ) -> Result<(), String> {
        // For now, create basic blocks from function symbols
        // In a real implementation, we'd disassemble the actual binary data

        let entry_point_addr = 0x1000; // Placeholder - would extract from binary

        // Create entry point basic block
        let entry_block = BasicBlock {
            block_type: BasicBlockType::FunctionEntry {
                function_name: "_start".to_string(),
                address: entry_point_addr,
            },
            instructions: vec![Instruction {
                address: entry_point_addr,
                mnemonic: "push".to_string(),
                operands: "rbp".to_string(),
                bytes: vec![0x55],
                size: 1,
                is_branch: false,
                is_call: false,
                is_return: false,
                branch_target: None,
            }],
            size_bytes: 1,
            execution_count: None,
        };

        let entry_node = self.graph.add_node(entry_block);
        self.address_to_node.insert(entry_point_addr, entry_node);
        self.function_entries
            .insert("_start".to_string(), entry_node);

        // Create basic blocks for detected symbols (functions)
        let mut current_addr = entry_point_addr + 0x100;

        for symbol in &analysis.detected_symbols {
            if !symbol.is_empty() && !symbol.starts_with("__") {
                let func_block = BasicBlock {
                    block_type: BasicBlockType::FunctionEntry {
                        function_name: symbol.clone(),
                        address: current_addr,
                    },
                    instructions: self.create_placeholder_instructions(current_addr, symbol),
                    size_bytes: 32, // Placeholder
                    execution_count: None,
                };

                let func_node = self.graph.add_node(func_block);
                self.address_to_node.insert(current_addr, func_node);
                self.function_entries.insert(symbol.clone(), func_node);

                // Add edge from entry point to this function (simplified)
                self.graph.add_edge(entry_node, func_node, EdgeType::Call);

                current_addr += 0x100;
            }
        }

        // Create call sites for imported functions
        for import in &analysis.imports {
            let call_addr = current_addr;
            let call_block = BasicBlock {
                block_type: BasicBlockType::FunctionCall {
                    address: call_addr,
                    target: import.clone(),
                },
                instructions: vec![Instruction {
                    address: call_addr,
                    mnemonic: "call".to_string(),
                    operands: import.clone(),
                    bytes: vec![0xE8, 0x00, 0x00, 0x00, 0x00], // Placeholder
                    size: 5,
                    is_branch: false,
                    is_call: true,
                    is_return: false,
                    branch_target: None,
                }],
                size_bytes: 5,
                execution_count: None,
            };

            let call_node = self.graph.add_node(call_block);
            self.address_to_node.insert(call_addr, call_node);

            current_addr += 0x10;
        }

        Ok(())
    }

   pub fn build_basic_blocks_from_binary(
        &mut self,
        analysis: &BinaryAnalysis,
        cs: &Capstone,
        binary_data: &[u8],
    ) -> Result<(), String> {
        tracing::info!(
            "Performing advanced binary disassembly for {} format (size: {} bytes)",
            analysis.format,
            binary_data.len()
        );

        // Extract entry point based on binary format
        let entry_point = self.extract_entry_point_from_binary(analysis, binary_data)?;

        // Get executable code sections based on format
        let code_sections =
            self.extract_code_sections_by_format(analysis, binary_data, entry_point)?;

        // Disassemble each code section
        for section in &code_sections {
            self.disassemble_code_section(cs, binary_data, section, entry_point)?;
        }

        // Build edges between basic blocks
        self.build_control_flow_edges()?;

        Ok(())
    }

    fn extract_entry_point_from_binary(
        &self,
        analysis: &BinaryAnalysis,
        binary_data: &[u8],
    ) -> Result<u64, String> {
        // First check if entry point is explicitly provided
        if let Some(ep_str) = &analysis.entry_point {
            if let Ok(ep) = u64::from_str_radix(ep_str.trim_start_matches("0x"), 16) {
                return Ok(ep);
            }
        }

        // Extract entry point based on binary format
        match analysis.format.as_str() {
            "ELF" => self.extract_elf_entry_point(binary_data),
            "PE" => self.extract_pe_entry_point(binary_data),
            "Intel HEX" => self.extract_intel_hex_entry_point(binary_data),
            "Motorola S-record" => self.extract_srec_entry_point(binary_data),
            "ARM Cortex-M" => self.extract_arm_cortex_m_entry_point(binary_data),
            "Raw Firmware" => self.extract_raw_firmware_entry_point(analysis, binary_data),
            "DICOM" => Ok(0x0), // DICOM doesn't have traditional entry points
            _ => {
                tracing::warn!(
                    "Unknown binary format: {}, using default entry point",
                    analysis.format
                );
                Ok(0x1000)
            }
        }
    }

    pub fn extract_code_sections_by_format(
        &self,
        analysis: &BinaryAnalysis,
        binary_data: &[u8],
        entry_point: u64,
    ) -> Result<Vec<CodeSection>, String> {
        if !analysis.code_sections.is_empty() {
            return Ok(analysis.code_sections.clone());
        }

        // Generate code sections based on binary format
        match analysis.format.as_str() {
            "ELF" => self.extract_elf_code_sections(binary_data),
            "PE" => self.extract_pe_code_sections(binary_data),
            "Intel HEX" => self.extract_intel_hex_code_sections(binary_data, entry_point),
            "Motorola S-record" => self.extract_srec_code_sections(binary_data, entry_point),
            "ARM Cortex-M" => self.extract_arm_cortex_m_code_sections(binary_data, entry_point),
            "Raw Firmware" => self.extract_raw_firmware_code_sections(binary_data, entry_point),
            _ => {
                // Default single code section
                Ok(vec![CodeSection {
                    name: ".text".to_string(),
                    start_address: entry_point,
                    end_address: entry_point + std::cmp::min(binary_data.len() as u64, 4096),
                    size: std::cmp::min(binary_data.len() as u64, 4096),
                    permissions: "rx".to_string(),
                    section_type: crate::binary::CodeSectionType::Text,
                }])
            }
        }
    }

    // ELF Entry Point and Code Section Extraction
   pub fn extract_elf_entry_point(&self, binary_data: &[u8]) -> Result<u64, String> {
        if binary_data.len() < 64 {
            return Ok(0x1000);
        }

        // Check ELF magic
        if &binary_data[0..4] != b"\x7fELF" {
            return Ok(0x1000);
        }

        let is_64bit = binary_data[4] == 2;

        if is_64bit && binary_data.len() >= 32 {
            let entry_bytes = &binary_data[24..32];
            let entry_point = u64::from_le_bytes(entry_bytes.try_into().unwrap_or([0; 8]));
            Ok(entry_point)
        } else if binary_data.len() >= 28 {
            let entry_bytes = &binary_data[24..28];
            let entry_point = u32::from_le_bytes(entry_bytes.try_into().unwrap_or([0; 4])) as u64;
            Ok(entry_point)
        } else {
            Ok(0x1000)
        }
    }

    pub fn extract_elf_code_sections(&self, binary_data: &[u8]) -> Result<Vec<CodeSection>, String> {
        if binary_data.len() < 64 || &binary_data[0..4] != b"\x7fELF" {
            let entry_point = self.extract_elf_entry_point(binary_data)?;
            return Ok(vec![CodeSection {
                name: ".text".to_string(),
                start_address: entry_point,
                end_address: entry_point + std::cmp::min(binary_data.len() as u64 / 2, 8192),
                size: std::cmp::min(binary_data.len() as u64 / 2, 8192),
                permissions: "rx".to_string(),
                section_type: crate::binary::CodeSectionType::Text,
            }]);
        }

        let is_64bit = binary_data[4] == 2;
        let is_little_endian = binary_data[5] == 1;

        // Parse ELF header to get section header table
        let (shoff, shentsize, shnum, shstrndx) = if is_64bit {
            if binary_data.len() < 64 {
                return self.extract_elf_code_sections_fallback(binary_data);
            }
            let shoff = if is_little_endian {
                u64::from_le_bytes(binary_data[40..48].try_into().unwrap_or([0; 8]))
            } else {
                u64::from_be_bytes(binary_data[40..48].try_into().unwrap_or([0; 8]))
            };
            let shentsize = if is_little_endian {
                u16::from_le_bytes(binary_data[58..60].try_into().unwrap_or([0; 2]))
            } else {
                u16::from_be_bytes(binary_data[58..60].try_into().unwrap_or([0; 2]))
            };
            let shnum = if is_little_endian {
                u16::from_le_bytes(binary_data[60..62].try_into().unwrap_or([0; 2]))
            } else {
                u16::from_be_bytes(binary_data[60..62].try_into().unwrap_or([0; 2]))
            };
            let shstrndx = if is_little_endian {
                u16::from_le_bytes(binary_data[62..64].try_into().unwrap_or([0; 2]))
            } else {
                u16::from_be_bytes(binary_data[62..64].try_into().unwrap_or([0; 2]))
            };
            (shoff, shentsize, shnum, shstrndx)
        } else {
            if binary_data.len() < 52 {
                return self.extract_elf_code_sections_fallback(binary_data);
            }
            let shoff = if is_little_endian {
                u32::from_le_bytes(binary_data[32..36].try_into().unwrap_or([0; 4])) as u64
            } else {
                u32::from_be_bytes(binary_data[32..36].try_into().unwrap_or([0; 4])) as u64
            };
            let shentsize = if is_little_endian {
                u16::from_le_bytes(binary_data[46..48].try_into().unwrap_or([0; 2]))
            } else {
                u16::from_be_bytes(binary_data[46..48].try_into().unwrap_or([0; 2]))
            };
            let shnum = if is_little_endian {
                u16::from_le_bytes(binary_data[48..50].try_into().unwrap_or([0; 2]))
            } else {
                u16::from_be_bytes(binary_data[48..50].try_into().unwrap_or([0; 2]))
            };
            let shstrndx = if is_little_endian {
                u16::from_le_bytes(binary_data[50..52].try_into().unwrap_or([0; 2]))
            } else {
                u16::from_be_bytes(binary_data[50..52].try_into().unwrap_or([0; 2]))
            };
            (shoff, shentsize, shnum, shstrndx)
        };

        // Validate section header table parameters
        if shoff == 0 || shnum == 0 || shentsize == 0 {
            return self.extract_elf_code_sections_fallback(binary_data);
        }

        if shoff as usize + (shnum as usize * shentsize as usize) > binary_data.len() {
            return self.extract_elf_code_sections_fallback(binary_data);
        }

        // Get string table section for section names
        let string_table = if shstrndx != 0 && (shstrndx as usize) < shnum as usize {
            self.get_elf_string_table(
                binary_data,
                shoff,
                shentsize,
                shstrndx,
                is_64bit,
                is_little_endian,
            )
        } else {
            None
        };

        let mut code_sections = Vec::new();

        // Parse section headers
        for i in 0..shnum {
            let section_offset = shoff as usize + (i as usize * shentsize as usize);
            if section_offset + shentsize as usize > binary_data.len() {
                break;
            }

            let section_data = &binary_data[section_offset..section_offset + shentsize as usize];

            let (sh_name, sh_type, sh_flags, sh_addr, sh_size) = if is_64bit {
                if section_data.len() < 64 {
                    continue;
                }
                let sh_name = if is_little_endian {
                    u32::from_le_bytes(section_data[0..4].try_into().unwrap_or([0; 4]))
                } else {
                    u32::from_be_bytes(section_data[0..4].try_into().unwrap_or([0; 4]))
                };
                let sh_type = if is_little_endian {
                    u32::from_le_bytes(section_data[4..8].try_into().unwrap_or([0; 4]))
                } else {
                    u32::from_be_bytes(section_data[4..8].try_into().unwrap_or([0; 4]))
                };
                let sh_flags = if is_little_endian {
                    u64::from_le_bytes(section_data[8..16].try_into().unwrap_or([0; 8]))
                } else {
                    u64::from_be_bytes(section_data[8..16].try_into().unwrap_or([0; 8]))
                };
                let sh_addr = if is_little_endian {
                    u64::from_le_bytes(section_data[16..24].try_into().unwrap_or([0; 8]))
                } else {
                    u64::from_be_bytes(section_data[16..24].try_into().unwrap_or([0; 8]))
                };
                let sh_size = if is_little_endian {
                    u64::from_le_bytes(section_data[32..40].try_into().unwrap_or([0; 8]))
                } else {
                    u64::from_be_bytes(section_data[32..40].try_into().unwrap_or([0; 8]))
                };
                (sh_name, sh_type, sh_flags, sh_addr, sh_size)
            } else {
                if section_data.len() < 40 {
                    continue;
                }
                let sh_name = if is_little_endian {
                    u32::from_le_bytes(section_data[0..4].try_into().unwrap_or([0; 4]))
                } else {
                    u32::from_be_bytes(section_data[0..4].try_into().unwrap_or([0; 4]))
                };
                let sh_type = if is_little_endian {
                    u32::from_le_bytes(section_data[4..8].try_into().unwrap_or([0; 4]))
                } else {
                    u32::from_be_bytes(section_data[4..8].try_into().unwrap_or([0; 4]))
                };
                let sh_flags = if is_little_endian {
                    u32::from_le_bytes(section_data[8..12].try_into().unwrap_or([0; 4])) as u64
                } else {
                    u32::from_be_bytes(section_data[8..12].try_into().unwrap_or([0; 4])) as u64
                };
                let sh_addr = if is_little_endian {
                    u32::from_le_bytes(section_data[12..16].try_into().unwrap_or([0; 4])) as u64
                } else {
                    u32::from_be_bytes(section_data[12..16].try_into().unwrap_or([0; 4])) as u64
                };
                let sh_size = if is_little_endian {
                    u32::from_le_bytes(section_data[20..24].try_into().unwrap_or([0; 4])) as u64
                } else {
                    u32::from_be_bytes(section_data[20..24].try_into().unwrap_or([0; 4])) as u64
                };
                (sh_name, sh_type, sh_flags, sh_addr, sh_size)
            };

            // Check if this is an executable section (SHT_PROGBITS with SHF_EXECINSTR)
            const SHT_PROGBITS: u32 = 1;
            const SHF_EXECINSTR: u64 = 0x4;

            if sh_type == SHT_PROGBITS && (sh_flags & SHF_EXECINSTR) != 0 && sh_size > 0 {
                // Get section name from string table
                let section_name = if let Some(ref strtab) = string_table {
                    self.get_string_from_table(strtab, sh_name as usize)
                        .unwrap_or_else(|| format!(".section_{}", i))
                } else {
                    format!(".section_{}", i)
                };

                code_sections.push(CodeSection {
                    name: section_name,
                    start_address: sh_addr,
                    end_address: sh_addr + sh_size,
                    size: sh_size,
                    permissions: "rx".to_string(),
                    section_type: crate::binary::CodeSectionType::Text,
                });
            }
        }

        if code_sections.is_empty() {
            return self.extract_elf_code_sections_fallback(binary_data);
        }

        Ok(code_sections)
    }

    fn extract_elf_code_sections_fallback(
        &self,
        binary_data: &[u8],
    ) -> Result<Vec<CodeSection>, String> {
        let entry_point = self.extract_elf_entry_point(binary_data)?;
        Ok(vec![CodeSection {
            name: ".text".to_string(),
            start_address: entry_point,
            end_address: entry_point + std::cmp::min(binary_data.len() as u64 / 2, 8192),
            size: std::cmp::min(binary_data.len() as u64 / 2, 8192),
            permissions: "rx".to_string(),
            section_type: crate::binary::CodeSectionType::Text,
        }])
    }

    pub fn get_elf_string_table(
        &self,
        binary_data: &[u8],
        shoff: u64,
        shentsize: u16,
        shstrndx: u16,
        is_64bit: bool,
        is_little_endian: bool,
    ) -> Option<Vec<u8>> {
        let strtab_section_offset = shoff as usize + (shstrndx as usize * shentsize as usize);
        if strtab_section_offset + shentsize as usize > binary_data.len() {
            return None;
        }

        let section_data =
            &binary_data[strtab_section_offset..strtab_section_offset + shentsize as usize];

        let (sh_offset, sh_size) = if is_64bit {
            if section_data.len() < 64 {
                return None;
            }
            let sh_offset = if is_little_endian {
                u64::from_le_bytes(section_data[24..32].try_into().ok()?)
            } else {
                u64::from_be_bytes(section_data[24..32].try_into().ok()?)
            };
            let sh_size = if is_little_endian {
                u64::from_le_bytes(section_data[32..40].try_into().ok()?)
            } else {
                u64::from_be_bytes(section_data[32..40].try_into().ok()?)
            };
            (sh_offset, sh_size)
        } else {
            if section_data.len() < 40 {
                return None;
            }
            let sh_offset = if is_little_endian {
                u32::from_le_bytes(section_data[16..20].try_into().ok()?) as u64
            } else {
                u32::from_be_bytes(section_data[16..20].try_into().ok()?) as u64
            };
            let sh_size = if is_little_endian {
                u32::from_le_bytes(section_data[20..24].try_into().ok()?) as u64
            } else {
                u32::from_be_bytes(section_data[20..24].try_into().ok()?) as u64
            };
            (sh_offset, sh_size)
        };

        if sh_offset as usize + sh_size as usize > binary_data.len() {
            return None;
        }

        Some(binary_data[sh_offset as usize..(sh_offset + sh_size) as usize].to_vec())
    }

    pub fn get_string_from_table(&self, string_table: &[u8], offset: usize) -> Option<String> {
        if offset >= string_table.len() {
            return None;
        }

        let mut end = offset;
        while end < string_table.len() && string_table[end] != 0 {
            end += 1;
        }

        String::from_utf8(string_table[offset..end].to_vec()).ok()
    }

    // PE Entry Point and Code Section Extraction
    pub fn extract_pe_entry_point(&self, binary_data: &[u8]) -> Result<u64, String> {
        if binary_data.len() < 64 || &binary_data[0..2] != b"MZ" {
            return Ok(0x401000); // Default PE image base
        }

        let pe_offset =
            u32::from_le_bytes(binary_data[0x3C..0x3C + 4].try_into().unwrap_or([0; 4])) as usize;

        if pe_offset + 40 > binary_data.len() || &binary_data[pe_offset..pe_offset + 4] != b"PE\0\0"
        {
            return Ok(0x401000);
        }

        let entry_rva_offset = pe_offset + 24 + 16;
        if entry_rva_offset + 4 <= binary_data.len() {
            let entry_rva = u32::from_le_bytes(
                binary_data[entry_rva_offset..entry_rva_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            Ok(entry_rva as u64 + 0x400000)
        } else {
            Ok(0x401000)
        }
    }

    pub fn extract_pe_code_sections(&self, binary_data: &[u8]) -> Result<Vec<CodeSection>, String> {
        let entry_point = self.extract_pe_entry_point(binary_data)?;
        Ok(vec![CodeSection {
            name: ".text".to_string(),
            start_address: entry_point,
            end_address: entry_point + std::cmp::min(binary_data.len() as u64 / 2, 8192),
            size: std::cmp::min(binary_data.len() as u64 / 2, 8192),
            permissions: "rx".to_string(),
            section_type: crate::binary::CodeSectionType::Text,
        }])
    }

    // Intel HEX Entry Point and Code Section Extraction
    pub fn extract_intel_hex_entry_point(&self, binary_data: &[u8]) -> Result<u64, String> {
        let hex_content = String::from_utf8_lossy(binary_data);
        let mut lowest_address = u64::MAX;
        let mut entry_point_found = None;

        for line in hex_content.lines() {
            if !line.starts_with(':') || line.len() < 11 {
                continue;
            }

            if let Ok(record_type) = u8::from_str_radix(&line[7..9], 16) {
                match record_type {
                    0x00 => {
                        // Data record
                        if let Ok(address) = u16::from_str_radix(&line[3..7], 16) {
                            let addr = address as u64;
                            if addr < lowest_address {
                                lowest_address = addr;
                            }
                        }
                    }
                    0x05 => {
                        // Start Linear Address
                        if line.len() >= 19 {
                            if let Ok(entry) = u32::from_str_radix(&line[9..17], 16) {
                                entry_point_found = Some(entry as u64);
                            }
                        }
                    }
                    0x03 => {
                        // Start Segment Address
                        if line.len() >= 15 {
                            if let Ok(cs) = u16::from_str_radix(&line[9..13], 16) {
                                if let Ok(ip) = u16::from_str_radix(&line[13..17], 16) {
                                    entry_point_found = Some((cs as u64) * 16 + (ip as u64));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(entry_point_found.unwrap_or(if lowest_address != u64::MAX {
            lowest_address
        } else {
            0x0000
        }))
    }

    pub fn extract_intel_hex_code_sections(
        &self,
        binary_data: &[u8],
        entry_point: u64,
    ) -> Result<Vec<CodeSection>, String> {
        let hex_content = String::from_utf8_lossy(binary_data);
        let mut memory_regions = Vec::new();
        let mut current_base_address = 0u64;

        for line in hex_content.lines() {
            if !line.starts_with(':') || line.len() < 11 {
                continue;
            }

            if let Ok(record_type) = u8::from_str_radix(&line[7..9], 16) {
                match record_type {
                    0x00 => {
                        // Data record
                        if let Ok(byte_count) = u8::from_str_radix(&line[1..3], 16) {
                            if let Ok(address) = u16::from_str_radix(&line[3..7], 16) {
                                let full_address = current_base_address + (address as u64);
                                memory_regions.push((full_address, byte_count as u64));
                            }
                        }
                    }
                    0x04 => {
                        // Extended Linear Address
                        if let Ok(base) = u16::from_str_radix(&line[9..13], 16) {
                            current_base_address = (base as u64) << 16;
                        }
                    }
                    _ => {}
                }
            }
        }

        if memory_regions.is_empty() {
            return Ok(vec![CodeSection {
                name: "flash".to_string(),
                start_address: entry_point,
                end_address: entry_point + 1024,
                size: 1024,
                permissions: "rx".to_string(),
                section_type: crate::binary::CodeSectionType::Text,
            }]);
        }

        memory_regions.sort_by_key(|&(addr, _)| addr);
        let total_size: u64 = memory_regions.iter().map(|&(_, size)| size).sum();

        Ok(vec![CodeSection {
            name: "flash".to_string(),
            start_address: memory_regions[0].0,
            end_address: memory_regions[0].0 + total_size,
            size: total_size,
            permissions: "rx".to_string(),
            section_type: crate::binary::CodeSectionType::Text,
        }])
    }

    // Motorola S-Record Entry Point and Code Section Extraction
    pub fn extract_srec_entry_point(&self, binary_data: &[u8]) -> Result<u64, String> {
        let srec_content = String::from_utf8_lossy(binary_data);
        let mut entry_point = None;
        let mut lowest_address = u64::MAX;

        for line in srec_content.lines() {
            if !line.starts_with('S') || line.len() < 4 {
                continue;
            }

            let record_type = &line[1..2];
            match record_type {
                "1" | "2" | "3" => {
                    // Data records
                    if let Ok(_byte_count) = u8::from_str_radix(&line[2..4], 16) {
                        let addr_len = match record_type {
                            "1" => 4,
                            "2" => 6,
                            "3" => 8,
                            _ => 4,
                        };

                        if line.len() >= 4 + addr_len {
                            if let Ok(address) = u64::from_str_radix(&line[4..4 + addr_len], 16) {
                                if address < lowest_address {
                                    lowest_address = address;
                                }
                            }
                        }
                    }
                }
                "7" | "8" | "9" => {
                    // Start address records
                    let addr_len = match record_type {
                        "9" => 4,
                        "8" => 6,
                        "7" => 8,
                        _ => 4,
                    };

                    if line.len() >= 4 + addr_len {
                        if let Ok(start_addr) = u64::from_str_radix(&line[4..4 + addr_len], 16) {
                            entry_point = Some(start_addr);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(entry_point.unwrap_or(if lowest_address != u64::MAX {
            lowest_address
        } else {
            0x0000
        }))
    }

    pub fn extract_srec_code_sections(
        &self,
        binary_data: &[u8],
        entry_point: u64,
    ) -> Result<Vec<CodeSection>, String> {
        let srec_content = String::from_utf8_lossy(binary_data);
        let mut memory_regions = Vec::new();

        for line in srec_content.lines() {
            if !line.starts_with('S') || line.len() < 4 {
                continue;
            }

            let record_type = &line[1..2];
            if matches!(record_type, "1" | "2" | "3") {
                if let Ok(byte_count) = u8::from_str_radix(&line[2..4], 16) {
                    let addr_len = match record_type {
                        "1" => 4,
                        "2" => 6,
                        "3" => 8,
                        _ => 4,
                    };

                    if line.len() >= 4 + addr_len {
                        if let Ok(address) = u64::from_str_radix(&line[4..4 + addr_len], 16) {
                            let data_bytes = byte_count - (addr_len as u8 / 2) - 1;
                            memory_regions.push((address, data_bytes as u64));
                        }
                    }
                }
            }
        }

        if memory_regions.is_empty() {
            return Ok(vec![CodeSection {
                name: "program".to_string(),
                start_address: entry_point,
                end_address: entry_point + 1024,
                size: 1024,
                permissions: "rx".to_string(),
                section_type: crate::binary::CodeSectionType::Text,
            }]);
        }

        memory_regions.sort_by_key(|&(addr, _)| addr);
        let total_size: u64 = memory_regions.iter().map(|&(_, size)| size).sum();

        Ok(vec![CodeSection {
            name: "program".to_string(),
            start_address: memory_regions[0].0,
            end_address: memory_regions[0].0 + total_size,
            size: total_size,
            permissions: "rx".to_string(),
            section_type: crate::binary::CodeSectionType::Text,
        }])
    }

    // ARM Cortex-M Entry Point and Code Section Extraction
    pub fn extract_arm_cortex_m_entry_point(&self, binary_data: &[u8]) -> Result<u64, String> {
        if binary_data.len() < 8 {
            return Ok(0x00000000);
        }

        // Reset vector is at offset 4 (little-endian)
        let reset_vector = u32::from_le_bytes(binary_data[4..8].try_into().unwrap_or([0; 4]));

        // ARM Cortex-M addresses have bit 0 set for Thumb mode, clear it
        Ok((reset_vector & !1) as u64)
    }

    fn extract_arm_cortex_m_code_sections(
        &self,
        binary_data: &[u8],
        entry_point: u64,
    ) -> Result<Vec<CodeSection>, String> {
        let flash_base = if entry_point >= 0x08000000 {
            0x08000000
        } else {
            0x00000000
        };

        Ok(vec![CodeSection {
            name: "flash".to_string(),
            start_address: flash_base,
            end_address: flash_base + binary_data.len() as u64,
            size: binary_data.len() as u64,
            permissions: "rx".to_string(),
            section_type: crate::binary::CodeSectionType::Text,
        }])
    }

    // Raw Firmware Entry Point and Code Section Extraction
    pub fn extract_raw_firmware_entry_point(
        &self,
        analysis: &BinaryAnalysis,
        _binary_data: &[u8],
    ) -> Result<u64, String> {
        match analysis.architecture.as_str() {
            "ARM" | "ARM64" | "AARCH64" => {
                if analysis
                    .detected_symbols
                    .iter()
                    .any(|s| s.contains("cortex") || s.contains("thumb"))
                {
                    Ok(0x08000000) // STM32-style
                } else {
                    Ok(0x00000000) // Generic ARM
                }
            }
            "x86" | "x86_64" => Ok(0x00100000), // Common x86 firmware base
            "MIPS" => Ok(0xBFC00000),           // MIPS boot ROM
            "PowerPC" => Ok(0xFFF00000),        // PowerPC boot vector
            "RISC-V" => Ok(0x80000000),         // RISC-V common base
            _ => Ok(0x00000000),                // Default
        }
    }

    pub fn extract_raw_firmware_code_sections(
        &self,
        binary_data: &[u8],
        entry_point: u64,
    ) -> Result<Vec<CodeSection>, String> {
        Ok(vec![CodeSection {
            name: "firmware".to_string(),
            start_address: entry_point,
            end_address: entry_point + binary_data.len() as u64,
            size: binary_data.len() as u64,
            permissions: "rx".to_string(),
            section_type: crate::binary::CodeSectionType::Text,
        }])
    }

    pub fn disassemble_code_section(
        &mut self,
        cs: &Capstone,
        binary_data: &[u8],
        section: &CodeSection,
        entry_point: u64,
    ) -> Result<(), String> {
        let section_start = section.start_address as usize;
        let section_size = section.size as usize;

        // Bounds checking
        if section_start >= binary_data.len() {
            return Ok(()); // Section is beyond binary data
        }

        let actual_size = std::cmp::min(section_size, binary_data.len() - section_start);
        let section_data = &binary_data[section_start..section_start + actual_size];

        tracing::info!(
            "Disassembling section {} at 0x{:x} (size: {})",
            section.name,
            section.start_address,
            actual_size
        );

        // Disassemble the section
        let instructions = cs
            .disasm_all(section_data, section.start_address)
            .map_err(|e| format!("Disassembly failed: {}", e))?;

        // Build basic blocks from disassembled instructions
        self.build_basic_blocks_from_instructions(&instructions, entry_point)?;

        Ok(())
    }

    pub fn build_basic_blocks_from_instructions(
        &mut self,
        instructions: &capstone::Instructions,
        entry_point: u64,
    ) -> Result<(), String> {
        if instructions.is_empty() {
            return Ok(());
        }

        // Find basic block boundaries
        let mut block_starts = std::collections::HashSet::new();
        block_starts.insert(entry_point);

        // Add instruction addresses that start basic blocks
        for insn in instructions.iter() {
            let addr = insn.address();

            // Check if this is a jump target or function start
            if self.is_block_boundary_instruction(&insn) {
                block_starts.insert(addr);

                // Also mark the next instruction as a block start
                if let Some(next_insn) = instructions.iter().find(|i| i.address() > addr) {
                    block_starts.insert(next_insn.address());
                }
            }

            // Mark targets of branch instructions
            if let Some(target) = self.get_branch_target(&insn) {
                block_starts.insert(target);
            }
        }

        // Convert to sorted vector
        let mut starts: Vec<u64> = block_starts.into_iter().collect();
        starts.sort();

        // Build basic blocks
        for i in 0..starts.len() {
            let start_addr = starts[i];
            let end_addr = if i + 1 < starts.len() {
                starts[i + 1]
            } else {
                instructions
                    .iter()
                    .last()
                    .map(|i| i.address() + i.bytes().len() as u64)
                    .unwrap_or(start_addr + 1)
            };

            // Collect instructions for this block
            let block_instructions: Vec<Instruction> = instructions
                .iter()
                .filter(|insn| insn.address() >= start_addr && insn.address() < end_addr)
                .map(|insn| Instruction {
                    address: insn.address(),
                    mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                    operands: insn.op_str().unwrap_or("").to_string(),
                    bytes: insn.bytes().to_vec(),
                    size: insn.bytes().len() as u32,
                    is_branch: self.is_branch_instruction(&insn),
                    is_call: self.is_call_instruction(&insn),
                    is_return: self.is_return_instruction(&insn),
                    branch_target: self.get_branch_target(&insn),
                })
                .collect();

            if block_instructions.is_empty() {
                continue;
            }

            // Determine block type with improved heuristics
            let block_type = if start_addr == entry_point {
                BasicBlockType::FunctionEntry {
                    function_name: format!("entry_{:x}", start_addr),
                    address: start_addr,
                }
            } else if self.is_function_entry_heuristic(start_addr, &block_instructions) {
                BasicBlockType::FunctionEntry {
                    function_name: format!("func_{:x}", start_addr),
                    address: start_addr,
                }
            } else if self.is_conditional_block(&block_instructions) {
                BasicBlockType::ConditionalBranch {
                    address: start_addr,
                    condition: self.extract_condition(&block_instructions),
                }
            } else if self.is_call_block(&block_instructions) {
                BasicBlockType::FunctionCall {
                    address: start_addr,
                    target: self.extract_call_target(&block_instructions),
                }
            } else {
                BasicBlockType::Sequential {
                    start_address: start_addr,
                    end_address: end_addr,
                }
            };

            let basic_block = BasicBlock {
                instructions: block_instructions,
                block_type,
                size_bytes: (end_addr - start_addr) as usize,
                execution_count: None,
            };

            // Track function entries before moving basic_block
            let function_name = if let BasicBlockType::FunctionEntry { function_name, .. } =
                &basic_block.block_type
            {
                Some(function_name.clone())
            } else {
                None
            };

            let node = self.graph.add_node(basic_block);
            self.address_to_node.insert(start_addr, node);

            if let Some(name) = function_name {
                self.function_entries.insert(name, node);
            }
        }

        Ok(())
    }

    pub fn get_block_end_address(&self, block: &BasicBlock) -> u64 {
        if let Some(last_insn) = block.instructions.last() {
            last_insn.address + last_insn.size as u64
        } else {
            match &block.block_type {
                BasicBlockType::FunctionEntry { address, .. } => *address,
                BasicBlockType::Sequential { end_address, .. } => *end_address,
                BasicBlockType::ConditionalBranch { address, .. } => *address,
                BasicBlockType::UnconditionalJump { address, .. } => *address,
                BasicBlockType::FunctionCall { address, .. } => *address,
                BasicBlockType::Return { address } => *address,
                BasicBlockType::ExceptionHandler { address, .. } => *address,
            }
        }
    }

    pub fn build_control_flow_edges(&mut self) -> Result<(), String> {
        let nodes: Vec<_> = self.graph.node_indices().collect();

        for node_idx in nodes {
            if let Some(block) = self.graph.node_weight(node_idx).cloned() {
                let end_address = self.get_block_end_address(&block);
                match &block.block_type {
                    BasicBlockType::Sequential { .. } => {
                        if let Some(next_node) = self.find_block_at_address(end_address) {
                            self.graph
                                .add_edge(node_idx, next_node, EdgeType::Sequential);
                        }
                    }
                    BasicBlockType::ConditionalBranch { .. } => {
                        // Connect to both fall-through and branch target
                        if let Some(next_node) = self.find_block_at_address(end_address) {
                            self.graph
                                .add_edge(node_idx, next_node, EdgeType::ConditionalFalse);
                        }
                        // TODO: Extract and connect to branch target
                    }
                    BasicBlockType::FunctionCall { .. } => {
                        if let Some(return_node) = self.find_block_at_address(end_address) {
                            self.graph.add_edge(node_idx, return_node, EdgeType::Call);
                        }
                    }
                    _ => {
                        if let Some(next_node) = self.find_block_at_address(end_address) {
                            self.graph
                                .add_edge(node_idx, next_node, EdgeType::Sequential);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn find_block_at_address(&self, address: u64) -> Option<NodeIndex> {
        self.address_to_node.get(&address).copied()
    }

    // Helper methods for instruction analysis
    pub fn is_function_entry_heuristic(&self, addr: u64, instructions: &[Instruction]) -> bool {
        if instructions.is_empty() {
            return false;
        }

        let first_insn = &instructions[0];

        // Common function prologue patterns
        match first_insn.mnemonic.as_str() {
            // x86/x64 function prologues
            "push" if first_insn.operands.contains("bp") || first_insn.operands.contains("rbp") => {
                true
            }
            "mov" if first_insn.operands.contains("bp") || first_insn.operands.contains("rbp") => {
                true
            }
            "sub" if first_insn.operands.contains("sp") || first_insn.operands.contains("rsp") => {
                true
            }

            // ARM function prologues
            "push" if first_insn.operands.contains("lr") => true,
            "stmdb" if first_insn.operands.contains("sp!") => true,
            "str" if first_insn.operands.contains("lr") => true,

            // RISC-V function prologues
            "addi" if first_insn.operands.contains("sp") => true,
            "sd" if first_insn.operands.contains("ra") => true,

            _ => {
                // Check if address is aligned (common for function entries)
                addr % 4 == 0 || addr % 8 == 0
            }
        }
    }

    pub fn is_block_boundary_instruction(&self, insn: &capstone::Insn) -> bool {
        if let Some(mnemonic) = insn.mnemonic() {
            matches!(
                mnemonic,
                // x86/x64
                "ret" | "retq" | "retn" |           // Returns
                "jmp" | "jmpq" |                    // Unconditional jumps
                "je" | "jne" | "jz" | "jnz" |       // Conditional jumps
                "jl" | "jle" | "jg" | "jge" |
                "ja" | "jae" | "jb" | "jbe" |
                "jo" | "jno" | "js" | "jns" |
                "call" | "callq" |                  // Function calls
                
                // ARM
                "bx" | "blx" | "b" | "bl" |
                "bmi" | "bpl" | "bvs" | "bvc" | "bhi" | "bls" |
                
                // RISC-V/ARM/MIPS shared conditional branches
                "beq" | "bne" | "blt" | "ble" | "bgt" | "bge" |
                
                // RISC-V/MIPS specific
                "bltu" | "bgeu" | "jal" | "jalr" |
                "j" | "jr" | "bgtz" | "blez" | "bltz" | "bgez"
            )
        } else {
            false
        }
    }

    pub fn is_branch_instruction(&self, insn: &capstone::Insn) -> bool {
        if let Some(mnemonic) = insn.mnemonic() {
            matches!(
                mnemonic,
                "jmp"
                    | "jmpq"
                    | "je"
                    | "jne"
                    | "jz"
                    | "jnz"
                    | "jl"
                    | "jle"
                    | "jg"
                    | "jge"
                    | "ja"
                    | "jae"
                    | "jb"
                    | "jbe"
                    | "jo"
                    | "jno"
                    | "js"
                    | "jns"
                    | "b"
                    | "bl"
                    | "bx"
                    | "blx"
                    | "beq"
                    | "bne"
                    | "blt"
                    | "ble"
                    | "bgt"
                    | "bge"
                    | "bmi"
                    | "bpl"
                    | "bvs"
                    | "bvc"
                    | "bhi"
                    | "bls"
                    | "jal"
                    | "jalr"
                    | "j"
                    | "jr"
                    | "bgtz"
                    | "blez"
                    | "bltz"
                    | "bgez"
                    | "bltu"
                    | "bgeu"
            )
        } else {
            false
        }
    }

    pub fn is_call_instruction(&self, insn: &capstone::Insn) -> bool {
        if let Some(mnemonic) = insn.mnemonic() {
            matches!(mnemonic, "call" | "callq" | "bl" | "blx" | "jal" | "jalr")
        } else {
            false
        }
    }

    pub fn is_return_instruction(&self, insn: &capstone::Insn) -> bool {
        if let Some(mnemonic) = insn.mnemonic() {
            matches!(mnemonic, "ret" | "retq" | "retn" | "bx" | "jr")
        } else {
            false
        }
    }

    pub fn get_branch_target(&self, insn: &capstone::Insn) -> Option<u64> {
        if let Some(op_str) = insn.op_str() {
            // Try to parse hex addresses (e.g., "0x401000")
            if op_str.starts_with("0x") {
                if let Ok(addr) = u64::from_str_radix(&op_str[2..], 16) {
                    return Some(addr);
                }
            }
            // Try to parse decimal addresses
            if let Ok(addr) = op_str.parse::<u64>() {
                return Some(addr);
            }
        }
        None
    }

    pub fn is_conditional_block(&self, instructions: &[Instruction]) -> bool {
        instructions.iter().any(|insn| {
            matches!(
                insn.mnemonic.as_str(),
                // x86/x64 conditional jumps
                "je" | "jne" | "jz" | "jnz" |
                "jl" | "jle" | "jg" | "jge" |
                "ja" | "jae" | "jb" | "jbe" |
                "jo" | "jno" | "js" | "jns" |
                
                // ARM specific
                "bmi" | "bpl" | "bvs" | "bvc" | "bhi" | "bls" |
                
                // Shared conditional branches (ARM/RISC-V/MIPS)
                "beq" | "bne" | "blt" | "ble" | "bgt" | "bge" |
                
                // RISC-V/MIPS specific
                "bltu" | "bgeu" | "bgtz" | "blez" | "bltz" | "bgez"
            )
        })
    }

   pub fn is_call_block(&self, instructions: &[Instruction]) -> bool {
        instructions.iter().any(|insn| {
            matches!(
                insn.mnemonic.as_str(),
                "call" | "callq" |      // x86/x64
                "bl" | "blx" |          // ARM
                "jal" | "jalr" // RISC-V
            )
        })
    }

    pub fn extract_condition(&self, instructions: &[Instruction]) -> String {
        for insn in instructions {
            if matches!(
                insn.mnemonic.as_str(),
                "je" | "jne"
                    | "jz"
                    | "jnz"
                    | "jl"
                    | "jle"
                    | "jg"
                    | "jge"
                    | "ja"
                    | "jae"
                    | "jb"
                    | "jbe"
                    | "jo"
                    | "jno"
                    | "js"
                    | "jns"
                    | "beq"
                    | "bne"
                    | "blt"
                    | "ble"
                    | "bgt"
                    | "bge"
                    | "bmi"
                    | "bpl"
                    | "bvs"
                    | "bvc"
                    | "bhi"
                    | "bls"
                    | "bgtz"
                    | "blez"
                    | "bltz"
                    | "bgez"
                    | "bltu"
                    | "bgeu"
            ) {
                return format!("{} {}", insn.mnemonic, insn.operands);
            }
        }
        "unknown".to_string()
    }

    pub fn extract_call_target(&self, instructions: &[Instruction]) -> String {
        for insn in instructions {
            if matches!(
                insn.mnemonic.as_str(),
                "call" | "callq" | "bl" | "blx" | "jal" | "jalr"
            ) {
                return insn.operands.clone();
            }
        }
        "unknown".to_string()
    }

    pub fn create_placeholder_instructions(
        &self,
        start_addr: u64,
        function_name: &str,
    ) -> Vec<Instruction> {
        // Create realistic instruction sequences based on function names
        let mut instructions = Vec::new();
        let mut addr = start_addr;

        // Function prologue
        instructions.push(Instruction {
            address: addr,
            mnemonic: "push".to_string(),
            operands: "rbp".to_string(),
            bytes: vec![0x55],
            size: 1,
            is_branch: false,
            is_call: false,
            is_return: false,
            branch_target: None,
        });
        addr += 1;

        instructions.push(Instruction {
            address: addr,
            mnemonic: "mov".to_string(),
            operands: "rbp, rsp".to_string(),
            bytes: vec![0x48, 0x89, 0xE5],
            size: 3,
            is_branch: false,
            is_call: false,
            is_return: false,
            branch_target: None,
        });
        addr += 3;

        // Add function-specific instructions based on name patterns
        if function_name.contains("malloc") || function_name.contains("alloc") {
            instructions.push(Instruction {
                address: addr,
                mnemonic: "test".to_string(),
                operands: "rdi, rdi".to_string(),
                bytes: vec![0x48, 0x85, 0xFF],
                size: 3,
                is_branch: false,
                is_call: false,
                is_return: false,
                branch_target: None,
            });
            addr += 3;

            instructions.push(Instruction {
                address: addr,
                mnemonic: "jz".to_string(),
                operands: format!("0x{:x}", addr + 10),
                bytes: vec![0x74, 0x08],
                size: 2,
                is_branch: true,
                is_call: false,
                is_return: false,
                branch_target: Some(addr + 10),
            });
        }

        // Function epilogue
        addr += 10;
        instructions.push(Instruction {
            address: addr,
            mnemonic: "pop".to_string(),
            operands: "rbp".to_string(),
            bytes: vec![0x5D],
            size: 1,
            is_branch: false,
            is_call: false,
            is_return: false,
            branch_target: None,
        });
        addr += 1;

        instructions.push(Instruction {
            address: addr,
            mnemonic: "ret".to_string(),
            operands: "".to_string(),
            bytes: vec![0xC3],
            size: 1,
            is_branch: false,
            is_call: false,
            is_return: true,
            branch_target: None,
        });

        instructions
    }

    pub fn detect_loops(&mut self) {
        // Implement natural loop detection using dominator analysis
        // This is a simplified version - would need proper back-edge detection

        for node_idx in self.graph.node_indices() {
            if let Some(block) = self.graph.node_weight(node_idx) {
                // Look for back edges (edges to blocks that dominate the current block)
                for edge in self.graph.edges_directed(node_idx, Direction::Outgoing) {
                    let target = edge.target();

                    // Simple heuristic: if target address < current address, it might be a back edge
                    if let (Some(current_addr), Some(target_addr)) = (
                        self.get_block_address(block),
                        self.get_block_address_by_node(target),
                    ) {
                        if target_addr < current_addr {
                            // Potential back edge - create loop info
                            let loop_info = LoopInfo {
                                header: target_addr,
                                back_edges: vec![(current_addr, target_addr)],
                                loop_blocks: HashSet::from([current_addr, target_addr]),
                                nesting_level: 1,
                                loop_type: LoopType::Natural,
                            };

                            self.loops.push(loop_info);
                        }
                    }
                }
            }
        }
    }

    pub fn build_dominators(&mut self) {
        if let Some(entry_node) = self.graph.node_indices().next() {
            self.dominators = Some(dominators::simple_fast(&self.graph, entry_node));
        }
    }

    pub fn get_block_address(&self, block: &BasicBlock) -> Option<u64> {
        match &block.block_type {
            BasicBlockType::FunctionEntry { address, .. } => Some(*address),
            BasicBlockType::Sequential { start_address, .. } => Some(*start_address),
            BasicBlockType::ConditionalBranch { address, .. } => Some(*address),
            BasicBlockType::UnconditionalJump { address, .. } => Some(*address),
            BasicBlockType::FunctionCall { address, .. } => Some(*address),
            BasicBlockType::Return { address } => Some(*address),
            BasicBlockType::ExceptionHandler { address, .. } => Some(*address),
        }
    }

   pub fn get_block_address_by_node(&self, node_idx: NodeIndex) -> Option<u64> {
        self.graph
            .node_weight(node_idx)
            .and_then(|block| self.get_block_address(block))
    }

    /// Analyze call graph relationships
    pub fn analyze_call_graph(&self, analysis: &BinaryAnalysis) -> CallGraphAnalysis {
        let mut call_sites = Vec::new();
        let mut function_summaries = HashMap::new();
        let mut recursive_functions = Vec::new();
        let mut dead_functions = Vec::new();

        // Build function summaries
        for (func_name, &node_idx) in &self.function_entries {
            let mut calls_made = Vec::new();
            let mut total_size = 0;

            // Traverse all blocks reachable from this function entry
            let reachable = dijkstra(&self.graph, node_idx, None, |_| 1);
            let basic_blocks = reachable.len();

            // Analyze outgoing call edges
            for edge in self.graph.edges_directed(node_idx, Direction::Outgoing) {
                if matches!(edge.weight(), EdgeType::Call) {
                    if let Some(target_block) = self.graph.node_weight(edge.target()) {
                        if let BasicBlockType::FunctionCall { target, .. } =
                            &target_block.block_type
                        {
                            calls_made.push(target.clone());

                            call_sites.push(CallSite {
                                caller_address: self.get_block_address(target_block).unwrap_or(0),
                                callee: target.clone(),
                                call_type: CallType::Direct,
                                arguments: vec![], // Would analyze calling convention
                            });
                        }
                    }
                }
            }

            // Calculate cyclomatic complexity (simplified)
            let mut complexity = 1; // Base complexity
            for reachable_node in reachable.keys() {
                if let Some(block) = self.graph.node_weight(*reachable_node) {
                    total_size += block.size_bytes;

                    match &block.block_type {
                        BasicBlockType::ConditionalBranch { .. } => complexity += 1,
                        _ => {}
                    }
                }
            }

            // Check for recursion
            if calls_made.contains(func_name) {
                recursive_functions.push(func_name.clone());
            }

            function_summaries.insert(
                func_name.clone(),
                FunctionSummary {
                    entry_address: self.get_block_address_by_node(node_idx).unwrap_or(0),
                    size_bytes: total_size,
                    basic_blocks,
                    cyclomatic_complexity: complexity,
                    calls_made,
                    calls_received: vec![], // Would be filled by reverse analysis
                    has_loops: self.loops.iter().any(|l| {
                        l.loop_blocks
                            .contains(&self.get_block_address_by_node(node_idx).unwrap_or(0))
                    }),
                    max_call_depth: 1, // Would require recursive analysis
                },
            );
        }

        // Find dead functions (not called by anyone)
        for symbol in &analysis.detected_symbols {
            if !call_sites.iter().any(|cs| cs.callee == *symbol)
                && symbol != "_start"
                && symbol != "main"
            {
                dead_functions.push(symbol.clone());
            }
        }

        CallGraphAnalysis {
            call_sites,
            function_summaries,
            recursive_functions,
            dead_functions,
        }
    }

    /// Get basic blocks that are loop headers
    #[allow(dead_code)]
    pub fn get_loop_headers(&self) -> Vec<u64> {
        self.loops.iter().map(|l| l.header).collect()
    }

    /// Check if an address is in a loop
    #[allow(dead_code)]
    pub fn is_in_loop(&self, address: u64) -> bool {
        self.loops.iter().any(|l| l.loop_blocks.contains(&address))
    }

    /// Get dominator information for a block
    #[allow(dead_code)]
    pub fn get_dominators(&self, node: NodeIndex) -> Option<Vec<NodeIndex>> {
        self.dominators.as_ref().map(|dom| {
            let mut dominators = Vec::new();
            let mut current = Some(node);

            while let Some(n) = current {
                dominators.push(n);
                current = dom.immediate_dominator(n);
            }

            dominators
        })
    }
}

/// Separate exploitability analysis that uses the CFG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityAnalysis {
    pub is_reachable: bool,
    pub path: Option<Vec<String>>,
    pub sink: String,
    pub confidence: f32,
    pub attack_vectors: Vec<AttackVector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackVector {
    pub vector_type: String,
    pub entry_points: Vec<u64>,
    pub vulnerable_path: Vec<u64>,
    pub prerequisites: Vec<String>,
    pub impact: String,
}

impl ExploitabilityAnalysis {
    pub fn analyze(cfg: &ControlFlowGraph, sources: &[String], sink: &str) -> Self {
        // Use the CFG to perform more sophisticated reachability analysis
        let mut is_reachable = false;
        let mut path = None;
        let mut attack_vectors = Vec::new();

        // Find sink node
        if let Some(&sink_node) = cfg.function_entries.get(sink) {
            // Check reachability from each source
            for source in sources {
                if let Some(&source_node) = cfg.function_entries.get(source) {
                    let paths = dijkstra(&cfg.graph, source_node, Some(sink_node), |_| 1);

                    if paths.contains_key(&sink_node) {
                        is_reachable = true;

                        // Build path description
                        let mut path_nodes = Vec::new();
                        let current = sink_node;
                        while let Some(block) = cfg.graph.node_weight(current) {
                            if let Some(addr) = cfg.get_block_address(block) {
                                path_nodes.push(format!("0x{:x}", addr));
                                // This is simplified - would need proper path reconstruction
                                break;
                            }
                        }

                        path = Some(vec![source.clone(), sink.to_string()]);

                        // Create attack vector
                        attack_vectors.push(AttackVector {
                            vector_type: "Control Flow".to_string(),
                            entry_points: vec![
                                cfg.get_block_address_by_node(source_node).unwrap_or(0),
                            ],
                            vulnerable_path: vec![
                                cfg.get_block_address_by_node(sink_node).unwrap_or(0),
                            ],
                            prerequisites: vec!["User input control".to_string()],
                            impact: "Code execution".to_string(),
                        });

                        break;
                    }
                }
            }
        }

        ExploitabilityAnalysis {
            is_reachable,
            path,
            sink: sink.to_string(),
            confidence: if is_reachable { 0.8 } else { 0.0 },
            attack_vectors,
        }
    }
}
