![](./public/banner.png)

# The Atelier Logos API Platform

[![Rust Version](https://img.shields.io/badge/rust-1.82%2B-orange?style=flat-square)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue?style=flat-square)](https://hub.docker.com/r/jdbohrman/nabla)
[![OpenAI Enriched](https://img.shields.io/badge/LLM-OpenAI-purple?style=flat-square&logo=openai&logoColor=white)](https://platform.openai.com/)

A comprehensive dependency intelligence, SBOM generation, binary analysis API platform built with Rust, Axum, and Goblin that provides an interface for extracting deep insights into the security and implementation of Rust packages and binaries of various types. 

## Features

- **Security Insights**: Scan Rust crates for vulnerabilities and unsafe code
- **License Analysis**: Detection and analysis of licenses using `cargo-license`
- **Source Code Analysis**: Using `syn` to extract structural information
- **Binary Analysis**: Using `goblin` to extract structural information
- **Documentation Analysis**: Evaluates documentation coverage and quality
- **SBOM Generation**: Generates Software Bill of Materials (SBOM)
- **API Integration**: RESTful API for integration with any platform
- **Database Storage**: Full analysis results stored in PostgreSQL

## LLM Enrichment Details

The following fields are **enriched via OpenAI** (LLM):
- **Module Descriptions**: Natural-language summaries of each module's purpose and contents
- **Struct/Enum/Type Descriptions**: Human-readable explanations of data structures
- **Function/Trait Descriptions**: Summaries of what each function or trait does
- **Usage Examples**: LLM-generated code snippets or usage patterns
- **Documentation Summaries**: High-level summaries of documentation coverage and quality

The following fields are **not LLM-enriched** (static analysis only):
- **Security Audit Results**: Direct output from `cargo-audit`
- **License Information**: Direct output from `cargo-license`
- **Dependency Graphs**: From `cargo metadata`
- **Unsafe Code Locations**: From static code analysis
- **Git History**: From `git2`/repository inspection
- **Build Information**: Static detection of build scripts, macros, etc.

## API Endpoints

### POST /packages

Analyzes a Rust package and stores results in the database.

**Request Body:**
```json
{
  "name": "serde",
  "version": "1.0.0",
  "api_key": "your-api-key",
}
```

**Response:**
```json
{
  "success": true,
  "package_id": "uuid-of-analysis",
  "message": "Package serde:1.0.0 analyzed successfully",
  "enriched_fields": [
    "module_descriptions",
    "struct_descriptions",
    "function_descriptions",
    "trait_descriptions",
    "usage_examples",
    "documentation_summaries"
  ]
}
```

### GET /binary

Analyzes a binary and stores results in the database.

**Request Body:**
```json
{
  "path": "/path/to/binary",
  "api_key": "your-api-key",
}
```

**Response:**
```json
{
  "success": true,
  "binary_id": "uuid-of-analysis",
  "message": "Binary analyzed successfully",
  "enriched_fields": [
    "module_descriptions",
    "struct_descriptions",
    "function_descriptions",
    "trait_descriptions",
    "usage_examples",
    "documentation_summaries"
  ]
}
```

**Note:** You can find documentation for other endpoints at the [Platform Docs](https://docs.atelierlogos.studio).

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "nabla",
  "version": "0.1.0"
}
```

## Analyzed Data

The API extracts and stores the following information:

- **Package Metadata**: Name, version, description, repository, homepage, documentation *(not LLM-enriched)*
- **Dependencies**: Full dependency graph with version requirements *(not LLM-enriched)*
- **Source Analysis**: Key modules, structs, functions, traits *(LLM-enriched: descriptions, summaries, usage examples)*
- **Security**: Cargo audit results, unsafe code locations, CVE references *(not LLM-enriched)*
- **Licenses**: License information from multiple sources *(not LLM-enriched)*
- **Documentation**: Coverage analysis and quality metrics *(LLM-enriched: summaries and quality analysis)*
- **Build Information**: Presence of build.rs, macro usage *(not LLM-enriched)*
- **Git History**: Last commit date, estimated publish date *(not LLM-enriched)*

## Setup

### Prerequisites

- Rust 1.82+
- PostgreSQL database (or Supabase)
- `cargo-audit` (automatically installed)
- `cargo-license` (automatically installed)
- `goblin` (automatically installed)
- `syn` (automatically installed)
- `git2` (automatically installed)
- `sqlx` (automatically installed)

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
DATABASE_URL=postgresql://username:password@localhost/nabla
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
PORT=8080
OPENAI_API_KEY=sk-**************************************
```

### Database Setup

1. Run migrations:
```bash
cargo install sqlx-cli
sqlx migrate run
```

2. The migration creates a test API key: `test-api-key-12345`

### Running

```bash
cargo run
```

The server will start on the configured port (default: 8080).

## Database Schema

### packages table

Stores complete analysis results with fields for:
- Package metadata (name, version, description, etc.) *(not LLM-enriched)*
- Structural analysis (modules, structs, functions, traits) *(LLM-enriched: descriptions, summaries, usage)*
- Security analysis (audit reports, unsafe usage, CVEs) *(not LLM-enriched)*
- Documentation metrics *(LLM-enriched: summaries)*
- Git information *(not LLM-enriched)*
- License data *(not LLM-enriched)*

### api_keys table

Manages API authentication:
- UUID key IDs
- API key strings
- Key names and status

### binary table

Stores complete analysis results with fields for:
- Binary metadata (path, size, etc.) *(not LLM-enriched)*
- Structural analysis (modules, structs, functions, traits) *(LLM-enriched: descriptions, summaries, usage)*
- Security analysis (audit reports, unsafe usage, CVEs) *(not LLM-enriched)*
- Documentation metrics *(LLM-enriched: summaries)*
- Git information *(not LLM-enriched)*
- License data *(not LLM-enriched)*

## Integration

## Tools Integration

- **cargo-audit**: Vulnerability scanning with advisory database *(not LLM-enriched)*
- **cargo-license**: License information extraction *(not LLM-enriched)*
- **cargo metadata**: Package metadata and dependency graphs *(not LLM-enriched)*
- **syn**: AST parsing for source code analysis *(partially LLM-enriched)*
- **rustdoc**: Documentation generation and analysis *(partially LLM-enriched)*
- **git2**: Repository history analysis *(not LLM-enriched)*

## Performance

- Parallel analysis execution where possible
- Efficient database operations with connection pooling
- Streaming analysis for large packages
- Temporary file cleanup

## Error Handling

- Comprehensive error responses
- Logging integration with tracing
- Graceful degradation when tools fail
- Database transaction safety

## Security

- API key authentication
- SQL injection protection via SQLx
- Input validation
- Secure temporary file handling

## License

This project is licensed under the Functional Source License - see the LICENSE file for details.
