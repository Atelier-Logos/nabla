# Ferropipe Audit

A comprehensive Rust package analysis API built with Axum that provides detailed security and code quality analysis for Rust crates.

## Features

- **Security Analysis**: Integration with `cargo-audit` for vulnerability scanning
- **License Analysis**: Detection and analysis of licenses using `cargo-license`
- **Source Code Analysis**: Using `syn` to extract structural information
- **Unsafe Code Detection**: Locates and reports unsafe code blocks
- **Documentation Analysis**: Evaluates documentation coverage and quality
- **Git Analysis**: Extracts repository history and commit information
- **API Integration**: RESTful API for integration with NextJS frontends
- **Database Storage**: Full analysis results stored in Supabase/PostgreSQL

## API Endpoints

### POST /analyze

Analyzes a Rust package and stores results in the database.

**Request Body:**
```json
{
  "name": "serde",
  "version": "1.0.0",
  "api_key": "your-api-key",
  "extraction_depth": "deep"
}
```

**Response:**
```json
{
  "success": true,
  "package_id": "uuid-of-analysis",
  "message": "Package serde:1.0.0 analyzed successfully"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "ferropipe-audit",
  "version": "0.1.0"
}
```

## Analyzed Data

The API extracts and stores the following information:

- **Package Metadata**: Name, version, description, repository, homepage, documentation
- **Dependencies**: Full dependency graph with version requirements
- **Source Analysis**: Key modules, structs, functions, traits
- **Security**: Cargo audit results, unsafe code locations, CVE references
- **Licenses**: License information from multiple sources
- **Documentation**: Coverage analysis and quality metrics
- **Build Information**: Presence of build.rs, macro usage
- **Git History**: Last commit date, estimated publish date

## Setup

### Prerequisites

- Rust 1.70+
- PostgreSQL database (or Supabase)
- `cargo-audit` (automatically installed)
- `cargo-license` (automatically installed)

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
DATABASE_URL=postgresql://username:password@localhost/ferropipe_audit
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
PORT=3001
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

The server will start on the configured port (default: 3001).

## Database Schema

### packages table

Stores complete analysis results with fields for:
- Package metadata (name, version, description, etc.)
- Structural analysis (modules, structs, functions, traits)
- Security analysis (audit reports, unsafe usage, CVEs)
- Documentation metrics
- Git information
- License data

### api_keys table

Manages API authentication:
- UUID key IDs
- API key strings
- Key names and status

## Integration

### NextJS Frontend

```typescript
const analyzePackage = async (name: string, version: string) => {
  const response = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      version,
      api_key: process.env.FERROPIPE_API_KEY,
      extraction_depth: 'deep'
    })
  });
  
  return response.json();
};
```

## Tools Integration

- **cargo-audit**: Vulnerability scanning with advisory database
- **cargo-license**: License information extraction
- **cargo metadata**: Package metadata and dependency graphs
- **syn**: AST parsing for source code analysis
- **rustdoc**: Documentation generation and analysis
- **git2**: Repository history analysis

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

This project is licensed under the MIT License - see the LICENSE file for details.
