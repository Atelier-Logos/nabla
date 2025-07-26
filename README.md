![](https://github.com/Atelier-Logos/nabla/blob/main/public/banner.png?raw=true)

[![codecov](https://codecov.io/github/Atelier-Logos/nabla/branch/main/graph/badge.svg?token=A25NWBGGB9)](https://codecov.io/github/Atelier-Logos/nabla)
[![CI](https://github.com/Atelier-Logos/nabla/actions/workflows/coverage.yml/badge.svg)](https://github.com/Atelier-Logos/nabla/actions/workflows/coverage.yml)
[![License: FSL](https://img.shields.io/badge/license-FSL-lightgrey)](LICENSE)


# Nabla - A fair-source SAST/SCA API for calculating your SSCS gradients

![terminal demo](demo.gif)

> The nabla is used in vector calculus as part of three distinct differential operators: the gradient (∇), the divergence (∇⋅), and the curl (∇×)

Nabla is a binary-first, fair-source, secure API for SAST/SCA tasks — designed to analyze, monitor, and validate the binaries used in your tools, applications, or infrastructure.

Built in Rust and deployable anywhere via Docker, Nabla helps modern teams build resilient CI/CD pipelines by generating attestations, SBOMs, CVE reports, and more — all from binaries alone.

## 🧐 Why Nabla?

We built this tool because as ecosystems like Rust and Wasm grow, it's becoming more and more common for developers to use third-party binaries in their code and infrastructure. 

This introduces risk into the software supply chain, including:

    - Shadow dependencies and bundled binaries
    - Missing or unverifiable SBOMs
    - Unknown vulnerabilities (CVEs)
    - Inability to produce attestations or verify signatures

Nabla acts like a firewall for your binary inputs — providing deep binary analysis, vulnerability detection, attestation, and SBOMs in a clean, simple API.

## ✨ Features

- **🔍 Binary Analysis**:  ELF, PE, Mach-O, and Wasm parsing via `goblin`
- **🧾 SBOM Generation**: CycloneDX format generation from extracted packages
- **🚨 CVE Lookup**: Detect vulnerabilities in known packages and binary patterns
- **✍️ Attestation**: Sigstore-compatible predicate output ready for signing
- **⛓️‍💥 Diffing**: Compare two binaries and view differences in content and structure
- **⚙️ REST API**: JSON-first API built on Axum, ready for CI/CD pipelines

## 🔌 API Endpoints

All endpoints require an `Authorization: Bearer` token header unless otherwise configured.

### POST /binary/analyze

Uploads a binary and returns detailed metadata, a package list, and a CycloneDX SBOM. 

**Example:
```bash
curl -X POST http://localhost:8080/binary/analyse \
  -H "Authorization: Bearer your_license_key" \
  -F "file=@./your_binary"
```

**Request Params:

```json
{
  "file": "<binary file>"  // multipart/form-data
}
```

**Response Format:
```json
{
  "format": "ELF" | "MachO" | "PE" | "WASM",
  "hashes": {
    "sha256": "string"
  },
  "metadata": {
    "arch": "x86_64",
    "os": "linux",
    "entrypoint": "0x400000"
  },
  "packages": [
    {
      "name": "openssl",
      "version": "1.1.1",
      "origin": "debian",
      "license": "OpenSSL",
      "source": "extracted"
    }
  ],
}
```


### POST /binary/diff

Compares two binaries and returns metadata, symbol, and package-level differences.

**Example:
```bash
curl -X POST http://localhost:8080/binary/diff \
  -H "Authorization: Bearer your_license_key" \
  -F "file1=@old_binary" \
  -F "file2=@new_binary"
```

**Request Params:

```json
{
  "file1": "<binary file>",
  "file2": "<binary file>"
}
```

**Response Format:
```json
{
  "diff": {
    "added": [
      {
        "name": "libssl",
        "version": "3.0.0"
      }
    ],
    "removed": [
      {
        "name": "libssl",
        "version": "1.1.1"
      }
    ],
    "changed": [
      {
        "name": "libcurl",
        "old_version": "7.78.0",
        "new_version": "7.88.0"
      }
    ]
  },
  "file1": {
    "hash": "sha256:...",
    "format": "ELF"
  },
  "file2": {
    "hash": "sha256:...",
    "format": "ELF"
  }
}

```

### POST /binary/attest

Generates a unsigned Sigstore-compatible attestation from the given binary. 

**Example:
```bash
curl -X POST http://localhost:8080/binary/attest \
  -H "Authorization: Bearer your_license_key" \
  -F "file=@./my_binary" \
  -o attestation.json
```

**Request Params:

```json
{
  "file": "<binary file>"
}
```

**Response Format:
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [
    {
      "name": "your_binary",
      "digest": {
        "sha256": "..."
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "nabla:internal"
    },
    "buildType": "nabla/binary-analysis",
    "metadata": {
      "buildStartedOn": "2025-07-21T12:34:00Z"
    },
    "materials": [
      {
        "uri": "file:./my_binary",
        "digest": {
          "sha256": "..."
        }
      }
    ]
  }
}
```

### POST /binary/check-cves

Extracts known packages and checks them against a CVE database.

**Example Request:
```bash
curl -X POST http://localhost:8080/binary/check-cves \
  -H "Authorization: Bearer your_license_key" \
  -F "file=@./my_binary"
```

**Request Params:

```json
{
  "file": "<binary file>"
}
```

**Response Format:
```json
{
  "hash": "sha256:...",
  "packages": [
    {
      "name": "openssl",
      "version": "1.1.1",
      "vulnerabilities": [
        {
          "id": "CVE-2023-0464",
          "cvss": 7.5,
          "summary": "Potential buffer overflow in TLS handshake",
          "references": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0464"
          ]
        }
      ]
    }
  ],
  "unresolved": []
}
```

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

## 🧾 SBOM Generation

Nabla provides intelligent SBOM (Software Bill of Materials) generation using AI-powered analysis. The system can generate CycloneDX format SBOMs from binary analysis data, providing detailed component information, dependencies, and metadata.

### POST /binary/chat

Generate SBOMs and perform AI-powered binary analysis through natural language queries.

**Features:**
- **AI-Powered Analysis**: Uses inference providers to analyze binary structure and generate detailed SBOMs
- **CycloneDX Format**: Generates standard-compliant CycloneDX SBOMs
- **Multiple Providers**: Supports local llama.cpp servers, remote APIs, and third-party services
- **Clean JSON Output**: Returns properly formatted JSON without markdown or explanations

#### Basic SBOM Generation

```bash
curl -X POST http://localhost:8080/binary/chat \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "utility_bins/vulnerable_elf",
    "question": "Generate a CycloneDX SBOM for this binary",
    "provider": "http",
    "inference_url": "https://api.together.xyz",
    "provider_token": "YOUR_TOGETHER_API_KEY",
    "options": {
      "max_tokens": 4096,
      "temperature": 0.1,
      "top_p": 0.9,
      "model": "moonshotai/Kimi-K2-Instruct",
      "stop_sequences": []
    }
  }'
```

**Response Format:**
```json
{
  "answer": "{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.5\",\n  \"serialNumber\": \"urn:uuid:...\",\n  \"version\": 1,\n  \"metadata\": {\n    \"timestamp\": \"2024-05-30T12:00:00Z\",\n    \"tools\": [{\n      \"vendor\": \"binary-analysis\",\n      \"name\": \"static-analyzer\",\n      \"version\": \"1.0\"\n    }],\n    \"component\": {\n      \"type\": \"application\",\n      \"name\": \"vulnerable_elf\",\n      \"version\": \"unknown\",\n      \"hashes\": [{\n        \"alg\": \"SHA-256\",\n        \"content\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n      }],\n      \"purl\": \"pkg:generic/vulnerable_elf@unknown\"\n    }\n  },\n  \"components\": [{\n    \"type\": \"library\",\n    \"name\": \"libcurl\",\n    \"version\": \"4\",\n    \"purl\": \"pkg:generic/libcurl@4\",\n    \"externalReferences\": [{\n      \"type\": \"website\",\n      \"url\": \"https://curl.se/libcurl/\"\n    }]\n  }],\n  \"dependencies\": [{\n    \"ref\": \"pkg:generic/vulnerable_elf@unknown\",\n    \"dependsOn\": [\n      \"pkg:generic/libcurl@4\",\n      \"pkg:generic/libSystem@B\"\n    ]\n  }]\n}",
  "model_used": "moonshotai/Kimi-K2-Instruct",
  "tokens_used": 840
}
```

#### Save SBOM to File

```bash
# Generate and save SBOM directly to file
curl -X POST http://localhost:8080/binary/chat \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"file_path": "utility_bins/vulnerable_elf", "question": "Generate a CycloneDX SBOM for this binary", "provider": "http", "inference_url": "https://api.together.xyz", "provider_token": "YOUR_TOGETHER_API_KEY", "options": {"max_tokens": 4096, "temperature": 0.1, "top_p": 0.9, "model": "moonshotai/Kimi-K2-Instruct", "stop_sequences": []}}' | \
jq -r '.answer' > sbom.json
```

### SBOM Features

- **🔍 Binary Analysis**: Extracts libraries, dependencies, and metadata from binaries
- **📋 CycloneDX Format**: Generates standard-compliant SBOMs
- **🔗 Dependency Mapping**: Identifies and maps all dependencies
- **🏷️ Metadata Extraction**: Captures version info, hashes, and PURLs
- **🛡️ Security Context**: Includes security metadata and vulnerability info
- **🎯 AI-Powered**: Uses inference models for intelligent analysis
- **📄 Clean Output**: Returns valid JSON without markdown formatting

### Supported SBOM Formats

Currently supports **CycloneDX 1.5** format with:
- Component metadata (name, version, type, hashes)
- Dependency relationships
- External references (websites, documentation)
- Security metadata
- Tool information
- Timestamps and serial numbers

## Inference Architecture

The `nabla` service supports multiple inference providers through a unified interface. All providers implement the `InferenceProvider` trait and can be configured via the `/binary/chat` endpoint.

### HTTP Provider

The `HTTPProvider` is a unified provider that can connect to:
- Local `llama.cpp` servers
- Remote inference servers
- OpenAI-compatible APIs (OpenAI, Together, etc.)
- Hugging Face repositories

#### Local llama.cpp Server

```bash
curl -X POST http://localhost:8080/binary/chat \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "utility_bins/vulnerable_elf",
    "question": "Generate a CycloneDX SBOM for this binary. Output ONLY the JSON structure.",
    "provider": "http",
    "inference_url": "http://localhost:11434",
    "model_path": "models/DeepSeek-R1-0528-Qwen3-8B-Q3_K_M.gguf",
    "options": {
      "max_tokens": 4096,
      "temperature": 0.1,
      "top_p": 0.9,
      "stop_sequences": ["\n\n", "```", "Explanation:", "Note:"]
    }
  }'
```

#### Remote Server

```bash
curl -X POST http://localhost:8080/binary/chat \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "utility_bins/vulnerable_elf",
    "question": "Generate a CycloneDX SBOM for this binary. Output ONLY the JSON structure.",
    "provider": "http",
    "inference_url": "https://your-remote-server.com",
    "provider_token": "YOUR_REMOTE_API_KEY",
    "options": {
      "max_tokens": 4096,
      "temperature": 0.1,
      "top_p": 0.9,
      "model": "llama2:7b",
      "stop_sequences": ["\n\n", "```", "Explanation:", "Note:"]
    }
  }'
```

#### Hugging Face Repository

```bash
curl -X POST http://localhost:8080/binary/chat \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "utility_bins/vulnerable_elf",
    "question": "Generate a CycloneDX SBOM for this binary. Output ONLY the JSON structure.",
    "provider": "http",
    "inference_url": "http://localhost:11434",
    "options": {
      "max_tokens": 4096,
      "temperature": 0.1,
      "top_p": 0.9,
      "hf_repo": "microsoft/DialoGPT-medium",
      "stop_sequences": ["\n\n", "```", "Explanation:", "Note:"]
    }
  }'
```

#### Third-Party APIs (Together, OpenAI, etc.)

```bash
curl -X POST http://localhost:8080/binary/chat \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "utility_bins/vulnerable_elf",
    "question": "Generate a CycloneDX SBOM for this binary. Output ONLY the JSON structure.",
    "provider": "http",
    "inference_url": "https://api.together.xyz",
    "provider_token": "YOUR_TOGETHER_API_KEY",
    "options": {
      "max_tokens": 4096,
      "temperature": 0.1,
      "top_p": 0.9,
      "model": "moonshotai/Kimi-K2-Instruct",
      "stop_sequences": ["\n\n", "```", "Explanation:", "Note:"]
    }
  }'
```

### Adding Custom Providers

To add a new inference provider:

1. Create a new file in `src/providers/` (e.g., `src/providers/bedrock.rs`)
2. Implement the `InferenceProvider` trait
3. Add the module to `src/providers/mod.rs`
4. Update the route handler in `src/routes/binary.rs` to support your new provider

Example provider structure:
```rust
// src/providers/bedrock.rs
use async_trait::async_trait;
use super::{InferenceProvider, GenerationOptions, GenerationResponse, InferenceError};

pub struct BedrockProvider {
    // Your provider-specific fields
}

#[async_trait]
impl InferenceProvider for BedrockProvider {
    async fn generate(&self, prompt: &str, options: &GenerationOptions) -> Result<GenerationResponse, InferenceError> {
        // Your implementation
    }

    async fn is_available(&self) -> bool {
        // Check if provider is available
    }
}
```

## Setup

### Prerequisites

- Rust 1.82+
- A Nabla License Key

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
PORT=8080
```

### Getting Started

Clone the repo:

```bash
git clone https://github.com/jdbohrman/nabla.git
cd nabla
```

Setup your environment:

```bash
cp .env.example .env
```

Edit .env:

```env
PORT=8080
```

Run locally:

```bash
cargo run
```

Or with Docker:

```bash
docker build -t nabla .
docker run -p 8080:8080 -e nabla
```

## License

This project is licensed under the Functional Source License - see the LICENSE file for details.

## Want a license key? Chat up the Atelier Logos team and get a 14-day trial
