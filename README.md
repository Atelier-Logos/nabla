![](https://github.com/Atelier-Logos/nabla/blob/main/public/banner.png?raw=true)

[![codecov](https://codecov.io/github/Atelier-Logos/nabla/branch/main/graph/badge.svg?token=A25NWBGGB9)](https://codecov.io/github/Atelier-Logos/nabla)
[![CI](https://github.com/Atelier-Logos/nabla/actions/workflows/coverage.yml/badge.svg)](https://github.com/Atelier-Logos/nabla/actions/workflows/coverage.yml)
[![License: FSL](https://img.shields.io/badge/license-FSL-lightgrey)](LICENSE)


# Nabla - A fair-source SAST/SCA API for calculating your SSCS gradients

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

All endpoints require an `X-API-KEY` header unless otherwise configured.

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
