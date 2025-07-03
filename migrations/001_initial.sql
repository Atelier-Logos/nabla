-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- API Keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key TEXT NOT NULL UNIQUE,
    name TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Packages table with all the required fields
CREATE TABLE packages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    extraction_depth TEXT NOT NULL,
    description TEXT,
    downloads BIGINT,
    repository TEXT,
    homepage TEXT,
    documentation TEXT,
    key_modules JSONB NOT NULL DEFAULT '[]'::jsonb,
    important_structs JSONB NOT NULL DEFAULT '[]'::jsonb,
    notable_functions JSONB NOT NULL DEFAULT '[]'::jsonb,
    traits JSONB NOT NULL DEFAULT '[]'::jsonb,
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    api_usage_examples JSONB NOT NULL DEFAULT '[]'::jsonb,
    dependency_graph JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cargo_toml TEXT,
    source JSONB NOT NULL DEFAULT '{}'::jsonb,
    docs_quality_score JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_git_commit TIMESTAMPTZ,
    key_id UUID NOT NULL REFERENCES api_keys(id),
    publish_date TIMESTAMPTZ,
    cargo_audit_report JSONB NOT NULL DEFAULT '{}'::jsonb,
    unsafe_usage_locations JSONB NOT NULL DEFAULT '[]'::jsonb,
    uses_unsafe BOOLEAN NOT NULL DEFAULT false,
    license(s) JSONB NOT NULL DEFAULT '{}'::jsonb,
    macro_usage JSONB NOT NULL DEFAULT '[]'::jsonb,
    build_rs_present BOOLEAN NOT NULL DEFAULT false,
    public_api_surface BIGINT NOT NULL DEFAULT 0,
    known_cve_references JSONB NOT NULL DEFAULT '[]'::jsonb,
    external_crates_used TEXT[] NOT NULL DEFAULT '{}'
);

-- Create indexes for better performance
CREATE INDEX idx_packages_name_version ON packages(package_name, version);
CREATE INDEX idx_packages_created_at ON packages(created_at);
CREATE INDEX idx_packages_key_id ON packages(key_id);
CREATE INDEX idx_api_keys_key ON api_keys(key);

-- Insert a default API key for testing
INSERT INTO api_keys (key, name, active) 
VALUES ('test-api-key-12345', 'Test API Key', true); 