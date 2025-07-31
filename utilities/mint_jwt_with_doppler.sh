#!/bin/bash

# Script to mint a new JWT token using the LICENSE_SIGNING_KEY from Doppler
set -e

echo "🔑 Fetching LICENSE_SIGNING_KEY from Doppler..."

# Get the signing key from Doppler
LICENSE_SIGNING_KEY=$(doppler secrets get LICENSE_SIGNING_KEY --plain --project nabla --config prd_nabla)

if [ -z "$LICENSE_SIGNING_KEY" ]; then
    echo "❌ Failed to retrieve LICENSE_SIGNING_KEY from Doppler"
    exit 1
fi

echo "✅ Retrieved signing key from Doppler"

# Export the key so the mint_license tool can use it
export LICENSE_SIGNING_KEY

echo "🔨 Minting new JWT token..."

# Generate a new JWT token with the Doppler signing key
NEW_JWT=$(cargo run --bin mint_license -- \
    --sub test-user \
    --uid 123 \
    --deployment-id 09d111a0-340f-4e42-8411-2fde71e1d0ab \
    --rate-limit 60 \
    --chat-enabled \
    --api-access \
    --file-upload-limit-mb 10 \
    --concurrent-requests 1 \
    --sbom-generation \
    --vulnerability-scanning \
    --signed-attestation \
    --monthly-binaries 100 \
    --trial-30)

if [ -z "$NEW_JWT" ]; then
    echo "❌ Failed to mint JWT token"
    exit 1
fi

echo "✅ Successfully minted new JWT token:"
echo "$NEW_JWT"

echo ""
echo "🔐 Now testing JWT authentication with the new token..."

# Test the new JWT token with the CLI
export NABLA_DEPLOYMENT="private"
cargo run --bin nabla-cli -- auth --set-jwt "$NEW_JWT"

echo ""
echo "📊 Checking authentication status..."
cargo run --bin nabla-cli -- auth status

echo ""
echo "🎉 JWT authentication with Doppler key is working!"