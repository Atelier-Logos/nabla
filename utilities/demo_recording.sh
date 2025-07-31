#!/bin/bash

# Nabla CLI Demo Recording Script
# This script creates a beautiful terminal recording using asciinema with lolcat

set -e

# Colors and formatting
BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to mint JWT with Doppler key
mint_jwt_with_doppler() {
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
    
    echo "✅ Successfully minted new JWT token"
    JWT_TOKEN="$NEW_JWT"
    export JWT_TOKEN
}

# Function to print colorful messages
print_step() {
    echo -e "${BOLD}${BLUE}==>${NC} ${BOLD}$1${NC}"
    sleep 2
}

print_success() {
    echo -e "${BOLD}${GREEN}✓${NC} $1"
    sleep 1
}

print_command() {
    echo -e "${YELLOW}$${NC} $1"
    sleep 1
}

# Function to run commands with output
run_demo_command() {
    print_command "$1"
    eval "$1"
    sleep 2
}

# Create demo script content
cat << 'EOF' > /tmp/nabla_demo_commands.sh
#!/bin/bash

# Display ASCII intro
echo "
    ███╗   ██╗ █████╗ ██████╗ ██╗      █████╗ 
    ████╗  ██║██╔══██╗██╔══██╗██║     ██╔══██╗
    ██╔██╗ ██║███████║██████╔╝██║     ███████║
    ██║╚██╗██║██╔══██║██╔══██╗██║     ██╔══██║
    ██║ ╚████║██║  ██║██████╔╝███████╗██║  ██║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
                                              
    🔒 Binary Analysis & Security Platform"

echo "🌈 Welcome to Nabla CLI Demo! 🌈"
echo "================================"
sleep 2

echo ""
echo "🖥️ Step 1: Starting Nabla Server"
echo "Starting the server in the background..."
cargo run --bin nabla-cli -- server --port 8080 &
SERVER_PID=$!
echo "✅ Server started with PID: $SERVER_PID"
sleep 5

echo ""
echo "🔧 Step 2: Authentication Setup"
echo "Setting JWT token for API access..."
cargo run --bin nabla-cli -- auth --set-jwt "$JWT_TOKEN"
sleep 3

echo ""
echo "📊 Checking authentication status..."
cargo run --bin nabla-cli -- auth status
sleep 3

echo ""
echo "⚙️ Step 3: Configuration Management"
echo "Viewing configuration settings..."
cargo run --bin nabla-cli -- config list
sleep 3

echo ""
echo "🔍 Step 4: Binary Analysis Demo"
echo "Using pre-created test binaries for analysis..."
echo "✅ Test binaries ready!"
sleep 2

echo ""
echo "🔬 Analyzing the binary..."
cargo run --bin nabla-cli -- binary analyze test_binaries/test_binary1
sleep 4

echo ""
echo "🛡️ Step 5: CVE Scanning"
echo "Scanning for vulnerabilities..."
cargo run --bin nabla-cli -- binary check-cves test_binaries/test_binary1
sleep 4

echo ""
echo "📝 Step 6: Binary Comparison"
echo "Comparing our test binaries..."
echo "✅ Second binary ready!"
sleep 2

echo ""
echo "⚖️ Comparing binaries..."
cargo run --bin nabla-cli -- diff test_binaries/test_binary1 test_binaries/test_binary2
sleep 4

echo ""
echo "🤖 Step 7: AI-Powered Analysis"
echo "Using AI chat for SBOM generation..."
cargo run --bin nabla-cli -- chat "Analyze this binary structure and provide insights"
sleep 4

echo ""
echo "🏆 Step 8: Additional Commands"
echo "Showing help information..."
cargo run --bin nabla-cli -- --help
sleep 3

echo ""
echo "🛑 Stopping server..."
kill $SERVER_PID 2>/dev/null || true
echo "✅ Server stopped"

echo ""
echo "🎉 Demo Complete! 🎉"
echo "==================="
echo "✨ All Nabla CLI features demonstrated successfully!"
echo "🚀 Ready for production use!"

# Note: test binaries remain in test_binaries/ directory for reuse
EOF

chmod +x /tmp/nabla_demo_commands.sh

echo "🎬 Starting Nabla CLI Demo Recording..."
echo "This will create demo.cast with a colorful demonstration of all CLI features"
sleep 2

# Set deployment to private to use Doppler
export NABLA_DEPLOYMENT="private"

# Mint JWT with Doppler signing key
mint_jwt_with_doppler

# Start asciinema recording with the demo script
asciinema rec demo.cast -c "bash /tmp/nabla_demo_commands.sh"

# Cleanup
rm -f /tmp/nabla_demo_commands.sh

echo ""
echo "🎉 Recording complete! 🎉"
echo "📹 Demo saved as: demo.cast"
echo "🎬 You can play it back with: asciinema play demo.cast"
echo "🌐 Or upload it with: asciinema upload demo.cast"