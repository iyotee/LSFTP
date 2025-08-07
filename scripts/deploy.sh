#!/bin/bash

# LSFTP Deployment Script
# Author: Jérémy Noverraz - 1988
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="1.0.0"
PROJECT_NAME="LSFTP"
AUTHOR="Jérémy Noverraz - 1988"
LICENSE="MIT License"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Rust
    if ! command -v cargo &> /dev/null; then
        log_error "Rust is not installed. Please install Rust first."
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_warning "Docker is not installed. Docker builds will be skipped."
        DOCKER_AVAILABLE=false
    else
        DOCKER_AVAILABLE=true
    fi
    
    # Check system dependencies
    if ! pkg-config --exists openssl; then
        log_error "OpenSSL development libraries are not installed."
        exit 1
    fi
    
    log_success "Prerequisites check completed"
}

# Build project
build_project() {
    log_info "Building LSFTP project..."
    
    # Clean previous builds
    cargo clean
    
    # Build debug version
    log_info "Building debug version..."
    cargo build --all-targets --all-features
    
    # Build release version
    log_info "Building release version..."
    cargo build --release --all-targets --all-features
    
    log_success "Build completed successfully"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    # Run unit tests
    cargo test --all-features
    
    # Run integration tests
    cargo test --all-features --test '*'
    
    # Run security audit
    cargo audit
    
    log_success "Tests completed successfully"
}

# Generate documentation
generate_docs() {
    log_info "Generating documentation..."
    
    # Build documentation
    cargo doc --all-features --no-deps
    
    log_success "Documentation generated successfully"
}

# Create release packages
create_release_packages() {
    log_info "Creating release packages..."
    
    # Create dist directory
    mkdir -p dist
    
    # Copy release binaries
    cp target/release/lsftp-server dist/
    cp target/release/lsftp-client dist/
    cp target/release/lsftp-tools dist/
    
    # Create Linux x86_64 package
    tar -czf "lsftp-v${VERSION}-linux-x86_64.tar.gz" -C dist .
    sha256sum "lsftp-v${VERSION}-linux-x86_64.tar.gz" > "lsftp-v${VERSION}-linux-x86_64.tar.gz.sha256"
    
    log_success "Release packages created successfully"
}

# Build Docker images
build_docker_images() {
    if [ "$DOCKER_AVAILABLE" = false ]; then
        log_warning "Skipping Docker builds (Docker not available)"
        return
    fi
    
    log_info "Building Docker images..."
    
    # Build server image
    docker build --target server -t "lsftp-server:v${VERSION}" .
    docker build --target server -t "lsftp-server:latest" .
    
    # Build client image
    docker build --target client -t "lsftp-client:v${VERSION}" .
    docker build --target client -t "lsftp-client:latest" .
    
    # Build tools image
    docker build --target tools -t "lsftp-tools:v${VERSION}" .
    docker build --target tools -t "lsftp-tools:latest" .
    
    # Build complete image
    docker build --target complete -t "lsftp:v${VERSION}" .
    docker build --target complete -t "lsftp:latest" .
    
    log_success "Docker images built successfully"
}

# Run Docker tests
test_docker_images() {
    if [ "$DOCKER_AVAILABLE" = false ]; then
        log_warning "Skipping Docker tests (Docker not available)"
        return
    fi
    
    log_info "Testing Docker images..."
    
    # Test server
    docker run --rm "lsftp-server:v${VERSION}" --help
    
    # Test client
    docker run --rm "lsftp-client:v${VERSION}" --help
    
    # Test tools
    docker run --rm "lsftp-tools:v${VERSION}" --help
    
    log_success "Docker tests completed successfully"
}

# Create release notes
create_release_notes() {
    log_info "Creating release notes..."
    
    cat > "RELEASE_NOTES_v${VERSION}.md" << EOF
# LSFTP v${VERSION} Release Notes

## Linux Secure File Transfer Protocol

**Version:** ${VERSION}  
**Author:** ${AUTHOR}  
**License:** ${LICENSE}  

### What's New

- Post-quantum cryptography with ML-KEM and ML-DSA
- Hardware authentication (TPM 2.0, YubiKey, Smart Cards)
- QUIC transport with TLS 1.3
- Perfect Forward Secrecy
- Immutable audit trails

### Installation

\`\`\`bash
# Extract binary
tar -xzf lsftp-v${VERSION}-linux-x86_64.tar.gz

# Or use Docker
docker load < lsftp-v${VERSION}.tar.gz
\`\`\`

### Quick Start

\`\`\`bash
# Generate keys
lsftp-tools keygen --key-type hybrid --output-cert server.crt --output-key server.key

# Start server
lsftp-server --cert server.crt --key server.key

# Connect client
lsftp-client --server-address localhost:8443
\`\`\`

### Security Features

- **Post-Quantum Cryptography**: ML-KEM-768/1024, ML-DSA-65/87
- **Hardware Authentication**: TPM 2.0, YubiKey, Smart Cards
- **Perfect Forward Secrecy**: Ephemeral key exchange
- **Cryptographic Integrity**: BLAKE3 hashing
- **Audit Trails**: Immutable, cryptographically signed logs

### Compliance

- FIPS 140-2 Level 3 (target)
- Common Criteria EAL4+ (target)
- NIST Cybersecurity Framework
- ISO 27001
- GDPR

### Documentation

See [README.md](README.md) for complete documentation.

### Support

For issues and questions, please use GitHub Issues.

---

*Secure File Transfer for the Post-Quantum Era*
EOF
    
    log_success "Release notes created successfully"
}

# Main deployment function
deploy() {
    log_info "Starting LSFTP deployment..."
    log_info "Version: ${VERSION}"
    log_info "Author: ${AUTHOR}"
    
    # Run all deployment steps
    check_prerequisites
    build_project
    run_tests
    generate_docs
    create_release_packages
    build_docker_images
    test_docker_images
    create_release_notes
    
    log_success "LSFTP v${VERSION} deployment completed successfully!"
    log_info "Release files created:"
    ls -la lsftp-v${VERSION}*
    ls -la RELEASE_NOTES_v${VERSION}.md
}

# Show help
show_help() {
    echo "LSFTP Deployment Script v${VERSION}"
    echo "Author: ${AUTHOR}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --version  Show version information"
    echo "  --build-only   Only build the project (skip tests)"
    echo "  --test-only    Only run tests (skip build)"
    echo "  --docker-only  Only build Docker images"
    echo ""
    echo "Examples:"
    echo "  $0              # Full deployment"
    echo "  $0 --build-only # Build only"
    echo "  $0 --test-only  # Test only"
}

# Parse command line arguments
BUILD_ONLY=false
TEST_ONLY=false
DOCKER_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "LSFTP Deployment Script v${VERSION}"
            exit 0
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --test-only)
            TEST_ONLY=true
            shift
            ;;
        --docker-only)
            DOCKER_ONLY=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute based on options
if [ "$BUILD_ONLY" = true ]; then
    check_prerequisites
    build_project
    create_release_packages
elif [ "$TEST_ONLY" = true ]; then
    run_tests
elif [ "$DOCKER_ONLY" = true ]; then
    check_prerequisites
    build_docker_images
    test_docker_images
else
    deploy
fi
