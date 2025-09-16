#!/bin/bash
# cert_gen_script.sh - Generate Ed25519 custom format certificates

SERIAL_NUM="$1"
DAYS="$2"
CN="$3"
OUTPUT_DIR="output"

if [ -z "$SERIAL_NUM" ] || [ -z "$DAYS" ] ; then
    cat <<EOT
Usage: $0 <serial-number> <validity-days> [common-name]
Example: $0 123456789012 365 "John Smith"

Note: If common-name is not provided, the serial number will be used as CN.

All output files will be saved to the ${OUTPUT_DIR}/ directory

CA public key: ca.pub, CA private key: ca.key
Certificate output: [serial]-cert.bin (raw binary custom format)
EOT
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Validate serial number format (must be a positive integer)
if [[ ! "$SERIAL_NUM" =~ ^[0-9]+$ ]] ; then
    echo "Error: Serial number must be a positive integer"
    exit 1
fi

# If CN is not provided, use the serial number as CN
if [ -z "$CN" ]; then
    CN="$SERIAL_NUM"
fi

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found"
    exit 1
fi

# Check if required Python modules are available
python3 -c "import cryptography" 2>/dev/null || {
    echo "Error: Python cryptography module is required"
    echo "Install with: pip install cryptography"
    exit 1
}

# Create CA key pair if not exists
if [ ! -f "${OUTPUT_DIR}/ca.key" ] || [ ! -f "${OUTPUT_DIR}/ca.pub" ] ; then
    echo "Generating CA Ed25519 key pair..."
    python3 << EOF
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cert_format import generate_ca_keypair, save_private_key, save_public_key

# Generate CA key pair
ca_private, ca_public = generate_ca_keypair()

# Save keys
save_private_key(ca_private, "${OUTPUT_DIR}/ca.key")
save_public_key(ca_public, "${OUTPUT_DIR}/ca.pub")

print("CA key pair generated:")
print("  Private key: ${OUTPUT_DIR}/ca.key")
print("  Public key: ${OUTPUT_DIR}/ca.pub")
EOF
fi

# Generate certificate
echo "Generating Ed25519 certificate..."
python3 << EOF
import sys
import os
from datetime import datetime, timezone, timedelta
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cert_format import Ed25519Certificate, load_private_key

# Load CA private key
try:
    ca_private = load_private_key("${OUTPUT_DIR}/ca.key")
except Exception as e:
    print(f"Error loading CA private key: {e}")
    sys.exit(1)

# Create certificate
not_before = datetime.now(timezone.utc)
not_after = not_before + timedelta(days=${DAYS})

cert = Ed25519Certificate(
    serial="${SERIAL_NUM}",
    cn="${CN}",
    not_before=not_before,
    not_after=not_after
)

# Sign certificate
cert.sign(ca_private)

# Save certificate in binary format
cert_bytes = cert.to_bytes()
with open("${OUTPUT_DIR}/${SERIAL_NUM}-cert.bin", "wb") as f:
    f.write(cert_bytes)

# Display certificate info
print(f"Certificate generated: ${OUTPUT_DIR}/${SERIAL_NUM}-cert.bin")
print(f"Serial Number: {cert.serial}")
print(f"Subject (CN): {cert.cn}")
print(f"Not Before: {cert.not_before.strftime('%Y-%m-%d %H:%M:%S %Z')}")
print(f"Not After: {cert.not_after.strftime('%Y-%m-%d %H:%M:%S %Z')}")
print(f"Certificate size: {len(cert_bytes)} bytes (binary)")

# Verify certificate
from cert_format import load_public_key
ca_public = load_public_key("${OUTPUT_DIR}/ca.pub")
is_valid = cert.verify(ca_public)
print(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
EOF

if [ $? -eq 0 ]; then
    echo "Certificate generation completed successfully!"
else
    echo "Error: Certificate generation failed"
    exit 1
fi