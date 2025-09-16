#!/bin/bash
# generate_cert.sh - Generate minimal certificate with 12-digit serial

SERIAL_NUM="$1"
DAYS="$2"
CN="$3"
OUTPUT_DIR="output"

if [ -z "$SERIAL_NUM" ] || [ -z "$DAYS" ] ; then
    cat <<EOT
Usage: $0 <12-digit-serial> <validity-days> [common-name]
Example: $0 123456789012 365 "John Smith"

Note: If common-name is not provided, the serial number will be used as CN.

All output files will be saved to the ${OUTPUT_DIR}/ directory

CA certificate: ca.crt, CA key: ca.key.
EOT
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Validate serial number format
if [[ ! "$SERIAL_NUM" =~ ^[0-9]{12}$ ]] ; then
    echo "Error: Serial number must be exactly 12 digits"
    exit 1
fi

# If CN is not provided, use the serial number as CN
if [ -z "$CN" ]; then
    CN="$SERIAL_NUM"
fi

# Create CA private key if not exists
if [ ! -f "${OUTPUT_DIR}/ca.key" ] ; then
    echo "Generating CA private key..."
    openssl ecparam -genkey -name prime256v1 -out "${OUTPUT_DIR}/ca.key"
fi

# Create CA certificate if not exists
if [ ! -f "${OUTPUT_DIR}/ca.crt" ] ; then
    echo "Generating CA certificate..."
    openssl req -new -x509 -key "${OUTPUT_DIR}/ca.key" -out "${OUTPUT_DIR}/ca.crt" -days 3650 \
        -subj "/CN=Very authoritative certificate authority" \
        -extensions v3_ca \
        -config <(cat <<EOF
[req]
distinguished_name = req
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
)
fi

# Generate device private key
openssl ecparam -genkey -name prime256v1 -out "${OUTPUT_DIR}/${SERIAL_NUM}-key.pem"

# Create certificate signing request with provided CN
openssl req -new -key "${OUTPUT_DIR}/${SERIAL_NUM}-key.pem" -out "${OUTPUT_DIR}/${SERIAL_NUM}.csr" \
    -subj "/CN=${CN}" \
    -config <(echo "[req]"; echo "distinguished_name=req")

# Sign the certificate with explicit serial number
openssl x509 -req -in "${OUTPUT_DIR}/${SERIAL_NUM}.csr" \
    -CA "${OUTPUT_DIR}/ca.crt" -CAkey "${OUTPUT_DIR}/ca.key" \
    -out "${OUTPUT_DIR}/${SERIAL_NUM}-cert.pem" \
    -days "$DAYS" \
    -set_serial "0x$(printf "%012x" "$SERIAL_NUM")"

# Clean up CSR
rm "${OUTPUT_DIR}/${SERIAL_NUM}.csr"

# Display certificate info
echo "Certificate generated: ${OUTPUT_DIR}/${SERIAL_NUM}-cert.pem"
openssl x509 -in "${OUTPUT_DIR}/${SERIAL_NUM}-cert.pem" -noout -text | grep -E "(Serial Number|Subject:|Not Before|Not After)"

# Get certificate size
echo "Certificate size: $(wc -c < "${OUTPUT_DIR}/${SERIAL_NUM}-cert.pem") bytes"
