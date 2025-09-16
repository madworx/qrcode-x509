#!/bin/bash

set -eEo pipefail

mkdir -p output

echo "Generate certificate..."
./cert_gen_script.sh 123456789012 365 "John Smith"
echo
echo

echo "Certificate details:"
openssl x509 -in output/123456789012-cert.der -inform DER -noout -text
echo
echo

echo "Generating QR code from certificate..."
python3 qr_generator.py output/123456789012-cert.der
echo
echo

echo "Validating certificate in QR code..."
python3 qr_validator.py output/123456789012-qr.png
