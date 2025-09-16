#!/bin/bash

set -eEo pipefail

mkdir -p output

echo "Generate certificate..."
./cert_gen_script.sh 4561337 365 "John Smith/196912120203"
echo
echo

echo "Certificate details (cert_format.py demo):"
python3 cert_format.py
echo
echo

echo "Generating QR code from certificate..."
python3 qr_generator.py output/4561337-cert.bin
echo
echo

echo "Validating certificate in QR code..."
python3 qr_validator.py output/4561337-qr.png