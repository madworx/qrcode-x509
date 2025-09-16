# QR Code ED25519 Digital Attestation

Minimal digital attestation system using Ed25519 signatures and QR codes for validating physical identity documents like ID cards, badges, and certificates.

This implementation is provided for research and educational purposes. Users should conduct their own security analysis before production use.

<p align="right">
  <a href="sample/"><img src="sample/4561337-qr.png" alt="Sample QR Code" width="180" /></a>
</p>

## Use Case: ID Card Validation

**Problem**: How do you verify that an ID card is authentic and that the printed information (name, ID number, expiry date) hasn't been tampered with?

**Solution**: The issuing authority (CA) creates a digital attestation of the card's information and embeds it in a QR code. Anyone can validate the card by scanning the QR code and verifying the signature against the CA's public key.

### Real-World Application Example

1. **Card Issuance**: Government agency issues an ID card for "John Smith" with ID "123456789012"
2. **Digital Attestation**: Agency creates a signed attestation containing the card details
3. **QR Embedding**: The attestation is embedded as a QR code printed on the physical card
4. **Verification**: Security personnel scan the QR code to verify the card is genuine and matches the printed information

## Features

- **Compact Attestations**: Custom binary format (78-90 bytes typically) vs standard X.509 (579+ bytes)
- **Strong Cryptography**: Ed25519 signatures provide 128-bit security level
- **Tamper Evidence**: Any modification to name, ID, or dates invalidates the signature
- **Offline Validation**: No network required - just the CA's public key
- **Physical Integration**: QR codes work on printed materials

## Digital Attestation Format

The attestations use a compact binary format optimized for QR code embedding:

```
[1 byte: version]
[2 bytes: notBefore Unix epoch in days] 
[2 bytes: notAfter Unix epoch in days]
[1 byte: serial length][N bytes: serial big-endian integer]
[1 byte: CN length][M bytes: CN UTF-8]
[64 bytes: Ed25519 signature over all above data]
```

This format is designed for identity document validation where you need to verify that human-readable details on a physical card match a digital attestation signed by a trusted issuing authority.

## Usage

A good starting point is to run:

```sh
./usage_example.sh
```

This script demonstrates the full workflow: issuing a digital attestation, creating a QR code for embedding on an ID card, and validating the attestation.

Or, follow the steps below to manually issue and validate an ID card:

1. **Issue a digital attestation for an ID card:**
   ```sh
   ./cert_gen_script.sh 123456789012 365 "John Smith/1337SSN"
   ```
2. **Generate QR code to print on the physical card:**
   ```sh
   python3 qr_generator.py output/123456789012-cert.bin
   ```
3. **Validate the ID card by scanning its QR code:**
   ```sh
   python3 qr_validator.py output/123456789012-qr.png
   ```

### Example invocation of usage_example.sh

```
Generate certificate...
Generating CA Ed25519 key pair...
CA key pair generated:
  Private key: output/ca.key
  Public key: output/ca.pub
Generating Ed25519 certificate...
Certificate generated: output/123456789012-cert.bin
Serial Number: 123456789012
Subject (CN): John Smith
Not Before: 2025-09-16 10:15:30 UTC
Not After: 2026-09-16 10:15:30 UTC
Certificate size: 93 bytes (binary)
Signature verification: VALID
Certificate generation completed successfully!


Certificate details (cert_format.py demo):
Ed25519Certificate(version=1, serial='123456789012', cn='John Smith', 
not_before='2025-09-16T10:15:30+00:00', not_after='2026-09-16T10:15:30+00:00')
Binary size: 93 bytes


Generating QR code from certificate...
QR code saved to: output/123456789012-qr.png
Certificate size: 93 bytes (binary)
QR version: 3


Validating certificate in QR code...
Scanning QR code from: output/123456789012-qr.png
QR code decoded successfully (93 bytes)
[OK] Certificate signature VALID

==================================================
Ed25519 CERTIFICATE VALIDATION RESULTS
==================================================
Certificate Version: 1
Subject (CN): John Smith
Serial Number: 123456789012
Valid From: 2025-09-16 10:15:30 UTC
Valid Until: 2026-09-16 10:15:30 UTC
Certificate Size: 93 bytes (binary)
Time Status: [OK] Valid (364 days remaining)

Overall: [OK] VALID
```

## Security Model

This system is designed for **identity document attestation** where:

- **Issuing Authority**: A trusted entity (government, organization) signs digital attestations
- **Physical Cards**: ID cards, badges, or certificates contain QR codes with signed attestations  
- **Verification**: Anyone with the issuer's public key can validate document authenticity
- **Trust Chain**: The issuer's public key is distributed through secure channels (websites, apps)

### Real-World Security Properties

- **Integrity**: Tampering with name, ID number, or expiry dates breaks the signature
- **Authenticity**: Only the issuing authority can create valid attestations
- **Non-repudiation**: Issuer cannot deny signing a valid attestation
- **Offline Verification**: No network connection needed for validation
- **Compact Size**: 78-90 bytes typically vs 579+ bytes for equivalent X.509 certificates

### What This System Provides

- **Document Validation**: Verify that printed information matches signed attestation
- **Tamper Detection**: Any alteration to card details invalidates the signature  
- **Issuer Authentication**: Confirm the document was issued by the claimed authority
- **Expiry Checking**: Built-in validity period enforcement

### What This System Does NOT Provide

- **Key Binding**: Attestations don't contain subject public keys (not needed for ID cards)
- **Revocation**: No built-in mechanism to revoke individual documents
- **Certificate Chains**: Single-level trust (issuer → document)
- **Identity Proofing**: Doesn't verify the person presenting the card

This design is intentional - the goal is validating **document authenticity**, not **key holder identity**.

## Requirements

- Python 3.8+
- zbar (for QR code scanning)
- See `requirements.txt` for Python dependencies

## Docker

A minimal Dockerfile is provided. Build and run:

```sh
docker build -t qr-attestation-ed25519 .
docker run --rm -it qr-attestation-ed25519
```

To persist generated attestations and QR codes, mount the `output` directory as a volume:

```sh
docker run --rm -it -v "${PWD}/output:/app/output" qr-attestation-ed25519
```

## License

WTFPL