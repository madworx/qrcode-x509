#!/usr/bin/env python3
"""
QR Code Generator for Ed25519 Custom Certificates
"""

import sys
import qrcode
from PIL import Image
import argparse
import os

def generate_qr_from_cert(cert_file, output_file=None, output_dir="output"):
    """Generate QR code from Ed25519 certificate file"""
    try:
        os.makedirs(output_dir, exist_ok=True)

        with open(cert_file, 'rb') as f:
            cert_bytes = f.read()

        # Create QR code with raw binary data
        qr = qrcode.QRCode(
            version=None,  # Auto-size
            error_correction=qrcode.constants.ERROR_CORRECT_L,  # Low error correction for max data
            box_size=3,
            border=2,
        )

        qr.add_data(cert_bytes)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        if output_file:
            img.save(output_file)
            print(f"QR code saved to: {output_file}")

        print(f"Certificate size: {len(cert_bytes)} bytes (binary)")
        print(f"QR version: {qr.version}")

        return cert_bytes

    except FileNotFoundError:
        print(f"Error: Certificate file '{cert_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error generating QR code: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Generate QR code from Ed25519 custom certificate')
    parser.add_argument('cert_file', help='Path to certificate file (.bin)')
    parser.add_argument('-o', '--output', help='Output PNG file (default: auto-generate in output directory)')
    parser.add_argument('-d', '--output-dir', default='output', help='Output directory (default: output/)')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    if not args.output:
        # Extract base name from certificate file path
        cert_basename = os.path.basename(args.cert_file)
        base_name = cert_basename.replace('.bin', '').replace('-cert', '')
        args.output = os.path.join(args.output_dir, f"{base_name}-qr.png")
    else:
        # If output is specified but doesn't include the output directory, add it
        if not os.path.dirname(args.output):
            args.output = os.path.join(args.output_dir, args.output)
    
    generate_qr_from_cert(args.cert_file, args.output, args.output_dir)

if __name__ == "__main__":
    main()