#!/usr/bin/env python3
"""
QR Code Attestation Validator for Ed25519 Custom Attestations
Scans QR codes and validates attestations against CA public key
"""

import sys
import argparse
import os
from datetime import datetime, timezone
from pyzbar import pyzbar
from PIL import Image

# Import our custom certificate format
try:
    from cert_format import Ed25519Certificate, load_public_key
except ImportError:
    # If running from different directory, try to import from current directory
    import importlib.util
    spec = importlib.util.spec_from_file_location("cert_format", 
                                                os.path.join(os.path.dirname(__file__), "cert_format.py"))
    cert_format = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cert_format)
    Ed25519Certificate = cert_format.Ed25519Certificate
    load_public_key = cert_format.load_public_key

class AttestationValidator:
    def __init__(self, ca_public_key_path="output/ca.pub"):
        self.ca_public_key_path = ca_public_key_path
        self.ca_public_key = None
        self._load_ca_public_key()
    
    def _load_ca_public_key(self):
        """Load CA public key"""
        try:
            self.ca_public_key = load_public_key(self.ca_public_key_path)
        except Exception as e:
            print(f"Error loading CA public key from '{self.ca_public_key_path}': {e}")
            sys.exit(1)
    
    def decode_qr_image(self, image_path):
        """Decode QR code from image file"""
        try:
            image = Image.open(image_path)
            decoded_objects = pyzbar.decode(image)
            
            if not decoded_objects:
                raise ValueError("No QR code found in image")
            
            if len(decoded_objects) > 1:
                print("Warning: Multiple QR codes found, using first one")
            
            # pyzbar returns UTF-8 encoded bytes from QR's ISO-8859-1 interpretation
            # Convert back to original binary data
            utf8_data = decoded_objects[0].data
            
            try:
                # Decode UTF-8 to get the ISO-8859-1 string, then encode back to original bytes
                iso_string = utf8_data.decode('utf-8')
                original_bytes = iso_string.encode('iso-8859-1')
                return original_bytes
            except UnicodeDecodeError:
                # Fallback: if UTF-8 decode fails, return raw data
                return utf8_data
            
        except Exception as e:
            print(f"Error decoding QR code: {e}")
            sys.exit(1)
    
    def validate_certificate(self, cert_bytes):
        """Validate certificate against CA public key"""
        try:
            # Parse certificate from binary data
            try:
                cert = Ed25519Certificate.from_bytes(cert_bytes)
            except Exception as e:
                print(f"[X] Attestation parsing FAILED: {e}")
                return False, {}

            # Verify signature
            try:
                is_signature_valid = cert.verify(self.ca_public_key)
            except Exception as e:
                print(f"[X] Signature verification FAILED: {e}")
                is_signature_valid = False

            if is_signature_valid:
                print("[OK] Attestation signature VALID")
            else:
                print("[X] Attestation signature INVALID")

            # Check expiry
            is_expired = cert.is_expired()
            days_until_expiry = cert.days_until_expiry()

            # Extract certificate info
            cert_info = {
                'version': cert.version,
                'serial_number': cert.serial,
                'subject_cn': cert.cn,
                'not_before': cert.not_before.strftime('%Y-%m-%d %H:%M:%S %Z'),
                'not_after': cert.not_after.strftime('%Y-%m-%d %H:%M:%S %Z'),
                'is_expired': is_expired,
                'days_until_expiry': days_until_expiry,
                'cert_size_bytes': len(cert_bytes)
            }

            return is_signature_valid and not is_expired, cert_info

        except Exception as e:
            print(f"Error validating attestation: {e}")
            return False, {}
    
    def validate_qr_image(self, image_path):
        """Complete validation workflow from QR image"""
        print(f"Scanning QR code from: {image_path}")

        # Decode QR code
        cert_bytes = self.decode_qr_image(image_path)
        print(f"QR code decoded successfully ({len(cert_bytes)} bytes)")

        # Validate certificate
        is_valid, cert_info = self.validate_certificate(cert_bytes)

        # Display results
        self.display_results(is_valid, cert_info)

        return is_valid
    
    def display_results(self, is_valid, cert_info):
        """Display validation results"""
        print("\n" + "="*50)
        print("Ed25519 ATTESTATION VALIDATION RESULTS")
        print("="*50)
        
        if cert_info.get('version'):
            print(f"Attestation Version: {cert_info['version']}")
        
        if cert_info.get('subject_cn'):
            print(f"Subject (CN): {cert_info['subject_cn']}")
        
        if cert_info.get('serial_number'):
            print(f"Serial Number: {cert_info['serial_number']}")
        
        if cert_info.get('not_before'):
            print(f"Valid From: {cert_info['not_before']}")
        
        if cert_info.get('not_after'):
            print(f"Valid Until: {cert_info['not_after']}")
        
        # Certificate size info
        if cert_info.get('cert_size_bytes'):
            print(f"Attestation Size: {cert_info['cert_size_bytes']} bytes (binary)")
        
        # Expiry status
        if cert_info.get('is_expired') is not None:
            if cert_info['is_expired']:
                print("Time Status: [X] EXPIRED")
            else:
                days = cert_info.get('days_until_expiry', 0)
                if days > 30:
                    print(f"Time Status: [OK] Valid ({days} days remaining)")
                elif days > 0:
                    print(f"Time Status: [!] Valid but expiring soon ({days} days)")
                else:
                    print("Time Status: [X] EXPIRED")
        
        # Overall validation
        print(f"\nOverall: {'[OK] VALID' if is_valid else '[X] INVALID'}")

def main():
    parser = argparse.ArgumentParser(description='Validate Ed25519 attestation from QR code')
    parser.add_argument('qr_image', help='Path to QR code image file')
    parser.add_argument('--ca-public-key', default='output/ca.pub', 
                       help='Path to CA public key (default: output/ca.pub)')
    
    args = parser.parse_args()
    
    # Check if CA public key exists
    try:
        with open(args.ca_public_key, 'rb'):
            pass
    except FileNotFoundError:
        print(f"Error: CA public key '{args.ca_public_key}' not found")
        print("Generate it first using the attestation generation script")
        sys.exit(1)
    
    validator = AttestationValidator(args.ca_public_key)
    is_valid = validator.validate_qr_image(args.qr_image)
    
    sys.exit(0 if is_valid else 1)

if __name__ == "__main__":
    main()