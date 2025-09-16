#!/usr/bin/env python3
"""
QR Code Certificate Validator (DER format)
Scans QR codes and validates DER certificates against CA
"""

import sys
import argparse
import os
import subprocess
import tempfile
import re
from datetime import datetime
from pyzbar import pyzbar
from PIL import Image

class CertificateValidator:
    def __init__(self, ca_cert_path="output/ca.crt"):
        self.ca_cert_path = ca_cert_path
    
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
    
    def validate_certificate(self, cert_der):
        """Validate certificate against CA"""
        try:
            # Write DER certificate to temporary file
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as temp_cert:
                temp_cert.write(cert_der)
                temp_cert_path = temp_cert.name

            # Verify certificate against CA
            verify_cmd = [
                'openssl', 'verify',
                '-CAfile', self.ca_cert_path,
                temp_cert_path
            ]

            result = subprocess.run(verify_cmd, capture_output=True, text=True)

            if result.returncode == 0:
                print("[OK] Certificate signature VALID")
                is_valid = True
            else:
                print("[X] Certificate signature INVALID")
                print(f"Error: {result.stderr.strip()}")
                is_valid = False

            # Extract certificate details
            cert_info = self.extract_cert_info(temp_cert_path)

            # Clean up temporary file
            subprocess.run(['rm', temp_cert_path], check=True)

            return is_valid, cert_info

        except Exception as e:
            print(f"Error validating certificate: {e}")
            return False, {}
    
    def extract_cert_info(self, cert_path):
        """Extract relevant information from certificate"""
        info = {}
        
        try:
            # Get certificate text output (specify DER input format)
            cmd = ['openssl', 'x509', '-in', cert_path, '-inform', 'DER', '-noout', '-text']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            cert_text = result.stdout
            
            # Extract serial number
            # Look for both formats: "123456789012 (0x1cbe991a14)" or just hex
            serial_match = re.search(r'Serial Number:\s*(?:(\d+)\s+\(0x[a-fA-F0-9]+\)|([a-fA-F0-9:]+))', cert_text)
            if serial_match:
                try:
                    # First group is decimal format, second is hex format
                    if serial_match.group(1):
                        info['serial_number'] = serial_match.group(1)
                    else:
                        serial_hex = serial_match.group(2).replace(':', '')
                        info['serial_number'] = str(int(serial_hex, 16)).zfill(12)
                except (ValueError, IndexError) as e:
                    print(f"Warning: Could not parse serial number properly: {e}")
                    # Fallback to just showing the raw match
                    info['serial_number'] = serial_match.group(0).split(':', 1)[1].strip()
            else:
                print("Warning: Could not find serial number in certificate")
            
            # Extract subject (should be our 12-digit serial)
            subject_match = re.search(r'Subject: CN\s*=\s*([^,\n]+)', cert_text)
            if subject_match:
                info['subject_cn'] = subject_match.group(1)
            
            # Extract validity dates
            not_before_match = re.search(r'Not Before:\s*(.+)', cert_text)
            not_after_match = re.search(r'Not After\s*:\s*(.+)', cert_text)
            
            if not_before_match:
                info['not_before'] = not_before_match.group(1).strip()
            if not_after_match:
                info['not_after'] = not_after_match.group(1).strip()
                
                # Check if certificate is expired
                try:
                    expiry_date = datetime.strptime(info['not_after'], '%b %d %H:%M:%S %Y %Z')
                    info['is_expired'] = datetime.now() > expiry_date
                    days_until_expiry = (expiry_date - datetime.now()).days
                    info['days_until_expiry'] = days_until_expiry
                except:
                    info['is_expired'] = None
            
            return info
            
        except subprocess.CalledProcessError as e:
            print(f"Error extracting certificate info: {e}")
            return {}
    
    def validate_qr_image(self, image_path):
        """Complete validation workflow from QR image"""
        print(f"Scanning QR code from: {image_path}")

        # Decode QR code
        cert_der = self.decode_qr_image(image_path)
        print(f"QR code decoded successfully ({len(cert_der)} bytes)")

        # Validate certificate
        is_valid, cert_info = self.validate_certificate(cert_der)

        # Display results
        self.display_results(is_valid, cert_info)

        return is_valid
    
    def display_results(self, is_valid, cert_info):
        """Display validation results"""
        print("\n" + "="*50)
        print("CERTIFICATE VALIDATION RESULTS")
        print("="*50)
        
        if cert_info.get('subject_cn'):
            print(f"Subject (CN): {cert_info['subject_cn']}")
        
        if cert_info.get('serial_number'):
            print(f"Serial Number: {cert_info['serial_number']}")
        
        if cert_info.get('not_before'):
            print(f"Valid From: {cert_info['not_before']}")
        
        if cert_info.get('not_after'):
            print(f"Valid Until: {cert_info['not_after']}")
        
        # Expiry status
        if cert_info.get('is_expired') is not None:
            if cert_info['is_expired']:
                print("Status: [X] EXPIRED")
            else:
                days = cert_info.get('days_until_expiry', 0)
                if days > 30:
                    print(f"Status: [OK] Valid ({days} days remaining)")
                elif days > 0:
                    print(f"Status: [!] Valid but expiring soon ({days} days)")
                else:
                    print("Status: [X] EXPIRED")
        
        # Overall validation
        print(f"\nOverall: {'[OK] VALID' if is_valid and not cert_info.get('is_expired', False) else '[X] INVALID'}")

def main():
    parser = argparse.ArgumentParser(description='Validate DER certificate from QR code')
    parser.add_argument('qr_image', help='Path to QR code image file')
    parser.add_argument('--ca-cert', default='output/ca.crt', 
                       help='Path to CA certificate (default: output/ca.crt)')
    
    args = parser.parse_args()
    
    # Check if CA certificate exists
    try:
        with open(args.ca_cert, 'r'):
            pass
    except FileNotFoundError:
        print(f"Error: CA certificate '{args.ca_cert}' not found")
        print("Generate it first using the certificate generation script")
        sys.exit(1)
    
    validator = CertificateValidator(args.ca_cert)
    is_valid = validator.validate_qr_image(args.qr_image)
    
    sys.exit(0 if is_valid else 1)

if __name__ == "__main__":
    main()