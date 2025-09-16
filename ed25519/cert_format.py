#!/usr/bin/env python3
"""
Custom Ed25519 Certificate Format Implementation

Certificate Format:
[1 byte: version]
[2 bytes: notBefore Unix epoch in days] 
[2 bytes: notAfter Unix epoch in days]
[1 byte: serial length][N bytes: serial big-endian integer]
[1 byte: CN length][M bytes: CN UTF-8]
[64 bytes: Ed25519 signature over all above data]
"""

import struct
import time
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# Certificate version
CERT_VERSION = 1

# Unix epoch start date
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

def days_since_epoch(dt):
    """Convert datetime to days since Unix epoch"""
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = dt - UNIX_EPOCH
        return int(delta.total_seconds() // 86400)
    raise ValueError("Expected datetime object")

def days_to_datetime(days):
    """Convert days since Unix epoch to datetime"""
    return UNIX_EPOCH + timedelta(days=days)

class Ed25519Certificate:
    """Custom Ed25519 certificate implementation"""
    
    def __init__(self, version=CERT_VERSION, not_before=None, not_after=None, 
                 serial=None, cn=None, signature=None):
        self.version = version
        self.not_before = not_before or datetime.now(timezone.utc)
        self.not_after = not_after or datetime.now(timezone.utc).replace(year=datetime.now().year + 1)
        self.serial = int(serial) if serial else 0
        self.cn = cn or ""
        self.signature = signature or b'\x00' * 64
    
    def _pack_data_to_sign(self):
        """Pack certificate data that will be signed"""
        # Convert dates to days since epoch
        not_before_days = days_since_epoch(self.not_before)
        not_after_days = days_since_epoch(self.not_after)
        
        # Encode CN as UTF-8
        cn_bytes = self.cn.encode('utf-8')
        
        # Encode serial as minimal big-endian bytes
        if self.serial < 0:
            raise ValueError("Serial number must be non-negative")
        if self.serial == 0:
            serial_bytes = b'\x00'
        else:
            # Calculate minimum number of bytes needed
            byte_length = (self.serial.bit_length() + 7) // 8
            serial_bytes = self.serial.to_bytes(byte_length, byteorder='big')
        
        # Validate lengths
        if len(serial_bytes) > 255:
            raise ValueError("Serial number too large (max 255 bytes)")
        if len(cn_bytes) > 255:
            raise ValueError("Common name too long (max 255 UTF-8 bytes)")
        
        # Pack data: version (1) + not_before (2) + not_after (2) + serial_len (1) + serial + cn_len (1) + cn
        data = struct.pack('!BHHB', self.version, not_before_days, not_after_days, len(serial_bytes))
        data += serial_bytes
        data += struct.pack('!B', len(cn_bytes))
        data += cn_bytes
        
        return data
    
    def sign(self, private_key):
        """Sign the certificate with an Ed25519 private key"""
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Expected Ed25519PrivateKey")
        
        data_to_sign = self._pack_data_to_sign()
        self.signature = private_key.sign(data_to_sign)
        return self.signature
    
    def verify(self, public_key):
        """Verify the certificate signature with an Ed25519 public key"""
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError("Expected Ed25519PublicKey")
        
        data_to_sign = self._pack_data_to_sign()
        
        try:
            public_key.verify(self.signature, data_to_sign)
            return True
        except InvalidSignature:
            return False
    
    def to_bytes(self):
        """Serialize certificate to binary format"""
        data_to_sign = self._pack_data_to_sign()
        return data_to_sign + self.signature
    
    @classmethod
    def from_bytes(cls, cert_bytes):
        """Deserialize certificate from binary format"""
        if len(cert_bytes) < 7:  # Minimum: version(1) + dates(4) + serial_len(1) + serial(1)
            raise ValueError("Certificate data too short")
        
        offset = 0
        
        # Unpack version, dates, and serial length
        version, not_before_days, not_after_days, serial_len = struct.unpack('!BHHB', cert_bytes[offset:offset+6])
        offset += 6
        
        # Unpack serial
        if offset + serial_len > len(cert_bytes):
            raise ValueError("Invalid serial length")
        if serial_len == 0:
            raise ValueError("Serial length cannot be zero")
        serial_bytes = cert_bytes[offset:offset+serial_len]
        serial = int.from_bytes(serial_bytes, byteorder='big')
        offset += serial_len
        
        # Unpack CN length
        if offset >= len(cert_bytes):
            raise ValueError("Missing CN length")
        cn_len = struct.unpack('!B', cert_bytes[offset:offset+1])[0]
        offset += 1
        
        # Unpack CN
        if offset + cn_len > len(cert_bytes):
            raise ValueError("Invalid CN length")
        cn = cert_bytes[offset:offset+cn_len].decode('utf-8')
        offset += cn_len
        
        # Unpack signature
        if offset + 64 != len(cert_bytes):
            raise ValueError(f"Invalid certificate length. Expected {offset + 64}, got {len(cert_bytes)}")
        signature = cert_bytes[offset:offset+64]
        
        # Convert days back to datetime
        not_before = days_to_datetime(not_before_days)
        not_after = days_to_datetime(not_after_days)
        
        return cls(version=version, not_before=not_before, not_after=not_after,
                  serial=serial, cn=cn, signature=signature)
    
    def is_expired(self):
        """Check if certificate is expired"""
        now = datetime.now(timezone.utc)
        return now > self.not_after or now < self.not_before
    
    def days_until_expiry(self):
        """Get days until certificate expires"""
        now = datetime.now(timezone.utc)
        delta = self.not_after - now
        return max(0, delta.days)
    
    def __str__(self):
        """String representation of certificate"""
        return (f"Ed25519Certificate(version={self.version}, "
                f"serial='{self.serial}', cn='{self.cn}', "
                f"not_before='{self.not_before.isoformat()}', "
                f"not_after='{self.not_after.isoformat()}')")

def generate_ca_keypair():
    """Generate a new Ed25519 CA key pair"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filepath):
    """Save Ed25519 private key to file in PEM format"""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filepath, 'wb') as f:
        f.write(pem_bytes)

def save_public_key(public_key, filepath):
    """Save Ed25519 public key to file in PEM format"""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, 'wb') as f:
        f.write(pem_bytes)

def load_private_key(filepath):
    """Load Ed25519 private key from PEM file"""
    with open(filepath, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(filepath):
    """Load Ed25519 public key from PEM file"""
    with open(filepath, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

if __name__ == "__main__":
    # Example usage
    print("Ed25519 Certificate Format Demo")
    print("=" * 40)
    
    # Generate CA key pair
    ca_private, ca_public = generate_ca_keypair()
    
    # Create a certificate
    cert = Ed25519Certificate(
        serial=123456789012,
        cn="John Smith",
        not_before=datetime.now(timezone.utc),
        not_after=datetime.now(timezone.utc).replace(year=datetime.now().year + 1)
    )
    
    # Sign the certificate
    cert.sign(ca_private)
    
    # Serialize and deserialize
    cert_bytes = cert.to_bytes()
    
    print(f"Certificate: {cert}")
    print(f"Binary size: {len(cert_bytes)} bytes")
    
    # Verify signature
    cert2 = Ed25519Certificate.from_bytes(cert_bytes)
    is_valid = cert2.verify(ca_public)
    print(f"Signature valid: {is_valid}")