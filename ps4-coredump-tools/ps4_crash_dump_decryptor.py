#!/usr/bin/env python
'''

PS4 Crash Dump Decryptor by SocraticBliss (R)

Thanks to... 
# Team FailOverflow
# CelesteBlue and zecoxao

How to use:
1) Put orbiscore-systemcrash.orbisstate in the same directory as this python script
2) Execute python ps4_crash_dump_decryptor.py

'''

from binascii import unhexlify as uhx, hexlify as hx
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import struct
import sys

class Header:
    def __init__(self, f):
        __slots__ = ('VERSION', 'OPEN_PSID', 'PADDING_1', 'PADDING_2',
                     'UNKNOWN', 'STATE', 'DATA_LEN', 'PADDING_3', 'DATA_HMAC')
        
        # Secure Header
        self.VERSION   = struct.unpack('<I', f.read(4))[0]
        self.PSID_ENC  = struct.unpack('<16s', f.read(16))[0]
        self.PADDING_1 = struct.unpack('<108x', f.read(108))
        
        # Padding
        self.PADDING_2 = struct.unpack('<32x', f.read(32))
        
        # Final Header
        self.UNKNOWN   = struct.unpack('<2Q', f.read(16))[0]
        self.STATE     = struct.unpack('<Q', f.read(8))[0]
        self.DATA_LEN  = struct.unpack('<Q', f.read(8))[0]
        self.PADDING_3 = struct.unpack('<16x', f.read(16))
        self.DATA_HMAC = struct.unpack('<32s', f.read(32))[0]

KEYS = [
    ['',''],
    [b'8F86DDEDCBF24A44EB6C30607AA26F76', b'4125715AAB8B78E569F512E65CA62DD3'], # 1.01-3.15
    [b'63AEF79DC49969FD8997B2F60DB65F81', b'1800A5DE2D0F0652FA5602FFADD440AA'], # 3.55
    [b'05205507B7A154E08A7A38B1897563FB', b'AD334D142EAF8B9438DB00D1D0BFF357'], # 4.05
    [b'04C1A0961BBB0CB2140361B0956AAABA', b'052D2FF3014FB38CAAF6898CB899982A'], # 4.07
]

def aes_ecb_encrypt(key, data):
    return AES.new(uhx(key), AES.MODE_ECB).encrypt(data)

def aes_ecb_decrypt(key, data):
    return AES.new(uhx(key), AES.MODE_ECB).decrypt(data)

def hmac_sha256(key, data):
    return HMAC.new(uhx(key), msg = data, digestmod = SHA256).digest()    


# PROGRAM START
def main (argc, argv):

    # 1) Read the orbisstate
    with open('orbiscore-systemcrash.orbisstate', 'rb') as f:
        ps = Header(f)
        
        f.seek(0x4000)
        DATA_ENC = f.read()
        
    KD = KEYS[ps.VERSION][0]
    KC = KEYS[ps.VERSION][1]
    print('\nHeader Version : %i' % ps.VERSION)
    print('Keyset : %i' % ps.VERSION)
    
    PSID_DEC = aes_ecb_decrypt(KD, ps.PSID_ENC)
    print('\nEncrypted PSID : %s' % hx(ps.PSID_ENC).upper())
    print('Decrypted PSID : %s' % hx(PSID_DEC).upper())
    
    # 2) HMAC DIGEST
    DIGEST = hmac_sha256(KC, ps.PSID_ENC)
    print('Digest : %s' % hx(DIGEST).upper())
    
    KD = DIGEST[0x10:]
    KC = DIGEST[:0x10]
    
    print('\nAES Key  : %s' % hx(KC).upper())
    print('HMAC Key : %s' % hx(KD).upper())
    
    # 3) Utilize the proper keys to decrypt the data
    IV = b'0000000000000000'
    DATA = AES.new(KD, AES.MODE_CBC, IV).decrypt(DATA_ENC)
    
    # 4) Save the decrypted data
    with open('debug.bin', 'wb') as f:
        f.write(DATA)
        
    print('\nSaved to debug.bin')

if __name__=='__main__':
    sys.exit(main(len(sys.argv), sys.argv))