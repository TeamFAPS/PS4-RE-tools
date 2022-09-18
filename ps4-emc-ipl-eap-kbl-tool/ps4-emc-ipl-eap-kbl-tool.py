#!/usr/bin/env python
'''
PS4 EMC IPL and EAP KBL Tool by SocraticBliss and CelesteBlue (R)
Thanks to...
# flatz, zecoxao
How to use:
1) Get PS4 EMC IPL or PS4 EAP KBL from a decrypted PS4 PUP or from a PS4 Serial Flash dump
2) Execute python ps4-emc-ipl-eap-kbl-tool.py in_file
'''
import struct
from binascii import unhexlify as uhx
from binascii import hexlify as hx
from Crypto.Cipher import AES
from Crypto.Hash import SHA, HMAC

import os
import sys


#EMC_IPL_CIPHER_KEY = ['5F74FE7790127FECF82CC6E6D91FA2D1'] # Aeolia
EMC_IPL_CIPHER_KEY = ['1A4B4DC4179114F0A6B0266ACFC81193'] # Belize

EMC_IPL_HASHER_KEY = ['73FE06F3906B05ECB506DFB8691F9F54'] # Aeolia
#EMC_IPL_HASHER_KEY = ['00000000000000000000000000000000'] # Belize

EAP_KBL_CIPHER_KEY = ['581A75D7E9C01F3C1BD7473DBD443B98'] # Aeolia
#EAP_KBL_CIPHER_KEY = ['00000000000000000000000000000000'] # Belize

EAP_KBL_HASHER_KEY = ['824D9BB4DBA3209294C93976221249E4'] # Aeolia
#EAP_KBL_HASHER_KEY = ['00000000000000000000000000000000'] # Belize

ZEROS128 = ['00000000000000000000000000000000']

def aes_decrypt_cbc(key, iv, input):
	return AES.new(key, AES.MODE_CBC, iv).decrypt(input)

def aes_encrypt_cbc(key, iv, input):
	return AES.new(key, AES.MODE_CBC, iv).encrypt(input)

def emc_ipl_decrypt_header(hdr):
	return hdr[:0x30] + aes_decrypt_cbc(uhx(EMC_IPL_CIPHER_KEY[0]), uhx(ZEROS128[0]), hdr[0x30:0x80])

def emc_ipl_encrypt_header(hdr):
	return hdr[:0x30] + aes_encrypt_cbc(uhx(EMC_IPL_CIPHER_KEY[0]), uhx(ZEROS128[0]), hdr[0x30:0x80])

def eap_kbl_decrypt_header(hdr):
	return hdr[:0x30] + aes_decrypt_cbc(uhx(EAP_KBL_CIPHER_KEY[0]), uhx(ZEROS128[0]), hdr[0x30:0x80])

def eap_kbl_encrypt_header(hdr):
	return hdr[:0x30] + aes_encrypt_cbc(uhx(EAP_KBL_CIPHER_KEY[0]), uhx(ZEROS128[0]), hdr[0x30:0x80])

def main(argc, argv):
	with open(sys.argv[1], 'rb') as f:
		data = f.read(0x80)
		type = data[7:8]
		if type == uhx('48'):
			print('PS4 EMC Initial Program Loader')
			hdr_dec = emc_ipl_decrypt_header(data)
		elif type == uhx('68'):
			print('PS4 EAP Kernel Boot Loader')
			hdr_dec = eap_kbl_decrypt_header(data)
		else:
			print("Unsupported file format!")
			return
		zeroes = hdr_dec[0x64:0x6C]
		if zeroes != b'\x00\x00\x00\x00\x00\x00\x00\x00':
			print("Bad decryption key or corrupted input file!")
			return
		body_aes_key = hdr_dec[0x30:0x40]
		body_hmac_key = hdr_dec[0x40:0x50]
		body_hmac = hdr_dec[0x50:0x64]
		header_hmac = hdr_dec[0x6C:0x80]

		hdr_dec_cut = hdr_dec[:0x6C]
		if type == uhx('48'):
			header_hmac_2 = HMAC.new(uhx(EMC_IPL_HASHER_KEY[0]), hdr_dec_cut, SHA)
		elif type == uhx('68'):
			header_hmac_2 = HMAC.new(uhx(EAP_KBL_HASHER_KEY[0]), hdr_dec_cut, SHA)
		print(header_hmac_2.hexdigest())
		print(hx(header_hmac))
		print(header_hmac_2.hexverify(hx(header_hmac)))

		body_len = struct.unpack('<L', hdr_dec[0xC:0x10])[0]
		enc_body = f.read(body_len)
		body_hmac_2 = HMAC.new(body_hmac_key, enc_body, SHA)
		body_dec = aes_decrypt_cbc(body_aes_key, uhx(ZEROS128[0]), enc_body)
		print(body_hmac_2.hexdigest())
		print(hx(body_hmac))
		print(body_hmac_2.hexverify(hx(body_hmac)))
		
		with open(sys.argv[1] + '_dec.bin', 'wb') as g:
			g.write(hdr_dec + body_dec)
		with open(sys.argv[1] + '_body_dec.bin', 'wb') as g:
			g.write(body_dec)

if __name__ == '__main__':
	main(len(sys.argv), sys.argv)