import base64
import random
from libs.crypto.blockciphermodes import AES128Encrypt_ECB
from libs.utils import hexdump

key = bytearray([random.randint(0,255) for _ in range(16)])

def encryptionOracle(input):
	appendix = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

	return AES128Encrypt_ECB(input + appendix, key)

def enumerateBlock(oneByteLess):
	all = list()
	for i in range(256):
		all.append(oneByteLess + bytearray([i]))

	return all
	

# Merge this with stuff from @Home
bs = 16

# Initialise known
known = bytearray(bs - 1)
howManyBlocks = len(encryptionOracle(bytearray([0x00]*bs)))//bs

for k in range(howManyBlocks):
	for iBytes in range( bs):
		# Generate iBytes Less input
		iBytesLess = bytearray(bs-1-iBytes)
		forgedInput = known[-1 *(bs-1):]
		realBlock = encryptionOracle(iBytesLess)
		for enum in enumerateBlock(forgedInput):
			forgedBlock = encryptionOracle(enum)
			if forgedBlock[0:bs] == realBlock[k*bs:k*bs+bs]:
				print("Block {0} Byte {1} MUST be {2:x}".format(k, iBytes, enum[-1]))
				known.append(enum[-1]) # Append cracked Byte
				break

hexdump(known[bs-1:], title="Broke the encryption Oracle")
