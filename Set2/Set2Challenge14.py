import base64
import random
from libs.crypto.blockciphermodes import AES128Encrypt_ECB
from libs.utils import hexdump

key = bytearray([random.randint(0,255) for _ in range(16)])

def encryptionOracle(input):
	prepend = bytearray([random.randint(0,255) for _ in range(random.randint(0, 16))])
	appendix = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

	return AES128Encrypt_ECB(prepend + input + appendix, key)


def getValidBlock(input):
	bs = 16
	hBs = bs//2

	sponge = [0x0] * hBs
	fixedData1 = [i for i in range(bs)]
	fixedData2 = fixedData1[:]
	block = bytearray(sponge + fixedData1 + fixedData2) + input

	while(True):
		ciphertext = encryptionOracle(block)
		i = determineEqualBlocks(ciphertext)
		if i != -1:
#			hexdump(ciphertext, title="GOT")
#			hexdump(ciphertext[i:], title="Would")
			return ciphertext[i:]

def determineEqualBlocks(blocks):
	i = 0
	j = 0
	bs = 16
	while(True):
		try:
			if blocks[i] != blocks[i+bs]:
				i += bs - (i % bs)
				j = 0
			else:
				i += 1
				j += 1

			if j == bs:		
				return i+bs
		except IndexError:
			return -1


def enumerateBlock(oneByteLess):
	yield (oneByteLess + bytearray([0]))
	for i in range(32, 127):
		yield (oneByteLess + bytearray([i]))
	

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
		realBlock = getValidBlock(iBytesLess)
		for enum in enumerateBlock(forgedInput):
			print(enum)
			forgedBlock = getValidBlock(enum)
			if forgedBlock[0:bs] == realBlock[k*bs:k*bs+bs]:
				print("Block {0} Byte {1} MUST be {2:x}".format(k, iBytes, enum[-1]))
				known.append(enum[-1]) # Append cracked Byte
				break

hexdump(known[bs-1:], title="Broke the encryption Oracle")
