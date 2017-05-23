# https://cryptopals.com/sets/1/challenges/5

from libs.utils import hexdump, hex2bytes
from libs.crypto.xor import repeatingKeyXOR

plaintext = bytearray("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "utf-8")
key = bytearray("ICE", "utf-8")

solution = hex2bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
ciphertext = repeatingKeyXOR(plaintext, key)

print("Plaintext:")
hexdump(plaintext)
print("Encrypted with k={0}".format(key))
hexdump(ciphertext)

if ciphertext == solution:
	print("Challenge 5 successful!")
else:
	print("Challenge 5 failed miserably")
	