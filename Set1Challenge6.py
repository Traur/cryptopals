# https://cryptopals.com/sets/1/challenges/5

from libs.utils import hexdump, hex2bytes, partitionList
from libs.crypto.xor import repeatingKeyXOR, breakSingleByteXOR, estimateKeysize
from libs.analysis import editDistance
import base64  # TODO


# "Task 1: Calulate Edit Distance between those two strings and make sure its 37"
a = bytearray("this is a test", "utf-8")
b = bytearray("wokka wokka!!!", "utf-8")
assert editDistance(a, b) == 37


# Read encrypted file:
with open("Set1Challenge6.txt", "rb") as file:
    # TODO write own b64decode
    ciphertext = base64.b64decode(file.read())

bestKeysize = estimateKeysize(ciphertext, 40)[0]
# A Word on libs.crypto.xor.estimateKeysize():
# 	Let's assume len(realKey) = 5, then estimateKeysize will return [30, 15, 10, 5, 3, 2]
# 	This means multiple of len(realKey) have a lower normalized edit distance.
#
# 	If you alter the Challenge to try keysize from (2,60), estimateKeysize(c)=[59,28, ..], but the output becomes slightly wrong.
# 	The libs.crypto.xor.breakSingleByteXOR() produces a false key for keyposition 20 (b"\'" instead of b' ')
#
#	 So instead of
#		key=bytearray(b'Terminator X: Bring the noise')
# 	it becomes
# key=bytearray(b"Terminator X: Bring\'the noiseTerminator X: Bring the
# noise")

#"5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length."
blocks = partitionList(ciphertext, bestKeysize)
transposed = list()

#"6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on."
#(You basically transform the problem of repeatingKeyXOR to a single KeyXOR, which we can already break using libs.xor.breakSingleByteXOR)
for i in range(bestKeysize):
    tmp = bytearray()
    for block in blocks:
        if i < len(block):
            tmp.append(block[i])
    transposed.append(tmp)

#"7. Solve each block as if it was single-character XOR. You already have code to do this."
key = bytearray()
for i in range(len(transposed)):
    #"8. For each block, the single-byte XOR key that produces the best looking histogram
    # is the repeating-key XOR key byte for that block. Put them together and
    # you have the key."
    p, k, s = breakSingleByteXOR(transposed[i])
    key.append(k)

# Finally decrypt everything
print("Decrypt ciphertext with key={0}".format(key))
plaintext = repeatingKeyXOR(ciphertext, key)
hexdump(plaintext)
