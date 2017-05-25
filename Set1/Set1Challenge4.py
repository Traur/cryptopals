# https://cryptopals.com/sets/1/challenges/4

from libs.utils import hex2bytes, bytes2hex, hexdump
from libs.analysis import scoreEnglish
from libs.crypto.xor import breakSingleByteXOR

file = open("Set1/Set1Challenge4.txt", "r")
bestScore = 0
bestKey = None
bestPlaintext = None
bestCiphertext = None
for line in file:
    ciphertext = hex2bytes(line[:-1])  # ommit \n
    plaintext, key, score = breakSingleByteXOR(ciphertext)

    if bestScore < score:
        bestScore = score
        bestKey = key
        bestPlaintext = plaintext
        bestCiphertext = ciphertext

print("Ciphertext:")
hexdump(bestCiphertext)
print("Broke it with with k={0}:".format(bestKey))
hexdump(bestPlaintext)
