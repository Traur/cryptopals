# https://cryptopals.com/sets/1/challenges/3

from libs.utils import hex2bytes, bytes2hex, hexdump
from libs.analysis import scoreEnglish
from libs.crypto.xor import breakSingleByteXOR

ciphertext = hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
p,k,s = breakSingleByteXOR(ciphertext);

hexdump(ciphertext)
print("Broke it with with k={1}:".format(ciphertext, k))
hexdump(p)