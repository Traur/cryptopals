# https://cryptopals.com/sets/1/challenges/2


from libs.utils import hex2bytes, bytes2hex, hexdump
from libs.crypto.xor import fixedXOR

buffer1 = hex2bytes("1c0111001f010100061a024b53535009181c")
buffer2 = hex2bytes("686974207468652062756c6c277320657965")
result = fixedXOR(buffer1, buffer2)

hexdump(buffer1)
hexdump(buffer2)
print("== equals ==")
hexdump(result)

if result == hex2bytes("746865206b696420646f6e277420706c6179"):
	print("Challenge 2 successful!")
else:
	print("Challenge 2 failed miserably")