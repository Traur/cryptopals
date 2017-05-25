from libs.utils import hexdump, hex2bytes
from libs.crypto.aes import detectECB
import base64

# Read File
file =  open("Set1/Set1Challenge8.txt", "r")
i = 0
for line in file:
    ciphertext = hex2bytes(line[:-1])
    score = detectECB(ciphertext)
   
    if score > 0: 
        hexdump(ciphertext, title="Detected ECB-Encrypted Ciphertext with score={0}".format(score))
    i += 1
key = bytearray("YELLOW SUBMARINE", "utf-8")

