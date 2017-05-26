from libs.utils import hexdump
from libs.crypto.blockciphermodes import AES128Decrypt_ECB

import base64
# Read File
with open("Set1/Set1Challenge7.txt", "rb") as file:
    ciphertext = base64.b64decode(file.read())

key = bytearray("YELLOW SUBMARINE", "utf-8")
plaintext = AES128Decrypt_ECB(ciphertext, key)

hexdump(plaintext, title="Decrypted using AES128-ECB and k={0}".format(key))
