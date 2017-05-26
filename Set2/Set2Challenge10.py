from libs.crypto.blockciphermodes import AES128Decrypt_CBC
from libs.utils import hexdump
import base64

with open("Set2/Set2Challenge10.txt", "rb") as file:
    ciphertext = base64.b64decode(file.read())

key = bytearray("YELLOW SUBMARINE", "utf-8")
iv = bytearray([0x0]*16)

plaintext = AES128Decrypt_CBC(ciphertext, key, iv)
hexdump(plaintext, title="Decrypted using AES128-CBC, k={0} and iv={1}:".format(key, iv))
