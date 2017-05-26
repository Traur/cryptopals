from libs.crypto.aes import AES128Encrypt, AES128Decrypt
from libs.utils import partitionList
from libs.crypto.xor import fixedXOR
def PKCS7Padding(input, n):
    result = list(input)
    dif = n - len(input)
    result += ([dif]*dif)
    return bytearray(result)


def AES128Encrypt_ECB(input, key):
    plaintexts = partitionList(input, 16)
    ciphertext = bytearray()

    for block in plaintexts:
        c = AES128Encrypt(block, key)
        ciphertext += c

    return ciphertext


def AES128Decrypt_ECB(input, key):
    ciphertexts = partitionList(input, 16)
    plaintexts = bytearray()

    for block in ciphertexts:
        c = AES128Decrypt(block, key)
        plaintexts += c

    return plaintexts


def AES128Encrypt_CBC(input, key, iv):
    return -1 #TODO

def AES128Decrypt_CBC(input, key, iv):
    ciphertexts = partitionList(input, 16)
    plaintexts = bytearray()

    # Round 0
    plaintexts += fixedXOR(AES128Decrypt(ciphertexts[0], key), iv)
    for i in range(1, len(ciphertexts)):
        plaintexts += fixedXOR(AES128Decrypt(ciphertexts[i], key), ciphertexts[i-1])

    return plaintexts

