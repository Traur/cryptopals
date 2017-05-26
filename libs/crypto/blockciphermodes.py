from libs.crypto.aes import AES128Encrypt, AES128Decrypt
from libs.utils import partitionList, hexdump
from libs.crypto.xor import fixedXOR

def add7Padding(input, n):
    assert type(input) == bytearray
    if len(input) % n == 0:
        return input


    # Determine how many bytes needed to pad the last block to blocksize n
    dif = n - (len(input) % n)
    append = bytearray([dif]*dif)

    return input + append

def AES128Encrypt_ECB(input, key):
    input = add7Padding(input, 16)
    
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
    input = add7Padding(input, 16)
    plaintexts = partitionList(input, 16)
    ciphertexts = list()
    
    # Round 0
    ciphertexts.append(AES128Encrypt(fixedXOR(plaintexts[0], iv), key))
    for i in range(1, len(plaintexts)):
        ciphertexts.append(AES128Encrypt(fixedXOR(ciphertexts[i-1], plaintexts[i]), key))

    result = bytearray()
    for e in ciphertexts:
        for f in e:
            result.append(f)

    return result


def AES128Decrypt_CBC(input, key, iv):
    ciphertexts = partitionList(input, 16)
    plaintexts = bytearray()

    # Round 0
    plaintexts += fixedXOR(AES128Decrypt(ciphertexts[0], key), iv)
    for i in range(1, len(ciphertexts)):
        plaintexts += fixedXOR(AES128Decrypt(ciphertexts[i], key), ciphertexts[i-1])

    return plaintexts

