import base64
import random
from libs.crypto.blockciphermodes import AES128Encrypt_ECB
from libs.utils import hexdump

key = bytearray([random.randint(0, 255) for _ in range(16)])
totalBytes = 0

def encryptionOracle(input):
    global totalBytes
    prepend = bytearray([random.randint(0, 255)
                        for _ in range(random.randint(0, 16))])
    appendix = base64.b64decode(
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    todo = prepend + input + appendix
    totalBytes += len(todo)
    return AES128Encrypt_ECB(todo, key)


def getValidBlock(input):
    bs = 16
    hBs = bs // 2

    sponge = [0x0] * hBs
    fixedData1 = [0xfa, 0xab] * hBs
    fixedData2 = fixedData1[:] * 2
    block = bytearray(sponge + fixedData1 + fixedData2) + input

    while(True):
        ciphertext = encryptionOracle(block)
        i = determineEqualBlocks(ciphertext)
        if i != -1:
#            hexdump(ciphertext, title="GOT")
#            print("Cut of {0} blocks".format(i // bs))
            return ciphertext[i:]


def determineEqualBlocks(blocks):
    i = 0
    j = 0
    bs = 16
    while(True):
        try:
            if blocks[i] != blocks[i + bs]:
                i += bs - (i % bs)
                j = 0
            else:
                i += 1
                j += 1

            if j == bs+bs:
                return i + bs 
        except IndexError:
            return -1


def enumerateBlock(oneByteLess):
    yield (oneByteLess + bytearray([0]))
    ranked = [32, 101, 97, 114, 105, 111, 116, 110, 115, 108, 99, 69, 65, 82, 73, 79, 84, 78, 83, 76, 67, 117, 100, 112, 109, 104, 103, 98, 102, 121, 119, 107, 118, 120, 122, 106, 113, 85, 68, 80, 77, 72, 71, 66, 70, 89, 87, 75, 86, 88, 90, 74, 81, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94, 95, 96, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]

    for i in ranked:
        yield (oneByteLess + bytearray([i]))


# Merge this with stuff from @Home
bs = 16

# Initialise known
known = bytearray(bs - 1)
howManyBlocks = len(getValidBlock(bytearray([0x00] * bs))) // bs
print("Need to decrypt {0}".format(howManyBlocks-1))
for k in range(howManyBlocks-1):
    for iBytes in range(bs):
        # Generate iBytes Less input
        iBytesLess = bytearray(bs - 1 - iBytes)
        forgedInput = known[-1 * (bs - 1):]
        realBlock = getValidBlock(iBytesLess)
        for enum in enumerateBlock(forgedInput):
           # print(enum)
            forgedBlock = getValidBlock(enum)
            if forgedBlock[0:bs] == realBlock[k * bs:k * bs + bs]:
                print(
                    "Block {0} Byte {1} MUST be {2:x}".format(k, iBytes, enum[-1]))
                known.append(enum[-1])  # Append cracked Byte
                break

hexdump(known[bs - 1:], title="Broke the encryption Oracle")
print("Encrypted {0} bytes worth of data".format(totalBytes))
