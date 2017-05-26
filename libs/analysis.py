"""
This file offers functions which have something to do with analysis,
e.g. determine if a given bytestring is likely to be english,
 measuring the edit distance between to bytestrings, or other
"""
from libs.utils import partitionList
from libs.crypto.blockciphermodes import AES128Encrypt_ECB, AES128Encrypt_CBC
import random

def scoreEnglish(plaintext, fast=True):
    assert type(plaintext) == bytearray or type(plaintext) == bytes
    if(fast):
        topletters = ['E', 'T', 'A', 'O', 'I',
                      'N', ' ', 'S', 'H', 'R', 'D', 'L', 'U']
        score = 0
        for b in plaintext:
            try:
                if chr(b).upper() in topletters:
                    score += 1
            except:
                pass

        return score


def editDistance(bytes1, bytes2):
    longerBytes = bytes1 if len(bytes1) > len(bytes2) else bytes2
    shorterBytes = bytes2 if len(bytes2) < len(bytes1) else bytes1
    distance = 0

    for i in range(len(shorterBytes)):
        # After XOR, different bits appear as 1
        bytE = longerBytes[i] ^ shorterBytes[i]

        for k in range(8):
            # Compare each bit with 0x1
            if (bytE >> k) & 0x1 == 0x1:
                distance += 1

    # Add length difference
    distance += 8 * (len(longerBytes) - len(shorterBytes))
    return distance

def detectECB(ciphertext):
    p = partitionList(ciphertext, 16)
    score = 0
    for i in range(len(p)):
        for k in range(len(p)):
            if i != k and p[i] == p[k]:
                score += 1

    return score

def encryptionOracle(input):
    key = bytearray([random.randint(0,255) for _ in range(16)])
    prepend = bytearray([random.randint(0,255) for _ in range(random.randint(5,10)) ]) 
    append = bytearray([random.randint(0,255) for _ in range(random.randint(5,10))])
    
    plaintext = prepend + input + append
    coin = random.randint(0,1)

    if coin == 0:
        return AES128Encrypt_ECB(plaintext, key), 0
    else:
        iv = bytearray([random.randint(0,255) for _ in range(16)])
        return AES128Encrypt_CBC(plaintext, key, iv), 1
    
def detectEncryption():
    input = ""

