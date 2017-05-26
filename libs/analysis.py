"""
This file offers functions which have something to do with analysis,
e.g. determine if a given bytestring is likely to be english,
 measuring the edit distance between to bytestrings, or other
"""
from libs.utils import partitionList


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


