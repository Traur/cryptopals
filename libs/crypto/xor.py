"""
This file countains all related crypto functions using XOR
and to break it respectivly.
"""

def fixedXOR(buf1, buf2):
    assert len(buf1) == len(buf2), "{0} vs {1}".format(len(buf1), len(buf2))
    result = bytearray()
    for i in range(len(buf1)):
        result.append(buf1[i] ^ buf2[i])

    return result


def breakSingleByteXOR(ciphertext):
    assert type(ciphertext) == bytearray or type(ciphertext) == bytes
    from libs.analysis import scoreEnglish
    bestScore = 0
    bestPlaintext = None
    bestKey = None
    for key in range(0, 255):
        longkey = bytes([key]) * (len(ciphertext))
        plaintext = fixedXOR(longkey, ciphertext)

        lastScore = scoreEnglish(plaintext)

        if(lastScore > bestScore):
            bestScore = lastScore
            bestPlaintext = plaintext
            bestKey = key

    return bestPlaintext, bestKey, bestScore


def repeatingKeyXOR(ciphertext, key):
    assert type(ciphertext) == bytearray or type(ciphertext) == bytes
    assert type(key) == bytearray or type(key) == bytes

    n = len(ciphertext)
    longkey = (key * n)[0:n]

    return fixedXOR(ciphertext, longkey)


def estimateKeysize(ciphertext, maxlen):
    assert type(ciphertext) == bytearray or type(ciphertext) == bytes
    from libs.analysis import editDistance
    # Possible distances go from 0 (exakt same) to maxlen*8 (every bit is
    # different (0, maxlen*8]
    smallestDistance = 8 * maxlen + 1
    bestKeysize = list()
    for keysize in range(2, maxlen):
        # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
        # and find the edit distance between them. Normalize this result by
        # dividing by KEYSIZE.

        # It could happen that the ciphertext is too small to use 4 keysize blocks.
        # This is a problem for futute Me! Until then..
        assert len(ciphertext) >= keysize * 6

        b1 = ciphertext[0:keysize]
        b2 = ciphertext[keysize:keysize * 2]
        b3 = ciphertext[(keysize * 2):(keysize * 4)]
        b4 = ciphertext[(keysize * 4):(keysize * 6)]

        # There are n(n-1)/2 == 4*3/2 = 6 pairs
        d1 = editDistance(b1, b2)
        d2 = editDistance(b1, b3)
        d3 = editDistance(b1, b4)
        d4 = editDistance(b2, b3)
        d5 = editDistance(b2, b4)
        d6 = editDistance(b3, b4)

        distance = (d1 + d2 + d3 + d4 + d5 + d6) / (6 * keysize)
        # 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could
        # proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
        # KEYSIZE blocks instead of 2 and average the distances.
        if distance < smallestDistance:
            print("Better keysize n={0} found witch d={1}".format(
                keysize, distance))
            smallestDistance = distance
            bestKeysize.append(keysize)

    # reverse list so shortest distance keylength has i=0
    return bestKeysize[::-1]
