"""
Example implementation of the AES Algorithm standardized bye
http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

DO NOT USE THIS STUFF FOR ANYTHING but learning!
"""

from libs.crypto.xor import fixedXOR
from libs.utils import RotWordLeft, hexdump, partitionList, bytes2hex
from libs.math import gMul

import logging
logging.basicConfig(level=logging.WARN)
log = logging.getLogger(__name__)
# SBoxes should only be generated once
# and not every time SubBytes or InvSubBytes gets called
ForwardSBox = None
InverseSBox = None


def initializeSubstitutionBoxes():
    FSBOX = bytearray(256)
    ISBOX = bytearray(256)
    # Calculate the elements inverse to each other
    # from GF(2**8), so that element * inverse[element] == 1
    inverse = bytearray(256)
    for i in range(256):
        for j in range(256):
            tmp = gMul(i, j)
            if tmp == 0x1:
                inverse[i] = j
    # Perform Affine Transformation
    # b_i = b_i ^ b_i + 4%8 ^ b_i+5%8 ^ b_i+6%8 ^ b_i+7%8 ^0x63
    c = 0x63
    for enum in range(256):
        # Substitute each byte
        b = inverse[enum]
        B = 0
        # Reverse Order
        for i in [7, 6, 5, 4, 3, 2, 1, 0]:
            bi = (b >> i) & 0x1
            bi ^= (b >> ((i + 4) % 8)) & 0x1
            bi ^= (b >> ((i + 5) % 8)) & 0x1
            bi ^= (b >> ((i + 6) % 8)) & 0x1
            bi ^= (b >> ((i + 7) % 8)) & 0x1
            bi ^= (c >> i) & 0x1
            B = (B << 1) | bi
        FSBOX[enum] = B
        ISBOX[B] = enum

    return FSBOX, ISBOX


def SubBytes(s):
    global ForwardSBox, InverseSBox
    state = s[:]
    if ForwardSBox == None:
        ForwardSBox, InverseSBox = initializeSubstitutionBoxes()

    for i in range(len(s)):
        state[i] = ForwardSBox[s[i]]
    return state


def InvSubBytes(s):
    global ForwardSBox, InverseSBox
    state = s[:]
    if InverseSBox == None:
        ForwardSBox, InverseSBox = initializeSubstitutionBoxes()

    for i in range(len(s)):
        state[i] = InverseSBox[s[i]]
    return state


def ShiftRows(s):
    state = s[:]

    def shift(r, Nb): return r % 4

    def map(r, c): return r + (4 * (c + shift(r, 4))) % 16

    for r in range(4):
        for c in range(4):
            state[r + 4 * c] = s[map(r, c)]
    return state


def InvShiftRows(s):
    state = s[:]

    def shift(r, Nb): return r % 4

    def map(r, c): return r + (4 * (c + shift(r, 4))) % 16

    for r in range(4):
        for c in range(4):
            state[map(r, c)] = s[r + 4 * c]

    return state


def MixColumns(s):
    m = [0x02, 0x03, 0x01, 0x1]
    state = s[:]
    for c in range(4):
        for r in range(4):
            offset = 4 * c
            result = 0
            for i in range(4):
                result ^= gMul(m[i], s[i + offset])
            state[r + offset] = result
            m = RotWordLeft(m, 3)
    return state


def InvMixColumns(s):
    m = [0x0e, 0x0b, 0x0d, 0x09]
    state = s[:]
    for c in range(4):
        for r in range(4):
            offset = 4 * c
            result = 0
            for i in range(4):
                result ^= gMul(m[i], s[i + offset])
            state[r + offset] = result
            m = RotWordLeft(m, 3)
    return state


def word2bytes(word):
    result = bytearray(4)
    for i in range(4):
        result[i] = (word >> i * 8) & 0xff
    return result[::-1]


def bytes2word(bytes):
    result = 0x0
    bytes = bytes[::-1]
    for i, n in enumerate(bytes):
        result |= (n << i * 8)
    return result


def KeyExpansion(key):
    Nk = 4  # (number of words in Key)
    Nb = 4  # (Number of Bytes in Word)
    Nr = 10  # (12 or 14 -> Number of Rounds)

    necessaryWords = Nb * (Nr + 1)
    w = [0] * necessaryWords

    # Step 1: Copy key as 4Byte-Words into List()
    p = partitionList(key, 4)
    for i, l in enumerate(p):
        w[i] = bytes2word(l)

    Rcon = list(
        [0xCAFEBABE,  # Rcon starts with i=1
         0x01000000,
         0x02000000,
         0x04000000,
         0x08000000,
         0x10000000,
         0x20000000,
         0x40000000,
         0x80000000,
         0x1b000000,
         0x36000000])

    for i in range(Nk, necessaryWords):
        # Take the previous word
        temp = w[i - 1]
        if i % Nk == 0:
            afterRotWord = bytes2word(RotWordLeft(word2bytes(temp)))
            afterSubBytes = bytes2word(SubBytes(word2bytes(afterRotWord)))
            afterRcon = afterSubBytes ^ Rcon[i // Nk]
            temp = afterRcon

        elif Nk > 6 and i % Nk == 4:
            temp = bytes2word(SubBytes(word2byte(temp)))
        w[i] = w[i - Nk] ^ temp

    return w


def AddRoundKey(s, w_l):
    """
    XORs each row with every other row in w_l
    """
    return fixedXOR(s, w_l)


def getRoundKeys(keys):
    result = bytearray(4 * 4)

    for i, k in enumerate(keys):
        bytes = word2bytes(k)
        for j, b in enumerate(bytes):
            result[i * 4 + j] = b

    return result


def AES128Encrypt(input, key):
    """
    Encrypts the input with the key using the
    AES Cipher.
    """
    Nb = 4
    Nk = 4
    Nr = 10

    w = KeyExpansion(key)
    log.info("round[{0:1d}].input\t{1}".format(0, bytes2hex(input)))
    log.info("round[{0:1d}].k_sch\t{1}".format(0, bytes2hex(key)))

    state = input[:]
    state = AddRoundKey(state, getRoundKeys(w[0:Nb]))

    for round in range(1, Nr):
        log.info("round[{0:1d}].start\t{1}".format(round, bytes2hex(state)))
        state = SubBytes(state)
        log.info("round[{0:1d}].s_box\t{1}".format(round, bytes2hex(state)))
        state = ShiftRows(state)
        log.info("round[{0:1d}].s_row\t{1}".format(round, bytes2hex(state)))
        state = MixColumns(state)
        log.info("round[{0:1d}].m_col\t{1}".format(round, bytes2hex(state)))
        roundKey = getRoundKeys(w[round * Nb: (round + 1) * Nb])
        log.info("round[{0:1d}].k_sch\t{1}".format(round, bytes2hex(roundKey)))
        state = AddRoundKey(state, roundKey)

    log.info("round[{0:1d}].start\t{1}".format(10, bytes2hex(state)))
    state = SubBytes(state)
    log.info("round[{0:1d}].s_box\t{1}".format(10, bytes2hex(state)))
    state = ShiftRows(state)
    log.info("round[{0:1d}].s_row\t{1}".format(10, bytes2hex(state)))
    roundKey = getRoundKeys(w[Nr * Nb: (Nr + 1) * Nb])
    log.info("round[{0:1d}].k_sch\t{1}".format(10, bytes2hex(roundKey)))
    state = AddRoundKey(state, roundKey)
    log.info("round[{0:1d}].out  \t{1}".format(10, bytes2hex(state)))

    return state


def AES128Decrypt(input, key):
    """
    Encrypts the input with the key using the
    AES Cipher.
    """
    Nb = 4
    Nk = 4
    Nr = 10

    w = KeyExpansion(key)
    roundKey = getRoundKeys(w[Nr * Nb: (Nr + 1) * Nb])
    log.info("round[{0:1d}].iinput\t{1}".format(0, bytes2hex(input)))
    log.info("round[{0:1d}].ik_sch\t{1}".format(0, bytes2hex(roundKey)))

    state = input[:]
    state = AddRoundKey(state, roundKey)

    for round in range(Nr, 1, -1):
        log.info("round[{0:1d}].istart\t{1}".format(round, bytes2hex(state)))

        state = InvShiftRows(state)
        log.info("round[{0:1d}].is_row\t{1}".format(round, bytes2hex(state)))

        state = InvSubBytes(state)
        log.info("round[{0:1d}].is_box\t{1}".format(round, bytes2hex(state)))

        roundKey = getRoundKeys(w[(round - 1) * Nb: round * Nb])
        log.info(
            "round[{0:1d}].ik_sch\t{1}".format(round, bytes2hex(roundKey)))

        state = AddRoundKey(state, roundKey)
        log.info("round[{0:1d}].ik_add\t{1}".format(round, bytes2hex(state)))

        state = InvMixColumns(state)

    log.info("round[{0:1d}].start\t{1}".format(10, bytes2hex(state)))

    state = InvShiftRows(state)
    log.info("round[{0:1d}].is_row\t{1}".format(10, bytes2hex(state)))

    state = InvSubBytes(state)
    log.info("round[{0:1d}].is_box\t{1}".format(10, bytes2hex(state)))

    roundKey = getRoundKeys(w[0:Nb])
    log.info("round[{0:1d}].ik_sch\t{1}".format(10, bytes2hex(roundKey)))

    state = AddRoundKey(state, roundKey)
    log.info("round[{0:1d}].iout  \t{1}".format(10, bytes2hex(state)))

    return state


def AES128Encrypt_ECB(input, key):
    plaintexts = partitionList(input, 16)
    ciphertext = bytearray()

    for block in plaintexts:
        c = AES128Encrypt(block, key)
        ciphertexts += c

    return ciphertexts


def AES128Decrypt_ECB(input, key):
    ciphertexts = partitionList(input, 16)
    plaintexts = bytearray()

    for block in ciphertexts:
        c = AES128Decrypt(block, key)
        plaintexts += c

    return plaintexts


def detectECB(ciphertext):
    p = partitionList(ciphertext, 16)
    score = 0
    for i in range(len(p)):
        for k in range(len(p)):
            if i != k and p[i] == p[k]:
                score += 1

    return score
