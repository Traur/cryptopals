"""
Example implementation of the AES Algorithm standardized bye
http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

DO NOT USE THIS STUFF FOR ANYTHING but learning!
"""

from libs.crypto.xor import fixedXOR
from libs.utils import RotWordLeft, hexdump
from libs.math import gMul

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
        #Substitute each byte
        b = inverse[enum]
        B = 0
        # Reverse Order
        for i in [7, 6, 5, 4, 3, 2, 1, 0]:
            bi = (b >> i) & 0x1
            bi ^= (b >> ((i+4)%8)) & 0x1
            bi ^= (b >> ((i+5)%8)) & 0x1
            bi ^= (b >> ((i+6)%8)) & 0x1
            bi ^= (b >> ((i+7)%8)) & 0x1
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


def ShiftRows(s):
    state = s[:]
    def shift(r, Nb): return r % 4
    def map(r, c): return r + (4 * (c + shift(r, 4))) % 16

    for r in range(4):
        for c in range(4):
            state[r+4*c] = s[map(r,c)]
    return state

def MixColumns(s):
    m = [0x02, 0x03, 0x01, 0x1]
    state = s[:]
    for c in range(4):
        for r in range(4):
            offset = 4 * c
            result = 0
            for i in range(4):
               result ^= gMul(m[i], s[i+offset])
            state[r+offset] = result
            m = RotWordLeft(m, 3)
    return state

def KeyExpansion(key):
    w = key[:]
    Nk = 4 #(number of words in Key)
    Nb = 4 #(Number of Bytes in Word)
    Nr = 10 #(12 or 14 -> Number of Rounds)

    necessaryBytes = 4 * Nb * (Nr + 1)

    # Initialize Rcon
    Rcon = bytearray([0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])
    for i in range(Nk, necessaryBytes, 4):
        temp = w[i - 4:4 + (i - 4)]  # 4 Bytes
        hexdump(temp, title="temp in round={0}".format(i), width=4)
        if i % Nk == 0:
            # Transformation
            transformed = SubBytes(RotWordLeft(temp))
            temp = fixedXOR(transformed, Rcon[i // Nk: (i // Nk)+4])

        # Insert AES>128 here

        for k in range(4):
            w[i+k] = temp[k] ^ w[i-Nk+k]

    return w


def AddRoundKey(s, w_l):
    """
    XORs each row with every other row in w_l
    """
    for r in range(4):
        for c in range(4):
            s[r + 4 * c] = s[r + 4 * c] ^ w_l[r + 4 * c]

    return s


def AES128Encrypt(input, key):
    """
    Encrypts the input with the key using the
    AES Cipher. 
    """
    Nb = 4
    Nk = 4
    Nr = 10

    w = KeyExpansion(key)

    state = input[:]
    state = AddRoundKey(state, w[0:4])

    for round in range(1, Nr - 1):
        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, w[round * Nb: (round + 1) * Nb - 1])

    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, w[Nr * Nb: (Nr + 1) * Nb - 1])

    return state
