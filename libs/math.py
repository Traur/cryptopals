

def gMul(a, b):
    """
    Performs multiplication in GF(2**8)
    """
    p = 0x0
    for i in range(8):
        p ^= -(b & 1) & a
        m = -((a >> 7) & 0x1)
        a = (a << 1) ^ (0b100011011 & m)
        b >>= 1

    return p
