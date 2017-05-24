def bytes2hex(byarInput):
    # This is to preventing myself from using strings, so I work directly on
    # bytes
    assert type(byarInput) == bytearray or type(
        byarInput) == bytes or type(byarInput) == int

    # To enable single byte input
    if(type(byarInput) == int):
        byarInput = bytearray([byarInput])

    hex = ['0', '1', '2', '3', '4', '5', '6', '7',
           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    result = list()

    for b in byarInput:
        result.append(hex[(b >> 4) & 0b00001111])
        result.append(hex[b & 0b00001111])

    assert "".join(result) == byarInput.hex(
    ), "{0} ?===? {1}".format(result, byarInput.hex())
    return "".join(result)


def hex2bytes(hexstring):
    dict = {'0': 0x0, '1': 0x1, '2': 0x2, '3': 0x3, '4': 0x4, '5': 0x5, '6': 0x6, '7': 0x7,
            '8': 0x8, '9': 0x9, 'a': 0xa, 'b': 0xb, 'c': 0xc, 'd': 0xd, 'e': 0xe, 'f': 0xf}

    result = bytearray()

    for i in range(0, len(hexstring), 2):
        hex = hexstring[i:i + 2]

        if len(hex) == 1:
            hex = "0" + hex

        a = dict[hex[0]] << 4
        b = dict[hex[1]]
        result.append(a | b)

    assert result == bytearray.fromhex(hexstring), "{0} == {1}".format()
    return result


def bytes2ascii(bytes, replaceChar="."):
    result = list()
    for i in range(len(bytes)):
        if 32 < bytes[i] < 127:
            result.append(chr(bytes[i]))
        else:
            result.append(replaceChar)
    return "".join(result)


def hex2base64(hex):
    return bytes2base64(hex2bytes(hex))


def bytes2base64(bytes):
    strMap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = list()
    for i in range(0, len(bytes), 3):
        threeBytes = (bytes[i] << 16) | (bytes[i + 1] << 8) | (bytes[i + 2])
        result.append(strMap[(threeBytes >> 18) & 0b00111111])
        result.append(strMap[(threeBytes >> 12) & 0b00111111])
        result.append(strMap[(threeBytes >> 6) & 0b00111111])
        result.append(strMap[(threeBytes) & 0b00111111])

    return result


def hexdump(pBytes, title="", width=16):
    p = partitionList(pBytes, width)
    line = list()

    if(title != ""):
        print("{0}:".format(title))

    for i in range(len(p)):
        tmp = "{:05d}\t".format(i)

        element = p[i]
        dif = len(element) % width
        if dif > 0:
            [element.append(0x0) for k in range(width - dif)]
        tmp += bytes2hex(element)
        tmp += "\t| "
        tmp += bytes2ascii(element)
        line.append(tmp)
        print(line[i])

    print("")


def partitionList(mylist, buckets):
    result = list()
    for i in range(0, len(mylist), buckets):
        result.append(mylist[i:i + buckets])
    return result


def RotWordLeft(word, n=1):
    n = n % len(word)
    return word[n:]+word[:n] 


if __name__ == "__main__":
    from random import randint
    a = bytearray([randint(0, 255) for i in range(2000)])
    hexdump2(a, width=32)
    a = bytearray(55)
    hexdump2(a, width=32, title="Just 55x 0x0 bytes!")
