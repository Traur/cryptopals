from libs.crypto.aes import SubBytes, ShiftRows, MixColumns, KeyExpansion, AES128Encrypt, initializeSubstitutionBoxes
from libs.utils import hex2bytes


def testSBoxes():
    forward, inverse = initializeSubstitutionBoxes()
    realF = bytearray([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3,
                       0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16])
    realI = bytearray([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d])
    assert forward == realF, "Failed testSBoxes() with forwardSBox"
    assert inverse == realI, "Failed testSBoxes() with inverseSBox"


def testSubBytes():
    vector1 = hex2bytes("00102030405060708090a0b0c0d0e0f0")
    solution1 = hex2bytes("63cab7040953d051cd60e0e7ba70e18c")
    assert solution1 == SubBytes(vector1), "Failed testSubBytes() with v1"

    vector2 = hex2bytes("89d810e8855ace682d1843d8cb128fe4")
    solution2 = hex2bytes("a761ca9b97be8b45d8ad1a611fc97369")
    assert solution2 == SubBytes(vector2), "Failed testSubBytes() with v2"

    vector3 = hex2bytes("c81677bc9b7ac93b25027992b0261996")
    solution3 = hex2bytes("e847f56514dadde23f77b64fe7f7d490")
    assert solution3 == SubBytes(vector3), "Failed testSubBytes() with v3"

    print("Passed testSubBytes()")


def testShiftRows():
    vector1 = hex2bytes("a761ca9b97be8b45d8ad1a611fc97369")
    solution1 = hex2bytes("a7be1a6997ad739bd8c9ca451f618b61")
    assert solution1 == ShiftRows(vector1), "Failed testShiftRows() with v1"

    vector2 = hex2bytes("2dfb02343f6d12dd09337ec75b36e3f0")
    solution2 = hex2bytes("2d6d7ef03f33e334093602dd5bfb12c7")
    assert solution2 == ShiftRows(vector2), "Failed testShiftRows() with v2"

    vector3 = hex2bytes("5411f4b56bd9700e96a0902fa1bb9aa1")
    solution3 = hex2bytes("54d990a16ba09ab596bbf40ea111702f")
    assert solution3 == ShiftRows(vector3), "Failed testShiftRows() with v3"

    print("Passed testShiftRows()")


def testMixColumns():
    vector1 = hex2bytes("2d6d7ef03f33e334093602dd5bfb12c7")
    solution1 = hex2bytes("6385b79ffc538df997be478e7547d691")
    assert solution1 == MixColumns(vector1), "Failed testMixColumns() with v1"

    vector2 = hex2bytes("36339d50f9b539269f2c092dc4406d23")
    solution2 = hex2bytes("f4bcd45432e554d075f1d6c51dd03b3c")
    assert solution2 == MixColumns(vector2), "Failed testMixColumns() with v2"

    vector3 = hex2bytes("54d990a16ba09ab596bbf40ea111702f")
    solution3 = hex2bytes("e9f74eec023020f61bf2ccf2353c21c7")
    assert solution3 == MixColumns(vector3), "Failed testMixColumns() with v3"

    print("Passed testMixColumns()")


def testKeyExpansion():
    key = hex2bytes("2b7e151628aed2a6abf7158809cf4f3c")

    solution = hex2bytes("2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883ba8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6")

    assert solution == KeyExpansion(
        key), "Failed testKeyExpansion() with array comparison"


def testAES128Encrypt():
    input = hex2bytes("00112233445566778899aabbccddeeff")
    key = hex2bytes("000102030405060708090a0b0c0d0e0f")
    output = hex2bytes("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert output == AES128Encrypt(input, key), "Failed testAES128Encrypt()"

    print("Passed testAES128Encrypt()")


def main():
    testSBoxes()
    testSubBytes()
    testShiftRows()
    testMixColumns()
    testKeyExpansion()
    testAES128Encrypt()
    print("Passed all tests!", end="\n\n")


main()
