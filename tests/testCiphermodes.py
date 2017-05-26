
from libs.crypto.blockciphermodes import AES128Encrypt_CBC, AES128Decrypt_CBC, add7Padding
from libs.utils import hexdump


def testCBC():
    # http://www.sabaton.net/discography/union-slopes-st-benedict-lyrics/
    input = "Mile after mile our march carries on\nNo army may stop our approach\nFight side by side\nMany nations unite    \nAt the shadow of Monte Cassino\nWe fight and die together\nAs we head for the valley of death\nDestiny calls\nWe'l    l not surrender or fail\nTo arms!\nUnder one banner\nAs a unit we stand and united we fall\nAs one! Fighting togethe    r\nBringing the end to the slaughter\nWinds are changing\nhead on north"
    input = bytearray(input, "utf-8")
    input = add7Padding(input, 16)
    key = bytearray("SABATON IS BEST!", "utf-8")
    iv = bytearray([0x0]*16)
    ciphertext = AES128Encrypt_CBC(input, key, iv)
    plaintext = AES128Decrypt_CBC(ciphertext, key, iv)
    
    assert plaintext == input, "Failed testCBC()"
    print("Passed testCBC()")

def testPadding():
    input = bytearray(b'THEY ARE THE PANZER ELITE, BORN TO COMPETE, NEVER RETREAT! GHOST DIVISON')
    assert input + bytearray([0x8]*8) == add7Padding(input, 16), "Failed testPadding()"

    print("Passed testPadding()")


def main():
    testCBC()
    testPadding()
main()
