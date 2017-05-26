from libs.crypto.blockciphermodes import PKCS7Padding

input = bytearray("YELLOW SUBMARINE", "utf-8")
output = bytearray("YELLOW SUBMARINE\x04\x04\x04\x04", "utf-8")
solution = PKCS7Padding(input, 20)
assert solution == output


print("Produced {0}".format(output))
print("Challenge 9 successful")
