from libs.utils import hexdump
from libs.analysis import encryptionOracle, detectECB

def detectionOracle(plaintext):
    """
    Oracle to detect wheather the encryptionOracle uses ECB or CBC
    """    

    ciphertext, i = encryptionOracle(plaintext) 
    
    if detectECB(ciphertext) > 0:
        return "ECB"
    else:
        return "CBC"

for i in range(17):
   plaintext = bytearray(b'WHEN THE MOON SHINES RED')*5
   print(detectionOracle(plaintext))
