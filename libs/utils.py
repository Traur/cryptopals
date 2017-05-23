def bytes2hex(byarInput):
	# This is to preventing myself from using strings, so I work directly on bytes
	assert type(byarInput) == bytearray or type(byarInput) == bytes or type(byarInput) == int
	
	# To enable single byte input
	if(type(byarInput) == int):
		byarInput = bytearray([byarInput])
	
	hex = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
	result = list()

	for b in byarInput:
		result.append(hex[(b >> 4) & 0b00001111])
		result.append(hex[b & 0b00001111])

	assert "".join(result) == byarInput.hex(), "{0} ?===? {1}".format(result, byarInput.hex())
	return "".join(result)

def hex2bytes(hexstring):
	dict = {'0': 0x0, '1': 0x1, '2': 0x2, '3': 0x3, '4': 0x4, '5': 0x5, '6': 0x6, '7': 0x7, 
			'8': 0x8, '9': 0x9, 'a': 0xa, 'b': 0xb, 'c': 0xc, 'd': 0xd, 'e': 0xe, 'f': 0xf}
			
	result = bytearray()

	for i in range(0, len(hexstring), 2):
		hex = hexstring[i:i+2]
		
		if len(hex) == 1:
			hex = "0" + hex
		
		a = dict[hex[0]] << 4
		b = dict[hex[1]]
		result.append(a | b)
	
	assert result == bytearray.fromhex(hexstring), "{0} == {1}".format()
	return result;
	
def hex2base64(hex):
    return bytes2base64(hex2bytes(hex))
	
def bytes2base64(bytes):
	base64Dict2 = {
		0x0: "A",  0x10: "Q",  0x20: "g",  0x30: "w",
		0x1: "B",  0x11: "R",  0x21: "h",  0x31: "x",
		0x2: "C",  0x12: "S",  0x22: "i",  0x32: "y",
		0x3: "D",  0x13: "T",  0x23: "j",  0x33: "z",
		0x4: "E",  0x14: "U",  0x24: "k",  0x34: "0",
		0x5: "F",  0x15: "V",  0x25: "l",  0x35: "1",
		0x6: "G",  0x16: "W",  0x26: "m",  0x36: "2",
		0x7: "H",  0x17: "X",  0x27: "n",  0x37: "3",
		0x8: "I",  0x18: "Y",  0x28: "o",  0x38: "4",
		0x9: "J",  0x19: "Z",  0x29: "p",  0x39: "5",
		0xA: "K",  0x1A: "a",  0x2A: "q",  0x3A: "6",
		0xB: "L",  0x1B: "b",  0x2B: "r",  0x3B: "7",
		0xC: "M",  0x1C: "c",  0x2C: "s",  0x3C: "8",
		0xD: "N",  0x1D: "d",  0x2D: "t",  0x3D: "9",
		0xE: "O",  0x1E: "e",  0x2E: "u",  0x3E: "+",
		0xF: "P",  0x1F: "f",  0x2F: "v",  0x3F: "/"
		}

	result = list()
	for i in range(0, len(bytes), 3):
		threeBytes = (bytes[i] << 16) | (bytes[i+1] << 8) | (bytes[i+2])
		result.append(base64Dict2[(threeBytes >> 18) & 0b00111111]) 
		result.append(base64Dict2[(threeBytes >> 12) & 0b00111111]) 
		result.append(base64Dict2[(threeBytes >> 6) & 0b00111111]) 
		result.append(base64Dict2[(threeBytes) & 0b00111111]) 

	return result
	
def hexdump(pBytes, width=16):
	for i in range(0, len(pBytes), width):
		# Print Counter
		line = "{:06d}\t".format(i)
		
		# Print 16bytes as hex
		for j in range(width):
			try:
				h = bytes2hex(pBytes[i+j])
			except IndexError:
				h = "00"
				
			line += h + " "

		line += " | "
		# Print 16bytes as ascii
		for j in range(width):
			try:
				b = pBytes[i+j]
				if 32 < b < 127:
					ascii = chr(b)
				else:
					ascii = "."
			except IndexError:
				ascii = "."
			line += ascii
		
		print(line)
	print("")

def partitionList(mylist, buckets):
	result = list()
	for i in range(0, len(mylist), buckets):
		result.append(mylist[i:i+buckets])
	return result
	

	
	
if __name__ == "__main__":
	print(1==1)
