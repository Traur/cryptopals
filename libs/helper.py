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
	
	
def bytes2base64(byarInput):
	### Insert from my code
	return base64.b64encode(byarInput)
	
def hex2base64(hexstring):
	return bytes2base64(hex2bytes(hexstring))
	
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