# coding: utf-8
from idaapi import *
import zlib
import itertools
import string
import struct

class Bruteforce(object):
    def __init__(self, charset, min_lenght, max_lenght):
        self.charset = charset
        self.min_lenght = min_lenght
        self.max_lenght = max_lenght

    def set_charset(self, charset):
        self.charset = charset

    def set_min_lenght(self, min_lenght):
        self.min_lenght = min_lenght

    def set_max_lenght(self, max_lenght):
        self.max_lenght = max_lenght

    def __iter__(self):
        for i in range(self.min_lenght, self.max_lenght + 1):
            for candidate in itertools.product(self.charset, repeat=i):
                yield ''.join(candidate)

class DbgHook(DBG_Hooks):
    def __hooker__(self, ea):
        currentAddress = ea

        if currentAddress == 0x403B23:
            put_bytes(GetRegValue('rax'), 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2\n')
            rv = ida_idd.regval_t()
            rv.ival = 0x403B37
            set_reg_val('rip', rv)
        elif currentAddress == 0x402E8A:
            getSize()
        elif currentAddress == 0x402F06:
            patchCheck()

        idaapi.continue_process()       

    def dbg_bpt(self, tid, ea):
        self.__hooker__(ea)
        return 0

def findFibonacci(n):
	a, b = 0, 1
	i = 0

	while ( b != n ):
		a, b = b, (a+b) & 0xffffffffffffffff
		i += 1
		
	return i

def findCRC32(p, lenght):
    if lenght == 1:
        return crc1[p]
    elif lenght == 2:
        return crc2[p]
    else:
        return crc3[p]
    
def decryptRC4(ciphertext):
    data = ciphertext
    key = 'Tis but a scratch.'

    S = range(256)
    j = 0
    out = []

    # KSA Phase
    for i in range(256):
        j = (j + S[i] + ord( key[i % len(key)] )) % 256
        S[i] , S[j] = S[j] , S[i]

    # PRGA Phase
    i = j = 0
    for char in data:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out)

def decodeBase64(base64):
    charset = ''.join(chr(c) for c in [ 0x2A, 0x39, 0x5F, 0x64, 0xC2, 0xA7, 0x46, 0x23, 0x53, 0x6B, 0x74, 0x47, 0x28, 0x4D, 0x70, 0x42,
                                        0x49, 0x25, 0x52, 0x6A, 0x62, 0x38, 0x40, 0x4A, 0x69, 0x45, 0x44, 0x59, 0x2D, 0x31, 0x24, 0x50,
                                        0x67, 0x79, 0x54, 0x21, 0x4C, 0x76, 0x71, 0x66, 0x2B, 0x63, 0x68, 0x6D, 0x51, 0x57, 0x4F, 0x30,
                                        0x65, 0x4E, 0x5A, 0x34, 0x75, 0x6E, 0x33, 0x6C, 0x37, 0x48, 0x26, 0x32, 0x77, 0x61, 0x7A, 0x4B ])

    dic = dict(zip(charset, range(len(charset))))

    ns = []

    for c in base64:
        if c == '=':
            break
        try:
            ns.append(dic[c])
        except:
            pass
        pass

    data = ''
    rem = len(ns) % 4
    # Invalid when rem is 3. But run as if the last chunk does not exist
    if rem > 0: ns += [0] * (4 - rem)
    for i in range(0, len(ns), 4):
        b3 = (ns[i] << 18) | (ns[i + 1] << 12) | (ns[i + 2] << 6) | ns[i + 3]
        data += chr(b3 >> 16) + chr((b3 >> 8) & 0xff) + chr(b3 & 0xff)
        pass

    return data[:-rem] if rem > 0 else data

def decodeRot13(rot13):
    return ''.join(chr(ord(c) - 13) for c in rot13)

def decodeXOR(xor):
    return ''.join(chr(ord(c) ^ 0x2a) for c in xor)

def fibonacci(rdx, rsi, rdi):
    print '[!] Hooked fibonacci'
    print '[*] Extracting checks'

    data = []
    for i in range(0, 8 * rsi, 8):
        data.append(struct.unpack('<Q', get_many_bytes(rdx+i, 8))[0])

    if len(data) == 0:
        print '[-] Something went wrong while trying to extract checks from {:#x}'.format(rdx)
        return False

    print '[+] Checks extracted successfully'
    print '[*] Finding solutions'

    res = []
    for i in data:
        res.append(findFibonacci(i))

    if len(res) != len(data):
        print '[-] Something went wrong while finding solutions for {:#x}'.format(rdx)
        return False

    print '[+] Solutions found successfully: {}'.format(''.join(chr(c) for c in res))
    print '[*] Patching bytes'

    for i in range(rsi):
        put_byte(rdi+i, res[i])

    return True

def crc32(rdx, rsi, rdi):
    print '[!] Hooked crc32'
    print '[*] Extracting checks'

    data = struct.unpack('<L', get_many_bytes(rdx, 4))[0]

    if data == 0:
        print '[-] Something went wrong while trying to extract checks from {:#x}'.format(rdx)
        return False

    print '[+] Checks extracted successfully'
    print '[*] Finding solutions'

    res = findCRC32(data, rsi)

    if len(res) != rsi:
        print '[-] Something went wrong while finding solutions for {:#x}'.format(rdx)
        return False

    print '[+] Solutions found successfully: ' + str(res)
    print '[*] Patching bytes'

    for i in range(rsi):
        put_byte(rdi+i, ord(res[i]))

    return True

def rc4(rdx, rsi, rdi):
    print '[!] Hooked rc4'
    print '[*] Extracting data'

    data = get_many_bytes(rdx, rsi)

    if len(data) != rsi:
        print '[-] Something went wrong while trying to extract data from {:#x}'.format(rdx)
        return False

    print '[+] Data extracted successfully'
    print '[*] Decrypting ciphertext'

    res = decryptRC4(data)
    
    if len(res) != len(data):
        print '[-] Something went wrong while decrypting ciphertext from {:#x}'.format(rdx)
        return False

    print '[*] Ciphertext decrypted successfully: {}'.format(res)
    print '[*] Patching bytes'

    for i in range(rsi):
        put_byte(rdi+i, ord(res[i]))

    return True

def base64(rdx, rsi, rdi):
    print '[!] Hooked base64'
    print '[*] Extracting data'

    data = get_many_bytes(rdx, rsi+1)

    if len(data) != rsi+1:
        print '[-] Something went wrong while trying to extract data from {:#x}'.format(rdx)
        return False

    print '[+] Data extracted successfully'
    print '[*] Decoding data'

    res = decodeBase64(data)

    if len(res)+1 != len(data):
        print '[-] Something went wrong while decoding data from {:#x}'.format(rdx)
        return False

    print '[*] Data decoded successfully: {}'.format(res)
    print '[*] Patching bytes'

    for i in range(rsi):
        put_byte(rdi+i, ord(res[i]))
    
    return True

def rot13(rdx, rsi, rdi):
    print '[!] Hooked rot13'
    print '[*] Extracting data'

    data = get_many_bytes(rdx, rsi)

    if len(data) != rsi:
        print '[-] Something went wrong while trying to extract data from {:#x}'.format(rdx)
        return False

    print '[+] Data extracted successfully'
    print '[*] Decoding data'

    res = decodeRot13(data)

    if len(res) != len(data):
        print '[-] Something went wrong while decoding data from {:#x}'.format(rdx)
        return False

    print '[*] Data decoded successfully: {}'.format(res)
    print '[*] Patching bytes'

    for i in range(rsi):
        put_byte(rdi+i, ord(res[i]))
    
    return True

def compare(rdx, rsi, rdi):
    print '[!] Hooked compare'
    print '[*] Extracting data'

    data = get_many_bytes(rdx, rsi)
    
    if len(data) != rsi:
        print '[-] Something went wrong while trying to extract data from {:#x}'.format(rdx)
        return False

    print '[*] Data extracted successfully: {}'.format(data)
    print '[*] Patching bytes'

    for i in range(rsi):
        put_byte(rdi+i, ord(data[i]))
    
    return True

def xor(rdx, rsi, rdi):
    print '[!] Hooked xor'
    print '[*] Extracting data'

    data = get_many_bytes(rdx, rsi)

    if len(data) != rsi:
        print '[-] Something went wrong while trying to extract data from {:#x}'.format(rdx)
        return False

    print '[+] Data extracted successfully'
    print '[*] Decrypting ciphertext'

    res = decodeXOR(data)

    if len(res) != len(data):
        print '[-] Something went wrong while decoding data from {:#x}'.format(rdx)
        return False

    print '[*] Data decrypted successfully: {}'.format(res)
    print '[*] Patching bytes'

    for i in range(rsi):
        put_byte(rdi+i, ord(res[i]))

    return True


functions = {
                327: fibonacci,
                179: crc32,
                143: rot13,
                124: compare,
                132: xor,
                766: rc4,
                806: base64
}

def patchCheck():
    rdx, rsi, rdi = map(GetRegValue, ['rdx', 'rsi', 'rdi'])
    functions[func_size](rdx, rsi, rdi)

def getSize():
    global func_size
    func_size = GetRegValue('rsi')

print '[*] Initializing data structures' 

crc1 = {}
crc2 = {}
crc3 = {}

for i in Bruteforce(string.printable, 1, 1):
    crc1[zlib.crc32(i) & 0xffffffff] = i

for i in Bruteforce(string.printable, 1, 2):
    crc2[zlib.crc32(i) & 0xffffffff] = i

for i in Bruteforce(string.printable, 1, 3):
    crc3[zlib.crc32(i) & 0xffffffff] = i

try:
    if debugHook:
        print '[!] Removing previous hook'
        debugHook.unhook()
except:
    pass

debugHook = DbgHook()
debugHook.hook()
print '[*] Debug hook launched'