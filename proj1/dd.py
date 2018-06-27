'''
Network Security Lab 1
Chosen Cypher Attack 

0656511 willy
2018.3.23.
'''
#!/usr/bin/env python2

from pwn import *
from Crypto.PublicKey import RSA
import gmpy
import base64
import binascii

# connect to the server
connection = remote('140.113.194.66', 8888)

# find the public key with the function we know
def GetPublicKey():
    with open('./pub.pem', 'rb') as File:
        public_key = File.read()
	key = RSA.importKey(public_key)
    return key

# generate the (n, e)
n = GetPublicKey().n
e = GetPublicKey().e

# n = ......60859
# print n
# x be even will relative prime to n
X = 10 

# open the origin flag file
in_file = open('./flag.enc', 'r')
in_f = in_file.read()

# decode the base64 to byte string with the function
in_f_byte = base64.b64decode(in_f)

# transfer to the int!!!! ascii to hex
C = int(in_f_byte.encode('hex'), 16)

# Y = C*X^e mod n
Y = (C*(X ** e)) % n

# encrypted Y exclude 0x
Y = hex(Y)[2:]

# hex to byte string
Y_byte = binascii.unhexlify(Y)

# encode to base64
Y_encode = base64.b64encode(Y_byte)

# send the input to server
connection.sendline(Y_encode)
# receive the first line of server
connection.recvline()
# receive the output
Z_tmp = connection.recvline()[:-1]
connection.close()

# decode to byte string
Z_byte = base64.b64decode(Z_tmp)
# transfer to int 
Z = int(Z_byte.encode('hex'), 16)

# P = Z*X^{-1} mod n
P = (Z*(gmpy.invert(X, n))) % n

# to byte string!!! no 0x
P_byte = binascii.unhexlify(hex(P)[2:])

print P_byte


