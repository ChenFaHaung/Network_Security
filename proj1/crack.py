#!/usr/bin/env python2

from pwn import *
from Crypto.PublicKey import RSA
import base64
import binascii
import gmpy

conn = remote('140.113.194.66', 8888)

# Get public key
def getpubkey():
    with open('./pub.pem','rb') as f:
        pub = f.read()
        key = RSA.importKey(pub)
    return key

n = getpubkey().n
e = getpubkey().e

c_file = open('./flag.enc', 'r') # open file
c_byte_string = base64.b64decode(c_file.read()) # decode to get byte string
c = int(c_byte_string.encode('hex'), 16) # transfer byte string into integer

x = 2
y = (c * (x ** e)) % n

y_byte_string = binascii.unhexlify(hex(y)[2:]) # transfer integer into byte string
y_encoded = base64.b64encode(y_byte_string) # encode byte string with base64

conn.sendline(y_encoded)
conn.recvline()
z_encoded = conn.recvline()[:-1] # receive the result without \n
conn.close()

z_byte_string = base64.b64decode(z_encoded) # decode to get byte string
z = int(z_byte_string.encode('hex'), 16) # transfer byte string into integer

p = (gmpy.invert(x, n) * z) % n # find modular inverse of x mod n, then get p
p_byte_string = binascii.unhexlify(hex(p)[2:])

print (p_byte_string)
