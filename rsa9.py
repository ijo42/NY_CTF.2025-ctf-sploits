#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host ctf.mf.grsu.by --port 9040
from pwn import *

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'ctf.mf.grsu.by'
port = int(args.PORT or 9019)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
#

# Все что вам надо - расшифровать секрет, зашифрованный с помощью алгоритам RSA (Ривест-Шамир-Адлеман). И так раз 50 ... И время на ответ - не больше 5 секунд ...
#
# Как известно, стойкость алгоритма RSA определяется сложностью разложения больших чисел на простые множители.
# Но мы рассмотрим "совсем детский вариант" - вам даны модуль и обе экспоненты.
#
# Раунд 1/60
#
# e: 0x10001
# d: 0x401cc27fb2938bf3ad73b369d03fce8b0171d02019d259a026b027be0884564a2a80027d4ac5b014823751b1478ecd28f98a67dbeb6e62d5db693bfe8267a5fff5d3b2d8452ba095f42c11fecdfb16826e80e70833cd9f68255428cb52fec54858cb897088ba3067c785157f81ee6c9864db098361142a1c4e20262f079863627c6531a3c186caf2ecfa712d55d045029164a39236d2c2972c1a77166e31dbc005862698af1b35df1744705ed1a89e857ff47ff6da46d43f70f5fbe01a6814d47ea08d16be0970dc91869ba23820a34d2afe429cffdfe5a1d695f419533ea02c3b70154e476f6c6ea8038b725be9312645bf0108070a9e088fc45c377476a2fb
# n: 0xe746fe15401c630caaa2697e422e37433c49448449561fc11a0d3cd3ae1b966fc48286930083983c660b987ec7f7c7ea0e52690dbffd0b6c9c5056cc2be8fb190b6349cd3ae0d1ec5a8583f7e94fd36feb313148fb860b657cc61f5fa3ee1bb46a9c91c998bc8e09adf5af8182a16bc2546231243ac0e1b08b2b89eee785c9a4679990159dacc4d58046be8d0e01872d89fb1aea2509c8da79a805abf23500404a9b85693e7a9239fdcbea94d7740915fe0ed326c44b08cb57ee87a5772f9e467c554a6ec0957ef908acbf2b952a9d1161c92d84491228a8b8012dbf29293d547196f3094130b9f930332573be6a39bf29f08f12e7dbf29579794e3ab6adae65
# secret ciphertext (b64): OeFywrUlDt7VYw81LQwv8bXvuOszOjZbNFKpjiEJ/LF5Jub0htxtuPy0/BvgWGqGgdaZtJChQZPAk10KqL7M12sge5sprnkrZh+vqdfAVRqO7bBxrHN/gn93vGR/ElCT2/h6iYgrzN+vGo0V4kuSM0lEyCkRAPwUqFAT2LReuge2464PbOcUymnN3NszQeLCRAUkqIo3xV/JRcys4Xxo3OkARAgQ9UMBEMWvvcs8iNTm2I9W+4lTfIAEiHXpXj1pe+pe//yRLEhnJdS10ajSMgnJUJhF/bxAA/8TnlR3Wbd8fGauW9UMiZlnYzpGE4R2osNttwFDXQCWN9hf/mKkoQ==
#
# Plaintext is (b64):
import struct

import re

def truncate_string(s):
    # Ищем первое слово в строке
    match = re.search(r'^[\w_]+', s)
    if match:
        # Возвращаем первое слово
        return match.group()
    else:
        # Если строка пустая или не содержит слов, возвращаем пустую строку
        return ''

def decrypt_rsa(e, d, n, secret):
    # Decode the secret from base64
    secret_bytes = base64.b64decode(secret)
    
    # Convert the secret bytes to an integer
    secret_int = int.from_bytes(secret_bytes, byteorder='little')
    
    # Use the decryption formula
    decrypted_text = pow(secret_int, d, n)

    # Return the decrypted text as a string
    return base64.b64encode(truncate_string(decrypted_text.to_bytes((secret_int.bit_length() + 7) // 8, byteorder='little').decode()).encode())

io = start()

io.recvuntil(b"1/")
c = int(io.recvline().strip())
for i in range(c):
    print(io.recvuntil(b"e: ").decode())
    e = int(io.recvline().decode().strip(), 16) # possibly 0x10001
    d = int(io.recvline().decode()[2:].strip(), 16)
    n = int(io.recvline().decode()[2:].strip(), 16)
    io.recvuntil(b"(b64): ")
    secret = io.recvline().decode().strip()
    ans = decrypt_rsa(e,d,n,secret)
    io.sendline(ans)
print(io.recvall())

