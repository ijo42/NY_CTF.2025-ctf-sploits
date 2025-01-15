from PIL import Image
from pyzbar.pyzbar import decode, ZBarSymbol
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
port = int(args.PORT or 9032)

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

import re

def code128B_checksum(data):
    # Таблица значений для Code 128B
    code128B_table = {
        ' ': 0, '!': 1, '"': 2, '#': 3, '$': 4, '%': 5, '&': 6, "'": 7,
        '(': 8, ')': 9, '*': 10, '+': 11, ',': 12, '-': 13, '.': 14, '/': 15,
        '0': 16, '1': 17, '2': 18, '3': 19, '4': 20, '5': 21, '6': 22, '7': 23,
        '8': 24, '9': 25, ':': 26, ';': 27, '<': 28, '=': 29, '>': 30, '?': 31,
        '@': 32, 'A': 33, 'B': 34, 'C': 35, 'D': 36, 'E': 37, 'F': 38, 'G': 39,
        'H': 40, 'I': 41, 'J': 42, 'K': 43, 'L': 44, 'M': 45, 'N': 46, 'O': 47,
        'P': 48, 'Q': 49, 'R': 50, 'S': 51, 'T': 52, 'U': 53, 'V': 54, 'W': 55,
        'X': 56, 'Y': 57, 'Z': 58, '[': 59, '\\': 60, ']': 61, '^': 62, '_': 63,
        '`': 64, 'a': 65, 'b': 66, 'c': 67, 'd': 68, 'e': 69, 'f': 70, 'g': 71,
        'h': 72, 'i': 73, 'j': 74, 'k': 75, 'l': 76, 'm': 77, 'n': 78, 'o': 79,
        'p': 80, 'q': 81, 'r': 82, 's': 83, 't': 84, 'u': 85, 'v': 86, 'w': 87,
        'x': 88, 'y': 89, 'z': 90, '{': 91, '|': 92, '}': 93, '~': 94, '\x7f': 100,
        '\x80': 101, '\x81': 102, '\x82': 103, '\x83': 104, '\x84': 105, '\x85': 106,
        '\x86': 107, '\x87': 108, '\x88': 109, '\x89': 110, '\x8a': 111, '\x8b': 112,
        '\x8c': 113, '\x8d': 114, '\x8e': 115, '\x8f': 116, '\x90': 117, '\x91': 118,
        '\x92': 119, '\x93': 120, '\x94': 121, '\x95': 122, '\x96': 123, '\x97': 124,
        '\x98': 125, '\x99': 126, '\x9a': 127
    }

    # Начальный символ для Code 128B
    start_code = 104

    # Сумма для контрольной суммы
    checksum = start_code

    # Позиция символа
    position = 1

    # Вычисляем сумму
    for char in data:
        checksum += code128B_table[char] * position
        position += 1

    checksum = checksum % 103

    return checksum + 1

from pyzbar.pyzbar import decode

io = start()

io.recvuntil(b"50")
for i in range(50):
    io.recvuntil(b"barcode (b64): ")
    b64code = io.recvline().strip()  # Strip any newline characters

    # Decode the base64 string
    image_data = base64.b64decode(b64code)

    # Save the image data to a PNG file
    with open('received_qr.png', 'wb') as f:
        f.write(image_data)


    img = Image.open('received_qr.png')
    barcode = decode(img)[0]

    barcode_data = barcode.data.decode('utf-8')
    barcode_type = barcode.type

    # Extract the numeric substring at the end of barcode_data
    numeric_suffix = re.search(r'([0-9]|[1-9][0-9]|10[0-2])$', barcode_data).group()
    data = barcode_data[:-len(numeric_suffix)]  # Exclude the numeric suffix
    checksum = int(numeric_suffix)

    # Verify the checksum
    is_valid = False
    if barcode_type == "CODE128" and 1 <= len(data) <= 12 and checksum is not None:
        is_valid = code128B_checksum(data) == checksum

    ans = 'y' if is_valid else 'n'
    io.recvline()
    print(data, numeric_suffix, f'({code128B_checksum(data)})', len(data), is_valid, ans, f'\t{i+1}/50')
    io.sendline(f"{ans}".encode())
    msg = io.recvline().decode()
    print(msg)
    if "Error" in msg:
        print(io.recvline().decode())
        break
print(io.recvall())