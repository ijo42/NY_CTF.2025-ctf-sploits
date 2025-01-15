import hashlib

with open('rockyou.txt', 'r') as file:
    for line in file:
        md5_hash = hashlib.md5()
        md5_hash.update(line.strip().encode())
        md5_bytes = md5_hash.digest()
        if list(md5_bytes) == [ 246, 253, 255, 228, 140, 144, 141, 235, 15, 76, 59, 211, 108, 3, 46, 114]:
            print(f'MD5 hash of "{line.strip()}" is valid.')
            break
