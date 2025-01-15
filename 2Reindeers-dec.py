import reedsolo
import base64

def decrypt_data(encrypted_data, n0, n1):
    rs1 = reedsolo.RSCodec(n1)
    rs0 = reedsolo.RSCodec(n0)

    try:
        decoded_data1 = rs1.decode(encrypted_data)[0]
        decoded_data0 = rs0.decode(decoded_data1)[0]
        original_text = decoded_data0.decode('utf-8')
        return original_text
    except (reedsolo.ReedSolomonError, UnicodeDecodeError):
        return None

def brute_force_decrypt(encrypted_data, max_n=255):
    data_length = len(encrypted_data)
    for n1 in range(1, min(max_n, data_length) + 1):
        for n0 in range(1, min(max_n, data_length - n1) + 1):
            if n0 + n1 >= data_length:
                continue  # Пропускаем комбинации, где n0 + n1 >= длины данных
            decrypted_text = decrypt_data(encrypted_data, n0, n1)
            if decrypted_text:
                # Проверка на наличие читаемого текста
                if any(c.isalpha() for c in decrypted_text) and len(decrypted_text) > 5:
                    print(f"Возможная расшифровка найдена с n0={n0}, n1={n1}:")
                    print(decrypted_text)
                    print("------------------------")

# Использование функции
# Предполагается, что у вас есть переменная cd_b64 с зашифрованными данными в base64

# Декодирование base64
encrypted_data = base64.b64decode(b"TXkgZmF2b3JpdGUgcmVpbmQE/v9NMC7EPgT+fVKtYX1uAP1zYW1iaQT+ZXNpjl6WWlMZ+F06cKpDoSF7cIQ2Ug9OxlQ2VQ58otSA6jm+xjhwUFcr02pIxVfyY85y84/QFG8T94M=")

print("Начинаем подбор параметров...")
brute_force_decrypt(encrypted_data)
