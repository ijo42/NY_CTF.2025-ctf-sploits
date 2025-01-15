import reedsolo
import base64

def decrypt_data(encrypted_data, n1):
    rs1 = reedsolo.RSCodec(n1)

    try:
        decoded_data = rs1.decode(encrypted_data)[0]
        original_text = decoded_data.decode('utf-8')
        return original_text
    except (reedsolo.ReedSolomonError, UnicodeDecodeError):
        return None

def brute_force_decrypt(encrypted_data, max_n=255):
    data_length = len(encrypted_data)
    for n0 in range(1, min(max_n, data_length) + 1):
        if n0 >= data_length:
            continue  # Пропускаем комбинации, где n0 + n1 >= длины данных
        decrypted_text = decrypt_data(encrypted_data, n0)
        if decrypted_text:
            # Проверка на наличие читаемого текста
            if any(c.isalpha() for c in decrypted_text) and len(decrypted_text) > 5:
                print(f"Возможная расшифровка найдена с n0={n0}:")
                print(decrypted_text)
                print("------------------------")


encrypted_data = base64.b64decode(b"WW91ciBwcml6ZSBpcyAkMSwwMDAsMDAwLiBDb25ncmF0dWxhdGlvbnMh5rNF/Q8L2yDoKbF0K2B1DvApTlfJEDMgDL/bvVi6")

print("Начинаем подбор параметров...")
brute_force_decrypt(encrypted_data)
