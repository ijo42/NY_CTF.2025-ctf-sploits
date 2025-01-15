import string

import requests

def custom_shift(s, k):
    result = []
    for c in s:
        if c.islower():
            # Сдвиг маленьких букв на 13
            result.append(chr((ord(c) - ord('a') +
                               13) % 26 + ord('a')))
        elif c.isdigit():
            # Сдвиг цифр на 1
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(chr((ord(c) - ord('A') + k) % 26 + ord('A')))

    return ''.join(result)

def get_google_docs_status(url):
    try:
        response = requests.get(url)
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

code = "6IxNVieknb2apuaPxcHPpkjmSSQWyL0L9V6wg02ZKwnb"

url = "https://docs.google.com/document/d/"

alphabets = (string.ascii_uppercase, string.ascii_lowercase, string.digits)

for i in range(27):
    u = f'{url}{custom_shift(code, i)}/edit'
    status_code = get_google_docs_status(u)
    print(status_code, u)
