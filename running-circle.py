import requests


def shift_letters(s, n):
    """
    Сдвигает буквы в строке на n позиций.
    Если n положительное, сдвиг происходит справа налево.
    Если n отрицательное, сдвиг происходит слева направо.
    """
    if not s:
        return s

    n = n % len(s)  # Нормализуем n, чтобы оно было в пределах длины строки
    if n == 0:
        return s

    return s[-n:] + s[:-n]



def get_google_docs_status(url):
    try:
        response = requests.get(url)
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

code = "2sOeVtCFY3i3K9UEXqVWuoxvO-6X8LwE1Zp9J7D23ZOe"

url = "https://docs.google.com/document/d/"


for i in range(len(code)):
    u = f'{url}{shift_letters(code, i)}/edit'
    status_code = get_google_docs_status(u)
    print(status_code, u)
