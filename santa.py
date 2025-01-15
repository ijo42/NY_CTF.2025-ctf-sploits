# Словарь для соответствия окончаний строк и их номеров
line_ending_mapping = {
    b'\x00\x0A\x0D': 2,
    b'\x0A\x0D': 1,  # CRLF
    b'\x0A': 3,
    b'\x0D': 4,
    b'\x00\x0D': 0,
}
import re


# Регулярное выражение для поиска подстроки
pattern = re.compile(r"(\x00\x0A\x0D|\x0A\x0D|\x0A|\x0D|\x00\x0D)$")
ans = []
# Функция для чтения файла и поиска подстроки в каждой строке
def find_substring_in_file(file_path):
    with open(file_path, 'rb') as file:
        for line in file:
            # Декодируем байтовую строку в строку
            decoded_line = line.decode()
            matchs = pattern.finditer(decoded_line)
            ans.append(line_ending_mapping[matchs[-1].group().encode()])

file_path = 'santa-code.py'
find_substring_in_file(file_path)
print(ans)

