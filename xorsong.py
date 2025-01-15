from PIL import Image
import itertools

def get_bit_planes(image):
    # Преобразуем изображение в 8-битное (если оно не в этом формате)
    image = image.convert('L')
    pixels = image.load()
    width, height = image.size

    # Создаем список для хранения битовых плоскостей
    bit_planes = [Image.new('1', (width, height)) for _ in range(8)]

    # Извлекаем битовые плоскости
    for y in range(height):
        for x in range(width):
            pixel_value = pixels[x, y]
            for i in range(8):
                bit = (pixel_value >> i) & 1
                bit_planes[i].putpixel((x, y), bit)

    return bit_planes

def xor_images(images):
    # Выполняем XOR между несколькими изображениями
    width, height = images[0].size
    xor_image = Image.new('1', (width, height))
    xor_pixels = xor_image.load()

    # Инициализируем первое изображение
    pixels = images[0].load()
    for y in range(height):
        for x in range(width):
            xor_pixels[x, y] = pixels[x, y]

    # Выполняем XOR с остальными изображениями
    for image in images[1:]:
        pixels = image.load()
        for y in range(height):
            for x in range(width):
                xor_pixels[x, y] ^= pixels[x, y]

    return xor_image

# Открываем изображение
image = Image.open('fir_in_forest_song.png')

# Получаем битовые плоскости
bit_planes = get_bit_planes(image)
for i in range(len(bit_planes)):
    bit_planes[i].save(f"bitplane_{i}.png")
input()
# Выполняем XOR для всех возможных комбинаций битовых плоскостей
for r in range(2, len(bit_planes) + 1):
    for combination in itertools.combinations(range(len(bit_planes)), r):
        xor_result = xor_images([bit_planes[i] for i in combination])
        combination_str = '_'.join(map(str, combination))
        xor_result.save(f'result/xor_result_{combination_str}.png')
        # xor_result.show()