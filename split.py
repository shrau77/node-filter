import os

# Имя файла, куда ты вставишь все свои 50+ ссылок
INPUT_FILE = 'sources.txt'
# По сколько источников давать одному монолиту за раз
CHUNKS_SIZE = 5 

def split_sources():
    if not os.path.exists(INPUT_FILE):
        print(f"Ошибка: Создай файл {INPUT_FILE} и положи туда ссылки!")
        return

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        # Убираем пустые строки и пробелы
        sources = [line.strip() for line in f if line.strip()]

    if not sources:
        print("Файл с источниками пуст!")
        return

    # Режем список на куски
    for i in range(0, len(sources), CHUNKS_SIZE):
        chunk_index = i // CHUNKS_SIZE
        # Форматируем индекс как 00, 01, 02 для соответствия матрице в YAML
        chunk_name = f'src_part_{chunk_index:02d}.txt'
        with open(chunk_name, 'w', encoding='utf-8') as f_out:
            chunk_data = sources[i:i + CHUNKS_SIZE]
            f_out.write('\n'.join(chunk_data))
        print(f"Создан: {chunk_name} ({len(chunk_data)} источников)")

if __name__ == "__main__":
    split_sources()
