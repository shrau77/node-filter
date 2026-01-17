import os

# Имя твоего входного файла с 40к нодами
INPUT_FILE = 'all_nodes.txt' 
# По сколько строк даем монолиту (чтобы он не включал лимиты)
LINES_PER_CHUNK = 1000 

def split_file():
    if not os.path.exists(INPUT_FILE):
        print("Файл не найден!")
        return
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for i in range(0, len(lines), LINES_PER_CHUNK):
        chunk_name = f'input_{i//LINES_PER_CHUNK}.txt'
        with open(chunk_name, 'w', encoding='utf-8') as f_out:
            f_out.writelines(lines[i:i+LINES_PER_CHUNK])
    print(f"Разрезано на {len(lines)//LINES_PER_CHUNK + 1} частей.")

if __name__ == "__main__":
    split_file()
 
