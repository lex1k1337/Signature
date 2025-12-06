import os
import sys
from pathlib import Path

# Сигнатура должна точно совпадать с тем, что пишет вирус:
# signature db "EDU_VIRUS_2025", 0
VIRUS_SIG = b"EDU_VIRUS_2025\x00"
SIG_LEN = len(VIRUS_SIG)
TAIL_SIZE = 1024


def is_infected(path: Path) -> bool:
    # Проверяет, заражён ли файл:
    # 1) Открываем файл в двоичном режиме
    # 2) Читаем хвост файла (до TAIL_SIZE байт)
    # 3) Ищем в нём подпоследовательность VIRUS_SIG
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()

            if size < SIG_LEN:
                return False

            # Берём минимум из TAIL_SIZE и реального размера
            chunk_size = min(size, TAIL_SIZE)

            # Позиция начала хвоста
            f.seek(size - chunk_size, os.SEEK_SET)
            tail = f.read(chunk_size)

        # Просто проверяем наличие сигнатуры в хвосте
        return VIRUS_SIG in tail

    except OSError:
        # Если не удалось открыть/прочитать файл - считаем "не заражён"
        return False


def scan_directory(dir_path):
    # Сканирует все .exe в указанной директории
    dir_path = Path(dir_path)
    print(f"Сканирование каталога: {dir_path}")

    infected_count = 0

    for exe_path in dir_path.glob("*.exe"):
        if not exe_path.is_file():
            continue

        infected = is_infected(exe_path)

        status = "[ЗАРАЖЕНО]" if infected else "[OK]"
        print(f"{status} {exe_path.name}")

        # Для единообразия тоже выводим "причины"
        if infected:
            print("   - Обнаружена сигнатура вируса")

        print()

        if infected:
            infected_count += 1

    if infected_count == 0:
        print("\nЗаражённых файлов не найдено.")
    else:
        print(f"\nНайдено заражённых файлов: {infected_count}")


def main():
    dir_path = Path.cwd()
    scan_directory(dir_path)


if __name__ == "__main__":
    main()
    input()
