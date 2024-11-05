from typing import Optional

from constants.tables import *
from helpers import *

ROWS = 4
BLOCKS_SIZE = 16


class AES:
    def __init__(self, version: int):
        versions: dict[int, tuple[int, int, int]] = {
            128: (4, 4, 10),
            192: (6, 4, 12),
            256: (8, 4, 14)
        }

        if version not in versions:
            raise ValueError(f"Некорректное значение: {version}. Должно быть 128, 192 или 256.")

        # Nk - Количество слов (4-байтовых блоков) в ключе.
        # Nb - Количество слов (4-байтовых блоков) в блоке.
        # Nr - Количество раундов.

        self.Nk: int
        self.Nb: int
        self.Nr: int
        self.Nk, self.Nb, self.Nr = versions[version]

    def encrypt(self, input_bytes: List[int], key_bytes: List[int]) -> List[Optional[int]]:

        input_bytes_arrays = [input_bytes[i:i + BLOCKS_SIZE] for i in range(0, len(input_bytes), BLOCKS_SIZE)]

        encrypted_result = []

        for input_bytes_array in input_bytes_arrays:

            input_bytes = pad_to_multiple(input_bytes_array, BLOCKS_SIZE)

            if len(key_bytes) != self.Nk * 4:
                raise ValueError(
                    f"ERROR: Некорректная длина ключа: {len(key_bytes)}."
                    f"Ожидалась длина {self.Nk * 4} байт."
                )

            state: List[List[int]] = [[] for _ in range(self.Nb)]
            for r in range(ROWS):
                for c in range(self.Nb):
                    state[r].append(input_bytes[r + ROWS * c])

            # Генерация расписания ключей
            key_schedule: List[List[int]] = self.key_expansion(key_bytes=key_bytes, nk=self.Nk, nb=self.Nb, nr=self.Nr)

            # XOR ключ и наше сообщение
            state = self.add_round_key(state=state, key_schedule=key_schedule, nb=self.Nb)

            # Проходим через все раунды, кроме последнего
            for rnd in range(1, self.Nr):
                # Переставляем по SBOX
                state = self.sub_bytes(state)
                # Циклический сдвиг строк
                #     первая - сдвиг 0,
                #     вторая - сдвиг 1,
                #     третья - сдвиг 2,
                #     четвёртая - сдвиг 3
                state = self.shift_rows(state, nb=self.Nb)

                state = self.mix_columns(state, nb=self.Nb)
                state = self.add_round_key(state=state, key_schedule=key_schedule, round=rnd, nb=self.Nb)

            # Финальный раунд (без MixColumns)
            state = self.sub_bytes(state)
            state = self.shift_rows(state, nb=self.Nb)
            state = self.add_round_key(state=state, key_schedule=key_schedule, round=self.Nr, nb=self.Nb)

            output: List[Optional[int]] = [None for _ in range(ROWS * self.Nb)]
            for r in range(ROWS):
                for c in range(self.Nb):
                    output[r + ROWS * c] = state[r][c]

            encrypted_result += output

        return encrypted_result

    def decrypt(self, cipher_bytes: List[int], key_bytes: List[int]) -> List[Optional[int]]:

        cipher_bytes_arrays = [cipher_bytes[i:i + BLOCKS_SIZE] for i in range(0, len(cipher_bytes), BLOCKS_SIZE)]

        decrypted_result = []

        for cipher_bytes_array in cipher_bytes_arrays:

            cipher_bytes = pad_to_multiple(cipher_bytes_array, BLOCKS_SIZE)

            if len(key_bytes) != self.Nk * 4:
                raise ValueError(
                    f"ERROR: Некорректная длина ключа: {len(key_bytes)}."
                    f"Ожидалась длина {self.Nk * 4} байт."
                )

            state: List[List[int]] = [[] for _ in range(self.Nb)]
            for r in range(ROWS):
                for c in range(self.Nb):
                    state[r].append(cipher_bytes[r + ROWS * c])

            key_schedule: List[List[int]] = self.key_expansion(key_bytes=key_bytes, nk=self.Nk, nb=self.Nb, nr=self.Nr)

            state = self.add_round_key(state=state, key_schedule=key_schedule, round=self.Nr, nb=self.Nb)

            rnd: int = self.Nr - 1
            while rnd >= 1:
                state = self.shift_rows(state, nb=self.Nb, inv=True)
                state = self.sub_bytes(state, inv=True)
                state = self.add_round_key(state=state, key_schedule=key_schedule, round=rnd, nb=self.Nb)
                state = self.mix_columns(state, inv=True, nb=self.Nb)

                rnd -= 1

            state = self.shift_rows(state, nb=self.Nb, inv=True)
            state = self.sub_bytes(state, inv=True)
            state = self.add_round_key(state=state, key_schedule=key_schedule, round=rnd, nb=self.Nb)

            output: List[Optional[int]] = [None for _ in range(ROWS * self.Nb)]
            for r in range(ROWS):
                for c in range(self.Nb):
                    output[r + ROWS * c] = state[r][c]

            decrypted_result += output

        return decrypted_result

    @staticmethod
    def add_round_key(state: List[List[int]], key_schedule: List[List[int]], nb: int, round: int = 0) -> List[List[int]]:
        for col in range(nb):
            # Nb * round — это сдвиг, указывающий начало части KeySchedule.
            s0: int = state[0][col] ^ key_schedule[0][nb * round + col]
            s1: int = state[1][col] ^ key_schedule[1][nb * round + col]
            s2: int = state[2][col] ^ key_schedule[2][nb * round + col]
            s3: int = state[3][col] ^ key_schedule[3][nb * round + col]

            state[0][col] = s0
            state[1][col] = s1
            state[2][col] = s2
            state[3][col] = s3

        return state

    @staticmethod
    def sub_bytes(state: List[List[int]], inv: bool = False) -> List[List[int]]:
        box: List[int] = SBOX if not inv else INV_SBOX

        for i in range(len(state)):
            for j in range(len(state[i])):
                row: int = state[i][j] // 0x10
                col: int = state[i][j] % 0x10

                box_elem: int = box[16 * row + col]
                state[i][j] = box_elem

        return state

    @staticmethod
    def shift_rows(state: List[List[int]], nb: int, inv: bool = False) -> List[List[int]]:
        count: int = 1

        if not inv:  # encrypting
            for i in range(1, nb):
                state[i] = left_shift(state[i], count)
                count += 1
        else:  # decrypting
            for i in range(1, nb):
                state[i] = right_shift(state[i], count)
                count += 1

        return state

    @staticmethod
    def mix_columns(state: List[List[int]], nb: int, inv: bool = False) -> List[List[int]]:
        for i in range(nb):

            if not inv:  # encryption
                s0: int = galois_multiply(state[0][i], 2) ^ galois_multiply(state[1][i], 3) ^ state[2][i] ^ state[3][i]
                s1: int = state[0][i] ^ galois_multiply(state[1][i], 2) ^ galois_multiply(state[2][i], 3) ^ state[3][i]
                s2: int = state[0][i] ^ state[1][i] ^ galois_multiply(state[2][i], 2) ^ galois_multiply(state[3][i], 3)
                s3: int = galois_multiply(state[0][i], 3) ^ state[1][i] ^ state[2][i] ^ galois_multiply(state[3][i], 2)
            else:  # decryption
                s0: int = galois_multiply(state[0][i], 0x0e) ^ galois_multiply(state[1][i], 0x0b) ^ galois_multiply(
                    state[2][i], 0x0d) ^ galois_multiply(state[3][i], 0x09)
                s1: int = galois_multiply(state[0][i], 0x09) ^ galois_multiply(state[1][i], 0x0e) ^ galois_multiply(
                    state[2][i], 0x0b) ^ galois_multiply(state[3][i], 0x0d)
                s2: int = galois_multiply(state[0][i], 0x0d) ^ galois_multiply(state[1][i], 0x09) ^ galois_multiply(
                    state[2][i], 0x0e) ^ galois_multiply(state[3][i], 0x0b)
                s3: int = galois_multiply(state[0][i], 0x0b) ^ galois_multiply(state[1][i], 0x0d) ^ galois_multiply(
                    state[2][i], 0x09) ^ galois_multiply(state[3][i], 0x0e)

            state[0][i] = s0
            state[1][i] = s1
            state[2][i] = s2
            state[3][i] = s3

        return state

    @staticmethod
    def key_expansion(key_bytes: List[int], nk: int, nb: int, nr: int) -> List[List[int]]:
        """Составляет список RoundKeys для функции AddRoundKey."""

        key_schedule: List[List[int]] = [[] for _ in range(ROWS)]
        for r in range(ROWS):
            for c in range(nk):
                key_schedule[r].append(key_bytes[r + ROWS * c])

        # Продолжаем заполнять расписание ключей
        for col in range(nk, nb * (nr + 1)):
            if col % nk == 0:
                tmp: List[int] = [key_schedule[row][col - 1] for row in range(1, ROWS)]
                tmp.append(key_schedule[0][col - 1])

                # изменим его элементы, используя Sbox-таблицу, как в SubBytes...
                for j in range(len(tmp)):
                    sbox_row: int = tmp[j] // 0x10
                    sbox_col: int = tmp[j] % 0x10
                    sbox_elem: int = SBOX[16 * sbox_row + sbox_col]
                    tmp[j] = sbox_elem

                # XOR из 3 столбцов
                for row in range(ROWS):
                    s: int = (key_schedule[row][col - nk]) ^ (tmp[row]) ^ (RCON[row][int(col / nk - 1)])
                    key_schedule[row].append(s)

            else:
                # XOR из двух столбцов
                for row in range(ROWS):
                    s: int = key_schedule[row][col - nk] ^ key_schedule[row][col - 1]
                    key_schedule[row].append(s)

        return key_schedule
