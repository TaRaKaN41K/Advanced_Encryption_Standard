import base64
from typing import List

from AES import AES

if __name__ == '__main__':
    input_string: str = 'Kalashov Feodor Olegovich N34481'
    input_bytes: List[int] = list(input_string.encode('utf-8'))

    for i in [128, 192, 256]:
        aes_instance: AES = AES(i)

        key: str = f'{int(i / 8)}' * int(i / 16)
        key_bytes: List[int] = list(key.encode('utf-8'))

        # Шифрование
        ciphertext: List[int] = aes_instance.encrypt(input_bytes, key_bytes)

        # Расшифровка
        decrypted_text: List[int] = aes_instance.decrypt(ciphertext, key_bytes)

        print(f'\n                    AES-{i}                      \n')

        print(f'Текст:                       {input_string}')
        print(f'Key:                         {key}')
        print(f'Зашифрованный текст Base64:  {base64.b64encode(bytes(ciphertext)).decode("utf-8")}')
        print(f'Расшифрованный текст:        {bytes(decrypted_text).decode("utf-8")}')

        print(f'Текст байтлист:              {input_bytes}')
        print(f'Key байтлист:                {key_bytes}')
        print(f'Зашифрованный байтлист:      {ciphertext}')
        print(f'Расшифрованный байтлист:     {decrypted_text}')
