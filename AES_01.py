from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

def generate_key():
    # Генерация случайного ключа
    key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    key.update(os.urandom(16))
    return key.finalize()

def encrypt(message, key):
    # Инициализация шифра AES с режимом CBC
    cipher = Cipher(algorithms.AES(key), modes.CFB(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()

    # Шифрование сообщения
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

    # Возвращение зашифрованного текста в виде строки
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext, key):
    # Инициализация шифра AES с режимом CBC
    cipher = Cipher(algorithms.AES(key), modes.CFB(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()

    # Дешифрование сообщения
    decrypted_message = decryptor.update(base64.b64decode(ciphertext.encode('utf-8'))) + decryptor.finalize()

    # Возвращение дешифрованного текста в виде строки
    return decrypted_message.decode('utf-8')

if __name__ == "__main__":
    import os

    # Ввод текста
    message = input("Введите текст для шифрования: ")

    # Генерация ключа
    key = generate_key()

    # Вывод ключа в виде строки
    print("Сгенерированный ключ:", base64.b64encode(key).decode('utf-8'))

    # Шифрование и вывод зашифрованного текста
    ciphertext = encrypt(message, key)
    print("Зашифрованный текст:", ciphertext)

    # Ввод ключа для дешифрования
    decryption_key = input("Введите ключ для дешифрования: ")

    # Дешифрование и вывод дешифрованного текста
    decrypted_message = decrypt(ciphertext, base64.b64decode(decryption_key))
    print("Дешифрованный текст:", decrypted_message)

