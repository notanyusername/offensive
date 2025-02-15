import os
import getpass
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: bytes, salt: bytes, iterations: int = 100000) -> bytes:

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 бит для AES-256
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_message(message: str, password: str) -> bytes:
    
    backend = default_backend()
    # Генерация случайной соли
    salt = os.urandom(16)
    # Получение ключа из пароля и соли
    key = derive_key(password.encode(), salt)
    # Генерация случайного вектора инициализации (IV)
    iv = os.urandom(16)

    # Применяем PKCS7-паддинг к сообщению
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Шифрование с использованием AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Конкатенируем salt + iv + ciphertext для финального вывода
    return salt + iv + ciphertext

def main():
    print("=== Инструмент сложного шифрования ===")
    password = getpass.getpass("Введите пароль: ")
    message = input("Введите текст для шифрования: ")

    encrypted_data = encrypt_message(message, password)
    # Вывод зашифрованного сообщения в шестнадцатеричном формате
    print("\nЗашифрованный текст (hex):")
    print(encrypted_data.hex())

if __name__ == '__main__':
    main()
