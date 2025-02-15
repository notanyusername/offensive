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

def decrypt_message(encrypted_data: bytes, password: str) -> str:
    
    backend = default_backend()
    if len(encrypted_data) < 32:
        raise ValueError("Неверные зашифрованные данные (слишком короткие).")
    
    # Извлечение соли, IV и зашифрованного текста
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    # Получение ключа из пароля и соли
    key = derive_key(password.encode(), salt)
    
    # Дешифрование с использованием AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Удаление PKCS7-паддинга
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

def main():
    print("=== Инструмент сложного дешифрования ===")
    password = getpass.getpass("Введите пароль: ")
    encrypted_hex = input("Введите зашифрованный текст (hex): ")

    try:
        encrypted_data = bytes.fromhex(encrypted_hex)
    except ValueError:
        print("Ошибка: введённая строка не является корректной шестнадцатеричной последовательностью.")
        return

    try:
        plaintext = decrypt_message(encrypted_data, password)
        print("\nДешифрованный текст:")
        print(plaintext)
    except Exception as e:
        print("Ошибка при дешифровании:", e)

if __name__ == '__main__':
    main()
