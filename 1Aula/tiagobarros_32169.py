import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


def encrypt_message(message, key):
    # Converter a mensagem para bytes, se necessário
    if isinstance(message, str):
        message = message.encode()

    # Preparar o padder
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    # Gerar um IV aleatório
    iv = os.urandom(16)

    # Criar um objeto cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Criptografar a mensagem
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ct


def decrypt_message(ciphertext, key):
    # Separar o IV e o texto criptografado
    iv = ciphertext[:16]
    ct = ciphertext[16:]

    # Criar um objeto cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Descriptografar a mensagem
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    # Remover o padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    pt = unpadder.update(pt) + unpadder.finalize()

    return pt

def encrypt_file(filename, key):
    # Carregar o conteúdo do arquivo
    with open(filename, 'rb') as f:
        file_contents = f.read()

    # Criptografar o conteúdo do arquivo
    encrypted_contents = encrypt_message(file_contents, key)  # Reutilizar a função do exercício anterior

    # Salvar o conteúdo criptografado em um novo arquivo
    encrypted_filename = filename + '.encrypted'
    with open(encrypted_filename, 'wb') as f:
        f.write(encrypted_contents)
    return encrypted_filename


def decrypt_file(encrypted_filename, key):
    # Carregar o conteúdo criptografado
    with open(encrypted_filename, 'rb') as f:
        encrypted_contents = f.read()

    # Descriptografar o conteúdo
    decrypted_contents = decrypt_message(encrypted_contents, key)  # Reutilizar a função do exercício anterior

    # Salvar o conteúdo descriptografado em um novo arquivo
    original_filename = encrypted_filename.replace('.encrypted', '')
    with open('decrypted_' + original_filename, 'wb') as f:
        f.write(decrypted_contents)


def save_key_to_file(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key = key_file.read()
    return key

key = os.urandom(16)
save_key_to_file(key, 'chave.key')


filename = input("Escreve o nome do arquivo : ")
encrypted_file = encrypt_file(filename, key)
print(f"Arquivo criptografado saved como: {encrypted_file}")

#encrypted_filename = input("Escreve o nome do arquivo criptografado : ")
#print(encrypted_filename)
#decrypt_file(encrypted_filename, key)
#print("Arquivo descriptografado com sucesso.")
