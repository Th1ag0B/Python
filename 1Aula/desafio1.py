import time
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


def encrypt_message(message, key, hmac_key):
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

    # Calcular HMAC da mensagem criptografada
    tag = hmac.new(hmac_key, iv + ct, hashlib.sha256).digest()

    return iv + ct + tag


def decrypt_message(ciphertext, key, hmac_key):
    # Separar o IV, o texto criptografado e o HMAC
    iv = ciphertext[:16]
    ct = ciphertext[16:-32]
    tag = ciphertext[-32:]

    # Verificar HMAC
    if hmac.new(hmac_key, iv + ct, hashlib.sha256).digest() != tag:
        raise ValueError("HMAC verification failed. Data may have been tampered.")

    # Criar um objeto cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Descriptografar a mensagem
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    # Remover o padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    pt = unpadder.update(pt) + unpadder.finalize()

    return pt


def encrypt_file(filename, key, hmac_key):
    # Carregar o conteúdo do arquivo
    with open(filename, 'rb') as f:
        file_contents = f.read()

    # Criptografar o conteúdo do arquivo
    encrypted_contents = encrypt_message(file_contents, key, hmac_key)

    # Salvar o conteúdo criptografado em um novo arquivo
    encrypted_filename = filename + '.encrypted'
    with open(encrypted_filename, 'wb') as f:
        f.write(encrypted_contents)
    return encrypted_filename


def decrypt_file(encrypted_filename, key, hmac_key):
    # Carregar o conteúdo criptografado
    with open(encrypted_filename, 'rb') as f:
        encrypted_contents = f.read()

    # Descriptografar o conteúdo
    decrypted_contents = decrypt_message(encrypted_contents, key, hmac_key)

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


escolha = input("Se quiser criptografar(1), se quiser descriptografar (2): ")
if escolha == '1':
    filename = input("Escreve o nome do arquivo : ")
    key = os.urandom(32)
    hmac_key = os.urandom(32)  # Chave para HMAC
    save_key_to_file(key, 'chave.key')
    save_key_to_file(hmac_key, 'hmac_key.key')
    key = load_key_from_file('chave.key')
    hmac_key = load_key_from_file('hmac_key.key')
    encrypted_file = encrypt_file(filename, key, hmac_key)
    print(f"Arquivo criptografado saved como: {encrypted_file}")
elif escolha == '2':
    key = load_key_from_file('chave.key')
    hmac_key = load_key_from_file('hmac_key.key')
    encrypted_filename = input("Escreve o nome do arquivo criptografado : ")
    decrypt_file(encrypted_filename, key, hmac_key)
    print("Arquivo descriptografado com sucesso.")
else:
    print("Escolha inválida")
