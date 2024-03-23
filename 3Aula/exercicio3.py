from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import hashlib
import hmac

def encrypt_file(filename, key):
    aesgcm = AESGCM(key)
    with open(filename, 'rb') as f:
        file_contents = f.read()
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, file_contents, None)
    return ct, nonce

def save_encrypted_data(encrypted_data, nonce, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    output_file = os.path.join(output_folder, 'encrypted_data.bin')
    nonce_file = os.path.join(output_folder, 'nonce.bin')

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    with open(nonce_file, 'wb') as f:
        f.write(nonce)

def decrypt_file(output_folder, key):
    encrypted_file = os.path.join(output_folder, 'encrypted_data.bin')
    nonce_file = os.path.join(output_folder, 'nonce.bin')

    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()
    with open(nonce_file, 'rb') as f:
        nonce = f.read()

    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    return decrypted_data

print("Escolha uma opção:")
print("1. Encriptar ficheiro")
print("2. Decriptar ficheiro")
choice = input("Opção: ")

if choice == '1':
    filename = input("Insira o nome do ficheiro: ")
    key = input("Insira a chave para encriptação: ").encode('utf-8')
    output_folder = 'encrypted_files'
    encrypted_data, nonce = encrypt_file(filename, key)
    save_encrypted_data(encrypted_data, nonce, output_folder)
    print("Ficheiro encriptado e nonce salvo na pasta 'encrypted_files'")
elif choice == '2':
    folder_path = input("Insira o caminho para a pasta com os ficheiros encriptados: ")
    key = input("Insira a chave para desencriptação: ").encode('utf-8')
    decrypted_data = decrypt_file(folder_path, key)
    print("Conteúdo decriptado:")
    print(decrypted_data.decode())
else:
    print("Opção inválida.")