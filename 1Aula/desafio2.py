import os

def generate_key(file_size):
    return os.urandom(file_size)

def encrypt_file(filename, key):
    with open(filename, 'rb') as f:
        plaintext = f.read()
    ciphertext = bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])
    encrypted_filename = filename + '.encrypted'
    with open(encrypted_filename, 'wb') as f:
        f.write(ciphertext)
    return encrypted_filename

def decrypt_file(encrypted_filename, key):
    with open(encrypted_filename, 'rb') as f:
        ciphertext = f.read()
    plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
    decrypted_filename = encrypted_filename.replace('.encrypted', '_decrypted')
    with open(decrypted_filename, 'wb') as f:
        f.write(plaintext)
    return decrypted_filename

filename = input("Por favor, insira o nome do arquivo a ser processado: ")

if not os.path.exists(filename):
    print("O arquivo especificado não foi encontrado.")
else:
    file_size = os.path.getsize(filename)
    key = generate_key(file_size)
    encrypted_filename = encrypt_file(filename, key)
    print(f"Arquivo criptografado salvo como: {encrypted_filename}")
    decrypted_filename = decrypt_file(encrypted_filename, key)
    print(f"Arquivo descriptografado salvo como: {decrypted_filename}")
