from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# Geração de chave aleatória de 256 bits
key = AESGCM.generate_key(bit_length=256)


filename = input("Nome do Ficheiro: ").encode()
filename = str(filename)

with open(filename, 'rb') as f:
        file_contents = f.read()

    # Criptografar o conteúdo do arquivo
encrypted_contents = encrypt_message(file_contents, key)  

    # Salvar o conteúdo criptografado em um novo arquivo
encrypted_filename = filename + '.encrypted'
with open(encrypted_filename, 'wb') as f:
        f.write(encrypted_contents)


# Inicialização do AESGCM com a chave gerada
aesgcm = AESGCM(key)

# Dados a serem encriptados
data = b"dados secretos"
# Dados associados que você deseja autenticar, mas não encriptar
aad = b"dados autenticados"

# Geração de um nonce aleatório de 96 bits
nonce = os.urandom(12)

# Encriptação
ct = aesgcm.encrypt(nonce, data, aad)

# Decriptação
pt = aesgcm.decrypt(nonce, ct, aad)

print(f"Texto plano original: {data}")
print(f"Texto plano após decriptação: {pt}")

# Verifica se os dados decriptados são iguais aos originais
assert data == pt
