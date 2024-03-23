 # Exemplo de geracao de hash de mensagem usando SHA-256 com hashlib
import hashlib

filename = input("Insira o nome do ficheiro: ").encode()

with open(filename, 'rb') as f:
    file_contents = f.read()
    hash_value = hashlib.sha256(file_contents).hexdigest()

print(f"Hash '{filename}': {hash_value}")