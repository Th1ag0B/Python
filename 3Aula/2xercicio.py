import hashlib
import hmac

filename = input("Nome do Ficheiro: ").encode()
chave_secreta = input("Chave secreta: ").encode()
hash_filename = hashlib.sha256(filename).hexdigest()

with open(filename, 'rb') as f:
    file_contents = f.read()
    hash_value = hashlib.sha256(file_contents).hexdigest()



# Criacao do HMAC usando SHA-256 como algoritmo de hash
h = hmac.new(chave_secreta, filename, hashlib.sha256)


print(f"HMAC: {h.hexdigest()}")
print(f"Hash do conteúdo do ficheiro '{filename}': {hash_filename}")