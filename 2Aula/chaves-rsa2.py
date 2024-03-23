import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024, ##tentei com 1024, 2048, 4096
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public


def encrypt_message(message, pem_public):
    public_key = serialization.load_pem_public_key(
        pem_public,
        backend=default_backend()
    )

    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_message(encrypted_message, pem_private):
    private_key = serialization.load_pem_private_key(
        pem_private,
        password=None,
        backend=default_backend()
    )

    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode('utf-8')

def save_private_key(private_key, filename):
    with open(filename, 'wb') as pem_out:
        pem_out.write(private_key)

def save_public_key(public_key, filename):
    with open(filename, 'wb') as pem_out:
        pem_out.write(public_key)

def load_private_key(filename):
    with open(filename, 'rb') as pem_in:
        pem_lines = pem_in.read()
    private_key = serialization.load_pem_private_key(
        pem_lines,
        password=None,
        backend=default_backend()
    )
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as pem_in:
        pem_lines = pem_in.read()
    public_key = serialization.load_pem_public_key(
        pem_lines,
        backend=default_backend()
    )
    return public_key



user1_private_key, user1_public_key = generate_rsa_keys()
user2_private_key, user2_public_key = generate_rsa_keys()
print("Chaves Criadas")


save_private_key(user1_private_key, "user1_private.txt")
save_public_key(user1_public_key, "user1_public.txt")
save_private_key(user2_private_key, "user2_private.txt")
save_public_key(user2_public_key, "user2_public.txt")


print("Usuário 1 envia sua chave pública para o Usuário 2.")
print("Usuário 2 envia sua chave pública para o Usuário 1.")


mensagem_usuario1 = input("Mensagem Desejada: ")
mensagem_usuario1_criptografada = encrypt_message(mensagem_usuario1, user2_public_key)


mensagem_usuario1_descriptografada = decrypt_message(mensagem_usuario1_criptografada, user2_private_key)


mensagem_usuario2 = input("Mensagem Desejada: ")
mensagem_usuario2_criptografada = encrypt_message(mensagem_usuario2, user1_public_key)
mensagem_usuario2_descriptografada = decrypt_message(mensagem_usuario2_criptografada, user1_private_key)

print("Usuário 1 enviou:", mensagem_usuario1)
print("Mensagem criptografada:", mensagem_usuario1_criptografada)
print("Usuário 2 recebeu e descriptografou a mensagem:", mensagem_usuario1_descriptografada)
print("Usuário 2 enviou:", mensagem_usuario2)
print("Mensagem criptografada:", mensagem_usuario2_criptografada)
print("Usuário 1 recebeu e descriptografou a mensagem:", mensagem_usuario2_descriptografada)
