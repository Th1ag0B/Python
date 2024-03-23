import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, ##tentei com 1024, 2048, 4096
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



# tempo de execução
# Iniciar o cronômetro
start = time.time()

pem_private, pem_public = generate_rsa_keys()

save_private_key(pem_private,'private.pem')
message = input("Qual mensagem quer cryptografar: ")
encrypted_message = encrypt_message(message, pem_public)
original_message = decrypt_message(encrypted_message, pem_private)

print(f"Original Message: {original_message}")

print(f"Encrypted Message: {encrypted_message}")

# Mensagem criptografada representada em Base64
encrypted_message_base64 = encrypted_message.hex()
print(f"Mensagem criptografada (Base64): {encrypted_message_base64}")


# Parar o cronômetro
end = time.time()

# Exibir o tempo de execução
print(f"Tempo de execução: {end - start} segundos")