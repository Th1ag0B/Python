from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

symmetric_key = os.urandom(32)

shared_secret = private_key.exchange(ec.ECDH(), public_key)
derived_key_material = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'',
    backend=default_backend()
).derive(shared_secret)

cipher = Cipher(algorithms.AES(derived_key_material), modes.CTR(os.urandom(16)), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_symmetric_key = encryptor.update(symmetric_key) + encryptor.finalize()

print("Chave simétrica encriptada:")
print(encrypted_symmetric_key)

decryptor = cipher.decryptor()
decrypted_symmetric_key = decryptor.update(encrypted_symmetric_key) + decryptor.finalize()

assert symmetric_key == decrypted_symmetric_key

plaintext = b"Exemplo de mensagem a ser encriptada"
cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(os.urandom(16)), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

print("Chave privada ECC:")
print(private_key_pem.decode())
print("Chave pública ECC:")
print(public_key_pem.decode())
print("Chave simétrica original:")
print(symmetric_key)
print("Mensagem criptografada:")
print(ciphertext)
