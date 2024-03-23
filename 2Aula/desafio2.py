from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
import os

# Gerar um par de chaves ECC
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Serializar as chaves em formato PEM
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Assinar uma mensagem usando a chave privada ECC
message = b"O mundo nao e um filme da disney"
signature = private_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

# Verificar a assinatura usando a chave pública correspondente
try:
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print("Assinatura verificada: A mensagem é autêntica e íntegra.")
except InvalidSignature:
    print("Assinatura inválida: A mensagem pode ter sido adulterada.")

# Comparação entre ECC e RSA
# Vantagens do ECC:
# - Tamanho das chaves menores para o mesmo nível de segurança
# - Cálculos mais eficientes, especialmente em dispositivos com recursos limitados
# Desvantagens do ECC:
# - Implementações menos testadas em comparação com RSA
# - Potenciais problemas de patentes em alguns países

# Vantagens do RSA:
# - Amplamente implementado e amplamente aceito
# - Implementações maduras e bem testadas
# - Sem questões de patentes
# Desvantagens do RSA:
# - Chaves maiores são necessárias para o mesmo nível de segurança em comparação com o ECC
# - Operações de criptografia e descriptografia podem ser mais lentas que o ECC, especialmente para chaves maiores
