from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def generate_signature_and_verify(message, curve):
    # Geração das chaves ECC
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    # Geração da assinatura
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    # Verificação da assinatura
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print("A verificação da assinatura foi bem-sucedida.")
    except InvalidSignature:
        print("A verificação da assinatura falhou.")

    # Retornar o tamanho da assinatura
    return len(signature)

message = input("Digite a mensagem que deseja assinar: ").encode()

# Lista de curvas elípticas para experimentação
curves = [
    ec.SECP256R1(),  # Curva elíptica P-256
    ec.SECP384R1(),  # Curva elíptica P-384
    ec.SECP521R1()   # Curva elíptica P-521
]

print("Tamanhos das assinaturas para diferentes curvas elípticas:")

for curve in curves:
    signature_size = generate_signature_and_verify(message, curve)
    print(f"Tamanho da assinatura (para {curve.name}): {signature_size} bytes")
