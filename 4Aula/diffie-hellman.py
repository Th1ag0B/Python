from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_parameters

def generate_shared_key(key_size):
    # Parâmetros Diffie-Hellman
    parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())

    # Serialização dos parâmetros para compartilhamento
    pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    )

    # Chaves públicas e privadas da parte 1
    private_key1 = parameters.generate_private_key()
    public_key1 = private_key1.public_key()

    # A parte 1 envia os parâmetros DH e a chave pública para a parte 2
    # por um canal inseguro sem problema algum, pois os parâmetros DH são públicos
    print("Parâmetros DH:", pem)

    # Deserialização dos parâmetros DH recebidos
    parameters_received = load_pem_parameters(pem, backend=default_backend())

    # Chaves públicas e privadas da parte 2, são geradas com os parâmetros DH recebidos da parte 1
    private_key2 = parameters_received.generate_private_key()
    public_key2 = private_key2.public_key()
    shared_key2 = private_key2.exchange(public_key1)

    # A parte 2 envia a chave pública para a parte 1
    # A parte 1 gera a chave compartilhada com a chave pública recebida da parte 2
    shared_key1 = private_key1.exchange(public_key2)

    return shared_key1, shared_key2

def verify_shared_key(shared_key1, shared_key2):
    return shared_key1 == shared_key2

# Solicitar ao usuário o tamanho da chave
key_size = int(input("Digite o tamanho da chave em bits (por exemplo, 512, 1024, 2048): "))

# Gerar e verificar a chave compartilhada
shared_key1, shared_key2 = generate_shared_key(key_size)
if verify_shared_key(shared_key1, shared_key2):
    print("Chave compartilhada verificada com sucesso:", shared_key1.hex())
else:
    print("Erro: A chave compartilhada não coincide em ambas as extremidades.")
