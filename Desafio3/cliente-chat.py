import socket
import hmac
import hashlib

# Chave secreta compartilhada
chave_secreta = b'filmedaDisney'

# Cria o socket
cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define o host e a porta para conectar
host = 'localhost'
porta = 5000

# Conecta ao servidor
cliente.connect((host, porta))
print("Conectado ao servidor.")

# Função para enviar mensagens ao servidor
def enviar_mensagem(mensagem):
    hmac_calculado = hmac.new(chave_secreta, mensagem.encode(), hashlib.sha256).digest()
    mensagem_com_hmac = mensagem.encode() + hmac_calculado
    cliente.send(mensagem_com_hmac)

# Loop para envio de mensagens
while True:
    mensagem = input("Você: ")
    if mensagem.lower() == '/sair':
        enviar_mensagem('/sair')
        print("Encerrando conexão.")
        break
    enviar_mensagem(mensagem)
    dados = cliente.recv(1024).decode()
    print("Servidor:", dados)

cliente.close()
