import socket
import hmac
import hashlib

# Chave secreta compartilhada
chave_secreta = b'filmedaDisney'

# Cria o socket
servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define o host e a porta
host = 'localhost'
porta = 5000

# Liga o socket ao host e à porta
servidor.bind((host, porta))

# Escuta por conexões
servidor.listen(1)
print("Servidor esperando conexões em", host, ":", porta)

# Função para autenticar mensagens
def autenticar_mensagem(dados):
    mensagem, recebido_hmac = dados[:-32], dados[-32:]
    hmac_calculado = hmac.new(chave_secreta, mensagem, hashlib.sha256).digest()
    return hmac.compare_digest(hmac_calculado, recebido_hmac), mensagem

# Aceita uma conexão
conexao, endereco = servidor.accept()
print("Conectado por", endereco)

# Loop para recebimento e envio de mensagens
while True:
    dados = conexao.recv(1024)
    if not dados:
        break
    
    # Verifica se é comando de sair
    if dados.decode() == '/sair':
        print("Cliente encerrou a conexão.")
        break

    # Autentica a mensagem recebida
    autenticado, mensagem = autenticar_mensagem(dados)
    if autenticado:
        print("Cliente:", mensagem.decode())
        resposta = input("Você: ")
        conexao.send(resposta.encode())
    else:
        print("Mensagem não autenticada.")
        conexao.send('HMAC inválido'.encode())

conexao.close()
