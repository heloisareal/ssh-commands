import paramiko
import os

# Credenciais para login
LOGIN_USER = "heloreal"  # Alterável para o perfil
LOGIN_PASS = "real"  # Alterável para o perfil

# Credenciais SSH padrão
SSH_USER = "secadmin"  # Usuário em casos esporádicos
SSH_PASS = "Infinera2!"  # Senha padrão
SSH_PORT = 22  # Porta padrão

# Lista para armazenar conexões ativas
connections = {}

def mostrar_instrucoes():
    """Exibe as instruções do programa."""
    while True:
        print("\n📌 INSTRUÇÕES:")
        print("1️⃣ Para conectar um equipamento, insira o IP corretamente.")
        print("2️⃣ Digite 'over' para parar de conectar e realizar ações nos dispositivos.")
        print("3️⃣ Utilize a opção 'Funções' para interagir com os equipamentos conectados.")
        print("\n🔙 Pressione 'v' para voltar.")

        escolha = input("> ").strip().lower()
        if escolha == "v":
            break

def fazer_login():
    """Solicita credenciais para login."""
    while True:
        print("\n🔐 LOGIN:")
        usuario = input("Usuário: ").strip()
        senha = input("Senha: ").strip()

        if usuario == LOGIN_USER and senha == LOGIN_PASS:
            print("\n✅ Login bem-sucedido!\n")
            return True
        else:
            print("❌ Usuário ou senha incorretos! Tente novamente.\n")

def ssh_connect(host, password):
    """Realiza conexão SSH e armazena a conexão ativa."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=SSH_USER, password=password, port=SSH_PORT, timeout=5)
        
        shell = client.invoke_shell()  # Criando uma sessão interativa
        connections[host] = (client, shell)  # Salva a conexão ativa
        print(f"✅ Conectado a {host}!")
    
    except Exception as e:
        print(f"⚠️ Erro ao conectar em {host}: {e}\n")

def fazer_multiplas_conexoes():
    """Gerencia conexões SSH e permite executar ações nos dispositivos conectados."""
    print("\n🔗 MULTIPLAS CONEXÕES SSH 🔗")
    print("Digite os IPs para conectar. Digite 'over' para ir para as funções.\n")

    while True:
        ip = input("Digite o IP para conectar: ").strip()
        
        if ip.lower() == "over":
            if connections:
                menu_funcoes()
            else:
                print("⚠️ Nenhum dispositivo conectado. Conecte pelo menos um antes de continuar.")
            break
        
        if ip in connections:
            print(f"⚠️ Já conectado a {ip}!\n")
            continue
        
        escolha_senha = input(f"Deseja inserir uma senha diferente para {ip}? (s/n): ").strip().lower()
        if escolha_senha == "s":
            senha_personalizada = input("Digite a senha para este equipamento: ").strip()
            ssh_connect(ip, senha_personalizada)
        else:
            ssh_connect(ip, SSH_PASS)

def executar_ping():
    """Executa o comando ping para verificar a conectividade com os dispositivos conectados."""
    if not connections:
        print("⚠️ Nenhum dispositivo conectado!")
        return

    print("\n📡 Verificando conectividade com os dispositivos conectados...")

    for host in connections.keys():
        response = os.system(f"ping -c 3 {host}" if os.name != "nt" else f"ping -n 3 {host}")

        if response == 0:
            print(f"✅ {host} está acessível!")
        else:
            print(f"❌ {host} não está respondendo ao ping!")

def menu_funcoes():
    """Exibe as opções disponíveis para os dispositivos conectados."""
    while True:
        print("\n🔹 DISPOSITIVOS CONECTADOS NO MOMENTO🔹")
        for host in connections:
            print(f"✅ {host}")

        print("\n🔧 FUNÇÕES:")
        print("1️⃣  Executar Ping")
        print("2️⃣  Desconectar de Todos os Dispositivos")
        print("🔙  Pressione 'v' para voltar")

        opcao = input("> ").strip()

        if opcao == "1":
            executar_ping()
        elif opcao == "2":
            desconectar_todos()
            break
        elif opcao == "v":
            break

def desconectar_todos():
    """Fecha todas as conexões SSH ativas."""
    print("\nFinalizando conexões...")
    for host, (client, _) in connections.items():
        client.close()
        print(f"🔴 Desconectado de {host}")
    connections.clear()

def menu_principal():
    """Menu inicial do programa"""
    while True:
        print("\n🎛️  BEM-VINDO AO GX AUTOMATION TOOL 🎛️")
        print("1️⃣  Verificar instruções")
        print("2️⃣  Fazer Login")
        print("🛑  Digite 'sair' para encerrar")

        escolha = input("> ").strip()

        if escolha == "1":
            mostrar_instrucoes()
        elif escolha == "2":
            if fazer_login():
                while True:
                    print("\n🔹 MENU PÓS-LOGIN 🔹")
                    print("1️⃣ Fazer Múltiplas Conexões")
                    print("🔙 Pressione 'v' para voltar")

                    opcao = input("> ").strip()

                    if opcao == "1":
                        fazer_multiplas_conexoes()
                    elif opcao == "v":
                        break
        elif escolha.lower() == "sair":
            print("\n👋 Saindo do GX Automation Tool...")
            break

if __name__ == "__main__":
    menu_principal()
