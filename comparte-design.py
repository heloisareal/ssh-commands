import tkinter as tk
from tkinter import messagebox, filedialog
import paramiko
import threading
import time

# Global list to store connected devices and their SSH connections
connected_devices = []
ssh_clients = {}

# Função para executar comandos de maneira interativa no SSH
def execute_command_interactively(ssh_client, command):
    if not command.strip():
        return "Command is empty, skipping."

    try:
        # Abrir um canal de execução interativa
        channel = ssh_client.get_transport().open_session()
        channel.get_pty()  # Necessário para abrir um terminal
        channel.invoke_shell()  # Inicia o shell interativo

        # Enviar o comando para o shell
        channel.send(command + "\n")

        # Aguardar até que o comando seja executado
        output = ""
        time.sleep(1)  # Pequena pausa para garantir que a resposta seja processada

        while True:
            if channel.recv_ready():
                output += channel.recv(1024).decode()  # Leitura do buffer do canal

            # Verifica se a execução do comando terminou
            if channel.exit_status_ready():
                break
            time.sleep(0.1)  # Atraso para evitar sobrecarga da CPU

        return output.strip()  # Retorna a saída do comando sem espaços extras

    except Exception as e:
        return f"Error executing command: {str(e)}"

# Função para mostrar o progresso e resultado dos comandos
def update_progress(progress_text, message):
    progress_text.insert(tk.END, message + "\n")
    progress_text.yview(tk.END)
    progress_text.update_idletasks()

# Função para comparar comandos
def compare_commands():
    commands_file = filedialog.askopenfilename(filetypes=[("TXT Files", "*.txt")])
    if commands_file:
        try:
            # Lê os comandos do arquivo
            with open(commands_file, 'r') as file:
                commands = file.readlines()

            # Cria um arquivo para salvar os resultados
            result_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("TXT Files", "*.txt")])

            if not result_file:
                return  # Se o usuário não escolher o arquivo para salvar, aborta

            # Função para executar os comandos em todos os dispositivos conectados
            def execute_commands_on_devices(progress_text):
                all_results = ""
                for ip in connected_devices:
                    all_results += f"Results for {ip}:\n"
                    update_progress(progress_text, f"Executing commands on {ip}...")
                    ssh_client = ssh_clients.get(ip)
                    if ssh_client:
                        for command in commands:
                            try:
                                update_progress(progress_text, f"Running command: {command.strip()}")
                                output = execute_command_interactively(ssh_client, command.strip())
                                all_results += f"Command: {command.strip()}\n"
                                all_results += f"Output:\n{output}\n"
                                all_results += "-" * 50 + "\n"
                            except Exception as e:
                                all_results += f"Failed to execute command: {command.strip()}\nError: {str(e)}\n"
                                all_results += "-" * 50 + "\n"

                # Salva os resultados no arquivo
                with open(result_file, 'w') as result:
                    result.write(all_results)
                messagebox.showinfo("Success", "Commands executed and results saved successfully!")

            # Cria uma janela de progresso
            progress_window = tk.Toplevel()
            progress_window.title("Command Execution Progress")

            progress_text = tk.Text(progress_window, height=15, width=80)
            progress_text.pack(padx=10, pady=10)
            
            # Executa os comandos em uma thread separada
            threading.Thread(target=execute_commands_on_devices, args=(progress_text,)).start()

        except Exception as e:
            messagebox.showerror("Error", f"Error reading the commands file: {str(e)}")

# Função para remover IP
def remove_ip(devices_list):
    try:
        selected = devices_list.curselection()  # Get the selected IP from the list
        if not selected:
            messagebox.showerror("Error", "No IP selected for removal.")
            return
        
        # Retrieve the IP from the list and remove the prefix
        ip = devices_list.get(selected).replace("Connected: ", "")
        
        # Remove the IP from the list of connected devices
        if ip in connected_devices:
            connected_devices.remove(ip)

            # Close the SSH connection for the selected IP
            ssh_client = ssh_clients.get(ip)
            if ssh_client:
                ssh_client.close()  # Close the SSH connection for the selected device
                print(f"Disconnected from {ip}")
                del ssh_clients[ip]  # Remove the SSH client reference

            # Remove the IP from the listbox
            devices_list.delete(selected)

            # Update options when an IP is removed
            update_options(devices_list)

            # Inform the user that the IP has been removed
            messagebox.showinfo("Removed", f"The IP {ip} has been removed.")
        else:
            messagebox.showerror("Error", "IP not found in connected devices.")
    except Exception as e:
        messagebox.showerror("Error", f"Error removing the IP: {str(e)}")

# Função para habilitar as opções quando dois ou mais IPs estiverem conectados
def update_options(devices_list):
    if len(connected_devices) >= 2:
        options_button.config(state=tk.NORMAL)  # Enable the options button
    else:
        options_button.config(state=tk.DISABLED)  # Disable the button if there are less than 2 IPs

# Função para abrir as opções de configuração
def open_options_screen():
    options_screen = tk.Toplevel()
    options_screen.title("Connection Options")

    tk.Label(options_screen, text="Options for connected IPs:", font=("Arial", 14)).pack(pady=10)

    # Display connected IPs
    tk.Label(options_screen, text="Connected IPs:").pack(pady=5)
    ip_list = tk.Listbox(options_screen, height=5, width=50)
    for ip in connected_devices:
        ip_list.insert(tk.END, ip)
    ip_list.pack(pady=10)

    # Botão para rodar os comandos de comparação
    tk.Button(options_screen, text="Compare Commands", command=compare_commands).pack(pady=10)
    tk.Button(options_screen, text="Close", command=options_screen.destroy).pack(pady=10)

# Função para abrir a tela de login
def validate_login():
    username = entry_username.get()
    password = entry_password.get()

    if username == "heloreal" and password == "real":
        login_screen.destroy()
        open_main_screen()
    else:
        messagebox.showerror("Error", "Incorrect username or password.")

# Função para abrir a tela principal
def open_main_screen():
    global root
    root = tk.Tk()
    root.title("SSH Connection")

    tk.Label(root, text="Choose the connection method", font=("Arial", 14)).pack(pady=20)

    tk.Button(root, text="Enter IP and Password", command=open_connection_screen).pack(pady=10)
    tk.Button(root, text="Load TXT File", command=open_txt_screen).pack(pady=10)
    tk.Button(root, text="Exit", command=root.quit).pack(pady=10)

    root.mainloop()

# Função para abrir a tela de abrir arquivo TXT
def open_txt_screen():
    commands_file = filedialog.askopenfilename(filetypes=[("TXT Files", "*.txt")])
    if commands_file:
        try:
            # Lê os comandos do arquivo
            with open(commands_file, 'r') as file:
                commands = file.readlines()

            # Exibe os comandos na tela de progresso
            print(f"Comandos carregados: {len(commands)} comandos.")
            messagebox.showinfo("File Loaded", f"Successfully loaded {len(commands)} commands.")
        except Exception as e:
            messagebox.showerror("Error", f"Error loading the file: {str(e)}")

# Função para abrir a tela de conexão
def open_connection_screen():
    connection_screen = tk.Toplevel()
    connection_screen.title("SSH Connection - Enter IP")

    tk.Label(connection_screen, text="Enter IP, Username, Password, and Port", font=("Arial", 14)).pack(pady=10)

    tk.Label(connection_screen, text="IP Address:").pack(pady=5)
    entry_ip = tk.Entry(connection_screen)
    entry_ip.pack(pady=5)

    tk.Label(connection_screen, text="Username:").pack(pady=5)
    entry_user = tk.Entry(connection_screen)
    entry_user.insert(0, "secadmin")  # Default username
    entry_user.pack(pady=5)

    tk.Label(connection_screen, text="Password:").pack(pady=5)
    entry_password = tk.Entry(connection_screen, show="*")
    entry_password.insert(0, "Infinera2!")  # Default password
    entry_password.pack(pady=5)

    tk.Label(connection_screen, text="Port:").pack(pady=5)
    entry_port = tk.Entry(connection_screen)
    entry_port.insert(0, "22")  # Default port
    entry_port.pack(pady=5)

    devices_list = tk.Listbox(connection_screen, height=5, width=50)
    devices_list.pack(pady=10)

    def connect_ssh():
        ip = entry_ip.get()
        password = entry_password.get()
        ssh_user = entry_user.get()
        port = int(entry_port.get())  # Get port from input field

        def try_connection():
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(ip, username=ssh_user, password=password, port=port, timeout=5)
                
                if ip not in connected_devices:
                    connected_devices.append(ip)
                    devices_list.insert(tk.END, f"Connected: {ip}")
                    ssh_clients[ip] = ssh_client  # Store the SSH connection of the device
                    update_options(devices_list)  # Update options when a new IP is added
                else:
                    messagebox.showinfo("Connection", f"Already connected to {ip}")

                # Execute the 'show session' command to ensure the connection is successful
                stdin, stdout, stderr = ssh_client.exec_command("show session")
                output = stdout.read().decode()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to connect: {e}")

        threading.Thread(target=try_connection).start()

    tk.Button(connection_screen, text="Connect", command=connect_ssh).pack(pady=10)
    tk.Button(connection_screen, text="Remove IP", command=lambda: remove_ip(devices_list)).pack(pady=10)
    global options_button
    options_button = tk.Button(connection_screen, text="Options", command=open_options_screen, state=tk.DISABLED)
    options_button.pack(pady=10)
    tk.Button(connection_screen, text="Close", command=connection_screen.destroy).pack(pady=10)

# Tela de login
login_screen = tk.Tk()
login_screen.title("SSH Login")

tk.Label(login_screen, text="Enter your credentials", font=("Arial", 14)).pack(pady=20)

# Username
label_username = tk.Label(login_screen, text="Username:")
label_username.pack(pady=5)
entry_username = tk.Entry(login_screen)
entry_username.pack(pady=5)

# Password
label_password = tk.Label(login_screen, text="Password:")
label_password.pack(pady=5)
entry_password = tk.Entry(login_screen, show="*")
entry_password.pack(pady=5)

# Login button
login_button = tk.Button(login_screen, text="Login", command=validate_login)
login_button.pack(pady=20)

login_screen.mainloop()
