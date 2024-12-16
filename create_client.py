# create_client.py

import psycopg2
import bcrypt
import os
import logging
from getpass import getpass
from dotenv import load_dotenv

# Carregar as variáveis de ambiente do arquivo .env
load_dotenv()


# Configurações do banco de dados a partir do .env
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", 5432)  # Porta padrão 5432 se não definida
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# Configuração de logging
logging.basicConfig(
    filename='create_client.log',  # Arquivo de log
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("create_client")

def get_db_connection():
    """
    Estabelece uma conexão com o banco de dados PostgreSQL.
    Atualize as credenciais conforme necessário.
    """
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,  # Adicionando a porta
            database=DB_DATABASE,
            user=DB_USER,
            password=DB_PASSWORD
        )


        return conn
    except psycopg2.Error as e:
        logger.error(f"Erro ao conectar ao banco de dados: {e}")
        print("Erro ao conectar ao banco de dados. Verifique as configurações.")
        exit(1)

def hash_password(plain_password: str) -> str:
    """
    Gera um hash seguro para a senha fornecida.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def create_client(name: str, username: str, plain_password: str, max_backups: int = 3,
                 ssh_user: str = "", ssh_password: str = "",
                 pg_user: str = "", pg_password: str = "", vm_ip: str = ""):
    """
    Insere um novo cliente na tabela 'clients' com os campos adicionais.
    """
    hashed_password = hash_password(plain_password)
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        # Verificar se o username já existe
        cursor.execute(
            "SELECT id FROM clients WHERE username = %s",
            (username,)
        )
        if cursor.fetchone():
            print("Erro: Nome de usuário já existe. Por favor, escolha outro.")
            logger.warning(f"Tentativa de criação de cliente com username existente: {username}")
            return

        # Inserir o novo cliente na tabela 'clients' com os campos adicionais
        cursor.execute(
            """
            INSERT INTO clients (name, username, password, max_backups, ssh_user, ssh_password, pg_user, pg_password, vm_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                name,
                username,
                hashed_password,
                max_backups,
                ssh_user,
                ssh_password,  # Armazenado em texto plano
                pg_user,
                pg_password,    # Armazenado em texto plano
                vm_ip
            )
        )
        connection.commit()
        print(f"Cliente '{name}' criado com sucesso.")
        logger.info(f"Novo cliente criado: {name} (Username: {username})")
    except psycopg2.Error as e:
        connection.rollback()
        print(f"Erro ao criar cliente: {e}")
        logger.error(f"Erro ao criar cliente '{username}': {e}")
    finally:
        cursor.close()
        connection.close()

def create_client_interactive():
    """
    Solicita informações do usuário para criar um novo cliente e insere no banco de dados.
    """
    print("\n=== Criar Novo Cliente ===")
    try:
        name = input("Nome do Cliente: ").strip()
        username = input("Nome de Usuário: ").strip()
        
        # Solicitar senha do cliente com mínimo de 6 caracteres
        while True:
            password = getpass("Senha do Cliente (mín. 6 caracteres): ").strip()
            if len(password) < 6:
                print("Erro: A senha deve ter pelo menos 6 caracteres. Tente novamente.")
            else:
                break
        
        # Solicitar confirmação da senha do cliente
        while True:
            confirm_password = getpass("Confirme a Senha do Cliente: ").strip()
            if password != confirm_password:
                print("Erro: As senhas não correspondem. Tente novamente.")
            else:
                break
        
        # Solicitar número máximo de backups
        while True:
            max_backups_input = input("Número máximo de backups permitidos: ").strip()
            try:
                max_backups = int(max_backups_input)
                if max_backups < 1:
                    raise ValueError
                break
            except ValueError:
                print("Erro: Insira um número inteiro válido maior ou igual a 1.")
        
        print("\n=== Detalhes da VM de Armazenamento ===")
        vm_ip = input("IP da VM de Armazenamento: ").strip()
        ssh_user = input("Usuário SSH da VM de Armazenamento: ").strip()
        
        # Solicitar senha SSH da VM com mínimo de 6 caracteres
        while True:
            ssh_password = getpass("Senha SSH da VM de Armazenamento (mín. 6 caracteres): ").strip()
            if len(ssh_password) < 6:
                print("Erro: A senha SSH deve ter pelo menos 6 caracteres. Tente novamente.")
            else:
                break

        print("\n=== Credenciais do PostgreSQL ===")
        pg_user = input("Usuário do PostgreSQL: ").strip()
        
        # Solicitar senha do PostgreSQL com mínimo de 6 caracteres
        while True:
            pg_password = getpass("Senha do PostgreSQL (mín. 6 caracteres): ").strip()
            if len(pg_password) < 6:
                print("Erro: A senha do PostgreSQL deve ter pelo menos 6 caracteres. Tente novamente.")
            else:
                break

        # Chamar a função para criar o cliente
        create_client(
            name=name,
            username=username,
            plain_password=password,
            max_backups=max_backups,
            ssh_user=ssh_user,
            ssh_password=ssh_password,
            pg_user=pg_user,
            pg_password=pg_password,
            vm_ip=vm_ip
        )

    except Exception as e:
        print(f"Erro inesperado: {e}")
        logger.error(f"Erro inesperado durante a entrada de dados: {e}")

def main():
    """
    Função principal que executa o menu interativo.
    """
    while True:
        print("\n=== Gerenciador de Backups - Criar Cliente ===")
        print("1. Criar Novo Cliente")
        print("2. Sair")
        choice = input("Escolha uma opção: ").strip()

        if choice == '1':
            create_client_interactive()
        elif choice == '2':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Por favor, tente novamente.")

if __name__ == "__main__":
    main()
