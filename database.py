import psycopg2
import logging
import os
from dotenv import load_dotenv

# Carregar as variáveis de ambiente do arquivo .env
load_dotenv()

# Configuração de logging
logging.basicConfig(
    filename='database.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configurações do banco de dados a partir do .env
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", 5432)  # Porta padrão 5432 se não definida
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

def get_db_connection():
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
        print("Erro ao conectar ao banco de dados.")
        exit(1)

def get_vm_by_ip(ip: str, client_id: int):
    """
    Retorna as informações da VM com base no IP fornecido e client_id.
    """
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT vm_ip, ssh_user, ssh_password, pg_user, pg_password, has_postgre
            FROM clients
            WHERE vm_ip = %s AND id = %s
            """,
            (ip, client_id)
        )
        result = cursor.fetchone()
        if not result:
            return None
        vm_ip, ssh_user, ssh_password, pg_user, pg_password, has_postgre = result
        return {
            "vm_ip": vm_ip,
            "ssh_user": ssh_user,
            "ssh_password": ssh_password,
            "pg_user": pg_user,
            "pg_password": pg_password,
            "has_postgre": has_postgre
        }
    except psycopg2.Error as e:
        logger.error(f"Erro ao buscar VM por IP {ip}: {e}")
        return None
    finally:
        cursor.close()
        connection.close()

def get_vms_from_db(client_id: int):
    """
    Retorna todas as VMs associadas a um client_id.
    """
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT vm_ip, ssh_user, ssh_password, has_postgre, pg_user, pg_password, name
            FROM clients
            WHERE id = %s
            """,
            (client_id,)
        )
        results = cursor.fetchall()
        vms = []
        for row in results:
            vm_ip, ssh_user, ssh_password, has_postgre, pg_user, pg_password, name = row
            vms.append({
                "vm_ip": vm_ip,
                "ssh_user": ssh_user,
                "ssh_password": ssh_password,
                "has_postgre": has_postgre,
                "pg_user": pg_user,
                "pg_password": pg_password,
                "name": name
            })
        return vms
    except psycopg2.Error as e:
        logger.error(f"Erro ao buscar VMs para client_id {client_id}: {e}")
        return []
    finally:
        cursor.close()
        connection.close()
