import datetime
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from pydantic import BaseModel
import paramiko
import psycopg2
import os
from dotenv import load_dotenv
from urllib.parse import quote

# Carregar as variáveis de ambiente do arquivo .env
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", 5432)  # Porta padrão 5432 se não definida
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# Configuração de logging
logging.basicConfig(
    filename='backup_scheduler.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Escapar a senha para uso seguro na URL
DB_PASSWORD_ESCAPED = quote(DB_PASSWORD)

# Gerar a URL dinâmica do banco de dados
DB_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD_ESCAPED}@{DB_HOST}:{DB_PORT}/{DB_DATABASE}"

# Configuração do Job Store para PostgreSQL
jobstores = {
    'default': SQLAlchemyJobStore(
        url=DB_URL,
        engine_options={'pool_pre_ping': True}
    )
}
executors = {
    'default': ThreadPoolExecutor(20)
}
job_defaults = {
    'coalesce': False,
    'max_instances': 3,
    'misfire_grace_time': 350
}

scheduler = BackgroundScheduler(
    jobstores=jobstores,
    executors=executors,
    job_defaults=job_defaults,
    timezone='America/Sao_Paulo'
)

class ScheduleBackupRequest(BaseModel):
    ip: str
    database: str
    frequency: str
    day_of_week: str = None
    day_of_month: int = None
    hour: int = 0
    minute: int = 0

def get_db_connection():
    return psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,  # Adicionando a porta
            database=DB_DATABASE,
            user=DB_USER,
            password=DB_PASSWORD
        )

def get_vm_access_data(ip: str, client_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT ip_storage, ssh_user_storage, ssh_password_storage, user_pg, password_pg
            FROM vm_access
            WHERE ip = %s AND client_id = %s
            """,
            (ip, client_id)
        )
        row = cursor.fetchone()
        if row:
            return {
                "ip_storage": row[0],
                "ssh_user_storage": row[1],
                "ssh_password_storage": row[2],
                "user_pg": row[3],
                "password_pg": row[4]
            }
        return None
    except Exception as e:
        logger.error(f"Erro ao obter dados de acesso da VM com IP {ip} e client_id {client_id}: {str(e)}")
        return None
    finally:
        cursor.close()
        connection.close()

def perform_backup(ip: str, database: str, client_id: int, job_id: str):
    # Atualizar o status para 'em andamento' e registrar o start_time
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE client_backups
            SET status = %s, start_time = %s
            WHERE job_id = %s AND client_id = %s
            """,
            ('em andamento', datetime.datetime.now(), job_id, client_id)
        )
        connection.commit()
    except Exception as e:
        logger.error(f"Erro ao atualizar status do backup no início: {e}")
    finally:
        cursor.close()
        connection.close()

    access_data = get_vm_access_data(ip, client_id)
    if not access_data:
        logger.error(f"Dados de acesso para a VM {ip} do cliente {client_id} não encontrados.")
        # Atualizar o status para 'falha'
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE client_backups
                SET status = %s
                WHERE job_id = %s AND client_id = %s
                """,
                ('falha', job_id, client_id)
            )
            connection.commit()
        except Exception as e:
            logger.error(f"Erro ao atualizar status do backup após falha: {e}")
        finally:
            cursor.close()
            connection.close()
        return

    storage_ip = access_data["ip_storage"]
    ssh_user = access_data["ssh_user_storage"]
    ssh_password = access_data["ssh_password_storage"]
    pg_user = access_data["user_pg"]
    pg_password = access_data["password_pg"]

    if not all([storage_ip, ssh_user, ssh_password, pg_user, pg_password]):
        logger.error(f"Dados incompletos para a VM {ip} do cliente {client_id}.")
        # Atualizar o status para 'falha'
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE client_backups
                SET status = %s
                WHERE job_id = %s AND client_id = %s
                """,
                ('falha', job_id, client_id)
            )
            connection.commit()
        except Exception as e:
            logger.error(f"Erro ao atualizar status do backup após falha: {e}")
        finally:
            cursor.close()
            connection.close()
        return

    try:
        logger.info(f"Conectando ao IP {storage_ip} com usuário {ssh_user}.")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(storage_ip, username=ssh_user, password=ssh_password)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = "/home/bkp_bd"
        backup_file = f"{backup_dir}/{database}_{timestamp}_backup.dump"
        pg_dump_path = "/usr/bin/pg_dump"

        command_backup = (
            f"mkdir -p {backup_dir} && "
            f"export PGPASSWORD='{pg_password}' && "
            f"{pg_dump_path} -h {ip} -U {pg_user} -F c -d {database} -f {backup_file}"
        )
        logger.info(f"Executando comando de backup: {command_backup}")
        stdin, stdout, stderr = ssh.exec_command(command_backup)

        output_backup = stdout.read().decode().strip()
        error_backup = stderr.read().decode().strip()

        if error_backup:
            logger.error(f"Erro ao realizar backup: {error_backup}")
            status = 'falha'
        else:
            status = 'finalizado'
            command_size = f"du -h {backup_file} | cut -f1"
            stdin, stdout, stderr = ssh.exec_command(command_size)
            size_output = stdout.read().decode().strip()
            size_error = stderr.read().decode().strip()

            if size_error:
                dump_size = "Desconhecido"
                logger.error(f"Erro ao obter tamanho do dump: {size_error}")
            else:
                dump_size = size_output
                logger.info(f"Backup concluído com tamanho: {dump_size}")

        ssh.close()

    except paramiko.ssh_exception.AuthenticationException as e:
        logger.error(f"Erro de autenticação: {e}")
        status = 'falha'
    except Exception as e:
        logger.exception(f"Erro ao realizar backup: {e}")
        status = 'falha'

    # Atualizar o status e o end_time
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE client_backups
            SET status = %s, end_time = %s
            WHERE job_id = %s AND client_id = %s
            """,
            (status, datetime.datetime.now(), job_id, client_id)
        )
        connection.commit()
    except Exception as e:
        logger.error(f"Erro ao atualizar status do backup no final: {e}")
    finally:
        cursor.close()
        connection.close()

def schedule_backup(request: ScheduleBackupRequest, client_id: int):
    database = request.database
    frequency = request.frequency.lower()
    hour = request.hour
    minute = request.minute
    ip = request.ip

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM client_backups WHERE client_id = %s",
            (client_id,)
        )
        current_backups = cursor.fetchone()[0]

        cursor.execute(
            "SELECT max_backups FROM clients WHERE id = %s",
            (client_id,)
        )
        max_backups = cursor.fetchone()[0]

        if current_backups >= max_backups:
            return {"Error": f"Limite de backups atingido ({max_backups})."}

        if frequency == 'once':
            run_date = datetime.datetime.now() + datetime.timedelta(minutes=1)
            trigger = 'date'
            trigger_args = {'run_date': run_date}
        elif frequency == 'daily':
            trigger = 'cron'
            trigger_args = {'hour': hour, 'minute': minute}
        elif frequency == 'weekly':
            if not request.day_of_week:
                return {"Error": "Dia da semana obrigatório para frequência semanal."}
            trigger = 'cron'
            trigger_args = {'day_of_week': request.day_of_week, 'hour': hour, 'minute': minute}
        elif frequency == 'monthly':
            if not request.day_of_month:
                return {"Error": "Dia do mês obrigatório para frequência mensal."}
            trigger = 'cron'
            trigger_args = {'day': request.day_of_month, 'hour': hour, 'minute': minute}
        else:
            return {"Error": "Frequência inválida."}

        job_id = f"backup_{client_id}_{database}_{frequency}_{hour}_{minute}"
        if frequency == 'monthly':
            job_id += f"_day_{request.day_of_month}"
        elif frequency == 'weekly':
            job_id += f"_day_{request.day_of_week}"

        job = scheduler.add_job(
            perform_backup,
            trigger=trigger,
            args=[ip, database, client_id, job_id],
            id=job_id,
            replace_existing=True,
            **trigger_args
        )

        # Inserir no banco de dados com status 'agendado'
        cursor.execute(
            """
            INSERT INTO client_backups (client_id, job_id, vm_ip, database_name, status)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (client_id, job.id, ip, database, 'agendado')
        )
        connection.commit()

        logger.info(f"Backup agendado com sucesso para {ip}, banco {database}.")
        return {"message": "Backup agendado com sucesso.", "job_id": job.id}

    except Exception as e:
        logger.exception(f"Erro ao agendar backup: {e}")
        return {"Error": f"Erro ao agendar backup: {e}"}
    finally:
        cursor.close()
        connection.close()
