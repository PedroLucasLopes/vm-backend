# main.py

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import os
import datetime
import time
from pydantic import BaseModel
import paramiko
import psycopg2
import bcrypt
import logging
from vm_management import router as vm_management_router  # Importar o roteador
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from collections import deque
import threading
import re
import socket
import psycopg2


vm_metrics_cache = {}
vm_metrics_lock = threading.Lock()

# Carregar as variáveis de ambiente do arquivo .env
load_dotenv()

# Configurações do banco de dados a partir do .env
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", 5432)  # Porta padrão 5432 se não definida
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# Importações do módulo scheduler
from scheduler import (
    scheduler,
    ScheduleBackupRequest,
    perform_backup
)

app = FastAPI()

origins = ["http://localhost:3000", "http://example.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Domínios permitidos
    allow_credentials=True,  # Permitir envio de cookies/autenticação
    allow_methods=["*"],  # Métodos HTTP permitidos
    allow_headers=["*"],  # Cabeçalhos permitidos
)

app.include_router(vm_management_router)

security = HTTPBasic()

# Configuração de logging
logging.basicConfig(
    filename='backup_scheduler.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Função para conectar ao banco de dados
def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,  # Adicionando a porta
        database=DB_DATABASE,
        user=DB_USER,
        password=DB_PASSWORD
    )

# @app.websocket("/ws")
# async def websocket_endpoint(websocket: WebSocket):
#     await handle_websocket(websocket)

# Função de autenticação baseada em clientes com bcrypt
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        username = credentials.username
        password = credentials.password
        cursor.execute(
            "SELECT id, password FROM clients WHERE username = %s",
            (username,)
        )
        record = cursor.fetchone()
        if record:
            client_id = record[0]
            hashed_password = record[1]
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                return client_id
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Basic"},
        )
    finally:
        cursor.close()
        connection.close()

def get_vms(client_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT vm_name, ip, ssh_user, ssh_password, has_postgre, pg_user, pg_password, port, id, client_id
            FROM vm_access
            WHERE client_id = %s
            """,
            (client_id,)
        )
        rows = cursor.fetchall()
        vms = []
        for row in rows:
            vm = {
                "name": row[0],
                "ip": row[1],
                "ssh_user": row[2],
                "ssh_password": row[3],
                "has_postgre": row[4],
                "pg_user": row[5],
                "pg_password": row[6],
                "port": row[7],
                "id": row[8],
                "client_id": row[9]
            }
            vms.append(vm)
        return vms
    except Exception as e:
        logger.error(f"Erro ao obter VMs para o cliente {client_id}: {str(e)}")
        return []
    finally:
        cursor.close()
        connection.close()

def get_vm_by_ip(ip: str):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT vm_name, ip, ssh_user, ssh_password, has_postgre, pg_user, pg_password, port, id, client_id
            FROM vm_access
            WHERE ip = %s
            """,
            (ip,)
        )
        row = cursor.fetchone()
        if row:
            vm = {
                "name": row[0],
                "ip": row[1],
                "ssh_user": row[2],
                "ssh_password": row[3],
                "has_postgre": row[4],
                "pg_user": row[5],
                "pg_password": row[6],
                "port": row[7],
                "id": row[8],
                "client_id": row[9]
            }
            return vm
        return None
    except Exception as e:
        logger.error(f"Erro ao obter VM pelo IP {ip}: {str(e)}")
        return None
    finally:
        cursor.close()
        connection.close()

def execute_command_on_vm(ip, ssh_user, ssh_password, command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=ssh_user, password=ssh_password)

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        ssh.close()
        return output if output else error

    except Exception as e:
        logger.error(f"Erro ao executar comando na VM {ip}: {str(e)}")
        return str(e)

    
def check_vm_status(vms, client_id: int):
    results = []

    for vm in vms:
        ip = vm.get("ip")
        port = vm.get("port", 5432)
        vm_id = vm.get("id")
        client_id = vm.get("client_id")

        if not ip:
            logger.error(f"Cliente {client_id}: 'ip' não encontrado para uma VM.")
            results.append({
                "ID": vm_id,
                "Client ID": client_id,
                "Name": vm.get("name", "Unknown"),
                "IP": "Unknown",
                "Port": "Unknown",
                "Error": "'ip' não encontrado."
            })
            continue

        ssh_user = vm.get("ssh_user")
        ssh_password = vm.get("ssh_password")
        pg_user = vm.get("pg_user")
        pg_password = vm.get("pg_password")
        name = vm.get("name", "Unknown")

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=ssh_user, password=ssh_password, timeout=10)

            if pg_user and pg_password:
                # Verificar o status do PostgreSQL na porta especificada
                stdin, stdout, stderr = ssh.exec_command(f"sudo -H -u postgres systemctl is-active postgresql")
                postgres_status = stdout.read().decode().strip()

                # Conexão ao PostgreSQL usando a porta especificada
                connection_command = (
                    f"PGPORT={port} sudo -H -u postgres psql -t -c \"SELECT COUNT(*) FROM pg_stat_activity;\""
                )
                stdin, stdout, stderr = ssh.exec_command(connection_command)
                stdout.channel.recv_exit_status()  # Aguarda a conclusão do comando
                active_connections = stdout.read().decode().strip()

                # Verificar a versão do PostgreSQL na porta especificada
                version_command = f"PGPORT={port} sudo -H -u postgres psql -V"
                stdin, stdout, stderr = ssh.exec_command(version_command)
                postgres_version = stdout.read().decode().strip() if not stderr.read().decode().strip() else "Unknown"

                # Obter o máximo de conexões permitidas pelo PostgreSQL
                max_conn_command = (
                    f"PGPORT={port} sudo -H -u postgres psql -t -c \"SHOW max_connections;\""
                )
                stdin, stdout, stderr = ssh.exec_command(max_conn_command)
                stdout.channel.recv_exit_status()  # Aguarda a conclusão do comando
                max_connections = stdout.read().decode().strip()

                # Coletar estatísticas de leitura e escrita do banco de dados
                read_write_command = (
                    f"PGPORT={port} LANG=C sudo -H -u postgres psql --no-psqlrc -d postgres -t -A -F '|' -c \"SELECT "
                    f"COALESCE(SUM(tup_returned + tup_fetched), 0)::bigint, "
                    f"COALESCE(SUM(tup_inserted + tup_updated + tup_deleted), 0)::bigint "
                    f"FROM pg_stat_database;\" 2>/dev/null"
                )
                stdin, stdout, stderr = ssh.exec_command(read_write_command)
                stdout.channel.recv_exit_status()  # Aguarda a conclusão do comando
                read_write_output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()

                # Logar a saída bruta
                logger.debug(f"Raw read_write_output: '{read_write_output}'")
                logger.debug(f"Raw error_output: '{error_output}'")

                if error_output:
                    logger.error(f"Erro ao obter estatísticas de leitura/escrita do banco de dados: {error_output}")
                    total_reads = None
                    total_writes = None
                elif not read_write_output:
                    logger.error("A saída do comando read_write_command está vazia.")
                    total_reads = None
                    total_writes = None
                else:
                    try:
                        reads_str, writes_str = [s.strip() for s in read_write_output.strip().split('|')]
                        logger.debug(f"Before regex - reads_str: '{reads_str}', writes_str: '{writes_str}'")
                        # Remover quaisquer caracteres não numéricos
                        reads_str = re.sub(r'[^0-9]', '', reads_str)
                        writes_str = re.sub(r'[^0-9]', '', writes_str)
                        logger.debug(f"After regex - reads_str: '{reads_str}', writes_str: '{writes_str}'")
                        if reads_str.isdigit():
                            total_reads = int(reads_str)
                        else:
                            logger.error(f"Invalid reads_str after regex: '{reads_str}'")
                            total_reads = 0
                        if writes_str.isdigit():
                            total_writes = int(writes_str)
                        else:
                            logger.error(f"Invalid writes_str after regex: '{writes_str}'")
                            total_writes = 0
                    except Exception as e:
                        logger.error(f"Erro ao analisar estatísticas de leitura/escrita: {str(e)}")
                        total_reads = None
                        total_writes = None
            else:
                postgres_status = "Not Installed"
                active_connections = "N/A"
                postgres_version = "N/A"
                max_connections = "N/A"
                total_reads = None
                total_writes = None

            # Verificar espaço em disco
            stdin, stdout, stderr = ssh.exec_command("df -h --output=size,avail / | tail -1")
            disk_output = stdout.read().decode().strip()
            if disk_output:
                total_disk_space, free_disk_space = disk_output.split()
            else:
                total_disk_space = "Unknown"
                free_disk_space = "Unknown"

            cpu_command = (
                "LANG=C top -bn2 -d0.5 | grep 'Cpu(s)' | tail -n1 | "
                "sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'"
            )

            stdin, stdout, stderr = ssh.exec_command(cpu_command)
            stdout.channel.recv_exit_status()
            cpu_usage_output = stdout.read().decode().strip()
            error_output = stderr.read().decode().strip()

            if error_output:
                cpu_usage = "Unknown"
                cpu_usage_value = None
                logger.error(f"Error fetching CPU usage: {error_output}")
            elif cpu_usage_output:
                try:
                    cpu_usage_value = float(cpu_usage_output)
                    cpu_usage = f"{cpu_usage_value:.2f}%"
                except ValueError:
                    cpu_usage = "Unknown"
                    cpu_usage_value = None
                    logger.error(f"Invalid CPU usage value: {cpu_usage_output}")
            else:
                cpu_usage = "Unknown"
                cpu_usage_value = None
                logger.error("CPU usage output is empty")


            # Uso de memória em MB
            mem_command = "free -m | awk '/Mem:/ {print $2, $3}'"
            stdin, stdout, stderr = ssh.exec_command(mem_command)
            stdout.channel.recv_exit_status()
            mem_output = stdout.read().decode().strip()
            if mem_output:
                total_mem_str, used_mem_str = mem_output.split()
                total_mem = int(total_mem_str)  # Em MB
                used_mem = int(used_mem_str)    # Em MB
            else:
                total_mem = None
                used_mem = None

            # Uptime
            stdin, stdout, stderr = ssh.exec_command("uptime -p")
            stdout.channel.recv_exit_status()
            uptime = stdout.read().decode().strip().replace("up ", "")

            # Latência
            start_time = time.time()
            stdin, stdout, stderr = ssh.exec_command("echo teste")
            stdout.channel.recv_exit_status()  # Aguarda a conclusão do comando
            latency = (time.time() - start_time) * 1000  # Em milissegundos

            # Atualizar o cache com as novas métricas
            with vm_metrics_lock:
                if vm_id not in vm_metrics_cache:
                    vm_metrics_cache[vm_id] = {
                        'timestamps': deque(maxlen=20),
                        'cpu_usage': deque(maxlen=20),
                        'memory_usage': deque(maxlen=20),
                        'latency': deque(maxlen=20),
                        'db_reads': deque(maxlen=20),
                        'db_writes': deque(maxlen=20)
                    }
                vm_metrics_cache[vm_id]['timestamps'].append(datetime.datetime.now().isoformat())
                vm_metrics_cache[vm_id]['cpu_usage'].append(cpu_usage_value)
                vm_metrics_cache[vm_id]['memory_usage'].append(used_mem)
                vm_metrics_cache[vm_id]['latency'].append(latency)
                vm_metrics_cache[vm_id]['db_reads'].append(total_reads)
                vm_metrics_cache[vm_id]['db_writes'].append(total_writes)

                # Obter as métricas armazenadas
                timestamps = list(vm_metrics_cache[vm_id]['timestamps'])
                cpu_usages = list(vm_metrics_cache[vm_id]['cpu_usage'])
                mem_usages = list(vm_metrics_cache[vm_id]['memory_usage'])
                latencies = list(vm_metrics_cache[vm_id]['latency'])
                db_reads = list(vm_metrics_cache[vm_id]['db_reads'])
                db_writes = list(vm_metrics_cache[vm_id]['db_writes'])

            ssh.close()

            results.append({
                "ID": vm_id,
                "Client ID": client_id,
                "Name": name,
                "IP": ip,
                "Port": port,
                "PostgreSQL Status": "active" if postgres_status == "active" else "inactive" if pg_user and pg_password else "Not Installed",
                "Free Disk Space": free_disk_space,
                "Total Disk Space": total_disk_space,
                "Active Connections": active_connections,
                "Max Connections": max_connections,
                "CPU Usage": cpu_usage,
                "Memory Usage": f"{used_mem} MB" if used_mem else "Unknown",
                "Total Memory": f"{total_mem} MB" if total_mem else "Unknown",
                "Uptime": uptime,
                "PostgreSQL Version": postgres_version,
                "Response Time": f"{latency:.2f} ms",
                "Metrics History": {
                    "timestamps": timestamps,
                    "cpu_usage": cpu_usages,
                    "memory_usage": mem_usages,
                    "latency": latencies,
                    "db_reads": db_reads,
                    "db_writes": db_writes
                }
            })

        except Exception as e:
            logger.error(f"Erro ao monitorar VM {ip}: {str(e)}")
            results.append({
                "ID": vm_id,
                "Client ID": client_id,
                "Name": name,
                "IP": ip,
                "Port": port,
                "Error": str(e)
            })
        finally:
            ssh.close()

    return results
# Modelos de solicitação
class BackupRequest(BaseModel):
    ip: str
    database: str

class ControlRequest(BaseModel):
    ip: str
    action: str

class DumpAllRequest(BaseModel):
    ip: str

# Funções de agendamento, listagem e remoção de backups

def schedule_backup(request: ScheduleBackupRequest, get_vm_by_ip, client_id: int):
    ip = request.ip
    database = request.database
    frequency = request.frequency.lower()
    hour = request.hour
    minute = request.minute

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
            return {"Error": f"Limite de backups atingido ({max_backups}). Não é possível agendar novos backups."}

        if frequency == 'once':
            run_date = datetime.datetime.now() + datetime.timedelta(minutes=1)
            trigger = 'date'
            trigger_args = {'run_date': run_date}
        elif frequency == 'daily':
            trigger = 'cron'
            trigger_args = {'hour': hour, 'minute': minute}
        elif frequency == 'weekly':
            if not request.day_of_week:
                return {"Error": "Para backups semanais, o dia da semana deve ser especificado (e.g., 'mon', 'tue')."}
            trigger = 'cron'
            trigger_args = {'day_of_week': request.day_of_week, 'hour': hour, 'minute': minute}
        elif frequency == 'monthly':
            if not request.day_of_month:
                return {"Error": "Para backups mensais, o dia do mês deve ser especificado (e.g., 1, 15)."}
            trigger = 'cron'
            trigger_args = {'day': request.day_of_month, 'hour': hour, 'minute': minute}
        else:
            return {"Error": "Frequência inválida. Deve ser 'once', 'daily', 'weekly' ou 'monthly'."}

        job_id = f"backup_{client_id}_{database}_{frequency}_{hour}_{minute}"
        if frequency == 'monthly':
            job_id += f"_day_{request.day_of_month}"
        elif frequency == 'weekly':
            job_id += f"_day_{request.day_of_week}"

        try:
            job = scheduler.add_job(
                perform_backup,
                trigger=trigger,
                args=[ip, database, client_id, job_id],  # Passar job_id aqui
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

            logger.info(f"Cliente {client_id}: Agendado backup para VM {ip}, banco de dados {database}, frequência {frequency} às {hour:02d}:{minute:02d}.")

            return {"message": "Backup agendado com sucesso.", "job_id": job.id}
        except Exception as e:
            logger.exception(f"Erro ao agendar backup: {str(e)}")
            return {"Error": f"Erro ao agendar backup: {str(e)}"}
    finally:
        cursor.close()
        connection.close()

def list_backups(client_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT job_id, database_name, vm_ip, start_time, end_time, status
            FROM client_backups
            WHERE client_id = %s
            ORDER BY start_time DESC NULLS LAST
            """,
            (client_id,)
        )
        backups = cursor.fetchall()
        backup_list = []
        for backup in backups:
            backup_info = {
                "job_id": backup[0],
                "database_name": backup[1],
                "vm_ip": backup[2],
                "start_time": backup[3].isoformat() if backup[3] else None,
                "end_time": backup[4].isoformat() if backup[4] else None,
                "status": backup[5]
            }
            backup_list.append(backup_info)
        return {"scheduled_backups": backup_list}
    except Exception as e:
        logger.error(f"Erro ao listar backups: {e}")
        return {"Error": f"Erro ao listar backups: {e}"}
    finally:
        cursor.close()
        connection.close()

def remove_backup(job_id: str, client_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT id FROM client_backups WHERE job_id = %s AND client_id = %s",
            (job_id, client_id)
        )
        record = cursor.fetchone()
        if not record:
            return {"Error": "Agendamento não encontrado ou não pertence ao cliente."}

        scheduler.remove_job(job_id)
        cursor.execute(
            "DELETE FROM client_backups WHERE job_id = %s AND client_id = %s",
            (job_id, client_id)
        )
        connection.commit()
        logger.info(f"Cliente {client_id}: Agendamento de backup removido: {job_id}")
        return {"message": f"Agendamento {job_id} removido com sucesso."}
    except Exception as e:
        logger.error(f"Erro ao remover agendamento {job_id}: {str(e)}")
        return {"Error": f"Erro ao remover agendamento: {str(e)}"}
    finally:
        cursor.close()
        connection.close()

# Endpoint para Backup imediato
@app.post("/backup")
def backup_database(request: BackupRequest, client_id: int = Depends(authenticate)):
    # Gerar um job_id único para este backup imediato
    job_id = f"backup_{client_id}_{request.database}_once_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    perform_backup(request.ip, request.database, client_id, job_id)
    logger.info(f"Cliente {client_id}: Backup imediato iniciado para VM {request.ip}, banco de dados {request.database}.")
    return {"message": "Backup imediato iniciado."}

@app.post("/schedule_backup")
def schedule_backup_route(request: ScheduleBackupRequest, client_id: int = Depends(authenticate)):
    result = schedule_backup(request, get_vm_by_ip, client_id)
    if "Error" in result:
        logger.error(f"Cliente {client_id}: {result['Error']}")
        raise HTTPException(status_code=400, detail=result['Error'])
    else:
        logger.info(f"Cliente {client_id}: {result['message']}")
        return result

# Endpoint para Listar Backups
@app.get("/list_backups")
def list_backups_route(client_id: int = Depends(authenticate)):
    backups = list_backups(client_id)
    logger.info(f"Cliente {client_id}: Listagem de backups realizada.")
    return backups

# Endpoint para Remover Backup
@app.delete("/remove_backup/{job_id}")
def remove_backup_route(job_id: str, client_id: int = Depends(authenticate)):
    result = remove_backup(job_id, client_id)
    if "Error" in result:
        logger.error(f"Cliente {client_id}: {result['Error']}")
    else:
        logger.info(f"Cliente {client_id}: {result['message']}")
    return result

# Endpoint para Controlar PostgreSQL
@app.post("/control")
def control_postgresql(request: ControlRequest, client_id: int = Depends(authenticate)):
    vm = get_vm_by_ip(request.ip)
    if not vm:
        logger.warning(f"Cliente {client_id}: VM {request.ip} não encontrada.")
        raise HTTPException(status_code=404, detail="VM não encontrada.")

    ssh_user = vm["ssh_user"]
    ssh_password = vm["ssh_password"]
    pg_user = vm.get("pg_user")
    pg_password = vm.get("pg_password")

    if not pg_user or not pg_password:
        logger.warning(f"Cliente {client_id}: PostgreSQL não está configurado na VM {request.ip}.")
        raise HTTPException(status_code=400, detail="PostgreSQL não está configurado nesta VM.")

    if request.action == "start":
        command = "sudo systemctl start postgresql"
    elif request.action == "stop":
        command = "sudo systemctl stop postgresql"
    elif request.action == "restart":
        command = "sudo systemctl restart postgresql"
    else:
        logger.warning(f"Cliente {client_id}: Ação inválida '{request.action}'.")
        raise HTTPException(status_code=400, detail="Ação inválida.")

    result = execute_command_on_vm(request.ip, ssh_user, ssh_password, command)
    logger.info(f"Cliente {client_id}: Ação '{request.action}' executada na VM {request.ip}. Resultado: {result}")
    return {"IP": request.ip, "action": request.action, "result": result}

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

# Endpoint para Monitoramento
@app.get("/monitor")
async def monitor(client_id: int = Depends(authenticate)):
    vms = get_vms(client_id)
    status = check_vm_status(vms, client_id)
    await notify_clients(status)

    logger.info(f"Cliente {client_id}: Monitoramento realizado.")
    return status

@app.get("/monitor/{vm_id}")
def monitor_vm_by_id(vm_id: int, client_id: int = Depends(authenticate)):
    # Obter a VM pelo ID
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT vm_name, ip, ssh_user, ssh_password, has_postgre, pg_user, pg_password, port, id, client_id
            FROM vm_access
            WHERE id = %s AND client_id = %s
            """,
            (vm_id, client_id)
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="VM não encontrada para este cliente.")

        vm = {
            "name": row[0],
            "ip": row[1],
            "ssh_user": row[2],
            "ssh_password": row[3],
            "has_postgre": row[4],
            "pg_user": row[5],
            "pg_password": row[6],
            "port": row[7],
            "id": row[8],
            "client_id": row[9]
        }

        # Monitorar a VM
        status = check_vm_status([vm], client_id)[0]  # Obter o status da VM específica

        # Se a VM possui PostgreSQL, obter os bancos de dados
        databases = []
        if vm['has_postgre']:
            try:
                # Conectar via SSH à VM com timeout
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    vm['ip'],
                    port=int(vm['port']),
                    username=vm['ssh_user'],
                    password=vm['ssh_password'],
                    timeout=10  # Timeout de 10 segundos
                )

                # Criar um túnel SSH para o PostgreSQL
                transport = ssh.get_transport()

                # Encontrar uma porta local disponível
                local_port = find_free_port()

                # Abrir o canal de túnel
                dest_addr = ('localhost', 5432)  # Porta do PostgreSQL na VM
                local_addr = ('localhost', local_port)
                tunnel = transport.open_channel("direct-tcpip", dest_addr, local_addr)

                # Conectar ao PostgreSQL através do túnel SSH com timeout
                conn = psycopg2.connect(
                    database='postgres',
                    user=vm['pg_user'],
                    password=vm['pg_password'],
                    host='localhost',
                    port=local_port,
                    connect_timeout=10  # Timeout de 10 segundos
                )
                cursor_pg = conn.cursor()
                cursor_pg.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
                databases = [db[0] for db in cursor_pg.fetchall()]
                cursor_pg.close()
                conn.close()
                ssh.close()
            except Exception as e:
                logger.error(f"Erro ao obter bancos de dados da VM {vm_id}: {str(e)}")
                databases = []

        # Incluir os bancos de dados na resposta
        status['databases'] = databases

        return status

    except Exception as e:
        logger.error(f"Erro ao monitorar VM {vm_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro ao monitorar a VM.")
    finally:
        cursor.close()
        connection.close()

@app.post("/dumpall")
def dump_all_databases(request: DumpAllRequest, client_id: int = Depends(authenticate)):
    vm = get_vm_by_ip(request.ip)
    if not vm:
        logger.warning(f"Cliente {client_id}: VM {request.ip} não encontrada.")
        raise HTTPException(status_code=404, detail="VM não encontrada.")

    ip = vm["ip"]
    ssh_user = vm["ssh_user"]
    ssh_password = vm["ssh_password"]
    pg_user = vm.get("pg_user")
    pg_password = vm.get("pg_password")
    name = vm.get("name", "Unknown")
    port = vm.get("port", 5432)  # Porta padrão é 5432 caso não esteja definida

    if not pg_user or not pg_password:
        logger.warning(f"Cliente {client_id}: PostgreSQL não está configurado na VM {request.ip}.")
        raise HTTPException(status_code=400, detail="PostgreSQL não está configurado nesta VM.")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = "/home/bkp_bd"
    backup_file = f"{backup_dir}/dumpall_{name}_{timestamp}.sql"

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=ssh_user, password=ssh_password)

        pg_dumpall_path = "/usr/bin/pg_dumpall"

        # Adicionar a porta no comando
        command_dumpall = (
            f"mkdir -p {backup_dir} && "
            f"export PGPASSWORD='{pg_password}' && "
            f"{pg_dumpall_path} -h localhost -p {port} -U {pg_user} -f {backup_file}"
        )

        stdin, stdout, stderr = ssh.exec_command(command_dumpall)
        output_dumpall = stdout.read().decode().strip()
        error_dumpall = stderr.read().decode().strip()

        if error_dumpall:
            ssh.close()
            logger.error(f"Cliente {client_id}: Erro ao realizar dumpall na VM {ip}: {error_dumpall}")
            raise HTTPException(status_code=500, detail=f"Erro ao realizar dumpall: {error_dumpall}")

        command_size = f"du -h {backup_file} | cut -f1"
        stdin, stdout, stderr = ssh.exec_command(command_size)
        size_output = stdout.read().decode().strip()
        size_error = stderr.read().decode().strip()

        if size_error:
            dump_size = "Desconhecido"
            logger.error(f"Cliente {client_id}: Erro ao obter tamanho do dump na VM 'Dev': {size_error}")
        else:
            dump_size = size_output
            logger.info(f"Cliente {client_id}: Dumpall concluído na VM {ip}. Tamanho do dump: {dump_size}")

        ssh.close()

        return {
            "IP": ip,
            "Database": "all",
            "Dumpall": "Completed",
            "Dump Size": dump_size
        }

    except Exception as e:
        logger.exception(f"Cliente {client_id}: Erro ao realizar dumpall na VM {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Montar arquivos estáticos (se necessário)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Evento de Startup para iniciar o scheduler
@app.on_event("startup")
def start_scheduler():
    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler iniciado no evento de startup.")
