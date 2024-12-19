# alerts.py

import logging
from datetime import datetime
import json

# Configuração de logging para alerts.py
logger = logging.getLogger("alerts")
logger.setLevel(logging.DEBUG)  # Alterado para DEBUG para capturar logs de depuração
handler = logging.FileHandler('./logs_monitor/alerts.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Dicionários para rastrear uso contínuo acima do limite
cpu_high_usage = {}
memory_high_usage = {}

# Tempo limite para alertas contínuos (5 minutos)
ALERT_INTERVAL = 300  # 5 minutos em segundos

def send_alert(platform: str, message: str):
    """
    Gera um alerta e registra no log em formato JSON válido.
    """
    try:
        alert = {
            "platform": platform,
            "message": message,
            "status": "success",
            "timestamp": datetime.now().isoformat()
        }
        # Serializa o alerta como JSON com aspas duplas
        alert_json = json.dumps(alert)
        logger.info(f"Alerta gerado: {alert_json}")
        return alert
    except Exception as e:
        logger.error(f"Erro ao gerar alerta: {str(e)}")
        error_alert = {
            "platform": platform,
            "message": message,
            "status": "error",
            "error_detail": str(e),
            "timestamp": datetime.now().isoformat()
        }
        alert_json = json.dumps(error_alert)
        logger.info(f"Alerta gerado: {alert_json}")
        return error_alert

def check_conditions(vm_status):
    """
    Verifica as condições e gera alertas conforme necessário.
    """
    alerts = []
    vm_name = vm_status.get("Name", "Unknown")
    current_time = datetime.now()

    # Condição: Pouco espaço em disco
    disk_space = vm_status.get("Free Disk Space", "N/A")
    logger.debug(f"Verificando espaço em disco para VM {vm_name}: {disk_space}")
    if disk_space != "N/A":
        try:
            space_str = disk_space.replace('G', '').strip()
            space_value = int(space_str.lstrip('0') or '0')  # Remove zeros à esquerda
            logger.debug(f"Espaço em disco convertido para inteiro: {space_value}GB")
            if space_value < 20:  # Menos de 80GB livres
                alerts.append(send_alert("disk_space", f"VM {vm_name} com pouco espaço em disco ({disk_space})."))
                logger.debug(f"Alerta de espaço em disco gerado para VM {vm_name}")
        except ValueError as e:
            logger.warning(f"Falha ao converter espaço em disco para inteiro: {e}. Valor: {disk_space}")

    # Condição: Uso de CPU acima de 90% por mais de 5 minutos
    cpu_usage = vm_status.get("CPU Usage", "Unknown")
    logger.debug(f"Verificando uso de CPU para VM {vm_name}: {cpu_usage}")
    if cpu_usage != "Unknown":
        try:
            cpu_value = float(cpu_usage.replace('%', '').strip())
            logger.debug(f"Uso de CPU convertido para float: {cpu_value}%")
            if cpu_value > 90:
                last_alert_time = cpu_high_usage.get(vm_name)
                if not last_alert_time:
                    cpu_high_usage[vm_name] = current_time
                    logger.debug(f"Primeiro registro de CPU alta para VM {vm_name}")
                elif (current_time - last_alert_time).total_seconds() >= ALERT_INTERVAL:
                    alerts.append(send_alert("cpu_usage", f"VM {vm_name} com uso de CPU acima de 90% por mais de 5 minutos ({cpu_usage})."))
                    logger.debug(f"Alerta de CPU alta gerado para VM {vm_name}")
                    cpu_high_usage[vm_name] = current_time
            else:
                # Resetar o rastreamento se o uso de CPU voltar ao normal
                if vm_name in cpu_high_usage:
                    logger.debug(f"Uso de CPU normal para VM {vm_name}. Resetando rastreamento.")
                cpu_high_usage.pop(vm_name, None)
        except ValueError as e:
            logger.warning(f"Falha ao converter uso de CPU para float: {e}. Valor: {cpu_usage}")

    # Condição: Uso de memória acima de 90% por mais de 5 minutos
    memory_usage = vm_status.get("Memory Usage", "Unknown")
    logger.debug(f"Verificando uso de memória para VM {vm_name}: {memory_usage}")
    if memory_usage != "Unknown":
        try:
            mem_value = float(memory_usage.replace('%', '').strip())
            logger.debug(f"Uso de memória convertido para float: {mem_value}%")
            if mem_value > 90:
                last_alert_time = memory_high_usage.get(vm_name)
                if not last_alert_time:
                    memory_high_usage[vm_name] = current_time
                    logger.debug(f"Primeiro registro de memória alta para VM {vm_name}")
                elif (current_time - last_alert_time).total_seconds() >= ALERT_INTERVAL:
                    alerts.append(send_alert("memory_usage", f"VM {vm_name} com uso de memória acima de 90% por mais de 5 minutos ({memory_usage})."))
                    logger.debug(f"Alerta de memória alta gerado para VM {vm_name}")
                    memory_high_usage[vm_name] = current_time
            else:
                # Resetar o rastreamento se o uso de memória voltar ao normal
                if vm_name in memory_high_usage:
                    logger.debug(f"Uso de memória normal para VM {vm_name}. Resetando rastreamento.")
                memory_high_usage.pop(vm_name, None)
        except ValueError as e:
            logger.warning(f"Falha ao converter uso de memória para float: {e}. Valor: {memory_usage}")

    # Condição: PostgreSQL Offline
    postgres_status = vm_status.get("PostgreSQL Status", "N/A")
    logger.debug(f"Verificando status do PostgreSQL para VM {vm_name}: {postgres_status}")
    if postgres_status == "inactive":
        alerts.append(send_alert("postgres_status", f"PostgreSQL está offline na VM {vm_name}."))
        logger.debug(f"Alerta de PostgreSQL offline gerado para VM {vm_name}.")

    # Condição: VM Offline
    if "Error" in vm_status:
        alerts.append(send_alert("vm_status", f"VM {vm_name} ({vm_status['IP']}) está offline. Erro: {vm_status['Error']}."))
        logger.debug(f"Alerta de VM offline gerado para VM {vm_name}.")

    return alerts
