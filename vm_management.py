# vm_management.py

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional
from database import get_db_connection
from auth import authenticate  # Importar de auth.py
import logging
from fastapi import Query

router = APIRouter()

# Configuração de logging
logger = logging.getLogger(__name__)

class VMCreateRequest(BaseModel):
    vm_name: str = Field(..., title="Nome da VM")
    ip: str = Field(..., title="Endereço IP da VM")
    ssh_user: str = Field(..., title="Usuário SSH")
    ssh_password: str = Field(..., title="Senha SSH")
    has_postgre: bool = Field(..., title="A VM possui PostgreSQL?")
    pg_user: Optional[str] = Field(None, title="Usuário do PostgreSQL")
    pg_password: Optional[str] = Field(None, title="Senha do PostgreSQL")
    ip_storage: Optional[str] = Field(None, title="IP do Storage")
    ssh_user_storage: Optional[str] = Field(None, title="Usuário SSH do Storage")
    ssh_password_storage: Optional[str] = Field(None, title="Senha SSH do Storage")
    user_pg: Optional[str] = Field(None, title="Usuário PG")
    password_pg: Optional[str] = Field(None, title="Senha PG")
    port: Optional[str] = Field(None, title="Porta")

class VMResponse(BaseModel):
    id: int
    vm_name: str
    ip: str
    ssh_user: str
    has_postgre: bool
    pg_user: Optional[str]
    ip_storage: Optional[str]
    ssh_user_storage: Optional[str]
    user_pg: Optional[str]
    port: Optional[str]

@router.post("/api/vms", response_model=VMResponse, summary="Cadastrar nova VM", tags=["VM Management"])
def create_vm(request: VMCreateRequest, client_id: int = Depends(authenticate)):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        # Verificar se o cliente não excedeu o limite de VMs
        cursor.execute(
            "SELECT max_vm_monitoring FROM clients WHERE id = %s",
            (client_id,)
        )
        max_vms = cursor.fetchone()
        if max_vms is None:
            raise HTTPException(status_code=404, detail="Cliente não encontrado.")
        max_vm_monitoring = max_vms[0]

        # Contar quantas VMs o cliente já cadastrou
        cursor.execute(
            "SELECT COUNT(*) FROM vm_access WHERE client_id = %s",
            (client_id,)
        )
        current_vm_count = cursor.fetchone()[0]

        if current_vm_count >= max_vm_monitoring:
            raise HTTPException(status_code=400, detail="Limite de VMs cadastradas atingido.")

        # Verificar se a combinação de IP e porta já está cadastrada para este cliente
        cursor.execute(
            "SELECT id FROM vm_access WHERE ip = %s AND port = %s AND client_id = %s",
            (request.ip, request.port, client_id)
        )
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="VM com este IP e porta já cadastrada.")

        # Inserir a nova VM no banco de dados e retornar o ID
        cursor.execute(
            """
            INSERT INTO vm_access (
                vm_name, ip, ssh_user, ssh_password, has_postgre, pg_user, pg_password,
                client_id, ip_storage, ssh_user_storage, ssh_password_storage, user_pg,
                password_pg, port
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                request.vm_name,
                request.ip,
                request.ssh_user,
                request.ssh_password,  
                request.has_postgre,
                request.pg_user,
                request.pg_password,  
                client_id,
                request.ip_storage,
                request.ssh_user_storage,
                request.ssh_password_storage,
                request.user_pg,
                request.password_pg,
                request.port
            )
        )
        vm_id = cursor.fetchone()[0]
        connection.commit()

        logger.info(f"Cliente {client_id}: VM '{request.vm_name}' cadastrada com sucesso.")

        # Construir o objeto de resposta
        vm_response = VMResponse(
            id=vm_id,
            vm_name=request.vm_name,
            ip=request.ip,
            ssh_user=request.ssh_user,
            has_postgre=request.has_postgre,
            pg_user=request.pg_user,
            ip_storage=request.ip_storage,
            ssh_user_storage=request.ssh_user_storage,
            user_pg=request.user_pg,
            port=request.port
        )
        return vm_response

    except HTTPException as http_exc:
        logger.warning(f"Cliente {client_id}: {http_exc.detail}")
        raise http_exc
    except Exception as e:
        connection.rollback()
        logger.error(f"Cliente {client_id}: Erro ao cadastrar VM: {e}")
        raise HTTPException(status_code=500, detail="Erro ao cadastrar VM.")
    finally:
        cursor.close()
        connection.close()


@router.get("/api/vms", summary="Listar VMs", tags=["VM Management"])
def list_vms(
    page: int = Query(1, ge=1, description="Número da página"),
    page_size: int = Query(10, ge=1, description="Quantidade de VMs por página"),
    client_id: int = Depends(authenticate)
):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        # Obter o total de VMs para este cliente
        cursor.execute(
            """
            SELECT COUNT(*) FROM vm_access WHERE client_id = %s
            """,
            (client_id,)
        )
        total_items = cursor.fetchone()[0]
        
        # Calcular o OFFSET para a consulta SQL
        offset = (page - 1) * page_size

        # Obter as VMs com LIMIT e OFFSET
        cursor.execute(
            """
            SELECT id, vm_name, ip, ssh_user, has_postgre, pg_user, port
            FROM vm_access
            WHERE client_id = %s
            ORDER BY id
            LIMIT %s OFFSET %s
            """,
            (client_id, page_size, offset)
        )
        vms = cursor.fetchall()
        vm_list = []
        for vm in vms:
            vm_info = {
                "id": vm[0],
                "vm_name": vm[1],
                "ip": vm[2],
                "ssh_user": vm[3],
                "has_postgre": vm[4],
                "pg_user": vm[5],
                "port": vm[6]
            }
            vm_list.append(vm_info)
        logger.info(f"Cliente {client_id}: Listagem de VMs realizada.")
        return {
            "total_items": total_items,
            "page": page,
            "page_size": page_size,
            "total_pages": (total_items + page_size - 1) // page_size,
            "vms": vm_list
        }
    except Exception as e:
        logger.error(f"Cliente {client_id}: Erro ao listar VMs: {e}")
        raise HTTPException(status_code=500, detail="Erro ao listar VMs.")
    finally:
        cursor.close()
        connection.close()

# Endpoint para deletar uma VM
@router.delete("/api/vms/{vm_id}", summary="Deletar VM", tags=["VM Management"])
def delete_vm(vm_id: int, client_id: int = Depends(authenticate)):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        # Verificar se a VM pertence ao cliente
        cursor.execute(
            "SELECT id FROM vm_access WHERE id = %s AND client_id = %s",
            (vm_id, client_id)
        )
        if not cursor.fetchone():
            logger.warning(f"Cliente {client_id}: VM {vm_id} não encontrada ou não pertence ao cliente.")
            raise HTTPException(status_code=404, detail="VM não encontrada.")

        # Deletar a VM
        cursor.execute(
            "DELETE FROM vm_access WHERE id = %s AND client_id = %s",
            (vm_id, client_id)
        )
        connection.commit()
        logger.info(f"Cliente {client_id}: VM {vm_id} deletada com sucesso.")
        return {"message": "VM deletada com sucesso."}
    except Exception as e:
        connection.rollback()
        logger.error(f"Cliente {client_id}: Erro ao deletar VM {vm_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro ao deletar VM.")
    finally:
        cursor.close()
        connection.close()
