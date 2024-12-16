# auth.py

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import bcrypt
from database import get_db_connection
import logging

security = HTTPBasic()

# Configuração de logging
logger = logging.getLogger(__name__)

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
        logger.warning(f"Falha na autenticação para o usuário {username}.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Basic"},
        )
    finally:
        cursor.close()
        connection.close()
