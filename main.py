import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="TECNO ID API")

# Permitir peticiones desde cualquier origen (App móvil y Validador Web)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración híbrida: Usa Neon en la nube o tu PostgreSQL local en tu laptop
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    return psycopg2.connect(
        host="localhost",
        database="tecno_id",
        user="postgres",
        password="ricitos",
        port="5432"
    )

# Modelos Pydantic
class RegistroModel(BaseModel):
    tipo_usuario: str
    nombre: str
    apellido_paterno: str
    apellido_materno: str
    correo_institucional: str
    password: str
    id_dispositivo: str
    # Campos Estudiante
    numero_control: Optional[str] = None
    carrera: Optional[str] = None
    especialidad: Optional[str] = None
    semestre: Optional[str] = None
    # Campos Profesor
    numero_empleado: Optional[str] = None
    departamento_academico: Optional[str] = None
    grado_academico: Optional[str] = None

class LoginModel(BaseModel):
    identificador: str
    password: str

# RUTA RAÍZ DE VERIFICACIÓN
@app.get("/")
def home():
    return {"estado": "En línea", "sistema": "TECNO ID - TecNM Acapulco"}

# ENDPOINT DE REGISTRO
@app.post("/api/registro")
def registrar_usuario(datos: RegistroModel):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query_titular = """
            INSERT INTO virtual.titulares (nombre, apellido_paterno, apellido_materno, correo_institucional, fotografia_url, tipo_usuario, id_dispositivo, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id_titular
        """
        cursor.execute(query_titular, (
            datos.nombre, datos.apellido_paterno, datos.apellido_materno, 
            datos.correo_institucional, "sin_foto.png", datos.tipo_usuario, 
            datos.id_dispositivo, datos.password
        ))
        id_titular = cursor.fetchone()[0]

        if datos.tipo_usuario == 'Estudiante':
            query_est = "INSERT INTO virtual.estudiantes (id_titular, numero_control, carrera, especialidad, semestre) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query_est, (id_titular, datos.numero_control, datos.carrera, datos.especialidad or "General", datos.semestre))
        elif datos.tipo_usuario == 'Profesor':
            query_prof = "INSERT INTO virtual.profesores (id_titular, numero_empleado, departamento_academico, grado_academico) VALUES (%s, %s, %s, %s)"
            cursor.execute(query_prof, (id_titular, datos.numero_empleado, datos.departamento_academico, datos.grado_academico))

        conn.commit()
        return {"mensaje": "Registro institucional exitoso"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# ENDPOINT DE LOGIN
@app.post("/api/login")
def login_usuario(cred: LoginModel):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT t.id_titular, t.nombre, t.apellido_paterno, t.tipo_usuario, 
                   e.numero_control, p.numero_empleado
            FROM virtual.titulares t
            LEFT JOIN virtual.estudiantes e ON t.id_titular = e.id_titular
            LEFT JOIN virtual.profesores p ON t.id_titular = p.id_titular
            WHERE t.password_hash = %s AND (e.numero_control = %s OR p.numero_empleado = %s)
        """
        cursor.execute(query, (cred.password, cred.identificador, cred.identificador))
        usuario = cursor.fetchone()
        
        if not usuario:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        return usuario
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# ENDPOINT DE BÚSQUEDA (Incluye semestre y grado_academico para la credencial)
@app.get("/api/buscar/{identificador}")
def buscar_usuario(identificador: str):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT t.nombre, t.apellido_paterno, t.apellido_materno, t.tipo_usuario, 
                   e.numero_control, e.carrera, e.semestre,
                   p.numero_empleado, p.departamento_academico, p.grado_academico
            FROM virtual.titulares t
            LEFT JOIN virtual.estudiantes e ON t.id_titular = e.id_titular
            LEFT JOIN virtual.profesores p ON t.id_titular = p.id_titular
            WHERE e.numero_control = %s OR p.numero_empleado = %s
        """
        cursor.execute(query, (identificador, identificador))
        usuario = cursor.fetchone()
        if not usuario:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return usuario
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()