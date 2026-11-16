import os
import uuid
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="TECNO ID API - TecNM Campus Acapulco")

# Permitir peticiones desde la App móvil (.NET MAUI) y Validador de Caseta
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración híbrida: Neon en Render o PostgreSQL local
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

# ==========================================
# MODELOS PYDANTIC
# ==========================================

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
    id_dispositivo: str

class LoginAdminModel(BaseModel):
    usuario: str
    password: str

class ValidacionAccesoModel(BaseModel):
    codigo_leido: str
    metodo_validacion: str = "QR"  # "QR" o "NFC"

# ==========================================
# ENDPOINTS
# ==========================================

@app.get("/")
def home():
    return {"estado": "En línea", "sistema": "TECNO ID - TecNM Acapulco"}

# 1. REGISTRO INSTITUCIONAL + EMISIÓN AUTOMÁTICA DE CREDENCIAL
@app.post("/api/registro")
def registrar_usuario(datos: RegistroModel):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query_titular = """
            INSERT INTO virtual.titulares (
                nombre, apellido_paterno, apellido_materno, 
                correo_institucional, fotografia_url, tipo_usuario, 
                id_dispositivo, password_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) 
            RETURNING id_titular
        """
        cursor.execute(query_titular, (
            datos.nombre, datos.apellido_paterno, datos.apellido_materno,
            datos.correo_institucional, "sin_foto.png", datos.tipo_usuario,
            datos.id_dispositivo, datos.password
        ))
        id_titular = cursor.fetchone()[0]

        identificador_qr = ""

        if datos.tipo_usuario == 'Estudiante':
            query_est = """
                INSERT INTO virtual.estudiantes (id_titular, numero_control, carrera, especialidad, semestre) 
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query_est, (
                id_titular, datos.numero_control, datos.carrera,
                datos.especialidad or "General", datos.semestre
            ))
            identificador_qr = datos.numero_control.strip()

        elif datos.tipo_usuario == 'Profesor':
            query_prof = """
                INSERT INTO virtual.profesores (id_titular, numero_empleado, departamento_academico, grado_academico) 
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query_prof, (
                id_titular, datos.numero_empleado,
                datos.departamento_academico, datos.grado_academico
            ))
            identificador_qr = datos.numero_empleado.strip()

        if identificador_qr:
            uid_nfc_generado = f"NFC-{uuid.uuid4().hex[:12].upper()}"
            fecha_vencimiento = datetime.now() + timedelta(days=365)
            query_cred = """
                INSERT INTO virtual.credenciales (
                    id_titular, token_qr, uid_nfc, estado, fecha_vencimiento
                )
                VALUES (%s, %s, %s, 'Activa', %s)
            """
            cursor.execute(query_cred, (id_titular, identificador_qr, uid_nfc_generado, fecha_vencimiento))

        conn.commit()
        return {"mensaje": "Registro institucional y emisión de credencial exitosos"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# 2. INICIO DE SESIÓN CON BLOQUEO DE DISPOSITIVO ÚNICO (ALUMNOS / PROFESORES)
@app.post("/api/login")
def login_usuario(cred: LoginModel):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT t.id_titular, t.nombre, t.apellido_paterno, t.tipo_usuario, 
                   t.id_dispositivo, e.numero_control, p.numero_empleado
            FROM virtual.titulares t
            LEFT JOIN virtual.estudiantes e ON t.id_titular = e.id_titular
            LEFT JOIN virtual.profesores p ON t.id_titular = p.id_titular
            WHERE t.password_hash = %s AND (e.numero_control = %s OR p.numero_empleado = %s)
        """
        cursor.execute(query, (cred.password, cred.identificador.strip(), cred.identificador.strip()))
        usuario = cursor.fetchone()

        if not usuario:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        if usuario["id_dispositivo"] != cred.id_dispositivo:
            raise HTTPException(
                status_code=403,
                detail="Acceso bloqueado: Esta cuenta ya está vinculada a otro dispositivo móvil."
            )

        return usuario
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# 3. INICIO DE SESIÓN PARA PERSONAL DE RECEPCIÓN / CASETA
@app.post("/api/login-admin")
def login_administrativo(cred: LoginAdminModel):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT id_admin, nombre_completo, usuario, rol
            FROM virtual.usuarios_administrativos
            WHERE usuario = %s AND password_hash = %s AND activo = TRUE
        """
        cursor.execute(query, (cred.usuario.strip(), cred.password.strip()))
        admin = cursor.fetchone()

        if not admin:
            raise HTTPException(
                status_code=401, 
                detail="Credenciales de recepción incorrectas o usuario inactivo"
            )

        return admin
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# 4. CONSULTA DE DATOS DE CREDENCIAL (Con verificación de dispositivo)
@app.get("/api/buscar/{identificador}")
def buscar_usuario(identificador: str, x_device_id: Optional[str] = Header(default=None)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT t.nombre, t.apellido_paterno, t.apellido_materno, t.tipo_usuario,
                   t.id_dispositivo,
                   e.numero_control, e.carrera, e.semestre,
                   p.numero_empleado, p.departamento_academico, p.grado_academico,
                   c.estado AS estado_credencial
            FROM virtual.titulares t
            LEFT JOIN virtual.estudiantes e ON t.id_titular = e.id_titular
            LEFT JOIN virtual.profesores p ON t.id_titular = p.id_titular
            LEFT JOIN virtual.credenciales c ON t.id_titular = c.id_titular
            WHERE e.numero_control = %s OR p.numero_empleado = %s
        """
        cursor.execute(query, (identificador.strip(), identificador.strip()))
        usuario = cursor.fetchone()

        if not usuario:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        if x_device_id and usuario["id_dispositivo"] != x_device_id:
            raise HTTPException(
                status_code=403,
                detail="Sesión revocada: El dispositivo no coincide con el titular."
            )

        return usuario
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

# 5. VALIDACIÓN DE ACCESO PARA ESCÁNER FÍSICO QR / NFC (ZNEMAZ X7-1000A)
@app.post("/api/validar-acceso")
def validar_acceso(datos: ValidacionAccesoModel):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    codigo = datos.codigo_leido.strip()
    metodo = datos.metodo_validacion.upper() if datos.metodo_validacion.upper() in ["QR", "NFC"] else "QR"

    try:
        # Caso A: Pase Temporal de Invitado (ej. INV-XXXXX)
        if codigo.upper().startswith("INV-"):
            cursor.execute("""
                SELECT id_invitado, folio_qr, nombre_completo, area_destino, fecha_expiracion, estado
                FROM virtual.invitados
                WHERE folio_qr = %s
            """, (codigo.upper(),))
            invitado = cursor.fetchone()

            if not invitado:
                return {
                    "autorizado": False,
                    "mensaje": "Pase de invitado no encontrado",
                    "nombre_completo": "DESCONOCIDO",
                    "rol": "Invitado",
                    "detalle": "Folio inválido"
                }

            if invitado["estado"] != "Activo" or invitado["fecha_expiracion"] < datetime.now():
                return {
                    "autorizado": False,
                    "mensaje": "Pase de invitado expirado o revocado",
                    "nombre_completo": invitado["nombre_completo"],
                    "rol": "Invitado",
                    "detalle": f"Destino: {invitado['area_destino']}"
                }

            return {
                "autorizado": True,
                "mensaje": "Acceso de invitado autorizado",
                "nombre_completo": invitado["nombre_completo"],
                "rol": "Invitado",
                "detalle": f"Destino: {invitado['area_destino']}"
            }

        # Caso B: Credencial institucional (Estudiante o Profesor)
        query_cred = """
            SELECT c.id_credencial, c.estado, c.fecha_vencimiento,
                   t.nombre, t.apellido_paterno, t.apellido_materno, t.tipo_usuario,
                   e.numero_control, e.carrera, e.semestre,
                   p.numero_empleado, p.departamento_academico
            FROM virtual.credenciales c
            INNER JOIN virtual.titulares t ON c.id_titular = t.id_titular
            LEFT JOIN virtual.estudiantes e ON t.id_titular = e.id_titular
            LEFT JOIN virtual.profesores p ON t.id_titular = p.id_titular
            WHERE c.token_qr = %s OR c.uid_nfc = %s OR e.numero_control = %s OR p.numero_empleado = %s
        """
        cursor.execute(query_cred, (codigo, codigo, codigo, codigo))
        registro = cursor.fetchone()

        if not registro:
            return {
                "autorizado": False,
                "mensaje": "Credencial no registrada en el sistema",
                "nombre_completo": "NO IDENTIFICADO",
                "rol": "Desconocido",
                "detalle": f"Código leído: {codigo}"
            }

        nombre_completo = f"{registro['nombre']} {registro['apellido_paterno']} {registro['apellido_materno']}"
        detalle = (
            f"{registro['carrera']} • {registro['semestre']} Semestre"
            if registro["tipo_usuario"] == "Estudiante"
            else f"Depto: {registro['departamento_academico']}"
        )

        es_valida = (
            registro["estado"] == "Activa"
            and registro["fecha_vencimiento"] >= datetime.now()
        )
        resultado_texto = "Autorizado" if es_valida else "No autorizado"
        mensaje_respuesta = (
            "Acceso autorizado"
            if es_valida
            else f"Credencial {registro['estado']} o vencida"
        )

        cursor.execute("""
            INSERT INTO virtual.registros_acceso (id_credencial, metodo_validacion, resultado)
            VALUES (%s, %s, %s)
        """, (registro["id_credencial"], metodo, resultado_texto))
        conn.commit()

        return {
            "autorizado": es_valida,
            "mensaje": mensaje_respuesta,
            "nombre_completo": nombre_completo,
            "rol": registro["tipo_usuario"],
            "detalle": detalle
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()
