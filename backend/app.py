#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===========================================================
 LLAQTASHIELD — Sistema Inteligente de Alertas Comunitarias
 Backend Flask con SQLite + Seguridad + Rate Limit + Upload
===========================================================
"""

# ===========================================================
# IMPORTS
# ===========================================================
import os
import re
import time
import csv
import io
import random
import logging
import sqlite3
from datetime import datetime
from functools import wraps
from collections import deque
from typing import Optional, Dict

from flask import (
    Flask, g, render_template, request, jsonify,
    send_from_directory, abort, Response,
    session, redirect, url_for
)
from werkzeug.utils import secure_filename


# ===========================================================
# CONFIGURACIÓN GLOBAL Y MANEJO DE RUTAS (AJUSTE CRÍTICO PARA RENDER)
# ===========================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Detectar si estamos en un entorno de servidor (como Render)
IS_RENDER_ENV = os.environ.get("RENDER") is not None
# La carpeta /tmp es la única con permisos de escritura garantizados en Render.
TEMP_DIR = "/tmp" 
PROJECT_ROOT = os.path.join(BASE_DIR, "..")

# Base de Datos: Usa /tmp en Render, o la carpeta raíz en local
DB_PATH = os.environ.get(
    "LLAQTA_DB_PATH",
    os.path.join(TEMP_DIR, "llaqta.db") if IS_RENDER_ENV else os.path.join(PROJECT_ROOT, "llaqta.db")
)

# Carpeta de Uploads (Evidencias): Usa /tmp en Render para guardar archivos
UPLOAD_FOLDER = os.environ.get(
    "LLAQTA_UPLOAD_FOLDER",
    # En Render, las evidencias se guardan en /tmp/evidencias
    os.path.join(TEMP_DIR, "evidencias") if IS_RENDER_ENV else os.path.join(PROJECT_ROOT, "static", "evidencias")
)

# Carpeta de Reportes Generados: Usa /tmp en Render
REPORTS_FOLDER = os.path.join(TEMP_DIR, "reportes_generados") if IS_RENDER_ENV else os.path.join(PROJECT_ROOT, "reportes_generados")

# Crear carpetas si no existen (Esto creará los directorios dentro de /tmp en Render)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# ===========================================================
# SISTEMA DE USUARIOS — AGREGADO (según tu petición)
# ===========================================================
USERS = {
    "Cesar Lopez": "cesaralex017",
    "Admin": "123456789",
    "": ""  # Usuario y contraseña en blanco (tal como pediste)
}

def validar_credenciales(usuario, contraseña):
    return usuario in USERS and USERS[usuario] == contraseña


MAX_CONTENT_LENGTH = 6 * 1024 * 1024
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 60

CATEGORIES = [
    "EMERGENCIA", "BULLYING", "SALUD", "INFRAESTRUCTURA", "CLIMA",
    "APOYO ADULTO MAYOR", "MALTRATO ANIMAL", "ROBO A MANO ARMADA", "OTRO"
]


# ===========================================================
# INICIALIZACIÓN DE FLASK
# ===========================================================
app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "templates"),
    static_folder=os.path.join(PROJECT_ROOT, "static")
)

# Clave para sesiones (necesaria para login por formulario)
app.secret_key = "llaqtashield_2025_clave_segura"

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("llaqta")

# Memoria para rate limits
_rate_store: Dict[str, deque] = {}


# ===========================================================
# UTILIDADES DEL SISTEMA
# ===========================================================
def get_db_conn() -> sqlite3.Connection:
    """Retorna una conexión SQLite por request."""
    if "_database" not in g:
        # Usa el DB_PATH corregido que apunta a /tmp en Render
        conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        g._database = conn
    return g._database


@app.teardown_appcontext
def close_db_conn(_):
    conn = g.pop("_database", None)
    if conn:
        conn.close()


def init_db():
    """Crea tabla de reportes si no existe."""
    try:
        # Usa el DB_PATH corregido que apunta a /tmp en Render
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                categoria TEXT NOT NULL,
                descripcion TEXT NOT NULL,
                direccion TEXT,
                lat REAL,
                lng REAL,
                telefono TEXT,
                anonimo INTEGER DEFAULT 0,
                imagen_path TEXT
            )
        """)
        conn.commit()
        logger.info(f"📚 Base de datos inicializada correctamente en: {DB_PATH}")
    except Exception as e:
        logger.error("❌ Error inicializando la BD: %s", e)
    finally:
        conn.close()


def sanitize_text(s, max_len=2048):
    """Remueve spam, exceso de espacios y limita longitud."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()[:max_len]


def allowed_file(filename):
    """Verifica extensión de imagen segura."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def ip_for_request():
    """Obtiene IP real incluso con proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0] if forwarded else request.remote_addr or "0.0.0.0"


def rate_limited():
    """Anti-spam por IP."""
    ip = ip_for_request()
    now = time.time()

    dq = _rate_store.setdefault(ip, deque())
    while dq and dq[0] < now - RATE_LIMIT_WINDOW:
        dq.popleft()

    if len(dq) >= RATE_LIMIT_MAX:
        return True

    dq.append(now)
    return False


def require_admin(f):
    """Protección básica para panel admin (Basic Auth)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        # mantiene compatibilidad con Basic Auth original (si se usa)
        if auth and validar_credenciales(auth.username, auth.password):
            return f(*args, **kwargs)

        # si no hay Basic Auth válida, rechaza con 401 para que el navegador pida credenciales
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="Login Required"'}
        )
    return wrapper


# ===========================================================
# GENERACIÓN DE ARCHIVO HTML DE REPORTE
# ===========================================================
def generar_documento_reporte(data):
    """Genera archivo HTML profesional y seguro."""
    fecha = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reporte_{fecha}.html"
    # Ruta usa REPORTS_FOLDER (que ahora apunta a /tmp en Render)
    ruta = os.path.join(REPORTS_FOLDER, filename)

    html = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Reporte — LlaqtaShield</title>
<style>
body{{font-family:Arial;margin:28px;background:#fbfdfb;color:#07392f}}
h1{{color:#0b6b55;border-bottom:4px solid #dfe9e3;padding-bottom:8px}}
.box{{background:#fff;padding:16px;border-radius:8px;box-shadow:0 6px 18px rgba(3,19,14,.06)}}
.lab{{font-weight:700;color:#0b5f49}}
</style>
</head>
<body>
<h1>Reporte generado — Sistema LlaqtaShield</h1>
<div class="box">
{"".join(f"<p><span class='lab'>{k}:</span> {v}</p>" for k, v in data.items())}
</div>
</body>
</html>"""

    with open(ruta, "w", encoding="utf-8") as f:
        f.write(html)

    return ruta


# ===========================================================
# RUTAS PÚBLICAS
# ===========================================================
@app.route("/")
def index():
    return render_template("index.html", colegio="G.U.E. Leoncio Prado")


@app.route("/reportar")
def reportar():
    return render_template("reportar.html", categories=CATEGORIES)


@app.route("/mapa")
def mapa():
    return render_template("mapa.html")


# ===========================================================
# LOGIN / PANEL / LOGOUT (FORMULARIO)
# ===========================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Sistema de Login basado en formulario HTML.
    Valida contra el diccionario USERS.
    """
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        contraseña = request.form.get("contraseña", "").strip()

        if validar_credenciales(usuario, contraseña):
            session["usuario"] = usuario
            return redirect(url_for("panel"))

        return render_template("login.html", error="Usuario o contraseña incorrectos")

    return render_template("login.html")


@app.route("/panel")
def panel():
    """
    Panel principal después de iniciar sesión.
    Solo usuarios autenticados pueden entrar.
    """
    if "usuario" not in session:
        return redirect("/login")

    return render_template("panel.html", usuario=session["usuario"])


@app.route("/logout")
def logout():
    """
    Cierra la sesión.
    """
    session.clear()
    return redirect("/login")


# ===========================================================
# API DE ALERTAS (SIMULADAS)
# ===========================================================
@app.route("/api/alertas")
def api_alertas():
    def rnd(base, delta=0.01):
        return base + (random.random() * delta * 2 - delta)

    return jsonify([
        {
            "categoria": "EMERGENCIA",
            "descripcion": "Robo",
            "direccion": "Zona comercial",
            "lat": rnd(-9.93),
            "lng": rnd(-76.24)
        },
        {
            "categoria": "APOYO ADULTO MAYOR",
            "descripcion": "Ayuda requerida",
            "direccion": "Av. Principal",
            "lat": rnd(-9.935),
            "lng": rnd(-76.23)
        },
        {
            "categoria": "OTRO",
            "descripcion": "Reporte menor",
            "direccion": "",
            "lat": rnd(-9.94),
            "lng": rnd(-76.25)
        }
    ])


# ===========================================================
# API — REGISTRO DE REPORTES (AJUSTE DE RUTA DE IMAGEN)
# ===========================================================
@app.route("/report", methods=["POST"])
def report():
    if rate_limited():
        return jsonify({"error": "Too many requests"}), 429

    form = request.form
    files = request.files

    # Datos saneados
    categoria = sanitize_text(form.get("categoria", "OTRO"))
    descripcion = sanitize_text(form.get("descripcion"))
    direccion = sanitize_text(form.get("direccion"))
    telefono = sanitize_text(form.get("telefono"))
    anonimo = int(form.get("anonimo") == "on")

    if not descripcion:
        return jsonify({"error": "Descripción obligatoria"}), 400

    # Coordenadas seguras
    try:
        lat = float(form.get("lat")) if form.get("lat") else None
        lng = float(form.get("lng")) if form.get("lng") else None
    except ValueError:
        lat = lng = None

    # Manejo de imagen
    imagen_rel = None
    img = files.get("imagen")

    if img and img.filename:
        if not allowed_file(img.filename):
            return jsonify({"error": "Archivo no permitido"}), 400

        filename = f"{int(time.time()*1000)}_{secure_filename(img.filename)}"
        # full usa UPLOAD_FOLDER que apunta a /tmp en Render
        full = os.path.join(UPLOAD_FOLDER, filename)

        try:
            img.save(full)
            # La ruta pública (que se guarda en BD) debe ser la estática /static/...
            imagen_rel = "/static/evidencias/" + filename
        except:
            logger.exception("Error guardando imagen")
            # Este es el error de Permisos si ocurre en la subida
            return jsonify({"error": "Error guardando imagen"}), 500

    created_at = datetime.utcnow().isoformat()

    # Guardado BD
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports (
                created_at, categoria, descripcion, direccion,
                lat, lng, telefono, anonimo, imagen_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            created_at, categoria, descripcion, direccion,
            lat, lng, telefono, anonimo, imagen_rel
        ))
        conn.commit()

        new_id = cur.lastrowid
    except Exception as e:
        logger.exception("DB error")
        # El error que viste en el formulario ("DB error") proviene de aquí
        return jsonify({"error": "DB error"}), 500

    # Generar documento HTML
    doc_path = generar_documento_reporte({
        "Fecha": created_at,
        "Categoría": categoria,
        "Descripción": descripcion,
        "Dirección": direccion,
        "Latitud": lat,
        "Longitud": lng,
        "Teléfono": telefono,
        "Anónimo": anonimo,
        "Imagen": imagen_rel
    })

    return jsonify({
        "status": "OK",
        "id": new_id,
        "document": "/reporte/" + os.path.basename(doc_path)
    }), 201


# ===========================================================
# EXPORTAR REPORTES
# ===========================================================
@app.route("/api/reports")
def api_reports():
    if rate_limited():
        return jsonify({"error": "Too many requests"}), 429

    limit = int(request.args.get("limit", 200))
    offset = int(request.args.get("offset", 0))

    cur = get_db_conn().cursor()
    cur.execute("""
        SELECT * FROM reports
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))

    rows = cur.fetchall()
    return jsonify([{k: r[k] for k in r.keys()} for r in rows])


# ===========================================================
# SERVIR REPORTES HTML (Ajustado para REPORTS_FOLDER en /tmp)
# ===========================================================
@app.route("/reporte/<filename>")
def serve_generated(filename):
    safe = secure_filename(filename)
    # path usa REPORTS_FOLDER que apunta a /tmp en Render
    path = os.path.join(REPORTS_FOLDER, safe)

    if not os.path.exists(path):
        abort(404)

    return send_from_directory(REPORTS_FOLDER, safe)


# ===========================================================
# PANEL ADMIN (BASIC AUTH)
# ===========================================================
@app.route("/admin/reports")
@require_admin
def admin_reports():
    cur = get_db_conn().cursor()
    cur.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 500")
    rows = cur.fetchall()
    return render_template("admin_reports.html", rows=rows)


# ===========================================================
# MAIN (Ajustado para init_db con DB_PATH en /tmp)
# ===========================================================
def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", default="run", choices=["run", "init-db"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=os.environ.get("PORT", "5000"))
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.command == "init-db":
        init_db()
        print("DB initialized at", DB_PATH)
        return

    # IMPORTANTE: init_db se llama aquí, y usará la ruta corregida a /tmp
    # Si Render no tiene el archivo db, lo creará con éxito en /tmp
    if not os.path.exists(DB_PATH):
        init_db()

    app.run(
        host=args.host,
        port=int(args.port),
        debug=args.debug
    )


if __name__ == "__main__":
    main()
