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
    send_from_directory, abort, Response
)
from werkzeug.utils import secure_filename


# ===========================================================
# CONFIGURACIÓN GLOBAL
# ===========================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DB_PATH = os.environ.get(
    "LLAQTA_DB_PATH",
    os.path.join(BASE_DIR, "..", "llaqta.db")
)

UPLOAD_FOLDER = os.environ.get(
    "LLAQTA_UPLOAD_FOLDER",
    os.path.join(BASE_DIR, "..", "static", "evidencias")
)

REPORTS_FOLDER = os.path.join(os.path.dirname(DB_PATH), "reportes_generados")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# ===========================================================
# SISTEMA DE USUARIOS — MEJORADO SEGÚN TU PEDIDO
# ===========================================================
USERS = {
    "Cesar Lopez": "cesaralex017",
    "Admin": "123456789",
    "": ""  # Usuario y contraseña en blanco
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
    template_folder=os.path.join(BASE_DIR, "..", "templates"),
    static_folder=os.path.join(BASE_DIR, "..", "static")
)

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("llaqta")

_rate_store: Dict[str, deque] = {}


# ===========================================================
# UTILIDADES
# ===========================================================
def get_db_conn() -> sqlite3.Connection:
    if "_database" not in g:
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
    try:
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
        logger.info("📚 Base de datos inicializada correctamente.")
    except Exception as e:
        logger.error("❌ Error inicializando la BD: %s", e)
    finally:
        conn.close()


def sanitize_text(s, max_len=2048):
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()[:max_len]


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def ip_for_request():
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0] if forwarded else request.remote_addr or "0.0.0.0"


def rate_limited():
    ip = ip_for_request()
    now = time.time()

    dq = _rate_store.setdefault(ip, deque())
    while dq and dq[0] < now - RATE_LIMIT_WINDOW:
        dq.popleft()

    if len(dq) >= RATE_LIMIT_MAX:
        return True

    dq.append(now)
    return False


# ===========================================================
# DECORADOR DE LOGIN — MULTIUSUARIO
# ===========================================================
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not validar_credenciales(auth.username, auth.password):
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return wrapper


# ===========================================================
# GENERAR REPORTE HTML
# ===========================================================
def generar_documento_reporte(data):
    fecha = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reporte_{fecha}.html"
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
# API ALERTAS SIMULADAS
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
# API — REGISTRO DE REPORTES
# ===========================================================
@app.route("/report", methods=["POST"])
def report():
    if rate_limited():
        return jsonify({"error": "Too many requests"}), 429

    form = request.form
    files = request.files

    categoria = sanitize_text(form.get("categoria", "OTRO"))
    descripcion = sanitize_text(form.get("descripcion"))
    direccion = sanitize_text(form.get("direccion"))
    telefono = sanitize_text(form.get("telefono"))
    anonimo = int(form.get("anonimo") == "on")

    if not descripcion:
        return jsonify({"error": "Descripción obligatoria"}), 400

    try:
        lat = float(form.get("lat")) if form.get("lat") else None
        lng = float(form.get("lng")) if form.get("lng") else None
    except ValueError:
        lat = lng = None

    imagen_rel = None
    img = files.get("imagen")

    if img and img.filename:
        if not allowed_file(img.filename):
            return jsonify({"error": "Archivo no permitido"}), 400

        filename = f"{int(time.time()*1000)}_{secure_filename(img.filename)}"
        full = os.path.join(UPLOAD_FOLDER, filename)

        try:
            img.save(full)
            imagen_rel = "/static/evidencias/" + filename
        except:
            logger.exception("Error guardando imagen")
            return jsonify({"error": "Error guardando imagen"}), 500

    created_at = datetime.utcnow().isoformat()

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
    except:
        logger.exception("DB error")
        return jsonify({"error": "DB error"}), 500

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
# SERVIR REPORTES HTML
# ===========================================================
@app.route("/reporte/<filename>")
def serve_generated(filename):
    safe = secure_filename(filename)
    path = os.path.join(REPORTS_FOLDER, safe)

    if not os.path.exists(path):
        abort(404)

    return send_from_directory(REPORTS_FOLDER, safe)


# ===========================================================
# PANEL ADMIN
# ===========================================================
@app.route("/admin/reports")
@require_admin
def admin_reports():
    cur = get_db_conn().cursor()
    cur.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 500")
    rows = cur.fetchall()
    return render_template("admin_reports.html", rows=rows)


# ===========================================================
# MAIN
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

    if not os.path.exists(DB_PATH):
        init_db()

    app.run(
        host=args.host,
        port=int(args.port),
        debug=args.debug
    )


if __name__ == "__main__":
    main()
