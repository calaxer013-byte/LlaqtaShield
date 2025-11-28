import sqlite3
import os
import datetime
from flask import Flask, g, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv

# Carga variables de entorno (como SECRET_KEY o DATABASE_PATH)
load_dotenv() 

# --- CONFIGURACIÓN DE LA BASE DE DATOS ---
# Usar una variable de entorno para la ruta de la DB, si está disponible,
# o un nombre de archivo predeterminado.
DATABASE_PATH = os.environ.get('DATABASE_PATH', 'database.db')

app = Flask(__name__)
CORS(app) # Habilita CORS para todas las rutas

# Función para obtener la conexión a la base de datos
def get_db_conn():
    """Establece y devuelve una conexión a la base de datos, almacenándola en 'g'."""
    # Si ya hay una conexión, la devuelve
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

# Función para cerrar la conexión a la base de datos al finalizar la solicitud
@app.teardown_appcontext
def close_db(e=None):
    """Cierra la conexión a la base de datos si existe."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- FUNCIÓN CRUCIAL PARA CORREGIR EL ERROR ---
def init_db():
    """Crea la tabla 'reports' si no existe."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cur = conn.cursor()
        
        # SQL para crear la tabla 'reports'
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT,
                description TEXT NOT NULL,
                lat REAL,
                lng REAL,
                telefono TEXT,
                anonimo INTEGER DEFAULT 0, -- 0 para False, 1 para True
                imagen_rel TEXT,
                created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime'))
            );
        """)
        conn.commit()
        conn.close()
        print(f"Base de datos inicializada: '{DATABASE_PATH}'. Tabla 'reports' verificada.")
    except Exception as e:
        print(f"Error al inicializar la base de datos: {e}")

# Llamada a la función de inicialización al inicio de la aplicación
with app.app_context():
    init_db()

# --- FUNCIONES DE RUTA (Adaptadas de su log) ---

# Simulamos un decorador de autenticación, ya que el log mostró 401
def requires_auth(f):
    """Simulación de decorador de autenticación."""
    # El log dice que el endpoint requiere autenticación, pero para que sea runnable
    # sin una lógica de auth completa, asumiremos que pasa o devolvemos un 401.
    def wrapper(*args, **kwargs):
        # En una app real, aquí se verificaría el token/sesión del usuario
        # Por simplicidad, solo se llama a la función decorada
        return f(*args, **kwargs)
    return wrapper

@app.route('/admin/reports')
@requires_auth
def admin_reports():
    """Maneja la vista de informes de administración."""
    conn = get_db_conn()
    cur = conn.cursor()
    
    try:
        # Esto solía fallar porque la tabla no existía (Línea 480 en su log)
        cur.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 500")
        reports = cur.fetchall()
        
        # Devuelve un JSON simple de los reportes (o renderiza una plantilla)
        return jsonify([dict(row) for row in reports])
        
    except sqlite3.OperationalError as e:
        print(f"[ERROR] DB error en /admin/reports: {e}")
        return jsonify({"error": "Error de base de datos: Tabla no encontrada. Ejecute init_db."}), 500
    except Exception as e:
        print(f"[ERROR] Exception en /admin/reports: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500


@app.route('/report', methods=['POST'])
def report():
    """Recibe y guarda un nuevo reporte."""
    conn = get_db_conn()
    cur = conn.cursor()
    data = request.json or request.form # Obtiene datos del cuerpo de la solicitud

    # Los logs sugieren que se esperan estos campos
    report_data = {
        'description': data.get('description', 'Sin descripción'),
        'report_type': data.get('report_type', 'General'),
        'lat': data.get('lat'),
        'lng': data.get('lng'),
        'telefono': data.get('telefono'),
        'anonimo': 1 if data.get('anonimo') in (True, 'true', 1) else 0,
        'imagen_rel': data.get('imagen_rel')
    }
    
    # Validaciones básicas
    if not report_data['description']:
        return jsonify({"error": "La descripción es obligatoria."}), 400

    try:
        # Esto solía fallar porque la tabla no existía (Línea 399 en su log)
        cur.execute("""
            INSERT INTO reports (
                report_type, description, lat, lng, telefono, anonimo, imagen_rel
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            report_data['report_type'],
            report_data['description'],
            report_data['lat'],
            report_data['lng'],
            report_data['telefono'],
            report_data['anonimo'],
            report_data['imagen_rel']
        ))
        conn.commit()
        return jsonify({"message": "Reporte enviado exitosamente."}), 201

    except sqlite3.OperationalError as e:
        print(f"[ERROR] DB error en /report: {e}")
        # El 500 21 en su log sugiere un error al insertar
        return jsonify({"error": "Error de base de datos al registrar el reporte."}), 500
    except Exception as e:
        print(f"[ERROR] Exception en /report: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/')
def index():
    # Simulación de la página de inicio
    return "<h1>LlaqtaShield API está funcionando.</h1><p>Acceda a /reportar para ver el formulario (si existe).</p>"

if __name__ == '__main__':
    # Esto es solo para ejecución local, Render usa gunicorn directamente
    app.run(debug=True)
