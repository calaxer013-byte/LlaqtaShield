-- ===========================================
-- DATABASE INIT — Sistema de Alertas Ciudadanas
-- ===========================================

-- -------------------------
-- Tabla de reportes
-- -------------------------
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
);

-- -------------------------
-- Tabla de administradores
-- -------------------------
CREATE TABLE IF NOT EXISTS usuarios_admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

-- Insertar un usuario administrador inicial (opcional)
-- USER: admin
-- PASS: admin123  (recuerda cambiarla luego)
INSERT OR IGNORE INTO usuarios_admin (username, password)
VALUES ('admin', 'admin123');
