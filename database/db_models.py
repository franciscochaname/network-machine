from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, configure_mappers
from sqlalchemy.sql import func
import os
import sqlite3
import logging

# ==========================================
# 0. CONFIGURACIÓN ESCALABLE
# ==========================================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///database/sistema.db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, echo=False)
else:
    engine = create_engine(DATABASE_URL, pool_size=20, max_overflow=10, echo=False)

Base = declarative_base()

# ==========================================
# 1. TABLA DE AUDITORÍA (Definida primero para ser referenciada)
# ==========================================
class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(100), nullable=False)
    target = Column(String(100), nullable=False)
    details = Column(String(255))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="logs")

# ==========================================
# 2. TABLA DE USUARIOS
# ==========================================
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(20), default='viewer')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), onupdate=func.now())
    logs = relationship("AuditLog", back_populates="user")

# ==========================================
# 3. TABLA DE INFRAESTRUCTURA (Routers)
# ==========================================
class Router(Base):
    __tablename__ = 'routers'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    ip_address = Column(String(50), unique=True, nullable=False, index=True)
    api_user = Column(String(50), nullable=False)
    api_pass_encrypted = Column(String(200), nullable=False)
    location = Column(String(100))
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    wan_ip = Column(String(50), nullable=True)

    vip_assets = relationship("ActivoVIP", back_populates="router", cascade="all, delete-orphan")
    traffic_snapshots = relationship("TrafficSnapshot", back_populates="router", cascade="all, delete-orphan")

# ==========================================
# 4. TABLAS AIOPS Y SEGURIDAD
# ==========================================
class ActivoVIP(Base):
    __tablename__ = 'activos_vip'
    id = Column(Integer, primary_key=True)
    router_id = Column(Integer, ForeignKey('routers.id'))
    ip_address = Column(String(50), nullable=False, index=True)
    nombre = Column(String(100), nullable=False)
    tipo = Column(String(50), default='Servidor')
    alerta_activa = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    router = relationship("Router", back_populates="vip_assets")

class TrafficSnapshot(Base):
    __tablename__ = 'traffic_history'
    id = Column(Integer, primary_key=True)
    router_id = Column(Integer, ForeignKey('routers.id'), index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    total_rx = Column(Float, default=0)
    total_tx = Column(Float, default=0)
    cpu_load = Column(Integer, default=0)
    ram_pct = Column(Float, default=0)
    connections = Column(Integer, default=0)
    health_score = Column(Float, default=0)
    router = relationship("Router", back_populates="traffic_snapshots")

class BlockedDevice(Base):
    __tablename__ = 'blocked_devices'
    id = Column(Integer, primary_key=True)
    router_id = Column(Integer, ForeignKey('routers.id'), index=True)
    ip_address = Column(String(50), nullable=True)
    mac_address = Column(String(20), nullable=True)
    hostname = Column(String(100), nullable=True)
    connection_type = Column(String(20), default='LAN')
    block_type = Column(String(50), default='device')
    block_target = Column(String(200), nullable=True)
    reason = Column(String(255), default='Bloqueo Administrativo')
    blocked_by = Column(String(50), default='admin')
    firewall_rule_ids = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    router = relationship("Router")

class SOCActionLog(Base):
    __tablename__ = 'soc_action_logs'
    id = Column(Integer, primary_key=True)
    router_id = Column(Integer, ForeignKey('routers.id'), nullable=True)
    action = Column(String(500), nullable=False)
    status = Column(String(20), default='INFO')
    user = Column(String(50), default='admin')
    details = Column(String(1000), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# ==========================================
# INICIALIZACIÓN Y MIGRACIÓN
# ==========================================
def _migrate_sqlite():
    """Agrega columnas nuevas a tablas existentes sin perder datos (solo SQLite)."""
    if not DATABASE_URL.startswith("sqlite"):
        return

    db_path = DATABASE_URL.replace("sqlite:///", "")
    if not os.path.exists(db_path):
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Leer columnas existentes de 'routers'
        cursor.execute("PRAGMA table_info(routers)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        migrations = {
            'latitude': "ALTER TABLE routers ADD COLUMN latitude REAL",
            'longitude': "ALTER TABLE routers ADD COLUMN longitude REAL",
            'wan_ip': "ALTER TABLE routers ADD COLUMN wan_ip VARCHAR(50)",
        }

        for col, sql in migrations.items():
            if col not in existing_cols:
                cursor.execute(sql)
                logging.info(f"Migración: Columna '{col}' agregada a 'routers'.")

        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error en migración: {e}")


def init_db():
    """Crea tablas nuevas y migra columnas faltantes."""
    _migrate_sqlite()
    Base.metadata.create_all(engine)
    print("Base de datos inicializada (v3.5 — con soporte de geolocalización e historial).")


# Auto-inicializar al importar
configure_mappers()
init_db()

SessionLocal = sessionmaker(bind=engine)