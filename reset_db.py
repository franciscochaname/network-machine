from database.db_models import init_db, SessionLocal
from core.security import create_initial_admin

print("Iniciando reconstrucción de la Arquitectura de Base de Datos...")

# 1. Creamos el archivo .db vacío y le inyectamos todas las tablas nuevas (users, routers, activos_vip, audit_logs)
init_db()

# 2. Abrimos conexión y le pasamos la batuta a tu script de seguridad para que cree el usuario del .env
db = SessionLocal()
create_initial_admin(db)
db.close()

print("🏁 Reconstrucción finalizada. Sistema listo para operar.")