import os
import bcrypt
from dotenv import load_dotenv
from database.db_models import User, SessionLocal

# Cargamos las variables secretas del archivo .env
load_dotenv()

def hash_password(password: str) -> str:
    """Encripta la contraseña usando el algoritmo bcrypt."""
    # Genera una 'sal' aleatoria para mayor seguridad
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Comprueba si la contraseña ingresada es correcta."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_initial_admin(session):
    """Lee el .env y crea el superusuario si la base de datos está vacía."""
    admin_user = os.getenv("ADMIN_USER")
    admin_pass = os.getenv("ADMIN_PASS")

    if not admin_user or not admin_pass:
        print("Error: Revisa tu archivo .env, faltan las variables ADMIN_USER o ADMIN_PASS.")
        return

    # Verificamos si el usuario ya existe para no duplicarlo
    existing_admin = session.query(User).filter_by(username=admin_user).first()
    
    if not existing_admin:
        hashed = hash_password(admin_pass)
        new_admin = User(
            username=admin_user,
            password_hash=hashed,
            role='admin'
        )
        session.add(new_admin)
        session.commit()
        print(f"✅ ¡Éxito! Usuario administrador '{admin_user}' creado y encriptado en la base de datos.")
    else:
        print(f"ℹ️ El usuario '{admin_user}' ya estaba registrado.")

# Bloque de ejecución directa para inyectar el primer administrador
if __name__ == "__main__":
    db = SessionLocal()
    create_initial_admin(db)
    db.close()