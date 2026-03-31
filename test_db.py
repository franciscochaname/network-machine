import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

try:
    from database.db_models import SessionLocal, User, AuditLog
    print("Models imported successfully.")
    
    db = SessionLocal()
    # Try a simple query
    user_count = db.query(User).count()
    print(f"User count: {user_count}")
    
    db.close()
    print("Database query successful!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
