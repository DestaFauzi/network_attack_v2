from app import app, db
import pymysql

def init_database():
    # Configuration
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    
    try:
        from urllib.parse import urlparse
        result = urlparse(db_uri)
        username = result.username
        password = result.password
        hostname = result.hostname
        port = result.port or 3306
        dbname = result.path[1:] # Remove leading slash
        
        print(f"Connecting to MySQL server at {hostname}:{port}...")
        
        # Connect to MySQL server (without selecting DB) to create it if not exists
        conn = pymysql.connect(
            host=hostname,
            user=username,
            password=password,
            port=port
        )
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        print(f"Creating database '{dbname}' if not exists...")
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {dbname}")
        conn.commit()
        cursor.close()
        conn.close()
        
        print("Database created/verified successfully.")
        
        # Create tables using SQLAlchemy
        print("Creating tables...")
        with app.app_context():
            db.create_all()
            print("Tables created successfully!")
            
    except Exception as e:
        print(f"\nERROR: Failed to initialize database.\nDetails: {str(e)}")
        print("\nPossible solutions:")
        print("1. Ensure MySQL server (DBngin) is RUNNING.")
        print("2. Check if the username/password in app.py matches your DBngin config.")

if __name__ == "__main__":
    init_database()
