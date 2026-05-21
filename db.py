import os
from typing import Optional

DB_ENABLED = False
SessionLocal = None
engine = None
Base = None

try:
    from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
    from sqlalchemy.orm import sessionmaker, declarative_base
    from datetime import datetime
    from dotenv import load_dotenv
    import json

    load_dotenv()

    DATABASE_URL = os.getenv('DATABASE_URL')
    if not DATABASE_URL:
        # Fallback ke Postgres default; bisa diganti lewat .env
        # Format: postgresql+psycopg2://user:password@host:port/dbname
        DATABASE_URL = 'postgresql+psycopg2://nids_user:nids_password@localhost:5432/nids_db'

    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        future=True
    )
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base = declarative_base()

    class PacketLog(Base):
        __tablename__ = 'packet_logs'
        id = Column(Integer, primary_key=True, index=True)
        ts = Column(DateTime, default=datetime.utcnow, index=True)
        protocol = Column(String(16), index=True)
        src_ip = Column(String(64), index=True)
        src_port = Column(Integer, nullable=True)
        dst_ip = Column(String(64), index=True)
        dst_port = Column(Integer, nullable=True)
        size = Column(Integer)
        interface = Column(String(64), nullable=True)

    class Alert(Base):
        __tablename__ = 'alerts'
        id = Column(Integer, primary_key=True, index=True)
        ts = Column(DateTime, default=datetime.utcnow, index=True)
        type = Column(String(64), index=True)
        severity = Column(String(16), index=True)
        source_ip = Column(String(64), nullable=True, index=True)
        description = Column(String(512))

    def init_db():
        global DB_ENABLED
        Base.metadata.create_all(bind=engine)
        DB_ENABLED = True

    def get_session():
        if not SessionLocal:
            return None
        return SessionLocal()

    # Optional: NOTIFY untuk live pub/sub Postgres
    try:
        import psycopg2
        from psycopg2 import sql

        def _get_pg_dsn():
            url = os.getenv('DATABASE_URL') or DATABASE_URL
            if '+psycopg2' in url:
                url = url.replace('+psycopg2', '')
            return url

        def pg_notify(channel: str, payload_obj):
            try:
                dsn = _get_pg_dsn()
                conn = psycopg2.connect(dsn)
                conn.set_session(autocommit=True)
                cur = conn.cursor()
                payload = json.dumps(payload_obj)
                cur.execute(
                    sql.SQL("NOTIFY {} , %s").format(sql.Identifier(channel)),
                    [payload]
                )
                try:
                    cur.close()
                    conn.close()
                except Exception:
                    pass
            except Exception:
                # Diamkan jika gagal; SSE tetap berjalan via in-memory
                pass
    except Exception:
        def pg_notify(channel: str, payload_obj):
            # psycopg2 tidak tersedia, skip
            pass

except Exception as e:
    # Jika dependency belum terpasang, modul DB tetap dapat diimport
    # namun DB_ENABLED False sehingga writer tidak aktif.
    DB_ENABLED = False
    SessionLocal = None
    engine = None
    Base = None