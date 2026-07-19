import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Render provides DATABASE_URL for its managed Postgres add-on.
# Locally, fall back to a .env value or sqlite for quick testing.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./caseintel_dev.db")

# Render's Postgres URLs sometimes come as "postgres://" — SQLAlchemy 1.4+/2.0 needs "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models
    models.Base.metadata.create_all(bind=engine)
