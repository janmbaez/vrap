from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import settings

class Base(DeclarativeBase):
    pass

engine = create_engine(settings().database_url, pool_pre_ping=True,
                       connect_args={'check_same_thread': False, 'timeout': 30} if settings().database_url.startswith('sqlite') else {})
if settings().database_url.startswith('sqlite'):
    @event.listens_for(engine, 'connect')
    def sqlite_fk(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA busy_timeout=30000')
        # Local demo imports can be large; WAL keeps dashboard reads from
        # blocking session and assessment writes while they are processed.
        connection.execute('PRAGMA journal_mode=WAL')
SessionLocal = sessionmaker(engine, expire_on_commit=False)

def get_db():
    with SessionLocal() as db:
        yield db
