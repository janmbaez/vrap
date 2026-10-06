"""Additive migration startup, serialized independently of API process count."""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from tempfile import gettempdir

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from .db import engine

MIGRATION_LOCK = 861742037

@contextmanager
def migration_connection():
    """Hold a session advisory lock throughout migrations and bootstrap seeding."""
    if engine.dialect.name == 'postgresql':
        with engine.connect() as connection:
            connection.execute(text('SELECT pg_advisory_lock(:key)'), {'key': MIGRATION_LOCK})
            connection.commit()
            try:
                yield connection
            finally:
                if connection.in_transaction():
                    connection.rollback()
                connection.execute(text('SELECT pg_advisory_unlock(:key)'), {'key': MIGRATION_LOCK})
                connection.commit()
    else:
        # SQLite is used for isolated local/demo/test databases.
        import fcntl
        identity = sha256(str(engine.url).encode()).hexdigest()[:16]
        with open(Path(gettempdir()) / f'vrap-migration-{identity}.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                with engine.connect() as connection:
                    yield connection
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

def migrate(seed_demo=False):
    root = Path(__file__).resolve().parents[1]
    configuration = Config(str(root / 'alembic.ini'))
    configuration.set_main_option('script_location', str(root / 'migrations'))
    with migration_connection() as connection:
        configuration.attributes['connection'] = connection
        command.upgrade(configuration, 'head')
        connection.commit()
        if seed_demo:
            from .seed import seed
            seed(demo=True)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--demo', action='store_true')
    migrate(seed_demo=parser.parse_args().demo)
