import psycopg2
from playhouse.pool import PooledPostgresqlDatabase

def db_connect(dbname='nvddb', host='localhost'):
    global db
    dbname = ""

    if db is None:
        print("Connecting to [%s] @ [%s]" % (dbname, host))
        db = PooledPostgresqlDatabase(
            'nvddb', stale_timeout=300, 
            max_connections=50, 
            user='developer', 
            password='dev', 
            host='localhost',
            autorollback=True
            )
        db.connect()


def db_initialize(drop_db=False):
    conn = psycopg2.connect(dbname='nvddb', user='developer', password='dev', host='localhost')
    conn.set_isolation_level(0)

    # if drop_db:
    #     with conn:
    #         with conn.cursor() as cur:
    #             cur.execute('DROP DATABASE IF EXISTS %s' % 'nvd_db')

    # with conn:
    #     with conn.cursor() as cur:
    #         cur.execute('CREATE DATABASE %s' % 'nvd_db')
    #         pass
    conn.close()

def get_db():
    if not db: db_connect()
    return db

db_initialize()
db = None
get_db()