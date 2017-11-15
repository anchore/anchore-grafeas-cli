import sys
import sqlalchemy
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from contextlib import contextmanager

engine = None
Session = None

def doexit(ecode):
    try:
        sys.stdout.close()
    except:
        pass
    try:
        sys.stderr.close()
    except:
        pass
    sys.exit(ecode)

def do_dbconnect(db_connect):
    global engine, Session

    try:
        engine = sqlalchemy.create_engine(db_connect, echo=False)
    except Exception as err:
        raise Exception("could not create DB engine - exception: " + str(err))

    # set up the global session                                                                                                                                                
    try:
        Session = sessionmaker(bind=engine)
    except Exception as err:
        raise Exception("could not create DB session - exception: " + str(err))

    return(True)

@contextmanager
def session_scope():
    """Provide a transactional scope around a series of operations."""
    global Session
    session = Session()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()
