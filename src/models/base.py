from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
import os

# Get the artifacts directory path
ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'artifacts')
DB_PATH = os.path.join(ARTIFACTS_DIR, 'db', 'results.db')

# Create database engine
engine = create_engine(f'sqlite:///{DB_PATH}', connect_args={'check_same_thread': False})
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

# Create declarative base
Base = declarative_base()
