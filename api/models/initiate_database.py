import yaml
try:
    with open( '../config.yaml', 'r' ) as f:
        settings = yaml.safe_load( f )
except IOError:
    print "INITIATEDB: Error reading config.yaml, have you created one? (Hint: Try running ./generate_config.py)"
    exit()

from sqlalchemy import create_engine
engine = create_engine('postgresql://' + settings["postgreql_username"] + ':' + settings["postgreql_password"] + '@' settings["postgres_server"] + '/' + settings["postgres_db"] + '?client_encoding=utf8', pool_recycle=60, encoding='utf8')
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
from sqlalchemy import Column, Integer, String, func, update, Text, Binary, Boolean, BigInteger, event, select, exc
from sqlalchemy.orm import sessionmaker, scoped_session
Session = scoped_session(sessionmaker(bind=engine))
session = Session()
