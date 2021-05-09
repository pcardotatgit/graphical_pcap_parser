'''
    add an admin/password to the user database
'''
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tabledef import *
 
engine = create_engine('sqlite:///users.db', echo=True)
 
# create a Session
Session = sessionmaker(bind=engine)
session = Session()
 
user = User("admin","password")
session.add(user)
 
user = User("patrick","cisco")
session.add(user)
 
user = User("jumpiness","python")
session.add(user)
 
# commit the record the database
session.commit()
