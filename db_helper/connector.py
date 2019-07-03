from peewee import MySQLDatabase, Model

from config import DB_HOST, DB_NAME, DB_PWD, DB_USR, DB_PORT
dbo = MySQLDatabase(DB_NAME, user=DB_USR, password=DB_PWD, host=DB_HOST, port=DB_PORT)


class BaseModel(Model):
    class Meta:
        database = dbo
