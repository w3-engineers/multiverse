from db_helper.connector import dbo
from db_helper.models import *
from playhouse.migrate import MySQLMigrator, migrate
from peewee import BooleanField
from config import IS_DB_NEW

# dbo.connect()

dbo.create_tables([User, Message, Url])

#
# if IS_DB_NEW:
#     # For new database no need to run this.
#     migrator = MySQLMigrator(dbo)
#
#     with dbo.atomic():
#         migrate(
#             migrator.add_column('session', 'is_online', BooleanField(default=False))
#         )
