from datetime import datetime
from db_helper.connector import BaseModel
from peewee import BooleanField, CharField, \
    DateTimeField, ForeignKeyField, TextField,\
    CompositeKey, UUIDField

MESSAGE_STATUS = dict(server=0, buyer=1)


class User(BaseModel):
    id = UUIDField(primary_key=True)
    address = CharField(max_length=50)
    scope = CharField(max_length=50)
    sid = CharField(max_length=40, default=None, unique=True)
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)
    is_online = BooleanField(default=False)

    class Meta:
        address_scope = CompositeKey('address', 'scope')
        # primary_key = CompositeKey('address', 'scope')


class Message(BaseModel):
    id = UUIDField(primary_key=True)
    key = CharField(max_length=50)
    user_id = ForeignKeyField(User, backref='message', null=True, on_delete='CASCADE', on_update='CASCADE')
    message = TextField()
    status = BooleanField(default=MESSAGE_STATUS['server'])
    # TODO:: message validator using encryption
    created_on = DateTimeField(default=datetime.now)

    class Meta:
        txn = CompositeKey('key', 'user_id')
        # primary_key = CompositeKey('key', 'user_id')
