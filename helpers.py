from json import loads as json_dict, dumps as json_string
from uuid import uuid4
from db_helper.models import User, Message
from datetime import datetime
from config import DEBUG
from db_helper.connector import dbo


def peewee_exception():
    if dbo.connection():
        return True


def parse_message(msg):
    return json_dict(msg)


def set_json(data):
    return json_string(data)


def push_user_list(scope):
    user_list = []
    valid_info = User.select(User.address).where(
        (User.scope == scope) & (User.is_online == True))

    for row in valid_info:
        user_list.append(row.address)
    return user_list


def get_session_key(scope, address):
    return address + scope


def set_session(sid, scope, address):
    peewee_exception()
    update = User.update(sid=sid, last_seen=datetime.now(), is_online=True). \
        where((User.scope == scope) & (User.address == address)).execute()
    if update:
        return True
    user = User(id=uuid4(), scope=scope, address=address, sid=sid, is_online=True).save(force_insert=True)
    if user:
        return user


def get_session(scope, address, online=True):
    peewee_exception()
    result = None
    if online:
        data = User.select().where((User.scope == scope) & (User.address == address)
                                      & (User.is_online == online))
    else:
        data = User.select().where((User.scope == scope) & (User.address == address))

    for row in data:
        if row.address:
            result = row
            break
    return result


def remove_session(sid):
    peewee_exception()
    try:
        user = User.get(User.sid == sid)
        if user:
            user.last_seen = datetime.now()
            user.is_online = False
            user.save()

            return user
    except Exception as ex:
        trace_info(str(ex))
        peewee_exception()


def get_message_by_address(address, scope):
    pass


def get_user_message(session):
    peewee_exception()
    if session and session.id:
        return Message.select().where((Message.user_id == session.id))


def save_send_message(session, txn, message):
    peewee_exception()
    return Message(id=uuid4(), key=txn, user_id=session.id, message=message).save(force_insert=True)


def update_message_ack(txn, session):
    peewee_exception()
    return Message.delete().where((Message.user_id == session.id) & (Message.key == txn)).execute()
    # result = Message.select().where((Message.user_id == session.id) & (Message.key == txn)).execute()
    # for row in result:
    #     return row


def get_server_socket(sio, key):
    return sio.eio.sockets.get(key, None)


def trace_debug(item):
    if DEBUG:
        print("------------------DEBUG-----------------")
        print(item)
        print("----------------END DEBUG---------------")


def trace_info(item):
    print("**************INFO************")
    print(item)
    print("**************END INFO************")
