from json import loads as json_dict, dumps as json_string
from uuid import uuid4
from db_helper.models import User, Message, MESSAGE_STATUS
from datetime import datetime
from config import DEBUG
from db_helper.connector import connect, close


def parse_message(msg):
    return json_dict(msg)


def set_json(data):
    return json_string(data)


def push_user_list(scope):
    connect()
    user_list = []
    valid_info = User.select(User.address).where(
        (User.scope == scope) & (User.is_online == True))

    for row in valid_info:
        user_list.append(row.address)

    close()
    return user_list


def get_session_key(scope, address):
    return address + scope


def set_session(sid, scope, address):
    connect()
    update = User.update(sid=sid, last_seen=datetime.now(), is_online=True). \
        where((User.scope == scope) & (User.address == address)).execute()
    if update:
        close()
        return True
    user = User(id=uuid4(), scope=scope, address=address, sid=sid, is_online=True).save(force_insert=True)
    close()
    if user:
        return user


def get_session(scope, address, online=True):
    connect()
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
    close()
    return result


def remove_session(sid):
    connect()
    try:
        user = User.get(User.sid == sid)
        if user:
            user.last_seen = datetime.now()
            user.is_online = False
            user.save()
            close()
            return user
    except Exception as ex:
        trace_info(str(ex) + " --> Exception while remove session.")
        close()


def get_user_message(session):
    connect()
    if session and session.id:
        result = Message.select().where((Message.user_id == session.id))
        close()
        return result


def save_send_message(session, txn, message):
    connect()
    result = Message(id=uuid4(), key=txn, user_id=session.id, message=message).save(force_insert=True)
    close()
    return result


def update_message_ack(txn, session, offline=None):
    connect()
    if offline:
        result = Message.update(status=MESSAGE_STATUS['buyer']).where((Message.user_id == session.id)
                                                                    & (Message.key == txn)).execute() \
               and Message(id=uuid4(), key=txn, status=MESSAGE_STATUS['buyer'],
                           user_id=offline, message=json_string(dict(sender=session.address,
                                                                     txn=txn, text="ACK"))).save(force_insert=True)
    else:
        result = Message.delete().where((Message.user_id == session.id) & (Message.key == txn)).execute()

    close()

    return result


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
