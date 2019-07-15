from uuid import uuid4
from datetime import datetime

from db_helper.connector import connect, close
from db_helper.models import User, Message, MESSAGE_STATUS
from trace import trace_info
from helpers import set_json


def active_user_list(scope):
    connect()
    user_list = []
    valid_info = User.select(User.address).where(
        (User.scope == scope) & (User.is_online == True))

    for row in valid_info:
        user_list.append(row.address)

    close()
    return user_list


def set_user_info(sid, scope, address, url):
    connect()
    update = User.update(sid=sid, last_seen=datetime.now(), is_online=True, url=url). \
        where((User.scope == scope) & (User.address == address)).execute()
    if update:
        close()
        return True
    user = User(id=uuid4(), scope=scope, address=address, sid=sid, is_online=True, url=url).save(force_insert=True)
    close()
    if user:
        return user


def get_user_info(scope, address, online=True):
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


def update_user_online_info(sid):
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
                           user_id=offline, message=set_json(dict(sender=session.address,
                                                                     txn=txn, text="ACK"))).save(force_insert=True)
    else:
        result = Message.delete().where((Message.user_id == session.id) & (Message.key == txn)).execute()

    close()

    return result
