from json import loads as json_dict, dumps as json_string
from uuid import uuid4
from db_helper.models import Message, MESSAGE_STATUS
from db_helper.connector import connect, close


def parse_message(msg):
    return json_dict(msg)


def set_json(data):
    return json_string(data)


def get_dict(json):
    return json_dict(json)


def get_session_key(scope, address):
    return address + scope


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
