from uuid import uuid4
from datetime import datetime

from db_helper.connector import connect, close
from db_helper.models import User
from trace import trace_info


def active_user_list(scope):
    connect()
    user_list = []
    valid_info = User.select(User.address).where(
        (User.scope == scope) & (User.is_online == True))

    for row in valid_info:
        user_list.append(row.address)

    close()
    return user_list


def set_user_info(sid, scope, address):
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
