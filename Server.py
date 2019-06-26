from json import dumps as json_string, loads as json_dict
from eventlet.wsgi import server as eventlet_server
from eventlet import listen as eventlet_listen
from socketio import Server, WSGIApp
from socketio.exceptions import ConnectionRefusedError

sio = Server()
app = WSGIApp(sio)

SESSIONS = dict()
SOC_SESSIONS = dict()
SCOPE_WHITE_LIST = {"telemesh"}


def push_user_list(sid):
    user_list = []
    valid_info = SESSIONS.get(sid)
    if valid_info:
        scope = valid_info["scope"]
        for keyid, info in SESSIONS.items():
            if scope == info["scope"]:
                user_list.append(info['address'])
    print(user_list)
    return user_list


@sio.event
def connect(sid, env):
    sio.emit("register")


def parse_message(msg):
    return json_dict(msg)


@sio.event
def register(sid: str, scope: str, address: str):
    if scope not in SCOPE_WHITE_LIST:
        sio.disconnect(sid)
        raise ConnectionRefusedError("Scope is invalid.")

    sid = sid.strip()
    scope = scope.strip()
    address = address.strip()

    if sid and scope and address:
        user_address = SESSIONS.get(sid)
        if user_address:
            SESSIONS[sid].update({"scope": scope, "address": address})
            SOC_SESSIONS.update({address+scope: sid})
        else:
            SESSIONS[sid] = {"scope": scope, "address": address}
            SOC_SESSIONS[address + scope] = sid

        sio.emit("user_list", json_string(push_user_list(sid)))


@sio.event
def send_message(sid, scope, address, message):
    user_address = SESSIONS.get(sid)
    if user_address and user_address['scope'] == scope and user_address['address'] == address:
        print('Name=', address, "Message=", message)
        msg = parse_message(message)
        print(msg)
        action = msg['action']

        if action == "send":
            receiver = SOC_SESSIONS.get(msg['receiver']+scope)
            print(receiver)
            if receiver:
                sio.emit("new_message",
                         json_string({"txn": msg["txn"], "text": msg['text'], "sender": address}),
                         room=receiver)
                print("sent...!")


@sio.event
def get_user_list(sid):
    sio.emit("user_list", json_string(push_user_list(sid)))


@sio.event
def disconnect(sid):
    print('disconnect ', sid)
    user_info = SESSIONS.get(sid)
    if user_info:
        del SOC_SESSIONS[user_info["address"]+user_info["scope"]]
        del SESSIONS[sid]
        sio.emit("user_list", json_string(push_user_list(sid)))


if __name__ == '__main__':
    eventlet_server(eventlet_listen(('0.0.0.0', 5000)), app)


# https://socket.io/docs/using-multiple-nodes/
