from eventlet.wsgi import server as eventlet_server
from eventlet import listen as eventlet_listen
from socketio import Server, WSGIApp
from socketio.exceptions import ConnectionRefusedError

from helpers import parse_message, set_json, push_user_list

sio = Server()
app = WSGIApp(sio)

SESSIONS = dict()
SOC_SESSIONS = dict()
SCOPE_WHITE_LIST = {"telemesh"}
MSG_QUEUE = dict()
ACK_QUEUE = dict()

EMIT_REGISTER = "register"
EMIT_USER_LIST = "user_list"
EMIT_NEW_MESSAGE = "new_message"
EMIT_SENT_ACK = "sent_ack"
EMIT_RCV_ACK = "rcv_ack"


@sio.event
def connect(sid, env):
    check_duplicate = SESSIONS.get(sid)
    if check_duplicate:
        print("Duplicate connection found for->", sid, check_duplicate)  # "As:: ", check_duplicate, " Closed!")

    sio.emit(EMIT_REGISTER, room=sid)


@sio.event
def register(sid: str, scope: str, address: str):
    if scope not in SCOPE_WHITE_LIST:
        sio.disconnect(sid)
        raise ConnectionRefusedError("Scope is invalid.")

    sid = sid.strip()
    scope = scope.strip()
    address = address.strip()

    check_duplicate = SOC_SESSIONS.get(address+scope)
    if check_duplicate:
        print("Duplicate found for->", address, " with SID:: ", check_duplicate)
        sio.disconnect(check_duplicate)

    if sid and scope and address:
        user_address = SESSIONS.get(sid)
        if user_address:
            SESSIONS[sid].update({"scope": scope, "address": address})
            SOC_SESSIONS.update({address+scope: sid})
        else:
            SESSIONS[sid] = {"scope": scope, "address": address}
            SOC_SESSIONS[address + scope] = sid

        sio.emit(EMIT_USER_LIST, set_json(push_user_list(sid, SESSIONS)))

        new_message = MSG_QUEUE.get(scope)
        if new_message:
            new_message = new_message.get(address)
            if new_message:
                for msg in new_message:
                    sio.emit(EMIT_NEW_MESSAGE, msg, room=sid)
                    # For ack
                    msg = parse_message(msg)
                    receiver = SOC_SESSIONS.get(msg['sender'] + scope)
                    ack_ready_msg = set_json(dict(txn=msg["txn"], scope=scope))

                    if receiver:
                        sio.emit(EMIT_RCV_ACK,ack_ready_msg, room=receiver)
                    else:
                        ack_queue = ACK_QUEUE.get(scope)
                        if ack_queue:
                            ack_queue = ack_queue.get(msg['sender'])
                            if ack_queue:
                                ack_queue.append(ack_ready_msg)
                                ACK_QUEUE[scope].update({msg['sender']: ack_queue})
                            else:
                                ACK_QUEUE[scope].update({msg['sender']: [ack_ready_msg]})
                        else:
                            ACK_QUEUE[scope] = {msg['sender']: [ack_ready_msg]}

                # clear Receiver Message Queue if session available.
                MSG_QUEUE[scope].update({address: []})

        # send message ack if any to connected session
        new_ack = ACK_QUEUE.get(scope)
        if new_ack:
            new_ack = new_ack.get(address)
            if new_ack:
                for ack in new_ack:
                    sio.emit(EMIT_RCV_ACK, ack, room=sid)
                ACK_QUEUE[scope].update({address: []})

    print("SOCKET::", SOC_SESSIONS)
    print("SESSION::", SESSIONS)


@sio.event
def send_message(sid, scope, address, message):
    user_address = SESSIONS.get(sid)
    if user_address and user_address['scope'] == scope and user_address['address'] == address:
        print('Name=', address, "Message=", message)
        msg = parse_message(message)
        action = msg['action']

        if action == "send":
            receiver = SOC_SESSIONS.get(msg['receiver']+scope)
            send_ready_msg = set_json({"txn": msg["txn"], "text": msg['text'], "sender": address})
            print("Receiver", receiver, "For::", msg["receiver"])
            if receiver:
                sio.emit(EMIT_NEW_MESSAGE,
                         send_ready_msg,
                         room=receiver)
                sio.emit(EMIT_RCV_ACK, set_json(dict(txn=msg["txn"], scope=scope)), room=sid)
            else:
                msg_queue = MSG_QUEUE.get(scope)
                if msg_queue:
                    msg_queue = msg_queue.get(msg["receiver"])
                    if msg_queue:
                        msg_queue.append(send_ready_msg)
                        MSG_QUEUE[scope].update({msg["receiver"]: msg_queue})
                    else:
                        MSG_QUEUE[scope].update({msg["receiver"]: [send_ready_msg]})
                else:
                    MSG_QUEUE[scope] = {msg["receiver"]: [send_ready_msg]}

                sio.emit(EMIT_SENT_ACK, set_json(dict(txn=msg["txn"], scope=scope)), room=sid)


@sio.event
def get_user_list(sid):
    sio.emit(EMIT_USER_LIST, set_json(push_user_list(sid, SESSIONS)))


@sio.event
def disconnect(sid):

    user_info = SESSIONS.get(sid)
    if user_info:
        del SOC_SESSIONS[user_info["address"]+user_info["scope"]]
        del SESSIONS[sid]
        print('disconnected-->', sid, ": ", user_info["address"])
        sio.emit(EMIT_USER_LIST, set_json(push_user_list(sid, SESSIONS)))


if __name__ == '__main__':
    eventlet_server(eventlet_listen(('0.0.0.0', 5000)), app)


# https://socket.io/docs/using-multiple-nodes/
