from logging import basicConfig, CRITICAL
# , debug as trace_debug, info as trace_info, DEBUG as LOG_DEBUG, INFO as LOG_INFO
from eventlet.wsgi import server as eventlet_server
from eventlet import listen as eventlet_listen
from socketio import Server, WSGIApp
from socketio.exceptions import ConnectionRefusedError, ConnectionError

from config import DEBUG, HOST, PORT
from db_helper.models import MESSAGE_STATUS
from helpers import parse_message, set_json, \
    push_user_list, set_session, remove_session, \
    get_session, get_user_message, save_send_message, \
    update_message_ack, trace_info, trace_debug, get_server_socket

"""
TODO:: Auto Scale System Notification Implement.
Possible Solution Can be pass Server IP and make a internal emit to trigger.
"""

# if DEBUG:
#     basicConfig(level=LOG_DEBUG)
# else:
#     basicConfig(level=LOG_INFO)
basicConfig(level=CRITICAL)

sio = Server()
app = WSGIApp(sio)
# dbo.connect()


SCOPE_WHITE_LIST = {"telemesh"}

EMIT_REGISTER = "register"
EMIT_USER_LIST = "user_list"
EMIT_NEW_MESSAGE = "new_message"
EMIT_SENT_ACK = "sent_ack"
EMIT_RCV_ACK = "rcv_ack"
EMIT_BUYER_RCV = "buyer_received"
EMIT_BUYER_RCV_ACK = "buyer_received_ack"
EMIT_SUCCESS = "success"
EMIT_FAIL = "failed"


# EMIT_ERROR = "error"


@sio.event
def connect(sid, env):
    # check_duplicate = SESSIONS.get(sid)
    # if check_duplicate:
    #     trace_debug("Duplicate connection->{}, {}".format(sid, check_duplicate))
    #     # "As:: ", check_duplicate, " Closed!")
    sio.emit(EMIT_REGISTER, room=sid)


@sio.event
def register(sid: str, scope: str, address: str):
    if sid and scope and address:

        sid = sid.strip()
        scope = scope.strip()
        address = address.strip()

        if scope not in SCOPE_WHITE_LIST:
            # sio.disconnect(sid)
            sio.emit(EMIT_FAIL, set_json(dict(reason="Wrong APP/Scope", receiver=address)), room=sid)
            raise ConnectionRefusedError("Scope is invalid.")

        user_session = get_session(scope, address)
        if user_session and user_session.is_online == 1:
            trace_debug("Duplicate connection->{}, {}".format(user_session.address, user_session.sid))
            try:
                if get_server_socket(sio, user_session.sid):
                    sio.disconnect(user_session.sid)
            except KeyError as e:
                trace_debug(str(e) + "-->Nothing to close!")
                remove_session(user_session.sid)

        # user_session = set_session(sid, scope, address)
        if set_session(sid, scope, address):
            user_session = get_session(scope, address)
        if user_session:
            sio.emit(EMIT_SUCCESS, set_json(dict(reason="Session Created.", receiver=user_session.address)), room=sid)
            sio.emit(EMIT_USER_LIST, set_json(push_user_list(scope)))

            new_message = get_user_message(user_session)
            if new_message:
                # receiver = None
                for msg in new_message:

                    if msg.status == MESSAGE_STATUS['buyer']:
                        sio.emit(EMIT_BUYER_RCV_ACK, set_json(dict(scope=scope, txn=msg.key,
                                                                   receiver=user_session.address)), room=sid)
                        if update_message_ack(msg.key, user_session):
                            trace_debug("Message ACK {} sent for this user {}".
                                        format(msg.message, user_session.address))
                        else:
                            trace_debug("DB ERROR FOR ACK {}. user {}".
                                        format(msg.message, user_session.address))
                    else:
                        tmp_msg = parse_message(msg.message)
                        tmp_msg['receiver'] = user_session.address
                        sio.emit(EMIT_NEW_MESSAGE, tmp_msg, room=sid)

                    msg = parse_message(msg.message)
                    # if receiver and receiver.user_id.address != msg['sender']:
                    receiver = get_session(scope, msg['sender'])

                    ack_msg_own = dict(txn=msg["txn"], scope=scope, receiver=user_session.address)
                    ack_ready_msg_own = set_json(ack_msg_own)

                    if receiver and get_server_socket(sio, receiver.sid):
                        ack_msg_other = dict(txn=msg["txn"], scope=scope, receiver=receiver.address)
                        ack_ready_msg_other = set_json(ack_msg_other)
                        trace_debug("Receiver {}".format(receiver.address))

                        sio.emit(EMIT_RCV_ACK, ack_ready_msg_other, room=receiver.sid)
                        if update_message_ack(ack_msg_other['txn'], receiver):
                            sio.emit(EMIT_BUYER_RCV_ACK, ack_ready_msg_other, room=receiver.sid)
                            trace_debug("ACK for receiver {}".format(receiver.address))
                    else:
                        print(sio.eio.sockets)
                        print(receiver)
                        trace_debug("Receiver {} not found".format(msg['sender']))
        else:
            sio.emit(EMIT_FAIL,
                     set_json(dict(reason="User session establishment failed. Try again.", receiver=address)), room=sid)
    else:
        sio.emit(EMIT_FAIL, set_json(dict(reason="Invalid Info passed.", receiver=address)))
        trace_debug("Invalid Request. Address: {}, Session: {}, App:: {}".format(address, sid, scope))
        # sio.disconnect(sid)
        raise ConnectionRefusedError("Scope/Address/SID missing.")


@sio.event
def send_message(sid, scope, address, message):
    user_session = get_session(scope, address)
    if user_session.sid == sid:
        trace_debug("Name={}. Message={}".format(address, message))
        msg = parse_message(message)
        receiver = get_session(scope, msg['receiver'], False)
        if not receiver:
            sio.disconnect(sid)
            raise ConnectionRefusedError("User your tried was invalid ({}, {})".format(scope, address))

        raw_send_read_msg = {"txn": msg["txn"], "text": msg['text'],
                             "sender": address}
        send_ready_msg = set_json({"txn": msg["txn"], "text": msg['text'],
                                   "sender": address})
        trace_debug("Receiver={}, Message={}".format(receiver.address, send_ready_msg))
        save_message = None
        if receiver:
            raw_send_read_msg['receiver'] = receiver.address
            save_message = save_send_message(receiver, msg['txn'], set_json(raw_send_read_msg))
        if not save_message:
            raise ConnectionError("Message storage refused to save stuff. ({})".format(save_message))

        if receiver and get_server_socket(sio, receiver.sid):
            sio.emit(EMIT_NEW_MESSAGE,
                     set_json(raw_send_read_msg),
                     room=receiver.sid)
            sio.emit(EMIT_RCV_ACK, set_json(dict(txn=msg["txn"], scope=scope, receiver=user_session.address)), room=sid)
            trace_debug("Message received by -->{}, {}".format(receiver.address, receiver.sid))
        else:
            sio.emit(EMIT_SENT_ACK, set_json(dict(txn=msg["txn"], scope=scope, receiver=user_session.address)), room=sid)
            trace_debug("Message sent to -->{}, {}".format(receiver.address, receiver.sid))
    else:
        sio.disconnect(sid)


@sio.event
def buyer_received(sid, c_address, scope, address, txn):
    ack_user_session = get_session(scope, address, False)
    current_user_session = get_session(scope, c_address, False)
    if ack_user_session and get_server_socket(sio, ack_user_session.sid) and current_user_session:
        if update_message_ack(txn, current_user_session):
            trace_debug("Receive Ack Done -->{}, {}".format(ack_user_session.address, ack_user_session.sid))
            sio.emit(EMIT_BUYER_RCV_ACK, set_json(dict(scope=scope, txn=txn, receiver=ack_user_session.address)),
                     room=ack_user_session.sid)
            sio.emit(EMIT_BUYER_RCV_ACK, set_json(dict(scope=scope, txn=txn, receiver=current_user_session.address)),
                     room=sid)
        else:
            trace_debug(current_user_session)
            trace_debug("---**DB ERROR WHILE DELETE!**----")
    elif current_user_session and ack_user_session:
        if update_message_ack(txn, current_user_session, ack_user_session.id):
            trace_debug("ACK User Status Updated as he not online!")
            trace_debug("Current User for txn: {}, UserId: {}".format(txn, c_address))
            sio.emit(EMIT_RCV_ACK, set_json(dict(scope=scope, txn=txn, receiver=current_user_session.address)), room=sid)
        else:
            trace_debug(current_user_session)
            trace_debug("---**DB ERROR WHILE DELETE! UPDATE!!!**----")
    else:
        trace_debug("ACK User not online. Details--> {}, {}, {}, {}".format(sid, scope, address, txn))


@sio.event
def disconnect(sid):
    user = remove_session(sid)
    if user:
        trace_debug("Disconnected-->{}".format(user.address))
        sio.emit(EMIT_USER_LIST, set_json(push_user_list(user.scope)))
    else:
        trace_info("Disconnected with SID:: {}. No Info on DB!".format(sid))


if __name__ == '__main__':

    trace_info("Multiverse server starting at {}:{}".format(HOST, PORT))
    try:
        eventlet_server(eventlet_listen((HOST, PORT)), app)
    except Exception as ex:
        trace_info(str(ex))

# https://socket.io/docs/using-multiple-nodes/
