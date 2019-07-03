from logging import basicConfig, CRITICAL  # , debug as trace_debug, info as trace_info, DEBUG as LOG_DEBUG, INFO as LOG_INFO
from eventlet.wsgi import server as eventlet_server
from eventlet import listen as eventlet_listen
from socketio import Server, WSGIApp
from socketio.exceptions import ConnectionRefusedError, ConnectionError

from config import DEBUG, HOST, PORT
from helpers import parse_message, set_json, \
    push_user_list, set_session, remove_session,\
    get_session, get_user_message, save_send_message,\
    update_message_ack, trace_info, trace_debug, get_server_socket

# if DEBUG:
#     basicConfig(level=LOG_DEBUG)
# else:
#     basicConfig(level=LOG_INFO)
basicConfig(level=CRITICAL)

sio = Server()
app = WSGIApp(sio)
# dbo.connect()

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
EMIT_BUYER_RCV = "buyer_received"
EMIT_BUYER_RCV_ACK = "buyer_received_ack"


@sio.event
def connect(sid, env):
    check_duplicate = SESSIONS.get(sid)
    if check_duplicate:
        trace_debug("Duplicate connection->{}, {}".format(sid, check_duplicate))
        # "As:: ", check_duplicate, " Closed!")
    sio.emit(EMIT_REGISTER, room=sid)


@sio.event
def register(sid: str, scope: str, address: str):
    if sid and scope and address:

        sid = sid.strip()
        scope = scope.strip()
        address = address.strip()

        if scope not in SCOPE_WHITE_LIST:
            sio.disconnect(sid)
            raise ConnectionRefusedError("Scope is invalid.")

        user_session = get_session(scope, address)
        if user_session and user_session.is_online == 1:
            trace_debug("Duplicate connection->{}, {}".format(user_session.address, user_session.sid))
            try:
                if get_server_socket(sio, user_session.sid):
                    sio.disconnect(user_session.sid)
            except KeyError as e:
                trace_debug(str(e) + "-->Nothing to close!")

        user_session = set_session(sid, scope, address)
        if user_session:
            user_session = get_session(scope, address)
        if user_session:
            sio.emit(EMIT_USER_LIST, set_json(push_user_list(scope)))

            new_message = get_user_message(user_session)
            if new_message:
                receiver = None
                for msg in new_message:
                    sio.emit(EMIT_NEW_MESSAGE, msg.message, room=sid)

                    # For ack

                    msg = parse_message(msg.message)
                    # receiver = SOC_SESSIONS.get(msg['sender'] + scope)
                    if receiver and receiver.user_id.address != msg['sender']:
                        receiver = get_session(scope, msg['sender'])

                    ack_msg = dict(txn=msg["txn"], scope=scope)
                    ack_ready_msg = set_json(ack_msg)

                    if receiver and get_server_socket(sio, receiver.sid):
                        sio.emit(EMIT_RCV_ACK, ack_ready_msg, room=receiver.id)
                        # update_message_ack(ack_msg['txn'], receiver, MESSAGE_STATUS['seller'])
    else:
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
        send_ready_msg = set_json({"txn": msg["txn"], "text": msg['text'], "sender": address})
        trace_debug("Receiver={}, Message=".format(receiver.address, send_ready_msg))
        save_message = None
        if receiver:
            save_message = save_send_message(receiver, msg['txn'], send_ready_msg)
        if not save_message:
            raise ConnectionError("Message storage refused to save stuff. ({})".format(save_message))

        if receiver and get_server_socket(sio, receiver.sid):
            sio.emit(EMIT_NEW_MESSAGE,
                     send_ready_msg,
                     room=receiver.sid)
            sio.emit(EMIT_RCV_ACK, set_json(dict(txn=msg["txn"], scope=scope)), room=sid)
            # update_message_ack(msg['txn'], receiver, MESSAGE_STATUS['seller'])
            trace_debug("Message received by -->{}, {}".format(receiver.address, receiver.sid))
        else:
            sio.emit(EMIT_SENT_ACK, set_json(dict(txn=msg["txn"], scope=scope)), room=sid)
            trace_debug("Message sent to -->{}, {}".format(receiver.address, receiver.sid))


@sio.event
def buyer_received(sid, c_address, scope, address, txn):
    ack_user_session = get_session(scope, address, False)
    if ack_user_session and get_server_socket(sio, ack_user_session.sid):
        current_user_session = get_session(scope, c_address, False)
        if current_user_session:
            if update_message_ack(txn, current_user_session):
                trace_debug("Receive Ack Done -->{}, {}".format(ack_user_session.address, ack_user_session.sid))
                sio.emit(EMIT_BUYER_RCV_ACK, set_json(dict(scope=scope, txn=txn)), room=sid)
                sio.emit(EMIT_BUYER_RCV_ACK, set_json(dict(scope=scope, txn=txn)), room=ack_user_session.sid)
            else:
                trace_debug(current_user_session)
                trace_debug("---**DB ERROR WHILE DELETE!**----")
        else:
            trace_debug("Current User not found for txn: {}, UserId: {}".format(txn, c_address))
    else:
        trace_debug("{}, {}, {}, {}".format(sid, scope, address, txn))


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
            # trace_info(app)
    except Exception as ex:
        trace_info(str(ex))

# https://socket.io/docs/using-multiple-nodes/
