from logging import basicConfig, CRITICAL
from os import environ
from eventlet.wsgi import server as eventlet_server
from eventlet import listen as eventlet_listen
from socketio import Server, WSGIApp

from config import HOST, PORT, DEBUG
from db_helper.models import MESSAGE_STATUS
from db_helper.dao import set_user_info, get_user_info, update_user_online_info, active_user_list, \
    get_user_message, save_send_message, update_message_ack
from helpers import get_dict, set_json, get_session_key, get_server_socket
from response_helper import failed_response, success_response, user_list_response, buyer_receive_ack_response, \
    new_message_response, sent_ack_response, receive_ack_response, register_response, send_info_response, EMIT_REGISTER
from trace import trace_info, trace_debug
from Client import SendMessage, SendSentACK

"""
TODO:: Auto Scale System Notification Implement.
Possible Solution Can be pass Server IP and make a internal emit to trigger.
"""

basicConfig(level=CRITICAL)

sio = Server()

if DEBUG:
    app = WSGIApp(sio, static_files={
        '/': 'Client.html',
        '/socket.io.js': 'socket.io.js',
        # '/static/style.css': 'static/style.css',
    })
else:
    app = WSGIApp(sio)

SCOPE_WHITE_LIST = {"telemesh"}

USER_SESSION = dict()
SESSION_SID = dict()


def set_session(sid, scope, address, url):
    session_key = get_session_key(scope, address)
    session = USER_SESSION.get(session_key, None)
    if session and session.sid != sid:
        trace_debug("Duplicate Session for {}, SID:: {}. set_session".format(address, sid))
        return None

    user = set_user_info(sid, scope, address, url)
    if user:
        user_data = get_user_info(scope, address)
        if user_data:
            USER_SESSION.update({session_key: user_data})
            SESSION_SID.update({sid: session_key})
            return USER_SESSION.get(SESSION_SID.get(sid, None))
    else:
        trace_debug("Session set failed for {}, SID:: {}. set_session".format(address, sid))


def get_session(scope, address, online=True):
    session_key = get_session_key(scope, address)
    user = USER_SESSION.get(session_key, None)
    if user:
        if online and user.is_online:
            return user
        return user
    elif not online:
        user = get_user_info(scope, address, online)
        return user
    trace_debug("No session found for {}".format(address))


def no_session(sid=None, scope=None, address=None):
    if SESSION_SID.get(sid):
        sio.disconnect(sid)
        return False
    elif USER_SESSION.get(get_session_key(scope, address)):
        sio.disconnect(sid)
        return False

    return True


def get_server_info(socket, sid):
    headers = socket.environ.get(sid)
    raw_headers = headers.get('headers_raw')
    # trace_info(headers.get('REMOTE_ADDR'))
    # trace_info(headers.get('SERVER_NAME'))
    # trace_info(headers.get('SERVER_PORT'))
    if raw_headers and len(raw_headers) > 2:
        if 'Host' in raw_headers[0]:
            return raw_headers[0][1]
    return headers.get("SERVER_NAME", HOST) + ":" + headers.get("SERVER_PORT", PORT)


def remove_session(sid):
    update_user_online_info(sid)
    try:
        result = SESSION_SID.get(sid, False)
        if result:
            info = USER_SESSION.get(result, False)
            del USER_SESSION[result]
            del SESSION_SID[sid]
            return info
    except KeyError as e:
        trace_debug(str(e) + " :: Session not found on USER_SESSION/SESSION_SID. SID:: " + sid)
        return False


@sio.event
def connect(sid, env):
    if no_session(sid=sid):
        register_response(sio, sid)
    else:
        reason = "SID ALREADY FOUND IN SESSION_SID."
        failed_response(sio, reason, "N/A", sid)
        sio.disconnect(sid)


@sio.event
def register(sid: str, scope: str, address: str):
    if (no_session(sid=sid) or no_session(scope=scope, address=address)) and sid and scope and address:

        sid = sid.strip()
        scope = scope.strip()
        address = address.strip()

        if scope not in SCOPE_WHITE_LIST:
            failed_response(sid, "Wrong APP/Scope", address, sid)
        else:
            user_session = get_session(scope, address)
            if user_session and user_session.is_online == 1:
                try:
                    if get_server_socket(sio, user_session.sid):
                        sio.disconnect(user_session.sid)
                except KeyError as e:
                    trace_debug(str(e) + "-->No SID available on server as {}".format(user_session.sid))
                    remove_session(user_session.sid)

            url = get_server_info(sio, sid)
            user_session = set_session(sid, scope, address, url)
            if user_session:
                success_response(sio, "Session created for {}".format(user_session.address), user_session.address, sid)
                user_list_response(sio, scope)
                # SQS

                new_message = get_user_message(user_session)
                if new_message:
                    for msg in new_message:
                        msg_dict = get_dict(msg.message)
                        if msg.status == MESSAGE_STATUS['buyer']:

                            if update_message_ack(msg.key, user_session):
                                trace_debug("ACK Done and Removed for {}. ADDRESS: {}, SID:: {}. Key:: {}".
                                            format(msg.message, user_session.address, sid, msg.key))
                                buyer_receive_ack_response(sio, scope, msg.key, user_session.address, sid)
                            else:

                                failed_response(sio, "DB ERROR FOR ACK {}. user {}. Message Key:: {}".
                                                format(msg.message, user_session.address, msg.key),
                                                user_session.address, user_session.sid)
                        else:
                            new_message_response(sio, scope, msg.key, msg_dict.get('text', None),
                                                 msg_dict.get('sender', None), user_session.address, sid)

                        receiver = get_session(scope, msg_dict.get('sender', None))

                        # If Sender and receiver both are available
                        if receiver and get_server_socket(sio, receiver.sid):
                            # send receive ack for receive to receiver
                            receive_ack_response(sio, msg_dict['txn'], scope, receiver.address, receiver.sid)
                            if update_message_ack(msg_dict["txn"], receiver):
                                # send receive ack for buyer/targeted user
                                buyer_receive_ack_response(sio, scope, msg_dict['txn'], receiver.address, receiver.sid)
                                trace_debug("ACK DONE and removed {} with SID:: {}, TXN:: {}".
                                            format(receiver.address, receiver.sid, msg_dict['txn']))
                        else:
                            # SQS

                            trace_info("---------Receiver missing check sockets-------")
                            trace_info(receiver)
                            trace_debug("Receiver {} not found. TXN:: {}".format(msg_dict['sender'], msg_dict['txn']))
                            trace_debug("SESSION: {}, SID: {}".format(USER_SESSION, SESSION_SID))
                else:
                    trace_debug("No message found for {}, SID:: {}".format(address, sid))
            else:
                failed_response(sio, "User session establishment failed for {}. Try again.".format(address),
                                address, sid)
                sio.disconnect(sid)
    else:
        trace_info("USER SESSION:: {}".format(USER_SESSION))
        trace_info("USER SID:: {}".format(SESSION_SID))
        reason = "Invalid Request. Address: {}, Session: {}, App:: {}".format(address, sid, scope)
        failed_response(sio, reason, address, sid)
        sio.disconnect(sid)


@sio.event
def send_info(sid, scope, sender, receiver, info):
    user_session = get_session(scope, sender, False)
    receive_user_session = get_session(scope, receiver, False)
    if user_session and user_session.sid == sid and receive_user_session:
        send_info_response(sio, scope, sender, receiver, info, receive_user_session.sid)
        trace_debug("USER SEND INFO TRIGGERED for {} by {}".format(receiver, sender))
    else:
        trace_debug("Sender {}/Receiver {} missing.".format(sender, receiver))


@sio.event
def send_message(sid, scope, address, message):
    user_session = get_session(scope, address)
    if user_session.sid == sid:
        # trace_debug("Name={}. Message={}".format(address, message))
        msg = get_dict(message)
        receiver = get_session(scope, msg['receiver'], False)
        if not receiver:
            reason = "User you tried is not registered! ({}, {})".format(scope, address)
            failed_response(sio, reason, address, sid)
        else:
            raw_send_read_msg = {"txn": msg["txn"], "text": msg['text'],
                                 "sender": address, "to": receiver.address}

            save_message = save_send_message(receiver, msg['txn'], set_json(raw_send_read_msg))
            if save_message:
                if receiver and get_server_socket(sio, receiver.sid):
                    new_message_response(sio, scope, msg['txn'], msg['text'], address,
                                         receiver.address, receiver.sid)
                    receive_ack_response(sio, msg['txn'], scope, user_session.address, sid)
                    trace_debug("Message received by -->{}, SID: {}, TXN: {}, MSG: {}".
                                format(receiver.address, receiver.sid, msg['txn'], msg['text']))
                else:
                    # SQS
                    sent_ack_response(sio, msg['txn'], scope, user_session.address, sid)
                    data = dict(rurl=receiver.url, surl=user_session.url, scope=scope, txn=msg['txn'],
                                text=msg['text'], saddress=address, ssid=user_session.sid,
                                raddress=receiver.address, rsid=receiver.sid)

                    smt = SendMessage(data)
                    smt.start()
                    smt.join()
                    trace_debug("Message sent to -->{}, SID: {}, TXN: {}, MSG: {}".
                                format(receiver.address, receiver.sid, msg['txn'], msg['text']))
            else:
                failed_response(sio, "DB STORE FAILED. MSG: {}, RAW MSG: {}".format(msg, raw_send_read_msg), address,
                                sid)
    else:
        trace_info(">>>INVALID SESSION FOR {}".format(address))
        sio.disconnect(sid)


@sio.event
def buyer_received(sid, c_address, scope, address, txn):
    ack_user_session = get_session(scope, address, False)
    current_user_session = get_session(scope, c_address, False)
    if ack_user_session and get_server_socket(sio, ack_user_session.sid) \
            and current_user_session and get_server_socket(sio, current_user_session.sid) \
            and current_user_session.sid == sid:
        if update_message_ack(txn, current_user_session):
            trace_debug("Receive Ack Done for both-->{}, {}".format(ack_user_session.address, ack_user_session.sid))
            buyer_receive_ack_response(sio, scope, txn, ack_user_session.address, ack_user_session.sid)
            buyer_receive_ack_response(sio, scope, txn, current_user_session.address, current_user_session.sid)
        else:
            trace_debug(current_user_session)
            trace_debug("---**DB ERROR WHILE DELETE!**----")
            failed_response(sio, "DB ERROR WHILE DELETE", c_address, sid)
    elif current_user_session and current_user_session.sid == sid \
            and get_server_socket(sio, sid) \
            and ack_user_session and ack_user_session.sid != sid:
        if update_message_ack(txn, current_user_session, ack_user_session.id):
            # success_response(sio, "", current_user_session.address, sid)
            # SQS
            trace_debug("Receiver {} missing. Receive ACK to sender {}. TXN: {}".format(address, c_address, txn))
        else:
            failed_response(sio, "DB UPDATE FAILED FOR RECEIVER MISSING UPDATE. TXN {}".format(txn), c_address, sid)
    elif ack_user_session and get_server_socket(sio, ack_user_session.sid):
        reason = "Duplicate ACK USER {}".format(address)
        trace_debug(reason)
        failed_response(sid, reason, address, ack_user_session.sid)
        sio.disconnect(ack_user_session.sid)
    elif current_user_session:
        reason = "Duplicate CURRENT USER {}".format(c_address)
        trace_debug(reason)
        failed_response(sid, reason, current_user_session.address, current_user_session.sid)
        sio.disconnect(current_user_session.sid)
    else:
        trace_debug("ACK User not online. Details--> {}, {}, {}, {}".format(sid, scope, address, txn))
        buyer_receive_ack_response(sio, scope, txn, c_address, sid)


@sio.event
def disconnect(sid):
    user = remove_session(sid)
    if user:
        trace_debug("Disconnected-->{}".format(user))
        if USER_SESSION:
            user_list_response(sio, user.scope)
            # SQS
    else:
        trace_info("Disconnected with SID:: {}. No Info on DB!".format(sid))


# CLUSTER --!
@sio.event
def cluster_send_message(sid, data):
    trace_info("Triggered----> {}".format(data))
    new_message_response(sio, data['scope'], data['txn'], data['text'],
                         data['saddress'], data['raddress'], data['rsid'])

    sck = SendSentACK(data)
    sck.start()
    sck.join()
    sio.disconnect(sid)


@sio.event
def cluster_send_ack_message(sid, data):
    trace_info("Triggered----> {}".format(data))
    receive_ack_response(sio, data['txn'], data['scope'],
                         data['saddress'], data['ssid'])
    sio.disconnect(sid)


if __name__ == '__main__':
    trace_info("Multiverse server starting at {}:{}".format(HOST, PORT))
    try:
        eventlet_server(eventlet_listen((HOST, int(environ.get("MULTI_WS_PORT", PORT)))), app)
    except Exception as ex:
        trace_info(str(ex))

# https://socket.io/docs/using-multiple-nodes/
