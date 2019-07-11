from logging import basicConfig, CRITICAL
from eventlet.wsgi import server as eventlet_server
from eventlet import listen as eventlet_listen
from socketio import Server, WSGIApp

from config import HOST, PORT, DEBUG
from db_helper.models import MESSAGE_STATUS
from db_helper.dao import set_user_info, get_user_info, update_user_online_info, active_user_list, \
    get_user_message, save_send_message, update_message_ack
from helpers import get_dict, set_json, get_session_key, get_server_socket
from response_helper import failed_response, success_response, user_list_response, buyer_receive_ack_response, \
    new_message_response, sent_ack_response, receive_ack_response, register_response, send_info_response
from trace import trace_info, trace_debug

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


def set_session(sid, scope, address):
    session_key = get_session_key(scope, address)
    session = USER_SESSION.get(session_key, None)
    if session and session.sid != sid:
        trace_info("Duplicate session for {}, while trying to store session.".format(address))
        return False
    
    user = set_user_info(sid, scope, address)
    if user:
        user_data = get_user_info(scope, address)
        if user_data:

            USER_SESSION.update({session_key: user_data})
            SESSION_SID.update({sid: session_key})
            return USER_SESSION.get(SESSION_SID.get(sid, None))


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


def no_session(sid=None, scope=None, address=None):
    if SESSION_SID.get(sid):
        sio.disconnect(sid)
        return False
    elif USER_SESSION.get(get_session_key(scope, address)):
        sio.disconnect(sid)
        return False
    return True


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
        trace_debug(str(e) + " :: Session not found on USER_SESSION/SESSION_SID.")
        return False


@sio.event
def connect(sid, env):
    if no_session(sid=sid):
        register_response(sio, sid)
    else:
        reason = "SID ALREADY FOUND IN SESSION SID."
        trace_info(reason)
        failed_response(sio, "SID ALREADY FOUND IN SESSION SID.", "N/A", sid)
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
                trace_debug("Duplicate connection found for -> {}, {}".format(user_session.address, user_session.sid))
                try:
                    if get_server_socket(sio, user_session.sid):
                        sio.disconnect(user_session.sid)
                except KeyError as e:
                    trace_debug(str(e) + "-->No SID available on server as {}".format(user_session.sid))
                    remove_session(user_session.sid)

            user_session = set_session(sid, scope, address)
            if user_session:
                success_response(sio, "Session created for {}".format(user_session.address), user_session.address, sid)
                user_list_response(sio, scope)

                new_message = get_user_message(user_session)
                if new_message:
                    for msg in new_message:
                        msg_dict = get_dict(msg.message)
                        if msg.status == MESSAGE_STATUS['buyer']:
                            buyer_receive_ack_response(sio, scope, msg.key, user_session.address, sid)
                            if update_message_ack(msg.key, user_session):
                                trace_debug("Message ACK {} sent for this user {}".
                                            format(msg.message, user_session.address))
                            else:
                                trace_debug("DB ERROR FOR ACK {}. user {}".
                                            format(msg.message, user_session.address))
                        else:
                            new_message_response(sio, scope, msg.key, msg_dict.get('text', None),
                                                 msg_dict.get('sender', None), user_session.address, sid)

                        receiver = get_session(scope, msg_dict.get('sender', None))

                        # If Sender and receiver both are available
                        if receiver and get_server_socket(sio, receiver.sid):

                            trace_debug("Receiver for new message {}".format(receiver.address))

                            # send receive ack for receive to receiver
                            receive_ack_response(sio, msg_dict['txn'], scope, receiver.address, receiver.sid)
                            if update_message_ack(msg_dict["txn"], receiver):
                                # send receive ack for buyer/targeted user
                                buyer_receive_ack_response(sio, scope, msg_dict['txn'], receiver.address, receiver.sid)
                                trace_debug("ACK for receiver {}".format(receiver.address))
                        else:
                            trace_info("---------Receiver missing check sockets-------")
                            trace_info(sio.eio.sockets)
                            trace_info(receiver)
                            trace_debug("Receiver {} not found".format(msg_dict['sender']))
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
                                 "sender": address}

            trace_debug("Receiver={}, Message={}".format(receiver.address, raw_send_read_msg))
            raw_send_read_msg['to'] = receiver.address
            save_message = save_send_message(receiver, msg['txn'], set_json(raw_send_read_msg))
            if save_message:
                if receiver and get_server_socket(sio, receiver.sid):
                    new_message_response(sio, scope, msg['txn'], msg['text'], address, receiver.address, receiver.sid)
                    receive_ack_response(sio, msg['txn'], scope, user_session.address, sid)
                    trace_debug("Message received by -->{}, {}".format(receiver.address, receiver.sid))
                else:
                    sent_ack_response(sio, msg['txn'], scope, user_session.address, sid)
                    trace_debug("Message sent to -->{}, {}".format(receiver.address, receiver.sid))
            else:
                trace_info("Message storage refused to save stuff. ({})".format(save_message))
    else:
        trace_info(">>>INVALID SESSION FOR {}".format(address))
        sio.disconnect(sid)


@sio.event
def buyer_received(sid, c_address, scope, address, txn):
    ack_user_session = get_session(scope, address, False)
    current_user_session = get_session(scope, c_address, False)
    if ack_user_session and get_server_socket(sio, ack_user_session.sid) \
            and current_user_session and get_server_socket(sio, current_user_session.sid)\
            and current_user_session.sid == sid:
        if update_message_ack(txn, current_user_session):
            trace_debug("Receive Ack Done for both-->{}, {}".format(ack_user_session.address, ack_user_session.sid))
            buyer_receive_ack_response(sio, scope, txn, ack_user_session.address, ack_user_session.sid)
            buyer_receive_ack_response(sio, scope, txn, current_user_session.address, current_user_session.sid)
        else:
            trace_debug(current_user_session)
            trace_debug("---**DB ERROR WHILE DELETE!**----")
    elif current_user_session and current_user_session.sid == sid and get_server_socket(sio, sid) \
            and ack_user_session and ack_user_session.sid != sid:
        if update_message_ack(txn, current_user_session, ack_user_session.id):
            trace_debug("Receive Ack Done for Sender-->{}, {}".format(ack_user_session.address, ack_user_session.sid))
            receive_ack_response(sio, txn, scope, current_user_session.address, sid)
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


@sio.event
def disconnect(sid):
    user = remove_session(sid)
    if user:
        trace_debug("Disconnected-->{}".format(user))
        user_list_response(sio, user.scope)
    else:
        trace_info("Disconnected with SID:: {}. No Info on DB!".format(sid))


if __name__ == '__main__':

    trace_info("Multiverse server starting at {}:{}".format(HOST, PORT))
    try:
        eventlet_server(eventlet_listen((HOST, PORT)), app)
    except Exception as ex:
        trace_info(str(ex))

# https://socket.io/docs/using-multiple-nodes/
