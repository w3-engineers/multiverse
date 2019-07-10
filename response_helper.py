from helpers import set_json
from trace import trace_info
from db_helper.dao import active_user_list

EMIT_FAIL = "failed"
EMIT_SUCCESS = "success"
EMIT_USER_LIST = "user_list"
EMIT_REGISTER = "register"
EMIT_BUYER_RCV_ACK = "buyer_received_ack"
EMIT_NEW_MESSAGE = "new_message"
EMIT_SENT_ACK = "sent_ack"
EMIT_RCV_ACK = "rcv_ack"
EMIT_SEND_INFO = "send_info"
EMIT_RCV_INFO = "receive_info"


def failed_response(sio, reason, receiver, sid):
    """
    If failed it will send response as failed event with reason key as a reason.
    :param sio: socket
    :param reason: str
    :param receiver: str
    :param sid: str
    :return: None
    """
    sio.emit(EMIT_FAIL, set_json(dict(reason=reason, to=receiver)), room=sid)
    trace_info(reason)


def success_response(sio, reason, receiver, sid):
    """
    For successful session connection this will trigger a success event.
    :param sio: socket
    :param reason: str
    :param receiver: str
    :param sid: str
    :return: None
    """
    sio.emit(EMIT_SUCCESS, set_json(dict(reason=reason, to=receiver)), room=sid)
    trace_info(reason)


def user_list_response(sio, scope):
    """
    Trigger User List (online)
    :param sio: socket
    :param scope: str
    :return: None
    """
    sio.emit(EMIT_USER_LIST, set_json(active_user_list(scope)))


def buyer_receive_ack_response(sio, scope, txn, receiver, sid):
    """
    Trigger Buyer Receive ACK
    :param sio: socket
    :param scope: str
    :param txn: str
    :param receiver: str
    :param sid: str
    :return: None
    """
    sio.emit(EMIT_BUYER_RCV_ACK, set_json(dict(scope=scope, txn=txn,
                                               to=receiver)), room=sid)


def new_message_response(sio, scope, txn, text, sender, receiver, sid):
    """
    Trigger New Message Receive Event
    :param sio:
    :param scope:
    :param txn:
    :param text:
    :param sender:
    :param receiver:
    :param sid:
    :return: None
    """
    sio.emit(EMIT_NEW_MESSAGE,
             set_json(dict(txn=txn, scope=scope, text=text, sender=sender, to=receiver)),
             room=sid)


def sent_ack_response(sio, txn, scope, receiver, sid):
    """
    Trigger Event for Message Sent ACK
    :param sio: socket
    :param txn: str
    :param scope: str
    :param receiver: str
    :param sid: str
    :return: None
    """
    sio.emit(EMIT_SENT_ACK, set_json(dict(txn=txn, scope=scope, to=receiver)), room=sid)


def receive_ack_response(sio, txn, scope, receiver, sid):
    """
    Trigger Event while any user able to receive any message.
    :param sio: socket
    :param txn: str
    :param scope: str
    :param receiver: str
    :param sid: str
    :return: None
    """
    sio.emit(EMIT_RCV_ACK, set_json(dict(txn=txn, scope=scope, to=receiver)), room=sid)


def register_response(sio, sid):
    sio.emit(EMIT_REGISTER, room=sid)


def send_info_response(sio, scope, sender, receiver, info, sid):
    sio.emit(EMIT_RCV_INFO, set_json(dict(scope=scope, sender=sender, to=receiver, data=info)), room=sid)