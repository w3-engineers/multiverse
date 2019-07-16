from socketio import Client, exceptions
from concurrent.futures import ThreadPoolExecutor
from time import sleep

from config import HTTP_PREFIX
from trace import trace_info, trace_debug
from helpers import set_json


class CPool:
    pool = None
    future = None
    sio = None
    item = 1

    def __init__(self, item=100):
        self.sio = Client(reconnection_attempts=1)
        self.pool = ThreadPoolExecutor(1)
        self.item = item

    def submit(self, func, *args):
        self.future = self.pool.submit(func, *args)

    def done(self):
        return self.future.done()
        count = 0
        while True:
            if count > self.item:
                break
            elif self.future.done():
                return self.future.done()
            # trace_debug("Counting [Done] ...{}".format(count))
            count += 1
            # sleep(.5)

        trace_debug("Un finished.")
        return True

    def result(self):
        return self.future.result()
        count = 0
        while True:

            if count > self.item:
                break
            elif self.future.done():
                return self.future.result()
            # elif self.future.result():
            #     return True
            # trace_debug("Counting [Result] ...{}".format(count))
            count += 1
            # sleep(1)
        trace_debug("Forced Close Result.")
        return True


class SendMessage(CPool):

    def work(self, data):
        return self.submit(self.send_message, data)

    def send_message(self, data):
        try:
            self.sio.connect(HTTP_PREFIX+data['rurl'])
            while True:
                if self.sio.eio.state == "connected":
                    self.sio.emit("cluster_send_message", data)
                    break
                else:
                    trace_info("OFFLINE SendMSG")
        except exceptions.ConnectionError as e:
            trace_info(str(e))
            return
        return True


class SendSentACK(CPool):
    def work(self, data):
        return self.submit(self.send_ack, data)

    def send_ack(self, data):

        try:
            self.sio.connect(HTTP_PREFIX + data['surl'])
            while True:
                if self.sio.eio.state == "connected":
                    self.sio.emit("cluster_send_ack_message", data)
                    break
                else:
                    trace_info("OFFLINE SendACK")
        except exceptions.ConnectionError as ex:
            trace_info(str(ex))
            return
        return True


class DuplicateConnectionDestroy(CPool):
    def work(self, data):
        return self.submit(self.disconnect, data)

    def disconnect(self, data):
        try:
            while True:
                trace_debug(data['surl'])
                self.sio.connect(HTTP_PREFIX + data['surl'])
                if self.sio.eio.state == "connected":
                    self.sio.emit("cluster_destroy_connection", data)
                    break
                else:
                    trace_info("OFFLINE Duplicate")
        except exceptions.ConnectionError as ex:
            trace_info(str(ex))
            return False

        return True


class BuyerReceiveACK(CPool):

    def work(self, data):
        return self.submit(self.ack, data)

    def ack(self, data):

        try:
            rid = data.get("rid", None)
            sid = data.get("sid", None)
            if data.get("rid") and type(rid) != str:
                data['rid'] = data.get("rid").hex
            if data.get("sid") and type(sid) != str:
                data['sid'] = data.get("sid").hex

            self.sio.connect(HTTP_PREFIX + data['rurl'])
            while True:
                if self.sio.eio.state == "connected":
                    self.sio.emit("cluster_buyer_receive_ack", data)
                    break
                else:
                    trace_info("Offline BUYER ACK")
        except exceptions.ConnectionError as ex:
            trace_info(str(ex))
            return
        return True


class UserList(CPool):

    def work(self, urls, data, emit_ket):
        return self.submit(self.users, urls, data, emit_ket)

    def users(self, url, data, emit_key):
        try:
            trace_debug(url)
            trace_debug("NEW CONNECTION FOR USER LIST")
            self.sio.connect(HTTP_PREFIX + url)
            while True:
                trace_debug("INITIATED")
                if self.sio.eio.state == "connected":
                    self.sio.emit(emit_key, data)
                    trace_debug(emit_key)
                    break
                else:
                    trace_info("Offline USER LIST")
        except exceptions.ConnectionError as ex:
            trace_info(str(ex))

        return True
