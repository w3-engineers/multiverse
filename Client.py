from socketio import Client, exceptions
from concurrent.futures import ThreadPoolExecutor

from config import HTTP_PREFIX
from trace import trace_info


class CPool:
    pool = None
    future = None
    sio = None

    def __init__(self, item=1):
        self.sio = Client()
        self.pool = ThreadPoolExecutor(item)

    def submit(self, func, *args):
        self.future = self.pool.submit(func, *args)
        return self.future

    def done(self):
        return self.future.done()

    def result(self):
        return self.future.result()


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
                self.sio.connect(HTTP_PREFIX + data['surl'])
                if self.sio.eio.state == "connected":
                    self.sio.emit("cluster_destroy_connection", data)
                    break
        except exceptions.ConnectionError as ex:
            trace_info(str(ex))
            return False

        return True
