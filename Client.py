from socketio import Client, exceptions
from threading import Thread

from config import HTTP_PREFIX
from trace import trace_info


class SendMessage(Thread):

    sio = None
    data = None

    def __init__(self, data):
        Thread.__init__(self)
        self.data = data
        self.sio = Client()

    def run(self):
        try:
            self.sio.connect(HTTP_PREFIX+self.data['rurl'])
            sio = self.sio
            while True:
                if sio.eio.state == "connected":
                    self.sio.emit("cluster_send_message", self.data)
                    break
        except exceptions.ConnectionError as e:
            trace_info(str(e))
            return

        return


class SendSentACK(Thread):

    sio = None
    data = None

    def __init__(self, data):
        Thread.__init__(self)
        self.data = data
        self.sio = Client()
        self.sio.connect(HTTP_PREFIX+data['surl'])

    def run(self):
        try:
            sio = self.sio
            while True:
                if sio.eio.state == "connected":
                    self.sio.emit("cluster_send_ack_message", self.data)
                    break
        except exceptions.ConnectionError as ex:
            trace_info(str(ex))
            return

        return
