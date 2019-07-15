from socketio import Client
from threading import Thread

from config import HTTP_PREFIX


class SendMessage(Thread):

    sio = None
    data = None

    def __init__(self, data):
        Thread.__init__(self)
        self.data = data
        self.sio = Client()
        self.sio.connect(HTTP_PREFIX+data['rurl'])

    def run(self):
        sio = self.sio
        while True:
            if sio.eio.state == "connected":
                self.sio.emit("cluster_send_message", self.data)
                break

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
        sio = self.sio

        while True:
            if sio.eio.state == "connected":
                self.sio.emit("cluster_send_ack_message", self.data)
                break

        return
