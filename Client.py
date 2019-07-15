from socketio import Client
from threading import Thread, Lock


#
# sio = Client()
# # sio.connection_url = "http://localhost:5000"
# sio.connect("http://localhost:5000")
#
# sio.emit("cluster_send_message", dict("xxx"))
# #
# # @sio.on("connect")
# # def con():
# #     print("nce")
# #
# #
# # @sio.on("register")
# # def reg():
# #     print("rego")
# #
# #
# # @sio.on("disconnect")
# # def dis():
# #     print("disc")
#
# # import pdb; pdb.set_trace()
# sio.disconnect()

# sio = SocketIoHelper("http://localhost:5000")
# sio.send_new_message(dict("xxx"))
# # sio.close()
# new_message_response(sio, scope, msg['txn'], msg['text'], address,
#                                          receiver.address, receiver.sid)


class SendMessage(Thread):

    sio = None
    data = None

    def __init__(self, data):
        Thread.__init__(self)
        self.data = data
        self.sio = Client()
        self.sio.connect("http://"+data['rurl'])

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
        self.sio.connect("http://"+data['surl'])

    def run(self):
        sio = self.sio

        while True:
            if sio.eio.state == "connected":
                self.sio.emit("cluster_send_ack_message", self.data)
                break

        return
