from db_helper.models import Message

user = Message.select().where(Message.id>0)
for row in user:
    import pdb; pdb.set_trace()
# TODO:: Write proper use case for::
# register, send, receive, user list, ack (send/receive) status.
