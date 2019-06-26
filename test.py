d = dict()
d["x"] = {"y": [1, 2]}

n = d.get("x")
n = n.get("y")

for i in n:
    print(i)
    # d["x"]["y"].remove(i)
d["x"].update({"y": []})
print(d)


# TODO:: Write proper use case for::
# register, send, receive, user list, ack (send/receive) status.
