from json import loads as json_dict, dumps as json_string


def set_json(data):
    return json_string(data)


def get_dict(json):
    return json_dict(json)


def get_session_key(scope, address):
    return str(address) + str(scope)


def get_server_socket(sio, key):
    return sio.eio.sockets.get(key, None)
