from json import loads as json_dict, dumps as json_string


def parse_message(msg):
    return json_dict(msg)


def set_json(data):
    return json_string(data)


def push_user_list(sid, sessions):
    user_list = []
    valid_info = sessions.get(sid)
    if valid_info:
        scope = valid_info["scope"]
        for keyid, info in sessions.items():
            if scope == info["scope"]:
                user_list.append(info['address'])
    print(user_list)
    return user_list
