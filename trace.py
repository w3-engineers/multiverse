from config import DEBUG


def trace_debug(item):
    if DEBUG:
        print("************DEBUG*************")
        print(item)


def trace_info(item):
    print("###########INFO############")
    print(item)
