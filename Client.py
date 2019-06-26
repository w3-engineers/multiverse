#!/usr/bin/env python

# WS client example

from asyncio import get_event_loop
from websockets import connect
from json import dumps, loads
from datetime import datetime


def request_builder(sender, receiver, payload, txn):
    return dumps({"sender": sender, "receiver": receiver, "payload": payload, "txn": txn})


def response_parser(response):
    response = loads(response)
    return response


async def client():
    async with connect(
            'ws://localhost:8765/demo') as websocket:
        # data = input("Put your data.")
        data = request_builder("sabbir", "aziz", "Hello Aziz", str(datetime.now().timestamp()))
        await websocket.send(data)
        print(f"> {data}")

        response = await websocket.recv()
        response = response_parser(response)
        if response["type"] == "ok":
            greeting = response["response"]["payload"]
        else:
            greeting = "Error: "+response['response']

        print(f"< {greeting}")


get_event_loop().run_until_complete(client())
