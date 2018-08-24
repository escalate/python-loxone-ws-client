#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
from os import environ

from autobahn.asyncio.websocket import (WebSocketClientFactory,
                                        WebSocketClientProtocol)


MINISERVER_HOST = environ.get('MINISERVER_HOST', '127.0.0.1')
MINISERVER_PORT = environ.get('MINISERVER_PORT', 80)


class LoxoneClientProtocol(WebSocketClientProtocol):

    def onConnect(self, response):
        print("Server connected: {0}".format(response.peer))
        print("Version: {0}".format(response.version))
        print(response)

    def onOpen(self):
        print("WebSocket connection open.")

    def onMessage(self, payload, isBinary):
        if isBinary:
            print("Binary message received: {0} bytes".format(len(payload)))
        else:
            print("Text message received: {0}".format(payload.decode('utf8')))

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))


if __name__ == '__main__':

    print('Start WebSocket connection')
    ws_factory = WebSocketClientFactory('ws://{miniserver_host}:{miniserver_port}/ws/rfc6455'.format(
        miniserver_host=MINISERVER_HOST,
        miniserver_port=MINISERVER_PORT),
        protocols=['remotecontrol'])
    ws_factory.protocol = LoxoneClientProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(ws_factory, MINISERVER_HOST, MINISERVER_PORT)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
