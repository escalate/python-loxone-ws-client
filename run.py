#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging
from os import environ

from autobahn.asyncio.websocket import WebSocketClientFactory

from loxone_websocket_client import ClientProtocol

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

MINISERVER_HOST = environ.get('MINISERVER_HOST', '127.0.0.1')
MINISERVER_PORT = environ.get('MINISERVER_PORT', 80)
MINISERVER_USERNAME = environ.get('MINISERVER_USERNAME', 'admin')
MINISERVER_PASSWORD = environ.get('MINISERVER_PASSWORD', 'admin')


if __name__ == '__main__':

    _LOGGER.info('Start WebSocket connection')
    ws_factory = WebSocketClientFactory('ws://{host}:{port}/ws/rfc6455'.format(
        host=MINISERVER_HOST,
        port=MINISERVER_PORT),
        protocols=['remotecontrol'])
    ws_factory.protocol = ClientProtocol
    ws_factory.username = MINISERVER_USERNAME
    ws_factory.password = MINISERVER_PASSWORD

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(ws_factory, MINISERVER_HOST, MINISERVER_PORT)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
