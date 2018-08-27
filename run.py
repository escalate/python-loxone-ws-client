#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
from os import environ

from autobahn.asyncio.websocket import (WebSocketClientFactory,
                                        WebSocketClientProtocol)

from loxone_ws_client import Message, MessageHeader, TokenEnc

MINISERVER_HOST = environ.get('MINISERVER_HOST', '127.0.0.1')
MINISERVER_PORT = environ.get('MINISERVER_PORT', 80)
MINISERVER_USERNAME = environ.get('MINISERVER_USERNAME', 'admin')


class LoxoneClientProtocol(WebSocketClientProtocol):

    token_enc = TokenEnc()
    next_msg_header = None

    def onConnect(self, response):
        print("Server connected: {0}".format(response.peer))
        print("Version: {0}".format(response.version))
        print(response)
        connection_peer = response.peer.split(':')
        self.token_enc.miniserver_host = connection_peer[1]
        self.token_enc.miniserver_port = connection_peer[2]
        self.token_enc.miniserver_username = MINISERVER_USERNAME

    def onOpen(self):
        print("WebSocket connection open.")
        snr = self.token_enc.get_miniserver_snr()
        print(snr)

        version = self.token_enc.get_miniserver_version()
        print(version)

        public_key = self.token_enc.get_public_key()
        print(public_key)

        aes_key = self.token_enc.generate_aes256_key()
        print(aes_key)

        aes_iv = self.token_enc.generate_aes_iv()
        print(aes_iv)

        session_key = self.token_enc.generate_session_key()
        print(session_key)

        salt = self.token_enc.generate_salt()
        print(salt)

        self.sendMessage(self.token_enc.exchange_session_key())
        self.sendMessage(self.token_enc.get_key_and_salt())

    def onMessage(self, payload, isBinary):
        if isBinary:
            print("Binary message received: {0} bytes".format(len(payload)))
            self.next_msg_header = MessageHeader(payload)
            print('Identifier ' + str(self.next_msg_header.identifier))
            print('Payload length: ' + str(self.next_msg_header.payload_length))
        else:
            print("Text message received: {0}".format(payload.decode('utf8')))
            if self.next_msg_header.payload_length == len(payload):
                msg = Message(payload)
                print('Code: ' + msg.code)
                print('Control: ' + msg.control)
                print('Value: ' + msg.value)
                if msg.control_type == 'auth' and msg.code == '420':
                    print('Authentication failed with status code {0}'.format(msg.code))
                if msg.control_type == 'keyexchange' and msg.code == '200':
                    print('Keyexchange succeeded')
                if msg.control_type == 'keyexchange' and msg.code != '200':
                    print('Keyexchange failed with status code {0}'.format(msg.code))
                if msg.control_type == 'getkey2' and msg.code == 200:
                    print('Salt and key received for user')
                if msg.control_type == 'getkey2' and msg.code != 200:
                    print('Salt and key not received for user (status code {0})'.format(msg.code))
                if msg.control_type == 'unknown':
                    print('Unknown control ' + msg.control)
            else:
                print('ERROR: Promised length of payload does not match')

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))


if __name__ == '__main__':

    print('Start WebSocket connection')
    ws_factory = WebSocketClientFactory('ws://{host}:{port}/ws/rfc6455'.format(
        host=MINISERVER_HOST,
        port=MINISERVER_PORT),
        protocols=['remotecontrol'])
    ws_factory.protocol = LoxoneClientProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(ws_factory, MINISERVER_HOST, MINISERVER_PORT)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
