#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging

from autobahn.asyncio.websocket import WebSocketClientProtocol

from .message import Message
from .messageheader import MessageHeader
from .tokenenc import TokenEnc

_LOGGER = logging.getLogger(__name__)


class ClientProtocol(WebSocketClientProtocol):

    token_enc = TokenEnc()
    next_msg_header = None

    async def refresh_token_periodical(self, interval):
        while True:
            await asyncio.sleep(interval)
            self.sendMessage(self.token_enc.encrypt_command(self.token_enc.get_key()))

    def onConnect(self, response):
        _LOGGER.info('Server connected: {0}'.format(response.peer))
        _LOGGER.debug(response)
        self.token_enc.miniserver_host = self.factory.host
        self.token_enc.miniserver_port = self.factory.port
        self.token_enc.miniserver_username = self.factory.username
        self.token_enc.miniserver_password = self.factory.password

    def onOpen(self):
        _LOGGER.info('WebSocket connection open')
        snr = self.token_enc.get_miniserver_snr()
        _LOGGER.info('MiniServer serial number: {0}'.format(snr))

        version = self.token_enc.get_miniserver_version()
        _LOGGER.info('MiniServer version: {0}'.format(version))

        self.token_enc.get_public_key()
        self.token_enc.generate_session_key()

        self.sendMessage(self.token_enc.exchange_session_key())
        self.sendMessage(self.token_enc.encrypt_command(self.token_enc.get_key_and_salt()))

    def onMessage(self, payload, isBinary):
        if isBinary:
            _LOGGER.debug('Binary message received: {0} bytes'.format(len(payload)))
            self.next_msg_header = MessageHeader(payload)
            _LOGGER.debug('Identifier: {0}'.format(self.next_msg_header.identifier))
            _LOGGER.debug('Payload length: {0}'.format(self.next_msg_header.payload_length))
        else:
            _LOGGER.debug('Text message received: {0}'.format(payload.decode('utf8')))
            if self.next_msg_header.payload_length == len(payload):
                msg = Message(payload)
                _LOGGER.debug('Code: {0}'.format(msg.code))
                _LOGGER.debug('Control: {0}'.format(msg.control))
                _LOGGER.debug('Control type: {0}'.format(msg.control_type))
                _LOGGER.debug('Value: {0}'.format(msg.value))
                if msg.control_type == 'enc':
                    _LOGGER.info('Encrypted command received')
                    msg.control = self.token_enc.decrypt_command(msg.control)
                if msg.control_type == 'auth' and msg.code == 420:
                    _LOGGER.info('Authentication failed (status code {0})'.format(msg.code))
                if msg.control_type == 'keyexchange' and msg.code == 200:
                    _LOGGER.info('Keyexchange succeeded')
                if msg.control_type == 'keyexchange' and msg.code != 200:
                    _LOGGER.info('Keyexchange failed (status code {0})'.format(msg.code))
                if msg.control_type == 'getkey2' and msg.code == 200:
                    _LOGGER.info('Salt and key received for user')
                    self.token_enc.miniserver_user_key = msg.value.get('key')
                    self.token_enc.miniserver_user_salt = msg.value.get('salt')
                    self.sendMessage(self.token_enc.encrypt_command(self.token_enc.get_token()))
                if msg.control_type == 'getkey2' and msg.code != 200:
                    _LOGGER.info('Salt and key not received for user (status code {0})'.format(msg.code))
                if msg.control_type == 'gettoken' and msg.code == 200:
                    _LOGGER.info('Token received')
                    self.token_enc.client_token = msg.value.get('token')
                    self.token_enc.client_token_key = msg.value.get('key')
                    self.token_enc.client_token_valid_until = msg.value.get('validUntil')
                    self.token_enc.client_token_rights = msg.value.get('tokenRights')
                    self.token_enc.client_token_unsecure_pass = msg.value.get('unsecurePass')
                    self.factory.loop.create_task(self.refresh_token_periodical(15))
                if msg.control_type == 'gettoken' and msg.code != 200:
                    _LOGGER.info('Token not received (status code {0})'.format(msg.code))
                if msg.control_type == 'getkey' and msg.code == 200:
                    _LOGGER.info('Key received')
                    self.token_enc.client_token_key = msg.value
                    self.sendMessage(self.token_enc.encrypt_command(self.token_enc.refresh_token()))
                if msg.control_type == 'getkey' and msg.code != 200:
                    _LOGGER.info('Key not received (status code {0})'.format(msg.code))
                if msg.control_type == 'refreshtoken' and msg.code == 200:
                    _LOGGER.info('Token refreshed')
                    self.token_enc.client_token_valid_until = msg.value.get('validUntil')
                    self.token_enc.client_token_unsecure_pass = msg.value.get('unsecurePass')
                if msg.control_type == 'refreshtoken' and msg.code != 200:
                    _LOGGER.info('Token not refreshed (status code {0})'.format(msg.code))
                if msg.control_type == 'unknown':
                    _LOGGER.info('Unknown control {0}'.format(msg.control))
            else:
                _LOGGER.error('ERROR: Promised length of payload does not match')

    def onClose(self, wasClean, code, reason):
        _LOGGER.info('WebSocket connection closed: {0}'.format(reason))
