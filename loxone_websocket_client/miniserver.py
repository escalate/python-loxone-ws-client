#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging

from Crypto.PublicKey import RSA
from requests import codes, get

_LOGGER = logging.getLogger(__name__)


class MiniServer:

    def __init__(self, host, port=80, username='admin', password='admin'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.snr = ''
        self.version = ''
        self.public_key = None
        self.request_timeout = 5

        self.get_api()
        self.get_public_key()

    @staticmethod
    def _fix_json_data(data):
        return data.replace('\'', '"')

    def get_api(self):
        _LOGGER.info('Get MiniServer information')
        req = get('http://{host}:{port}/jdev/cfg/api'.format(
            host=self.host,
            port=self.port),
            timeout=self.request_timeout)
        if req.status_code == codes.ok:  # pylint: disable=E1101
            miniserver_api = json.loads(self._fix_json_data(
                req.json().get('LL').get('value')))
            self.snr = miniserver_api.get('snr')
            self.version = miniserver_api.get('version')

    @staticmethod
    def _fix_pem_certificate(certificate):
        return certificate \
            .replace('-----BEGIN CERTIFICATE-----', "-----BEGIN CERTIFICATE-----\n")  \
            .replace('-----END CERTIFICATE-----', "\n-----END CERTIFICATE-----")

    def get_public_key(self):
        _LOGGER.info('Get MiniServer public key')
        # Format: X.509 encoded key in ANS.1
        req = get('http://{host}:{port}/jdev/sys/getPublicKey'.format(
            host=self.host,
            port=self.port),
            timeout=self.request_timeout)
        if req.status_code == codes.ok:  # pylint: disable=E1101
            self.public_key = RSA.importKey(self._fix_pem_certificate(
                req.json().get('LL').get('value')))
