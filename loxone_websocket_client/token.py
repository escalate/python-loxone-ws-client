#!/usr/bin/env python
# -*- coding: utf-8 -*-

from binascii import a2b_hex


class Token:

    def __init__(self, payload):
        self._raw_data = payload

    @property
    def value(self):
        return self._raw_data.get('token').encode('utf8')

    @property
    def key(self):
        return a2b_hex(self._raw_data.get('key'))

    @key.setter
    def key(self, value):
        self._raw_data['key'] = value

    @property
    def valid_until(self):
        return self._raw_data.get('validUntil')

    @valid_until.setter
    def valid_until(self, value):
        self._raw_data['validUntil'] = value

    @property
    def token_rights(self):
        return self._raw_data.get('tokenRights')

    @property
    def unsecure_pass(self):
        return self._raw_data.get('unsecurePass')

    @unsecure_pass.setter
    def unsecure_pass(self, value):
        self._raw_data['unsecurePass'] = value

    def refresh(self, payload):
        self.valid_until = payload.get('validUntil')
        self.unsecure_pass = payload.get('unsecurePass')
