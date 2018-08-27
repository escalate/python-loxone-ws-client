#!/usr/bin/env python
# -*- coding: utf-8 -*-

from re import match
from json import loads


class Message(object):

    def __init__(self, payload):
        self._raw_data = loads(payload.decode('utf8'))
        self.data = self._raw_data.get('LL')
        if self.data.get('Code', None) is not None:
            self.code = int(self.data.get('Code', None))
        if self.data.get('code', None) is not None:
            self.code = int(self.data.get('code', None))
        self.control = self.data.get('control', None)
        self.value = self.data.get('value', None)

        if self.control == 'Auth':
            self.control_type = 'auth'
        elif match(r'^j?dev\/sys\/keyexchange\/', self.control) is not None:
            self.control_type = 'keyexchange'
        elif match(r'^j?dev\/sys\/getkey2\/', self.control) is not None:
            self.control_type = 'getkey2'
        else:
            self.control_type = 'unknown'
