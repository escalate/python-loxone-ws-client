#!/usr/bin/env python
# -*- coding: utf-8 -*-

from re import search
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
        self.control_type = self.discover_control_type()
        self.value = self.data.get('value', None)

    def discover_control_type(self):
        if self.control == 'Auth':
            return 'auth'
        elif search(r'j?dev\/sys\/enc\/', self.control) is not None:
            return 'enc'
        elif search(r'j?dev\/sys\/getkey2\/', self.control) is not None:
            return 'getkey2'
        elif search(r'j?dev\/sys\/getkey', self.control) is not None:
            return 'getkey'
        elif search(r'j?dev\/sys\/gettoken\/', self.control) is not None:
            return 'gettoken'
        elif search(r'j?dev\/sys\/keyexchange\/', self.control) is not None:
            return 'keyexchange'
        elif search(r'j?dev\/sys\/refreshtoken\/', self.control) is not None:
            return 'refreshtoken'
        else:
            return 'unknown'