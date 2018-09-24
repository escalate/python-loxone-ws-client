#!/usr/bin/env python
# -*- coding: utf-8 -*-

from re import search
from json import loads


class Message:

    def __init__(self, payload):
        self._raw_data = loads(payload.decode('utf8'))

    @property
    def data(self):
        return self._raw_data.get('LL', {})

    @property
    def code(self):
        if self.data.get('Code') is not None:
            return int(self.data.get('Code'))
        if self.data.get('code') is not None:
            return int(self.data.get('code'))
        else:
            return 0

    @property
    def control(self):
        return self.data.get('control', '')

    @control.setter
    def control(self, value):
        self._raw_data['LL']['control'] = value

    @property
    def value(self):
        return self.data.get('value', '')

    @property
    def control_type(self):
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