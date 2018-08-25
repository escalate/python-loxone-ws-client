#!/usr/bin/env python
# -*- coding: utf-8 -*-

from re import match
from json import loads


class Message(object):

    def __init__(self, payload):
        self._raw_data = loads(payload.decode('utf8'))
        self.data = self._raw_data.get('LL')
        self.code = self.data.get('Code', None)
        self.control = self.data.get('control', None)
        self.value = self.data.get('value', None)

        if self.control == 'Auth':
            self.control_type = 'auth'
        elif match(r'^j?dev\/sys\/keyexchange\/', self.control) is not None:
            self.control_type = 'keyexchange'
        else:
            self.control_type = 'unknown'
