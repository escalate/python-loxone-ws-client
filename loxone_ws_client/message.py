#!/usr/bin/env python
# -*- coding: utf-8 -*-

from json import loads


class Message(object):

    def __init__(self, payload):
        self._raw_data = loads(payload.decode('utf8'))
        self.data = self._raw_data.get('LL')
        self.code = self.data.get('Code', None)
        self.control = self.data.get('control', None)
        self.value = self.data.get('value', None)
