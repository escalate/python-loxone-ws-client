#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from requests import codes, get


class TokenEnc(object):

    def __init__(self, **kwargs):
        self.miniserver_host = kwargs.get('miniserver_host')
        self.miniserver_port = kwargs.get('miniserver_port')
        self.request_timeout = kwargs.get('request_timeout', 5)

    def test_connection(self):
        print('Ensure the MiniServer is reachable')
        req = get('http://{host}:{port}/jdev/cfg/api'.format(
            host=self.miniserver_host,
            port=self.miniserver_port),
            timeout=self.request_timeout)
        if (req.status_code == codes.ok):
            return True
        else:
            return False

    @staticmethod
    def _fix_json_data(data):
        return data.replace('\'', '"')

    def get_miniserver_snr(self):
        print('Get MiniServer serial number')
        req = get('http://{host}:{port}/jdev/cfg/api'.format(
            host=self.miniserver_host,
            port=self.miniserver_port),
            timeout=self.request_timeout)
        if (req.status_code == codes.ok):
            miniserver_api = json.loads(self._fix_json_data(
                req.json().get('LL').get('value')))
            return miniserver_api.get('snr')

    def get_miniserver_version(self):
        print('Get MiniServer version')
        req = get('http://{host}:{port}/jdev/cfg/api'.format(
            host=self.miniserver_host,
            port=self.miniserver_port),
            timeout=self.request_timeout)
        if (req.status_code == codes.ok):
            miniserver_api = json.loads(self._fix_json_data(
                req.json().get('LL').get('value')))
            return miniserver_api.get('version')
