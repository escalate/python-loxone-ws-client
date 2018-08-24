#!/usr/bin/env python
# -*- coding: utf-8 -*-

from requests import get, codes


class TokenEnc(object):

    def __init__(self, **kwargs):
        self.miniserver_host = kwargs.get('miniserver_host')
        self.miniserver_port = kwargs.get('miniserver_port')
        self.request_timeout = kwargs.get('request_timeout', 5)

    def test_connection(self):
        print('Ensure the MiniServer is reachable')
        req_api = get('http://{host}:{port}/jdev/cfg/api'.format(
            host=self.miniserver_host,
            port=self.miniserver_port),
            timeout=self.request_timeout)
        if (req_api.status_code == codes.ok):
            return True
        else:
            return False
