#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(name='loxone_websocket_client',
      version='0.1',
      description='Loxone Websocket Client Library',
      url='https://github.com/escalate/python-loxone-ws-client',
      author='Felix Börner',
      author_email='github@felix-boerner.de',
      license='MIT',
      packages=find_packages(),
      install_requires=[
          'autobahn>=18.8.1',
          'pycryptodome>=3.6.6',
          'requests>=2.19.1'
      ])
