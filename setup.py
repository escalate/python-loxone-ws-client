#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('README.md') as f:
    long_description = f.read()

setup(name='loxone_websocket_client',
      version='0.3',
      description='Loxone Websocket Client Library',
      long_description=long_description,
      long_description_content_type='text/markdown',
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
