#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from base64 import b64encode

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Util.py3compat import bchr
from requests import codes, get, utils


class TokenEnc(object):

    def __init__(self, **kwargs):
        self.request_timeout = kwargs.get('request_timeout', 5)
        self.miniserver_host = kwargs.get('miniserver_host')
        self.miniserver_port = kwargs.get('miniserver_port')
        self.miniserver_username = kwargs.get('miniserver_username')
        self.miniserver_public_key = None
        self.miniserver_user_key = None
        self.miniserver_user_salt = None
        self.client_aes_key = None
        self.client_aes_iv = None
        self.client_session_key = None
        self.client_salt = None

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

    @staticmethod
    def _fix_pem_certificate(certificate):
        return certificate \
            .replace('-----BEGIN CERTIFICATE-----', "-----BEGIN CERTIFICATE-----\n")  \
            .replace('-----END CERTIFICATE-----', "\n-----END CERTIFICATE-----")

    def get_public_key(self):
        print('Get MiniServer public key')
        # Format: X.509 encoded key in ANS.1
        req = get('http://{host}:{port}/jdev/sys/getPublicKey'.format(
            host=self.miniserver_host,
            port=self.miniserver_port),
            timeout=self.request_timeout)
        if (req.status_code == codes.ok):
            self.miniserver_public_key = self._fix_pem_certificate(
                req.json().get('LL').get('value'))
            return self.miniserver_public_key

    def generate_aes256_key(self):
        print('Generate AES-256 key')
        secret = Random.get_random_bytes(32)
        key = Random.get_random_bytes(32)
        iv = Random.new().read(AES.block_size)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        self.client_aes_key = cipher_aes.encrypt(secret)
        return self.client_aes_key

    def generate_aes_iv(self):
        print('Generate random AES IV (16 byte)')
        self.client_aes_iv = Random.get_random_bytes(16)
        return self.client_aes_iv

    def generate_session_key(self):
        print('Generate session key by RSA encrypt the "AES-256 key + AES IV" with the MiniServer public key')
        rsa_key = RSA.importKey(self.miniserver_public_key)
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        session_key = self.client_aes_key+b':'+self.client_aes_iv
        enc_session_key = cipher_rsa.encrypt(session_key)
        self.client_session_key = b64encode(enc_session_key)
        return self.client_session_key

    def generate_salt(self):
        print('Generate salt')
        self.client_salt = utils.quote(Random.get_random_bytes(16).hex())
        return self.client_salt

    def exchange_session_key(self):
        print('Exchange session key')
        return b'jdev/sys/keyexchange/'+self.client_session_key

    @staticmethod
    def zero_byte_paddding(data_to_pad, block_size):
        padding_len = block_size-len(data_to_pad) % block_size
        padding = bchr(0)*padding_len
        return data_to_pad + padding

    def encrypt_command(self, cmd):
        print('Encrypt command')
        if type(cmd) == bytes:
            cmd = cmd.decode('utf8')
        cipher_aes = AES.new(self.client_aes_key,
                             AES.MODE_CBC,
                             self.client_aes_iv)
        enc_cmd_part = cipher_aes.encrypt(self.zero_byte_paddding(
            'salt/{0}/{1}'.format(self.client_salt, cmd).encode('utf8'), AES.block_size))
        enc_cmd = 'jdev/sys/enc/{0}'.format(
            utils.quote(b64encode(enc_cmd_part))).encode('utf8')
        return enc_cmd

    def get_key_and_salt(self):
        print('Get key and salt for user')
        return 'jdev/sys/getkey2/{0}'.format(self.miniserver_username)

    def hash_password(self):
        print('Hash user password')
        hash_sha = SHA1.new()
        hash_sha.update('{0}:{1}'.format(
            self.miniserver_password,
            self.miniserver_user_salt).encode('utf8'))
        return hash_sha.hexdigest().upper()