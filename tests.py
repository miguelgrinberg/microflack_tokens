#!/usr/bin/env python
import os
os.environ['FLASK_CONFIG'] = 'test'

import mock
import unittest

from etcd import EtcdKeyNotFound
import jwt
import requests

from microflack_common.auth import generate_token
from microflack_common.test import FlackTestCase

from app import app


class TokenTests(FlackTestCase):
    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        self.client = app.test_client()

    def tearDown(self):
        self.ctx.pop()

    def test_valid_token(self):
        mock_response = requests.Response()
        mock_response.status_code = 200
        mock_response.encoding = 'utf-8'
        mock_response._content = b'{"id":123,"name":"foo"}'
        mock_response.headers['Content-Type'] = 'application/json'
        with mock.patch('app.requests.get', return_value=mock_response):
            r, s, h = self.post('/api/tokens', basic_auth='foo:bar')
        self.assertEqual(s, 200)
        claims = jwt.decode(r['token'], app.config['JWT_SECRET_KEY'])
        self.assertEqual(claims['user_id'], 123)

    def test_invalid_token(self):
        mock_response = requests.Response()
        mock_response.status_code = 401
        mock_response.encoding = 'utf-8'
        mock_response._content = b'{"error":"unauthorized"}'
        mock_response.headers['Content-Type'] = 'application/json'
        with mock.patch('app.requests.get', return_value=mock_response):
            r, s, h = self.post('/api/tokens', basic_auth='foo:bar')
        self.assertEqual(s, 401)

        mock_response.status_code = 500
        with mock.patch('app.requests.get', return_value=mock_response):
            r, s, h = self.post('/api/tokens', basic_auth='foo:bar')
        self.assertEqual(s, 401)

    def test_revoke_token(self):
        token = generate_token(123, expires_in=257)
        with mock.patch('app.etcd_client') as etcd_client:
            with mock.patch('microflack_common.auth.etcd_client',
                            new=etcd_client):
                etcd_client().read.side_effect = EtcdKeyNotFound
                r, s, h = self.delete('/api/tokens', token_auth=token)
                self.assertEqual(s, 204)
                etcd_client.assert_called_with()
                etcd_client().write.assert_called_once_with(
                    '/revoked-tokens/' + token, '', ttl=262)


if __name__ == '__main__':
    unittest.main(verbosity=2)
