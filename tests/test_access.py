# -*- coding: utf-8 -*-
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount access python sdk project
# https://github.com/Kount/kount-access-python-sdk/)
# Copyright (C) 2017 Kount Inc. All Rights Reserved.

from __future__ import absolute_import, unicode_literals, division, print_function
__author__ = "Kount Access SDK"
__version__ = "2.1.1"
__maintainer__ = "Kount Access SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

import unittest
import base64
import hashlib
import urllib
import requests
try:
    import urllib2
    from urllib2 import HTTPError
    py27 = True
except ImportError:
    from urllib.error import HTTPError
    py27 = False
import json
import logging
from kount_access.access_sdk import AccessSDK
merchantId = 999666
#~ apiKey = 'YOUR-API-KEY-GOES-HERE'
apiKey = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiI5OTk2NjYiLCJhdWQiOiJLb3VudC4xIiwiaWF0IjoxNDk5ODcwNDgwLCJzY3AiOnsia2EiOnRydWUsImtjIjp0cnVlLCJhcGkiOnRydWUsInJpcyI6dHJ1ZX19.yFan6moxBonnG8Vk9C_qRpF-eTF00_MRBwgqMdNdy8U'
serverName = 'api-sandbox01.kountaccess.com'
version = '0210'
pswd = 'password'
u_email = 'test@kount.com'

try:
    from local_settings import *
except ImportError as ie:
    #~ print("The default fake apikey set. Required actual one from Kount. ", ie)
    pass

logger = logging.getLogger('kount.test')
session_id = '8f18a81cfb6e3179ece7138ac81019aa'

methods_list = [func for func in dir(AccessSDK) if callable(getattr(AccessSDK, func)) and not func.startswith("_")]
method_request = [('decision', 'post'), ('device', 'get'), ('velocity', 'post')]
access_methods = {methods_list[i]: method_request[i] for i in range(len(methods_list))}
assert access_methods == {'get_decision': ('decision', 'post'), 'get_device': ('device', 'get'), 'get_velocity': ('velocity', 'post')}
logger.info(merchantId, serverName, version, session_id, u_email, methods_list)
arg = [session_id, u_email, pswd]


class TestAPIAccess(unittest.TestCase):
    def setUp(self):
        self.method_list = methods_list
        assert self.method_list == ['get_decision', 'get_device', 'get_velocity']
        self.access_sdk = AccessSDK(serverName, merchantId, apiKey, version)

    def error_handling(self, err):
        logger.debug("UNAUTHORIZED %s, %s", err.msg, err.code)
        self.assertEqual('UNAUTHORIZED', err.msg.upper())
        self.assertEqual(401, err.code)
        raise

    def test_api_access_get_hash(self):
        u = self.access_sdk._get_hash('admin')
        self.assertEqual('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', u)
        p = self.access_sdk._get_hash(u'password')
        self.assertEqual('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', p)

    def test_api_get_device(self):
        """get_device"""
        with self.assertRaises(HTTPError):
            self.assertRaises(HTTPError, self.access_sdk.get_device(session_id))
        try:
            self.access_sdk.get_device(session_id)
        except HTTPError as err:
            self.error_handling(err)

    def test_api_get_decision(self):
        """get_decision"""
        with self.assertRaises(HTTPError):
            self.assertRaises(HTTPError, self.access_sdk.get_decision(*arg))
        try:
            self.access_sdk.get_decision(*arg)
        except HTTPError as err:
            self.error_handling(err)

    def test_api_get_velocity(self):
        """get_velocity"""
        with self.assertRaises(HTTPError):
            self.assertRaises(HTTPError, self.access_sdk.get_velocity(*arg))
        try:
            self.access_sdk.get_velocity(*arg)
        except HTTPError as err:
            self.error_handling(err)


class TestAPIRequests(unittest.TestCase):
    def setUp(self):
        self.headers = {}
        self.url_get = "https://%s:%s@%s/api/"%(u_email, pswd, serverName)
        self.params = {'v': version, 's': session_id}
        #~ self.headers['Accept'] = 'application/json'
        self.headers['Content-Type'] = 'application/json'
        m = str(merchantId).encode('utf-8')
        a = base64.standard_b64encode(m + ":".encode('utf-8') + apiKey.encode('utf-8'))
        self.headers['Authorization'] = 'Basic %s' % a.decode('utf-8')

    def method_req(self, api_method='', params='', headers=''):
        "access_methods"
        if not params:
            params = self.params
        if not headers:
            params = self.headers
        if not api_method:
            api_method = unittest.TestCase.id(self).split('.test_')[-1]
        #~ method_list == ['get_decision', 'get_device', 'get_velocity']
        url = "%s%s"%(self.url_get, access_methods[api_method][0])
        logger.info("url = %s", url)
        if access_methods[api_method][1] == 'get':
            r = requests.get(url,
                            headers=headers,
                            params=params,
                            )
        else:
            r = requests.post(url,
                            headers=headers,
                            params=params,
                            )
        logger.debug("method=%s, self.r= %s, self.r.status_code= %s, text= %s", api_method, r, r.status_code, r.text)
        try:
            self.assertEqual(200, r.status_code)
        except AssertionError as e:
            logger.debug("method=%s: e= %s, text= %s", api_method, e, r.text)
            raise
        else:
            self.assertTrue(r.text)
            self.assertTrue(len(r.json()))
        self.assertNotIn('Error', r.text)
        return r

    def test_get_device(self):
        "check device response"
        response = self.method_req()
        #~ do somth with response
        self.assertItemsEqual(["device", "response_id"], list(responce.keys()))
        self.assertIsInstance(responce["device"]["geoLat"], float)

    def test_get_velocity(self):
        "check velocity response"
        response = self.method_req()
        self.assertItemsEqual(["device", "response_id", "velocity"], list(responce.keys()))
        self.assertIsInstance(responce["velocity"]["account"], dict)

    def test_get_decision(self):
        "check decision response"
        response = self.method_req()
        self.assertItemsEqual(["device", "response_id", "velocity", "decision"], list(responce.keys()))
        self.assertIsInstance(responce["decision"]["reply"], dict)

    def test_api_requests_missing_params(self):
        "missing_params in request"
        params = {}
        for target in methods_list:
            response = self.method_req(api_method=target, params=params, headers=self.headers)
            logger.info("target=%s, response = %s", target, responce)
            self.assertNotEqual(200, responce.status_code)

    def test_api_requests_missing_credentials(self):
        "missing_credentials"
        for target in methods_list:
            response = self.method_req(api_method=target, params=self.params, headers={})
            logger.info("target=%s, response = %s", target, responce)
            self.assertNotEqual(200, responce.status_code)


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestAPIAccess.test_get_decision"
    )
