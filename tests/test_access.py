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
import sys
import uuid

if sys.version_info[0] == 2:
    import urllib2
    from urllib2 import HTTPError
else:
    from urllib.error import HTTPError
import json
import logging
from kount_access.access_sdk import AccessSDK

"""
Kount Access integration tests

All parameters are provided by Kount and configured to utilize specific thresholds.
"""

#~ integration tests merchant ID
merchantId = 0

#~ API Key for Kount Access authorization
apiKey = 'PUT_YOUR_API_KEY_HERE'

#~ Kount Access service host for integration tests
serverName = 'api-sandbox01.kountaccess.com'
dataCollector = 'https://sandbox01.kaxsdc.com/logo.gif'

#~ Kount Access service version to use
version = '0210'

#~ username and password request parameter values
user = 'test@kount.com'
pswd = 'password'

logger = logging.getLogger('kount.test')

#~ Access SDK methods 
methods_list = [func for func in dir(AccessSDK) if callable(getattr(AccessSDK, func)) and not func.startswith("_")]

def generate_unique_id():
    "unique session id"
    return str(uuid.uuid4()).replace('-', '').upper()


#~ session ID parameter value
session_id_wrong = generate_unique_id()


class TestAPIAccess(unittest.TestCase):
    """Request and response from Kount Access API.
    If you are just looking for information about the device (like the
    device id, or pierced IP Address) then use the get_device function.
    When requesting Velocity information, the Device information is also
    included in this response.
    If you want Kount Access to evaluate possible threats using our
    Thresholds Engine, you will want to call the get_decision endpoint.
    This response includes Device information and Velocity data in addition
    to the Decision information. The decision value can be either 
    "A" - Approve, or "D" - Decline. In addition it will
    show the ruleEvents evaluated that forced a "D" (Decline) result. If you
    do not have any thresholds established it will always default to
    "A" (Approve). For more information on setting up thresholds, consult the
    User Guide.
    If you make a bad request you will get a response with an ERROR_CODE
    and ERROR_MESSAGE in it.
   """

    maxDiff = None

    @classmethod
    def setUpClass(self):
        self.session_id = generate_unique_id()[:32]
        self.arg = [self.session_id, user, pswd]
        self.method_list = methods_list
        assert self.method_list == ['get_decision', 'get_device', 'get_velocity']
        self.access_sdk = AccessSDK(serverName, merchantId, apiKey, version)
        self.fake_arg = [session_id_wrong, user, pswd]
        data1 = {'m':999666, 's':self.session_id}
        req = requests.Request('GET', dataCollector, params=data1)
        prepared = req.prepare()
        s = requests.Session()
        r1 = s.send(prepared)
        assert r1.status_code == 200
        logger.debug(merchantId, serverName, version, self.session_id, user, methods_list)

    def error_handling(self, err):
        "common error_handling for http 401 or 400"
        logger.debug("http error %s, %s", err.msg, err.code)
        if 401 == err.code:
            self.assertEqual('UNAUTHORIZED', err.msg.upper())
        else:
            logger.debug('DataCollector request needed first %s, %s', err.code, err.msg)
            self.assertEqual(400, err.code)
            self.assertIn('BAD REQUEST', err.msg.upper())
        raise

    def test_api_access_get_hash(self):
        u = self.access_sdk._get_hash(u'admin')
        self.assertEqual('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', u)
        p = self.access_sdk._get_hash(u'password')
        self.assertEqual('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', p)
        self.assertRaises(ValueError, self.access_sdk._get_hash, None)
        self.assertRaises(ValueError, self.access_sdk._get_hash, '')

    def test_api_get_device(self):
        "get_device"
        self.assertRaises(HTTPError, self.access_sdk.get_device, self.fake_arg[0])
        expected = {u'device': {u'geoLat': 42.6833, u'mobile': 0, u'country': u'BG',
                                u'region': u'42', u'geoLong': 23.3167, u'ipGeo': u'BG',
                                u'proxy': 0, u'ipAddress': u'188.254.215.212',
                                u'id': u'1895c3befcff48a29ccd7da7d163f7f7'},
                    u'response_id': u'3c67bcc418c14d6fbb3bb4da2db680c9'}
        if apiKey == 'PUT_YOUR_API_KEY_HERE' or merchantId == 0:
            self.assertRaises(HTTPError, self.access_sdk.get_device, self.session_id)
        else:
            dev = self.access_sdk.get_device(self.session_id)
            self.assertEqual(dev.keys(), expected.keys())

    def test_api_get_decision(self):
        "get_decision"
        self.assertRaises(HTTPError, self.access_sdk.get_decision, *self.fake_arg)
        expected = {u'decision': {u'errors': [],
                                  u'reply': {u'ruleEvents': {u'decision': u'A',
                                                   u'ruleEvents': None,
                                                   u'total': 0}},
                                  u'warnings': []},
                    u'device': {u'country': u'BG',
                                u'geoLat': 42.6833,
                                u'geoLong': 23.3167,
                                u'id': u'1895c3befcff48a29ccd7da7d163f7f7',
                                u'ipAddress': u'188.254.215.212',
                                u'ipGeo': u'BG',
                                u'mobile': 0,
                                u'proxy': 0,
                                u'region': u'42'},
                    u'response_id': u'5a7478d696e24f2fa4189b3661dacea4',
                    u'velocity': {u'account': {u'dlh': 1,
                                               u'dlm': 1,
                                               u'iplh': 1,
                                               u'iplm': 1,
                                               u'plh': 1,
                                               u'plm': 1,
                                               u'ulh': 1,
                                               u'ulm': 1},
                                  u'device': {u'alh': 2,
                                              u'alm': 1,
                                              u'iplh': 1,
                                              u'iplm': 1,
                                              u'plh': 2,
                                              u'plm': 1,
                                              u'ulh': 2,
                                              u'ulm': 1},
                                  u'ip_address': {u'alh': 2,
                                                  u'alm': 1,
                                                  u'dlh': 1,
                                                  u'dlm': 1,
                                                  u'plh': 2,
                                                  u'plm': 1,
                                                  u'ulh': 2,
                                                  u'ulm': 1},
                                  u'password': {u'alh': 1,
                                                u'alm': 1,
                                                u'dlh': 1,
                                                u'dlm': 1,
                                                u'iplh': 1,
                                                u'iplm': 1,
                                                u'ulh': 1,
                                                u'ulm': 1},
                                  u'user': {u'alh': 1,
                                            u'alm': 1,
                                            u'dlh': 1,
                                            u'dlm': 1,
                                            u'iplh': 1,
                                            u'iplm': 1,
                                            u'plh': 1,
                                            u'plm': 1}}}
        if apiKey == 'PUT_YOUR_API_KEY_HERE' or merchantId == 0:
            self.assertRaises(HTTPError, self.access_sdk.get_decision, *self.arg)
        else:
            dec = self.access_sdk.get_decision(*self.arg)
            self.assertEqual(dec.keys(), expected.keys())

    def test_api_get_velocity(self):
        "get_velocity"
        self.assertRaises(HTTPError, self.access_sdk.get_velocity, *self.fake_arg)
        expected = {u'device': {u'country': u'BG',
                                u'geoLat': 42.6833,
                                u'geoLong': 23.3167,
                                u'id': u'1895c3befcff48a29ccd7da7d163f7f7',
                                u'ipAddress': u'188.254.215.212',
                                u'ipGeo': u'BG',
                                u'mobile': 0,
                                u'proxy': 0,
                                u'region': u'42'},
                    u'response_id': u'fee499e367d14a11aadf36f28cfc8223',
                    u'velocity': {u'account': {u'dlh': 1,
                                               u'dlm': 1,
                                               u'iplh': 1,
                                               u'iplm': 1,
                                               u'plh': 1,
                                               u'plm': 1,
                                               u'ulh': 1,
                                               u'ulm': 1},
                                  u'device': {u'alh': 2,
                                              u'alm': 1,
                                              u'iplh': 1,
                                              u'iplm': 1,
                                              u'plh': 2,
                                              u'plm': 1,
                                              u'ulh': 2,
                                              u'ulm': 1},
                                  u'ip_address': {u'alh': 2,
                                                  u'alm': 1,
                                                  u'dlh': 1,
                                                  u'dlm': 1,
                                                  u'plh': 2,
                                                  u'plm': 1,
                                                  u'ulh': 2,
                                                  u'ulm': 1},
                                  u'password': {u'alh': 1,
                                                u'alm': 1,
                                                u'dlh': 1,
                                                u'dlm': 1,
                                                u'iplh': 1,
                                                u'iplm': 1,
                                                u'ulh': 1,
                                                u'ulm': 1},
                                  u'user': {u'alh': 1,
                                            u'alm': 1,
                                            u'dlh': 1,
                                            u'dlm': 1,
                                            u'iplh': 1,
                                            u'iplm': 1,
                                            u'plh': 1,
                                            u'plm': 1}}}
        if apiKey == 'PUT_YOUR_API_KEY_HERE' or merchantId == 0:
            self.assertRaises(HTTPError, self.access_sdk.get_velocity, *self.arg)
        else:
            vel = self.access_sdk.get_velocity(*self.arg)
            self.assertEqual(vel.keys(), expected.keys())

    def test_api_requests_empty_credentials(self):
        "empty credentials - ValueError: Invalid value ''"
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(HTTPError, getattr(self.access_sdk, target), *[self.session_id, '', ''])

    def test_api_requests_credentials_none(self):
        "credentials None - ValueError: Invalid value 'None'"
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(HTTPError, getattr(self.access_sdk, target), *[self.session_id, None, None])

    def test_api_requests_missing_credentials(self):
        "missing_credentials - TypeError: get_decision() missing 2 required positional arguments: 'username' and 'password'"
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(TypeError, getattr(self.access_sdk, target), self.session_id)

    def test_api_requests_empty_session(self):
        "session empty - HTTPError - HTTP Error 401: Unauthorized"
        self.assertRaises(HTTPError, self.access_sdk.get_device, '')
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(HTTPError, getattr(self.access_sdk, target), *['', user, pswd])

    def test_api_requests_missing_session(self):
        "missing_session - HTTPError - HTTP Error 401: Unauthorized"
        self.assertRaises(HTTPError, self.access_sdk.get_device, None)
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(HTTPError, getattr(self.access_sdk, target), *[None, user, pswd])


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestAPIAccess.test_api_get_decision"
    )
