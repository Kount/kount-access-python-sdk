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

import base64
import hashlib
import json
import six
import logging
import unittest

try:
    import urllib2
    from mock import patch, MagicMock, Mock
    from urllib2 import HTTPError
    py27 = True
except ImportError:
    from unittest.mock import patch, MagicMock, Mock
    from urllib.error import HTTPError
    py27 = False

import kount_access.access_sdk

#~ Merchant's customer ID.
merchantId = 999666

#~ Sample host. this should be the name of the Kount Access API server you want to connect to.
serverName = 'api-sandbox01.kountaccess.com'
version = '0210'
logger = logging.getLogger('kount.test')

#~ must be 32 characters long
session_id = '8f18a81cfb6e3179ece7138ac81019aa'
apiKey = 'YOUR-API-KEY-GOES-HERE'
logger = logging.getLogger('kount.test')
session_id = '8f18a81cfb6e3179ece7138ac81019aa'
device_responce = {
    "device":
        {"id": "06f5da990b2e9513267865eb0d6cf0df",
          "ipAddress": "64.128.91.251",
          "ipGeo": "US", "mobile": 1,
          "proxy": 0, "country": "US",
          "region": "ID",
          "geoLat": 43.37,
          "geoLong": -116.200
        },
    "response_id": "fc5c7cb1bd7538d3b64160c5dfedc3b9"
   }

velocity_responce = {
   "device":
       {"id": "92fd3030a2bc84d6985d9df229c60fda", "ipAddress": "64.128.91.251", "ipGeo": "US", "mobile": 0, "proxy": 0},
   "response_id": "3659d4bb91ba646987a1245d8af8c0a4", 
   "velocity":
       {"account": {"dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 1, "plm": 1, "ulh": 1, "ulm": 1},
         "device": {"alh": 3, "alm": 3, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
         "ip_address": {"alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
         "password": { "alh": 1, "alm": 1, "dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "ulh": 1, "ulm": 1 },
         "user": { "alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3}
       }
  }

decision_responce = {
    "decision":
        { "errors": [], 
        "reply":
            {"ruleEvents": { "decision": "A", "ruleEvents": [], "total": 0}},
            "warnings": []
        },
    "device":
        {"id": "92fd3030a2bc84d6985d9df229c60fda", "ipAddress": "64.128.91.251", "ipGeo": "US", "mobile": 1, "proxy": 0, 
          "country": "US", "region": "ID", "geoLat": 43.37, "geoLong": -116.200},
    "response_id": "5fa44f9de37834fcc6fdf2e05fa08537", 
    "velocity":
        {
            "account": {"dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 1, "plm": 1, "ulh": 1, "ulm": 1},
            "device": {"alh": 3, "alm": 3, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
            "ip_address": {"alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
            "password": { "alh": 1, "alm": 1, "dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "ulh": 1, "ulm": 1},
            "user": { "alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3}
        }
  }

#~ Access SDK methods 
method_list = ['get_device', 'get_decision', 'get_velocity']
u_email = 'test@test.com'
args = [session_id, u_email, 'password']
logger.debug("MOCK tests: ", merchantId, serverName, version, session_id, u_email, method_list)


class SequenceMeta(type):
    def __new__(mcs, name, bases, dict):

        def gen_test(m):
            def test(self):
                """main function that collect all methods from AccessSDK 
                and create unit-tests for them"""
                self.assertRaises(
                    HTTPError, 
                    Mock(side_effect=HTTPError(
                                url=serverName, code=401, msg='Not Authorised', hdrs=None, fp=None)))
            return test

        for i in range(len(method_list)):
            test_name = "test_%s" % method_list[i]
            dict[test_name] = gen_test(method_list[i])
        return type.__new__(mcs, name, bases, dict)


class TestSequence(six.with_metaclass(SequenceMeta, unittest.TestCase)):
    __metaclass__ = SequenceMeta


class TestAPIAccessMock(unittest.TestCase):
    maxDiff = None

    @patch('kount_access.access_sdk.AccessSDK')
    def setUp(self, MockAccessSDK):
        self.method_list = method_list
        self.access_sdk = MockAccessSDK(serverName, merchantId, apiKey, version)
        assert isinstance(MockAccessSDK, MagicMock)
        assert MockAccessSDK.called

    def test_api_access_methods(self):
        """mock of hash method"""
        self.access_sdk.mockhash.return_value = '42'
        u = self.access_sdk.mockhash(u'admin')
        self.assertEqual(self.access_sdk.mockhash.return_value, u)
        p = self.access_sdk.mockhash(u'password')
        self.assertEqual(self.access_sdk.mockhash.return_value, p)

    def access_methods_mocked(self, method, exp_response):
        """assert the expected results from access_sdk's methods"""
        access_methods = {'get_decision': args, 'get_device': args[0], 'get_velocity': args}
        real_method = MagicMock(name=method, return_value  = exp_response)
        assert real_method(access_methods[method]) == exp_response
        return True

    def test_mock_get_decision(self):
        """get_decision"""
        self.assertTrue(self.access_methods_mocked('get_decision', decision_responce))

    def test_mock_get_device(self):
        """get_device"""
        self.assertTrue(self.access_methods_mocked('get_device', device_responce))

    def test_mock_get_velocity(self):
        """get_velocity"""
        self.assertTrue(self.access_methods_mocked('get_velocity', velocity_responce))

    def invalid_credentials(self, error, param_list, msg):
        """should catch the empty or None username and password
         "missing_credentials - ValueError: Invalid value'
        """
        msg_Error = error
        msg = Mock(side_effect=error(msg_Error))
        for target in ['get_decision', 'get_velocity']:
            for params in param_list:
                with self.assertRaises(error):
                    getattr(self.access_sdk, target)(params, return_value = msg())
        return True

    def test_mock_invalid_credentials(self):
        """should catch the empty or None username and password
        if missing credentials raise ValueError: Invalid value'
        """
        self.assertTrue(self.invalid_credentials(
                            error=ValueError,
                            param_list=[[session_id, '', ''], [session_id, '', None]],
                            msg="ValueError: Invalid value"))

    def test_mock_missing_credentials(self):
        """should catch the missing username and password
         "missing_credentials - TypeError for missing required positional argument
        """
        msg_TypeError = "TypeError: get_decision() missing 2 required\
        positional arguments: 'username' and 'password'"
        self.assertTrue(self.invalid_credentials(
                            error=TypeError,
                            param_list=[session_id],
                            msg=msg_TypeError)
                            )

    @patch('kount_access.access_sdk.AccessSDK')
    def test_mock_invalid_session(self, access):
        """"session in [None, ''] - HTTPError - HTTP Error 401: Unauthorized"""
        msg = "HTTP Error 401: Unauthorized"
        self.assertEqual(access, kount_access.access_sdk.AccessSDK)
        msg_401 = Mock(side_effect=HTTPError(
            url=serverName, code=401, msg=msg, hdrs=None, fp=None))
        for session in [None, '']:
            try:
                d = self.access_sdk.get_device(session, return_value = msg_401())
            except HTTPError as err:
                self.assertEqual(msg, err.msg)
                self.assertEqual(401, err.code)
            with self.assertRaises(HTTPError):
                self.access_sdk.get_device(session_id, return_value = msg_401())
            with self.assertRaises(HTTPError):
                msg_401()


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestSequence"
    )
