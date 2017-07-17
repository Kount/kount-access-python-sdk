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

from kount_access.settings import pswd, u_email, version, serverName as api_url, apiKey, merchantId
import kount_access.access_sdk
assert apiKey != 'YOUR-API-KEY-GOES-HERE'

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

method_list = ['get_device', 'get_decision', 'get_velocity']


class SequenceMeta(type):
    def __new__(mcs, name, bases, dict):

        def gen_test(m):
            def test(self):
                """main function that collect all methods from AccessSDK 
                and create unit-tests for them"""
                if m in ['get_device']:
                    assert m=='get_device'
                    arg = [session_id]
                else:
                    arg = [session_id, 'admin', 'password']
                self.assertRaises(
                    HTTPError, 
                    Mock(side_effect=HTTPError(
                                url=api_url, code=401, msg='Not Autorised', hdrs=None, fp=None)))
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
        self.access_sdk = MockAccessSDK(api_url, merchantId, apiKey, version)
        assert isinstance(MockAccessSDK, MagicMock)
        assert MockAccessSDK.called

    def test_api_access_methods(self):
        "mock of hash method"
        self.access_sdk.mockhash.return_value = '42'
        u = self.access_sdk.mockhash(u'admin')
        self.assertEqual(self.access_sdk.mockhash.return_value, u)
        p = self.access_sdk.mockhash(u'password')
        self.assertEqual(self.access_sdk.mockhash.return_value, p)

    @patch('kount_access.access_sdk.AccessSDK')
    def test_mock(self, access):
        """Mock and MagicMock - AccessSDK"""
        msg = "UNAUTHORIZED"
        assert access is kount_access.access_sdk.AccessSDK
        response_list = [device_responce, decision_responce, velocity_responce]
        real = kount_access.access_sdk.AccessSDK(api_url, merchantId, apiKey, version)
        real.get_decision = MagicMock(name='get_decision', return_value  = decision_responce)
        real.get_device = MagicMock(name='get_device', return_value  = device_responce)
        real.get_velocity = MagicMock(name='get_velocity', return_value  = velocity_responce)
        if py27: return
        self.arg = [session_id, 'admin', 'password']
        for i in range(len(self.method_list)):
            arg = self.arg
            with self.subTest(i=i):
                if 'get_device' in self.method_list[i]:
                    arg = [session_id]
                assert getattr(real, self.method_list[i])(arg) == response_list[i]
        msg_401 = Mock(side_effect=HTTPError(
            url=api_url, code=401, msg=msg, hdrs=None, fp=None))
        try:
            d =  real.get_device(session_id, return_value  = msg_401())
        except HTTPError as err:
            self.assertEqual(msg, err.msg.upper())
            self.assertEqual(401, err.code)
        with self.assertRaises(HTTPError):
            real.get_device(session_id, return_value  = msg_401())
        with self.assertRaises(HTTPError):
            msg_401()

    @patch('kount_access.access_sdk.AccessSDK')
    def test_mock_missing_session(self, access):
        """should catch the missing sessionId and report up the error in the callback"""
        msg = "Invalid sessionId [None]"
        assert access is kount_access.access_sdk.AccessSDK
        response_list = [device_responce, decision_responce, velocity_responce]
        real = kount_access.access_sdk.AccessSDK(api_url, merchantId, apiKey, version)
        real.get_decision = MagicMock(name='get_decision', return_value  = decision_responce)
        real.get_device = MagicMock(name='get_device', return_value  = device_responce)
        real.get_velocity = MagicMock(name='get_velocity', return_value  = velocity_responce)
        if py27: return
        arg = [None, 'admin', 'password']
        for i in range(len(self.method_list)):
            with self.subTest(i=i):
                if 'get_device' in self.method_list[i]:
                    arg = [None]
                assert getattr(real, self.method_list[i])(arg) == response_list[i]
        msg_session = Mock(side_effect=HTTPError(
            url=api_url, code=401, msg=msg, hdrs=None, fp=None))
        try:
            d =  real.get_device(session_id, return_value  = msg_session())
        except HTTPError as err:
            self.assertEqual(msg, err.msg)
            self.assertEqual(401, err.code)
        with self.assertRaises(HTTPError):
            real.get_device(session_id, return_value  = msg_session())
        with self.assertRaises(HTTPError):
            msg_session()


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestSequence"
    )