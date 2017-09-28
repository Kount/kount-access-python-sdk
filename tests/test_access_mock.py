# -*- coding: utf-8 -*-
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount access python sdk project
# https://github.com/Kount/kount-access-python-sdk/)
# Copyright (C) 2017 Kount Inc. All Rights Reserved.
"unit tests with mock"
from __future__ import absolute_import, unicode_literals, division, print_function
__author__ = "Kount Access SDK"
__version__ = "2.1.1"
__maintainer__ = "Kount Access SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

import logging
import unittest
import urllib
import sys
if sys.version_info[0] == 2:
    from mock import patch, MagicMock, Mock, call
    from urllib2 import HTTPError
    import urllib2
    py27 = True
else:
    from unittest.mock import patch, MagicMock, Mock, call
    from urllib.error import HTTPError
    py27 = False
import six

import kount_access.access_sdk

#~ Merchant's customer ID.
merchantId = 999666

#~ Kount host for integration tests.
serverName = '%s.kountbox.net' % merchantId
version = '0210'
logger = logging.getLogger('kount.test')

#~ must be 32 characters long
session_id = '8f18a81cfb6e3179ece7138ac81019aa'
apiKey = 'FAKE-API-KEY'
logger = logging.getLogger('kount.test')
device_response = {
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

velocity_response = {
    "device":
        {"id": "92fd3030a2bc84d6985d9df229c60fda", "ipAddress": "64.128.91.251",
         "ipGeo": "US", "mobile": 0, "proxy": 0},
    "response_id": "3659d4bb91ba646987a1245d8af8c0a4",
    "velocity":
        {"account": {"dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 1, "plm": 1, "ulh": 1, "ulm": 1},
         "device": {"alh": 3, "alm": 3, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
         "ip_address": {"alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
         "password": {"alh": 1, "alm": 1, "dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "ulh": 1, "ulm": 1},
         "user": {"alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3}
        }
    }

decision_response = {
    "decision":
        {"errors": [],
         "reply":
            {"ruleEvents": {"decision": "A", "ruleEvents": [], "total": 0}},
         "warnings": []
        },
    "device":
        {"id": "92fd3030a2bc84d6985d9df229c60fda", "ipAddress": "64.128.91.251",
         "ipGeo": "US", "mobile": 1, "proxy": 0,
         "country": "US", "region": "ID", "geoLat": 43.37, "geoLong": -116.200},
    "response_id": "5fa44f9de37834fcc6fdf2e05fa08537",
    "velocity":
        {
            "account": {"dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 1, "plm": 1, "ulh": 1, "ulm": 1},
            "device": {"alh": 3, "alm": 3, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
            "ip_address": {"alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "plh": 3, "plm": 3, "ulh": 1, "ulm": 1},
            "password": {"alh": 1, "alm": 1, "dlh": 1, "dlm": 1, "iplh": 1, "iplm": 1, "ulh": 1, "ulm": 1},
            "user": {"alh": 3, "alm": 3, "dlh": 2, "dlm": 1, "iplh": 1, "iplm": 1, "plh": 3, "plm": 3}
        }}

#~ Access SDK methods
method_list = ['get_device', 'get_decision', 'get_velocity']
user = u'test@test.com'
pswd = u'password'
args = [session_id, user, pswd]
logger.debug("MOCK tests: merchantId=%s, serverName=%s, version=%s,\
             session_id=%s, method_list=%s",
             merchantId, serverName, version, session_id, method_list)


class SequenceMeta(type):
    "create tests for all methods in access sdk"
    def __new__(mcs, name, bases, dictionary):

        def gen_test(method):
            "create test for each method in access sdk"
            def test(self):
                """main function that collect all methods from AccessSDK
                and create unit-tests for them"""
                self.assertRaises(
                    HTTPError,
                    Mock(side_effect=HTTPError(
                        url=serverName, code=401, msg='Not Authorized', hdrs=None, fp=None)))
            return test

        for method in method_list:
            test_name = "test_%s" % method
            dictionary[test_name] = gen_test(method)
        return type.__new__(mcs, name, bases, dictionary)

class TestSequence(six.with_metaclass(SequenceMeta, unittest.TestCase)):
    "TestSequence - generate tests for each method in AccessSDK"
    __metaclass__ = SequenceMeta


class TestAPIAccessMock(unittest.TestCase):
    "TestAPIAccessMock"
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
        self.assertEqual(self.access_sdk.mockhash(pswd), '42')

    def access_methods_mocked(self, method, exp_response):
        """assert the expected results from access_sdk's methods"""
        access_methods = {'get_decision': args, 'get_device': args[0], 'get_velocity': args}
        real_method = MagicMock(name=method, return_value=exp_response)
        assert real_method(access_methods[method]) == exp_response
        return True

    def test_mock_get_decision(self):
        """get_decision"""
        self.assertTrue(self.access_methods_mocked('get_decision', decision_response))

    def test_mock_get_device(self):
        """get_device"""
        self.assertTrue(self.access_methods_mocked('get_device', device_response))

    def test_mock_get_velocity(self):
        """get_velocity"""
        self.assertTrue(self.access_methods_mocked('get_velocity', velocity_response))

    def invalid_credentials(self, error, param_list, msg):
        """should catch the empty or None username and password
         "missing_credentials - ValueError: Invalid value'
        """
        if error is TypeError:
            msg = Mock(side_effect=error(error))
        else:
            assert error is HTTPError
            msg = Mock(side_effect=error(url=serverName, code=401, msg=error, hdrs=None, fp=None))
        for target in ['get_decision', 'get_velocity']:
            for params in param_list:
                with self.assertRaises(error):
                    getattr(self.access_sdk, target)(params, return_value=msg())
        return True

    def test_mock_invalid_credentials(self):
        """should catch the empty or None username and password
        if missing credentials raise ValueError: Invalid value'
        """
        self.assertTrue(self.invalid_credentials(
            error=HTTPError,
            param_list=[[session_id, '', ''], [session_id, '', None]],
            msg="HttpError: Not Authorized"))

    def test_mock_missing_credentials(self):
        """should catch the missing username and password
         "missing_credentials - TypeError for missing required positional argument
        """
        msgTypeError = "TypeError: get_decision() missing 2 required\
        positional arguments: 'username' and 'password'"
        self.assertTrue(self.invalid_credentials(
            error=TypeError,
            param_list=[session_id],
            msg=msgTypeError))

    @patch('kount_access.access_sdk.AccessSDK')
    def test_mock_invalid_session(self, access):
        """"session in [None, ''] - HTTPError - HTTP Error 401: Unauthorized"""
        msg = "HTTP Error 401: Unauthorized"
        self.assertEqual(access, kount_access.access_sdk.AccessSDK)
        msg_401 = Mock(side_effect=HTTPError(
            url=serverName, code=401, msg=msg, hdrs=None, fp=None))
        for session in [None, '']:
            try:
                self.access_sdk.get_device(session, return_value=msg_401())
            except HTTPError as err:
                self.assertEqual(msg, err.msg)
                self.assertEqual(401, err.code)
            with self.assertRaises(HTTPError):
                self.access_sdk.get_device(session_id, return_value=msg_401())
            with self.assertRaises(HTTPError):
                msg_401()

    @patch('kount_access.access_sdk.logging')
    def test_mock_logger_get_device(self, mock_logger):
        """get_device"""
        with patch.object(kount_access.access_sdk.AccessSDK, method_list[0],
                          return_value=device_response) as mock_method:
            thing = kount_access.access_sdk.AccessSDK(1, 2, 3)
            thing.get_device(session_id)
            mock_logger.debug(session_id)
        mock_method.assert_has_calls([call(session_id)])
        mock_logger.debug.assert_has_calls([call(session_id)])
        self.assertTrue(self.access_methods_mocked(method_list[0], device_response))
        mock_method.assert_called_once_with(session_id)
        mock_logger.debug.assert_called_once_with(session_id)

    @patch('kount_access.access_sdk.logging')
    def test_mock_logger(self, mock_logger):
        """mock_logger debug"""
        mock_logger.debug(session_id)
        mock_logger.debug.assert_called_once_with(session_id)

    def test_mock_logger_all(self):
        """test_mock_logger all methods"""
        if py27:
            error1 = urllib2.URLError
        else:
            error1 = urllib.error.URLError
        user = 'USER'
        pswd = 'PASS'
        host = 'test.kount.net'
        with patch.object(kount_access.access_sdk.logger, 'error', return_value=None) as mock_method:
            thing = kount_access.access_sdk.AccessSDK(host, merchantId, 'apiKey')
            ah = thing._get_hash('%s:%s' % (user, pswd))
            p = "('%s',)" % thing._get_hash(pswd)
            if py27:
                ph = urllib.quote_plus(p)
                urllibr = 'urllib2.URLError'
            else:
                ph = urllib.parse.quote_plus(p)
                urllibr = 'urllib.request.URLError'
            uh = thing._get_hash(user)
            for target in method_list:
                method = target.split('get_')[1]
                h = 'https://%s/api/%s' % (host, method)
                if target == method_list[0]:
                    get_method = True
                    params = [session_id]
                    url_encodded = 's=%s&v=%s' % (session_id, version)
                    pp = u'url=%s?%s, values=None' % (h, url_encodded)
                else:
                    params = [session_id, user, pswd, None]
                    url_encodded = 'ah=%s&s=%s&ph=%s&uh=%s&v=%s' % (ah, session_id, ph, uh, version)
                    pp = u'url=%s, values=%s' % (h, url_encodded)
                param_list = "%s, %s" % (urllibr, pp)
                params_call = call(param_list)
                with self.assertRaises(error1):
                    getattr(thing, target)(*params)
                arg_list = [session_id, version, urllibr, uh, ah, ph]
                if get_method:
                    arg_text = str(mock_method.call_args[0])
                    for a in arg_list[:3]:
                        self.assertIn(a, arg_text)
                else:
                    for a in arg_list:
                        self.assertIn(a, arg_text)


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestAPIAccessMock.test_mock_logger"
    )
