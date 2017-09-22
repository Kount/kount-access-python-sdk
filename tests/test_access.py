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

#~ Kount Access service version to use
version = '0210'

#~ username and password request parameter values
user = 'test@kount.com'
pswd = 'password'

logger = logging.getLogger('kount.test')

#~ session ID parameter value
session_id = '8f18a81cfb6e3179ece7138ac81019aa'

#~ Access SDK methods 
methods_list = [func for func in dir(AccessSDK) if callable(getattr(AccessSDK, func)) and not func.startswith("_")]
logger.debug(merchantId, serverName, version, session_id, user, methods_list)
arg = [session_id, user, pswd]


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
    def setUp(self):
        self.method_list = methods_list
        self.assertEqual(self.method_list, ['get_decision', 'get_device', 'get_velocity'])
        self.access_sdk = AccessSDK(serverName, merchantId, apiKey, version)
        self.fake_arg = arg

    def error_handling(self, err):
        "common error_handling for http 401"
        logger.debug("UNAUTHORIZED %s, %s", err.msg, err.code)
        self.assertEqual('UNAUTHORIZED', err.msg.upper())
        self.assertEqual(401, err.code)
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
        try:
            self.access_sdk.get_device(session_id)
        except HTTPError as err:
            self.error_handling(err)

    def test_api_get_decision(self):
        "get_decision"
        self.assertRaises(HTTPError, self.access_sdk.get_decision, *self.fake_arg)
        try:
            self.access_sdk.get_decision(*arg)
        except HTTPError as err:
            self.error_handling(err)

    def test_api_get_velocity(self):
        "get_velocity"
        self.assertRaises(HTTPError, self.access_sdk.get_velocity, *self.fake_arg)
        try:
            self.access_sdk.get_velocity(*arg)
        except HTTPError as err:
            self.error_handling(err)

    def test_api_requests_empty_credentials(self):
        "empty credentials - ValueError: Invalid value ''"
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(HTTPError, getattr(self.access_sdk, target), *[session_id, '', ''])

    def test_api_requests_credentials_none(self):
        "credentials None - ValueError: Invalid value 'None'"
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(HTTPError, getattr(self.access_sdk, target), *[session_id, None, None])

    def test_api_requests_missing_credentials(self):
        "missing_credentials - TypeError: get_decision() missing 2 required positional arguments: 'username' and 'password'"
        for target in ['get_decision', 'get_velocity']:
            self.assertRaises(TypeError, getattr(self.access_sdk, target), session_id)

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
        #~ defaultTest="TestAPIAccess.test_get_decision"
    )
