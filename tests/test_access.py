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
from settings import pswd, u_email, version, serverName, apiKey, merchantId
assert apiKey != 'YOUR-API-KEY-GOES-HERE'

logger = logging.getLogger('kount.test')
session_id = '8f18a81cfb6e3179ece7138ac81019aa'

method_list = [func for func in dir(AccessSDK) if callable(getattr(AccessSDK, func)) and not func.startswith("__")]
logger.info(merchantId, serverName, version, session_id, u_email, method_list)


class TestAPIAccess(unittest.TestCase):
    def setUp(self):
        self.method_list = method_list
        assert self.method_list == ['get_decision', 'get_device', 'get_velocity']
        self.access_sdk = AccessSDK(serverName, merchantId, apiKey, version)
        self.arg = [session_id, u_email, pswd]

    def test_api_access_methods(self):
        u = self.access_sdk.__get_hash__('admin')
        self.assertEqual('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', u)
        p = self.access_sdk.__get_hash__(u'password')
        self.assertEqual('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', p)

    @unittest.skipIf(py27 is True, "subTest is not supported in this Python 2.7.x")
    def test_subtest(self):
        """python 3.6.x only - subTest"""
        for i in range(len(self.method_list)):
            with self.subTest(i=i):
                if 'get_device' in self.method_list[i]:
                    arg = [session_id]
                    self.assertRaises(HTTPError, getattr(self.access_sdk, self.method_list[i]), arg)
                else:
                    arg=self.arg
                    self.assertRaises(HTTPError, getattr(self.access_sdk, self.method_list[i]), session_id, u_email, pswd)
                try:
                    getattr(self.access_sdk, self.method_list[i])(*arg)
                except HTTPError as err:
                    logger.debug("UNAUTHORIZED %s, %s", err.msg, err.code)
                    self.assertEqual('UNAUTHORIZED', err.msg.upper())
                    self.assertEqual(401, err.code)
                    raise

def make_function(m):
    """make_function() is  the function used internally by def()
    to produce Python callable objects which wrap member functions.
    in order to execute a specific test for method in SDK, in unittest.main use:
    defaultTest="TestAPIAccess.test_{method_name}
    exmpl. defaultTest="TestAPIAccess.test_get_decision"
    """
    def common(self):
        """main function that collect all methods from AccessSDK and create unit-tests for them"""
        if m in ['get_device']:
            arg = [session_id]
        else:
            arg = [session_id, u_email, pswd]
        try:
            getattr(self.access_sdk, m)(*arg)
        except HTTPError as err:
            logger.debug("UNAUTHORIZED %s, %s", err.msg, err.code)
            self.assertEqual('UNAUTHORIZED', err.msg.upper())
            self.assertEqual(401, err.code)
    return common

def attributes_set_to_class(i, class_name=TestAPIAccess, make_function=make_function, **kwd):
    """set attributes to class like test_get_decision"""
    test_func = make_function(method_list[i])
    setattr(class_name, 'test_%s'%method_list[i], test_func)
    return class_name

for i in range(len(method_list)):
    attributes_set_to_class(i, class_name=TestAPIAccess, make_function=make_function)


class TestAPIRequests(unittest.TestCase):
    def setUp(self):
        self.headers = {}
        self.url_get = "https://%s:%s@%s/api/"%(u_email, pswd, serverName)
        self.params = {'v': version, 's': session_id}
        #~ self.headers['Accept'] = 'application/json'
        #~ self.headers['Content-Type'] = 'application/json'
        m = str(merchantId).encode('utf-8')
        a = base64.standard_b64encode(m +  ":".encode('utf-8') + apiKey.encode('utf-8'))
        self.headers['Authorization'] = 'Basic %s' %a.decode('utf-8')

    def test_api_requests(self):
        "returns device, velocity and decision response"
        failed = []
        for target in method_list:
            url = "%s%s"%(self.url_get, target.split('get_')[1])
            logger.info("url = %s", url)
            if 'device' in target:
                self.r = requests.get(url,
                                    headers=self.headers,
                                    params=self.params,
                                    )
            else:
                self.r = requests.post(url,
                                    headers=self.headers,
                                    params=self.params,
                                    )
            logger.debug("self.r= %s, self.r.status_code= %s, text= %s", self.r, self.r.status_code, self.r.text)
            try:
                self.assertEqual(200, self.r.status_code)
            except AssertionError as e:
                logger.debug("target= %s, e= %s, text= %s", target, e, self.r.text)
                failed.append((target, e, self.r.text))
            else:
                self.assertTrue(self.r.text)
                self.assertTrue(len(self.r.json()))
            self.assertNotIn('Error', self.r.text)
        if failed:
            raise Exception(failed)

    def test_api_requests_missing_params(self):
        "missing_params in request"
        params = {}
        for target in method_list:
            url = "%s%s"%(self.url_get, target.split('get_')[1])
            logger.info("url = %s", url)
            if 'device' in target:
                self.r = requests.get("%s"%(url),
                                    headers=self.headers,
                                    params=params,
                                    )
            else:
                self.r = requests.post("%s"%(url),
                                    headers=self.headers,
                                    params=params,
                                    )
            logger.debug("self.r= %s, self.r.status_code= %s, text= %s", self.r, self.r.status_code, self.r.text)
            self.assertNotEqual(200, self.r.status_code)
            self.assertNotIn('Error', self.r.text)

    def test_api_requests_missing_credentials(self):
        "missing_credentials"
        failed = []
        url_get = "https://%s:%s@%s/api/"%('', '', serverName)
        for target in method_list:
            url = "%s%s"%(url_get, target.split('get_')[1])
            logger.debug("url= %s", url)
            if 'device' in target:
                self.r = requests.get("%s"%(url),
                                    headers=self.headers,
                                    params=self.params,
                                    )
            else:
                self.r = requests.post("%s"%(url),
                                    headers=self.headers,
                                    params=self.params,
                                    )
            logger.debug("self.r= %s, self.r.status_code= %s, text= %s", self.r, self.r.status_code, self.r.text)
            try:
                self.assertEqual(401, self.r.status_code)
            except AssertionError as e:
                logger.debug("target= %s, e= %s, text= %s", target, e, self.r.text)
                failed.append((target, e, self.r.text))
            self.assertNotIn('Error', self.r.text)
        if failed:
            raise Exception(failed)


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestAPIAccess.test_get_decision"
    )
