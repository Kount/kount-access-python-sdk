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

"integration tests"

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
logger = logging.getLogger('kount.test')

#~ Access SDK methods
method_list = [func for func in dir(AccessSDK) if callable(getattr(AccessSDK, func)) and not func.startswith("__")]

#~ Sample host. this should be the name of the Kount Access API server you want to connect to.
serverName = 'api-sandbox01.kountaccess.com'


class BaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        """Sample Data (update with data used in your testing to receive the actual response from Kount Access)
        - Sample session ID - Fake user session (this should be retrieved from the 
            Kount Access Data Collector Client SDK.) This will be a 32 character hash value
        - Users credentials used to login for the test:
            - u_email,
            - pswd
        - apiKey - This should be the API Key you were issued from Kount
        - merchantId - Merchant's customer ID at Kount.
        """
        #~ THIS_IS_THE_USERS_SESSION_FROM_JAVASCRIPT_CLIENT_SDK
        self.session_id = '8f18a81cfb6e3179ece7138ac81019aa'
        self.merchantId = 999999
        self.apiKey = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIxMDAxMDAiLCJhdWQiOiJLb3VudC4wIiwiaWF0IjoxNDI0OTg5NjExLCJzY3AiOnsia2MiOm51bGwsImFwaSI6ZmFsc2UsInJpcyI6ZmFsc2V9fQ.S7kazxKVgDCrNxjuieg5ChtXAiuSO2LabG4gzDrh1x8'
        self.serverName = serverName
        self.version = '0210'
        self.u_email = 'test@test.com'
        self.pswd = 'password'
        self.method_list = method_list
        logger.info(self.merchantId, self.serverName, self.version, self.session_id, self.u_email, self.method_list)
        #~ Create an instance of the service
        self.access_sdk = AccessSDK(self.serverName, self.merchantId, self.apiKey, self.version)
        self.arg = [self.session_id, self.u_email, self.pswd]

    def setUp(self):
        """Do some custom setup"""
        self.assertEqual(self.method_list, ['get_decision', 'get_device', 'get_velocity'])


class TestAPIAccess(BaseTest):
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
                    arg = [self.session_id]
                    self.assertRaises(HTTPError, getattr(self.access_sdk, self.method_list[i]), arg)
                else:
                    arg=self.arg
                    self.assertRaises(HTTPError, getattr(self.access_sdk, self.method_list[i]), self.session_id, self.u_email, self.pswd)
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
            arg = [self.session_id]
        else:
            arg = [self.session_id, self.u_email, self.pswd]
        try:
            getattr(self.access_sdk, m)(*arg)
        except HTTPError as err:
            logger.debug("%s, %s", err.msg, err.code)
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


class TestAPIRequests(BaseTest):
    "tests for Python 2.7.x and 3.6.x, Python Requests used"
    def setUp(self):
        self.headers = {}
        self.url_get = "https://%s:%s@%s/api/"%(self.u_email, self.pswd, self.serverName)
        self.params = {'v': self.version, 's': self.session_id}
        m = str(self.merchantId).encode('utf-8')
        a = base64.standard_b64encode(m +  ":".encode('utf-8') + self.apiKey.encode('utf-8'))
        self.headers['Authorization'] = 'Basic %s' %a.decode('utf-8')

    def test_api_requests(self):
        """returns device, velocity and decision response,
        If you make a bad request you will get a response
        with an ERROR_CODE and ERROR_MESSAGE in it."""
        failed = []
        for target in self.method_list:
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
            logger.debug("r= %s, status_code= %s, text= %s", self.r, self.r.status_code, self.r.text)
            try:
                self.assertEqual(200, self.r.status_code)
                # do something with the response
                # TODO amend the test with real data assertions
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
            logger.debug("r= %s, status_code= %s, text= %s", self.r, self.r.status_code, self.r.text)
            self.assertNotEqual(200, self.r.status_code)
            # TODO - write the proper assertions after KS-167
            # Handle the Error. The two keys in the error resonse are ERROR_CODE and ERROR_MESSAGE

    def test_api_requests_missing_credentials(self):
        "missing_credentials in AccessSDK methods, in case of errors !=401, collect and raise Exception"
        failed = []
        url_get = "https://%s:%s@%s/api/"%('', '', self.serverName)
        for target in self.method_list:
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
            logger.debug("r= %s, status_code= %s, text= %s", self.r, self.r.status_code, self.r.text)
            try:
                self.assertEqual(401, self.r.status_code)
            except AssertionError as e:
                logger.debug("target= %s, e= %s, text= %s", target, e, self.r.text)
                failed.append((target, e, self.r.text))
        if failed:
            raise Exception(failed)


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestAPIAccess.test_get_decision"
    )
