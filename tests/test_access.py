# -*- coding: utf-8 -*-
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount access python sdk project
# https://github.com/Kount/kount-access-python-sdk/)
# Copyright (C) 2017 Kount Inc. All Rights Reserved.

from __future__ import absolute_import, unicode_literals, division, print_function
__author__ = "Kount Access SDK"
__version__ = "1.0.0"
__maintainer__ = "Kount Access SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

import unittest
from kount_access.access_sdk import AccessSDK

try:
    from urllib.error import HTTPError
    py27 = False
except ImportError:
    from urllib2 import HTTPError
    py27 = True

merchantId = 100100
apiKey = 'YOUR-API-KEY-GOES-HERE'
serverName = 'someserver.kountaccess.com'
version = '0210'
session_id = '8f18a81cfb6e3179ece7138ac81019aa'


class TestAPIAccess(unittest.TestCase):
    def setUp(self):
        self.method_list = [func for func in dir(AccessSDK) if callable(getattr(AccessSDK, func)) and not func.startswith("__")]
        self.access_sdk = AccessSDK("api-sandbox02.kountaccess.com", merchantId, apiKey, version)
        self.arg = [session_id, 'admin', 'password']

    def test_api_access_methods(self):
        u = self.access_sdk.__get_hash__('admin')
        self.assertEqual('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', u)
        p = self.access_sdk.__get_hash__(u'password')
        self.assertEqual('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', p)

    @unittest.skipIf(py27 is True, "subTest not supported in this Python 2.7.x")
    def test_subtest(self):
        """
        python 3.6.x only - subTest
        """
        for i in range(len(self.method_list)):
            with self.subTest(i=i):
                if 'get_device' in self.method_list[i]:
                    arg = [session_id]
                    self.assertRaises(HTTPError, getattr(self.access_sdk, self.method_list[i]), arg)
                else:
                    arg=self.arg
                    self.assertRaises(HTTPError, getattr(self.access_sdk, self.method_list[i]), session_id, 'admin', 'password')
                try:
                    getattr(self.access_sdk, self.method_list[i])(*arg)
                except HTTPError as err:
                    self.assertEqual('UNAUTHORIZED', err.msg)
                    self.assertEqual(401, err.code)

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
            arg = [session_id, 'admin', 'password']
        try:
            getattr(self.access_sdk, m)(*arg)
        except HTTPError as err:
            self.assertEqual('UNAUTHORIZED', err.msg)
            self.assertEqual(401, err.code)

    return common


def attributes_set_to_class(i, class_name=TestAPIAccess, make_function=make_function, **kwd):
    """set attributes to class like test_get_decision"""
    test_func = make_function(method_list[i])
    setattr(class_name, 'test_%s'%method_list[i], test_func)
    return class_name


method_list = [func for func in dir(AccessSDK) if callable(getattr(AccessSDK, func)) and not func.startswith("__")]
for i in range(len(method_list)):
    attributes_set_to_class(i, class_name=TestAPIAccess, make_function=make_function)


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        #~ defaultTest="TestAPIAccess.test_get_decision"
    )
