#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount python sdk project
# https://github.com/Kount/kount-ris-python-sdk/
# Copyright (C) 2017 Kount Inc. All Rights Reserved.

"""Test Basic Connectivity"""

import sys
import unittest
import pytest

from kount_access.access_sdk import AccessSDK


if sys.version_info[0] == 2:
    from urllib2 import HTTPError
else:
    from urllib.error import HTTPError

__author__ = "Kount SDK"
__version__ = '4.0.0'
__maintainer__ = "Kount SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

server_name = 'api-sandbox01.kountaccess.com'


@pytest.mark.usefixtures("api_key", "merchant_id")
class TestBasicConnectivity(unittest.TestCase):
    """Test Basic Connectivity"""
    merchant_id = None
    api_key = None
    version = '0400'

    SESSION_ID = "36C5024391374839B0D609785307C990"
    FAKE_SESSION = None
    FAKE_VERSION = '4.0.0'
    FAKE_UNIQ = ""
    FAKE_TRUSTED_STATE = ""
    FAKE_DEVICE_ID = ""
    USERNAME = "test@kount.net"
    PASSWORD = "password"
    UNIQ = "abc111@abc.com"
    DEVICE_ID = "9fbc4b5f963a4a109fa0aebf3dc677c7"

    def test_api_get_devicetrustbydevice(self):
        trusted_state = "trusted"

        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.FAKE_VERSION
        self.assertRaises(HTTPError, self.access_sdk.get_devicetrustbydevice, self.DEVICE_ID, self.UNIQ, trusted_state)

        self.access_sdk.version = self.version

        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, self.FAKE_DEVICE_ID,
                          self.UNIQ, trusted_state)

        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, self.DEVICE_ID,
                          self.FAKE_UNIQ, trusted_state)

        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, self.DEVICE_ID,
                          self.UNIQ, self.FAKE_TRUSTED_STATE)

        expected = None
        result = self.access_sdk.get_devicetrustbydevice(self.DEVICE_ID, self.UNIQ, trusted_state)
        self.assertEqual(result, expected)

    def test_api_get_devicetrustbysession(self):
        trusted_state = "trusted"

        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.FAKE_VERSION
        self.assertRaises(HTTPError, self.access_sdk.get_devicetrustbysession, self.SESSION_ID,
                          self.UNIQ, trusted_state)

        self.access_sdk.version = self.version

        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbysession,
                          self.FAKE_SESSION, self.UNIQ, trusted_state)

        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbysession,
                          self.SESSION_ID, self.FAKE_UNIQ, trusted_state)

        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbysession, self.SESSION_ID,
                          self.UNIQ, self.FAKE_TRUSTED_STATE)

        expected = None
        result = self.access_sdk.get_devicetrustbysession(self.SESSION_ID, self.UNIQ, trusted_state)
        self.assertEqual(result, expected)

    def test_api_get_uniques(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.FAKE_VERSION
        self.assertRaises(HTTPError, self.access_sdk.get_uniques, self.DEVICE_ID)

        self.access_sdk.version = self.version
        self.assertRaises(ValueError, self.access_sdk.get_uniques, self.FAKE_DEVICE_ID)

        expected = {
            'response_id': 'd73aabde31df4ff89f85a99ed1e835e1',
            'uniques': [{
                'unique': 'abc10@abc.com',
                'datelastseen': '2018-08-13T12:18:57.636Z',
                'truststate': 'trusted'
            }, {
                'unique': 'abc111@abc.com',
                'datelastseen': '2018-08-13T12:22:58.113Z',
                'truststate': 'trusted'
            }, {
                'unique': 'abc555555@abc.com',
                'datelastseen': '2018-08-13T12:16:56.165Z',
                'truststate': 'trusted'
            }, {
                'unique': 'abc5@abc.com',
                'datelastseen': '2018-08-13T12:16:47.144Z',
                'truststate': 'trusted'
            }]
        }
        result = self.access_sdk.get_uniques(self.DEVICE_ID)
        self.assertEqual(result.keys(), expected.keys())

    def test_api_get_devices(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.FAKE_VERSION
        self.assertRaises(HTTPError, self.access_sdk.get_devices, self.UNIQ)

        self.access_sdk.version = self.version
        self.assertRaises(ValueError, self.access_sdk.get_devices, self.FAKE_UNIQ)

        expected = {
            "response_id": "e4aba68fcae14d1e9a75f1bf6c5236cb",
            "devices": [
                {
                    "deviceid": "9fbc4b5f963a4a109fa0aebf3dc677c7",
                    "truststate": "trusted",
                    "datefirstseen": "2018-08-13T12:16:56.165Z",
                    "friendlyname": ""
                }
            ]
        }
        result = self.access_sdk.get_devices(self.UNIQ)
        self.assertEqual(result.keys(), expected.keys())


if __name__ == "__main__":
    unittest.main(
        # defaultTest="TestBasicConnectivity.test_api_get_devicetrustbydevice"
    )
