#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount python sdk project
# https://github.com/Kount/kount-ris-python-sdk/
# Copyright (C) 2017 Kount Inc. All Rights Reserved.

"""Test Basic Connectivity"""

import sys
import unittest
import pytest
import requests

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
data_collector = "https://sandbox01.kaxsdc.com/collect/sdk"


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
    FAKE_TIMING = ""
    FAKE_MERCHANT_ID = ""
    USERNAME = "test@kount.net"
    PASSWORD = "password"
    UNIQ = "abc111@abc.com"
    DEVICE_ID = "9fbc4b5f963a4a109fa0aebf3dc677c7"
    TIMING = "should_be_string"

    @classmethod
    def setUpClass(self):
        data = {
            'm': 999666,
            's': self.SESSION_ID
        }

        req = requests.Request('GET', data_collector, params=data)
        prepared = req.prepare()
        s = requests.Session()
        result = s.send(prepared)

        assert result.status_code == 200

    def test_api_get_devicetrustbydevice(self):
        trusted_state = "trusted"

        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.version
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, self.FAKE_DEVICE_ID,
                          self.UNIQ, trusted_state)
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, self.DEVICE_ID,
                          self.FAKE_UNIQ, trusted_state)
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, self.DEVICE_ID,
                          self.UNIQ, self.FAKE_TRUSTED_STATE)

        if self.api_key:
            self.access_sdk.version = self.FAKE_VERSION
            self.assertRaises(HTTPError, self.access_sdk.get_devicetrustbydevice, self.DEVICE_ID, self.UNIQ, trusted_state)

            expected = None
            self.access_sdk.version = self.version
            result = self.access_sdk.get_devicetrustbydevice(self.DEVICE_ID, self.UNIQ, trusted_state)
            self.assertEqual(result, expected)

    def test_api_get_devicetrustbysession(self):
        trusted_state = "trusted"

        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.version
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbysession,
                          self.FAKE_SESSION, self.UNIQ, trusted_state)
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbysession,
                          self.SESSION_ID, self.FAKE_UNIQ, trusted_state)
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbysession, self.SESSION_ID,
                          self.UNIQ, self.FAKE_TRUSTED_STATE)

        if self.api_key:
            self.access_sdk.version = self.FAKE_VERSION
            self.assertRaises(HTTPError, self.access_sdk.get_devicetrustbysession, self.SESSION_ID,
                              self.UNIQ, trusted_state)

            expected = None
            self.access_sdk.version = self.version
            result = self.access_sdk.get_devicetrustbysession(self.SESSION_ID, self.UNIQ, trusted_state)
            self.assertEqual(result, expected)

    def test_api_get_uniques(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.version
        self.assertRaises(ValueError, self.access_sdk.get_uniques, self.FAKE_DEVICE_ID)

        if self.api_key:
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

            self.access_sdk.version = self.FAKE_VERSION
            self.assertRaises(HTTPError, self.access_sdk.get_uniques, self.DEVICE_ID)

            self.access_sdk.version = self.version
            result = self.access_sdk.get_uniques(self.DEVICE_ID)
            self.assertEqual(result.keys(), expected.keys())

    def test_api_get_devices(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.version
        self.assertRaises(ValueError, self.access_sdk.get_devices, self.FAKE_UNIQ)

        if self.api_key:
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

            self.access_sdk.version = self.FAKE_VERSION
            self.assertRaises(HTTPError, self.access_sdk.get_devices, self.UNIQ)

            self.access_sdk.version = self.version
            result = self.access_sdk.get_devices(self.UNIQ)
            self.assertEqual(result.keys(), expected.keys())

    def test_api_get_info(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.access_sdk.version = self.version
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, uniq=self.FAKE_UNIQ,
                          info=True, trusted=True)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, uniq=self.FAKE_UNIQ,
                          info=True, trusted=True)

        if self.api_key:
            self.access_sdk.version = self.FAKE_VERSION
            self.assertRaises(HTTPError, self.access_sdk.get_info, self.SESSION_ID, info=True)

    def test_api_get_info_device_info(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        if self.api_key:
            expected = {
                "device": {
                    "id": "9fbc4b5f963a4a109fa0aebf3dc677c7",
                    "ipAddress": "93.123.21.68",
                    "ipGeo": "BG",
                    "mobile": 0,
                    "proxy": 0,
                    "tor": 0,
                    "region": "61",
                    "country": "BG",
                    "geoLat": 43.2167,
                    "geoLong": 27.9167
                },
                "response_id": "4f04917e14874b708511b46320e757ca"
            }
            result = self.access_sdk.get_info(self.SESSION_ID, info=True)
            self.assertEqual(result.keys(), expected.keys())

    def test_api_get_info_velocity(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, velocity=True)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, velocity=True, username=self.USERNAME)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, velocity=True, username=self.PASSWORD)

        if self.api_key:
            expected = {
                "response_id": "c1fc61e995134c368c3f43354e2c6261",
                "velocity": {
                    "account": {
                        "dlh": 1,
                        "dlm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "plh": 1,
                        "plm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "device": {
                        "alh": 1,
                        "alm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "plh": 1,
                        "plm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "ip_address": {
                        "alh": 1,
                        "alm": 1,
                        "dlh": 1,
                        "dlm": 1,
                        "plh": 1,
                        "plm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "password": {
                        "alh": 1,
                        "alm": 1,
                        "dlh": 1,
                        "dlm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "user": {
                        "alh": 1,
                        "alm": 1,
                        "dlh": 1,
                        "dlm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "plh": 1,
                        "plm": 1
                    }
                }
            }
            result = self.access_sdk.get_info(self.SESSION_ID, velocity=True,
                                              username=self.USERNAME, password=self.PASSWORD)
            self.assertEqual(result.keys(), expected.keys())

    def test_api_get_info_device_info_velocity(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, info=True, velocity=True)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, info=True,
                          velocity=True, username=self.USERNAME)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, info=True,
                          velocity=True, username=self.PASSWORD)

        if self.api_key:
            expected = {
                "device": {
                    "id": "9fbc4b5f963a4a109fa0aebf3dc677c7",
                    "ipAddress": "93.123.21.68",
                    "ipGeo": "BG",
                    "mobile": 0,
                    "proxy": 0,
                    "tor": 0,
                    "region": "61",
                    "country": "BG",
                    "geoLat": 43.2167,
                    "geoLong": 27.9167
                },
                "response_id": "81fb344540cb4871ac34a5ec64689b0c",
                "velocity": {
                    "account": {
                        "dlh": 1,
                        "dlm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "plh": 1,
                        "plm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "device": {
                        "alh": 1,
                        "alm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "plh": 1,
                        "plm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "ip_address": {
                        "alh": 1,
                        "alm": 1,
                        "dlh": 1,
                        "dlm": 1,
                        "plh": 1,
                        "plm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "password": {
                        "alh": 1,
                        "alm": 1,
                        "dlh": 1,
                        "dlm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "ulh": 1,
                        "ulm": 1
                    },
                    "user": {
                        "alh": 1,
                        "alm": 1,
                        "dlh": 1,
                        "dlm": 1,
                        "iplh": 1,
                        "iplm": 1,
                        "plh": 1,
                        "plm": 1
                    }
                }
            }

            result = self.access_sdk.get_info(self.SESSION_ID, info=True, velocity=True,
                                              username=self.USERNAME, password=self.PASSWORD)
            self.assertEqual(result.keys(), expected.keys())

    def test_api_get_info_decision(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, decision=True)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, decision=True, username=self.USERNAME)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, decision=True, username=self.PASSWORD)

        if self.api_key:
            expected = {
                "decision": {
                    "errors": [],
                    "warnings": [],
                    "reply": {
                        "ruleEvents": {
                            "decision": "A",
                            "total": 0,
                            "ruleEvents": None
                        }
                    }
                },
                "response_id": "fc9ba2b36a214477a105afb772e0da00"
            }

            result = self.access_sdk.get_info(self.SESSION_ID, decision=True,
                                              username=self.USERNAME, password=self.PASSWORD)
            self.assertEqual(result.keys(), expected.keys())

    def test_api_get_info_trusted(self):
        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, trusted=True)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, trusted=True, username=self.USERNAME)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID, trusted=True, password=self.PASSWORD)
        self.assertRaises(ValueError, self.access_sdk.get_info, self.SESSION_ID,
                          trusted=True, username=self.USERNAME, password=self.PASSWORD)

        if self.api_key:
            expected = {
                "response_id": "6ec2006514954c5793bdabbdd5fbdd95",
                "trusted": {
                    "state": "trusted"
                }
            }

            result = self.access_sdk.get_info(self.SESSION_ID, trusted=True, uniq=self.UNIQ,
                                              username=self.USERNAME, password=self.PASSWORD)
            self.assertEqual(result.keys(), expected.keys())



if __name__ == "__main__":
    unittest.main(
        # defaultTest="TestBasicConnectivity.test_api_get_devicetrustbydevice"
    )
