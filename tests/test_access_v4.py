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

    def test_api_get_devicetrustbydevice(self):
        device_id = "9fbc4b5f963a4a109fa0aebf3dc677c7"
        uniq = "abc111@abc.com"
        trusted_state = "trusted"

        self.access_sdk = AccessSDK(server_name, self.merchant_id, self.api_key, self.version)

        fake_version = '4.0.0'
        self.access_sdk.version = fake_version
        self.assertRaises(HTTPError, self.access_sdk.get_devicetrustbydevice, device_id, uniq, trusted_state)

        self.access_sdk.version = self.version

        fake_device_id = None
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, fake_device_id, uniq, trusted_state)

        fake_uniq = ""
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, device_id, fake_uniq, trusted_state)

        fake_trusted_state = ""
        self.assertRaises(ValueError, self.access_sdk.get_devicetrustbydevice, device_id, uniq, fake_trusted_state)

        expected = None
        result = self.access_sdk.get_devicetrustbydevice(device_id, uniq, trusted_state)
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main(
        # defaultTest="TestBasicConnectivity.test_api_get_devicetrustbydevice"
    )
