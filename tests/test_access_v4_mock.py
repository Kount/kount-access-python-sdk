from unittest import TestCase
from unittest.mock import patch, Mock


class TestAccessSDK(TestCase):
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
    TRUSTED_STATE = "trusted"
    TIMING = "should_be_string"

    @patch('kount_access.access_sdk.AccessSDK')
    def test_get_devicetrustbysession(self, MockAccessSDK):
        sdk = MockAccessSDK()

        sdk.get_devicetrustbysession.return_value = None
        response = sdk.get_devicetrustbysession(self.SESSION_ID, self.UNIQ, self.TRUSTED_STATE)
        self.assertIsNone(response)

    @patch('kount_access.access_sdk.AccessSDK')
    def test_get_devicetrustbydevice(self, MockAccessSDK):
        sdk = MockAccessSDK()

        sdk.get_devicetrustbydevice.return_value = None
        response = sdk.get_devicetrustbydevice(self.DEVICE_ID, self.UNIQ, self.TRUSTED_STATE)
        self.assertIsNone(response)

    @patch('kount_access.access_sdk.AccessSDK')
    def test_get_uniques(self, MockAccessSDK):
        sdk = MockAccessSDK()

        sdk.get_uniques.return_value = {
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

        response = sdk.get_uniques(self.DEVICE_ID)
        self.assertEqual(response, response)
        self.assertIsInstance(response, dict)

    @patch('kount_access.access_sdk.AccessSDK')
    def test_get_devices(self, MockAccessSDK):
        sdk = MockAccessSDK()

        sdk.get_devices.return_value = {
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

        response = sdk.get_devices(self.UNIQ)
        self.assertEqual(response, response)
        self.assertIsInstance(response, dict)

    @patch('kount_access.access_sdk.AccessSDK')
    def test_behaviosec(self, MockAccessSDK):

        merchant_id = 999666
        behaviosec_host = "api.behavio.kaptcha.com"
        behaviosec_environment = "sandbox"
        sdk = MockAccessSDK()

        sdk.behaviosec.return_value = None

        response = sdk.behaviosec(self.SESSION_ID, self.UNIQ, self.TIMING,
                                  merchant_id, behaviosec_host, behaviosec_environment)
        self.assertIsNone(response)
