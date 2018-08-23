#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount access python sdk project
# https://github.com/Kount/kount-access-python-sdk/)
# Copyright (C) 2017 Kount Inc. All Rights Reserved.
"""
access_sdk module Contains functions for a client to call Kount Access's API Service.
"""

from __future__ import absolute_import, unicode_literals, division, print_function
__author__ = "Kount Access SDK"
__version__ = "4.0.0"
__maintainer__ = "Kount Access SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

import base64
import hashlib
import urllib
import sys
import json
import logging

if sys.version_info[0] == 2:
    import urllib2 as urllibr
    py27 = True
else:
    py27 = False
    import urllib.request as urllibr

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

logger = logging.getLogger('kount.access')


class AccessSDK:
    """
    Class that wraps access to Kount Access's API via python interface.
    """

    # This is the default service version for this SDK - 0400.
    __version__ = '0400'

    BEHAVIOSEC_ENDPOINT = "/behavio/data"
    DEVICE_TRUST_BY_SESSION = "/api/devicetrustbysession"
    DEVICE_TRUST_BY_DEVICE = "/api/devicetrustbydevice"
    GET_UNIQUES_ENDPOINT = "/api/getuniques"
    GET_DEVICES_ENDPOINT = "/api/getdevices"
    INFO_ENDPOINT = "/api/info"
    TRUSTED_STATES = ["trusted", "not_trusted", "banned"]

    DATA_SET = {
        "info": 1,
        "velocity": 2,
        "decision": 4,
        "trusted": 8,
        "behaviosec": 16
    }

    def __init__(self, host, merchant_id, api_key, version=None, behavio_host=None, behavio_environment=None):
        """
        Constructor.
        :param behavio_host is BehavioSec host
        :param behavio_environment is working environment
        :param version:
        :param host Kount server to connect.
        :param merchant_id Merchant's id.
        :param api_key Merchant's api key.
        :param version Optional version string to override default.
        """
        self.host = host
        self.merchant_id = merchant_id
        self.behavio_host = behavio_host
        self.behavio_environment = behavio_environment
        self.api_key = str(api_key)
        self.authorization_header = self.__init_authorization_header()
        self.version = self.__version__
        if version is not None:
            self.version = version
        logger.info("Init AccessSDK -> merchantID: %s | APIKey: %s" %
                    (self.merchant_id, self.api_key[:20] + "..."))

    @staticmethod
    def __add_param(request, additional_params):
        """
        Add parameters to a request before making the call.
        get_device_request().
        @param request: Dictionary of URL and params.
        @param additional_params: Dictionary of key value pairs representing param name and param value.
        @return: None
        """
        if isinstance(additional_params, dict):
            for param in additional_params.keys():
                request['params'][param] = additional_params[param]
        else:
            raise Exception()

    @staticmethod
    def __format_response(response):
        """
        Convert the JSON response to a native dictionary.
        @param response: JSON representation of the response.
        @return: Dictionary representation of the response.
        """
        if not py27:
            response = response.decode('utf-8')

        json_response = None
        if response:
            json_response = json.loads(response)

        logger.debug(json_response)

        return json_response

    def get_velocity(self, session, username, password, additional_params=None):
        """
        Web request to the Kount Access API service's get velocity.
        @param session SSL session id.
        @param username Username.
        @param password Password.
        @param additional_params: Dictionary of key value pairs representing param name and param value.
        @return response from api.
        """
        return self.__get_data_using_velocity_params('velocity', session, username, password, additional_params)

    def __init_authorization_header(self):
        """
        Helper for building authorization header
        @return Encoded authorization value.
        """
        m = str(self.merchant_id).encode('utf-8')
        a = base64.standard_b64encode(m + ":".encode('utf-8') + self.api_key.encode('utf-8'))
        return {'Authorization': ('Basic %s' % a.decode('utf-8'))}

    def get_decision(self, session, username, password, additional_params=None):
        """
        Web request to the Kount Access API service's get decision.
        @param session SSL session id.
        @param username Username.
        @param password Password.
        @param additional_params: Dictionary of key value pairs representing param name and param value.
        @return response from api.
        """
        return self.__get_data_using_velocity_params('decision', session, username, password, additional_params)

    def _prepare_params(self, session, username, password):
        """
        prepare_params for requests; username or password could be Null or empty string.
        if any of username or password is Null or '', both are not in the params dict
        @param session - session id.
        @param username Username.
        @param password Password.
        @return dict.
        """
        params = {'v': self.version, 's': session}
        return self._prepare_hashes(params, username, password)

    def __get_data_using_velocity_params(self, endpoint, session, username, password, additional_params=None):
        """
        Helper, web request to the Kount Access API velocity based endpoints.
        @param endpoint
        @param session SSL session id.
        @param username Username.
        @param password Password.
        @param additional_params: Dictionary of key value pairs representing param name and param value.
        @return response from api.
        """
        self._validate_session(session)

        params = self._prepare_params(session, username, password)
        request = {
            'url': 'https://{}/api/{}'.format(self.host, endpoint),
            'params': params
        }
        if additional_params is not None:
            self.__add_param(request, additional_params)

        user_hash = params.get('uh', None)
        password_hash = params.get('ph', None)

        logger.info("get_%s -> v: %s, s: %s, username: %s, password: %s" %
                    (endpoint, self.version, session, user_hash, password_hash))

        return self.__request_post(request['url'], request['params'])

    def get_device(self, session, additional_params=None):
        """
        Web request to the Kount Access API service's get device.
        @param session SSL session id.
        @param additional_params: Dictionary of key value pairs representing param name and param value.
        @return response from api.
        """
        request = {
            'url': 'https://' + self.host + '/api/device',
            'params': {
                'v': self.version,
                's': session
            }
        }
        if additional_params is not None:
            self.__add_param(request, additional_params)

        logger.info("get_device -> v: %s, s: %s" % (self.version, session))

        return self.__request_get(request['url'], request['params'])

    @staticmethod
    def _get_hash(value):
        """
        Abstracted in case the hashing process should ever change.
        @param value: Value to hash.
        @return Hashed value.
        """
        if not value:
            raise ValueError("Invalid value '%s'." % value)
        return hashlib.sha256(str(value).encode('utf-8')).hexdigest()

    def __request(self, url, values=None, content_type=None):
        """
        Helper for making web requests and handling response.
        @param url URL to request.
        @param values
        @return request result.
        """
        if values:
            values = values.encode('utf-8')

        header = self.authorization_header
        if content_type:
            header['Content-Type'] = 'application/x-www-form-urlencoded'

        request = urllibr.Request(url, values, self.authorization_header)
        try:
            response = urllibr.urlopen(request)
        except urllibr.URLError as e:
            err = "%s.%s, url=%s, values=%s" % (urllibr.__name__, e.__class__.__name__, url, values)
            logger.error(err)
            raise
        result = response.read()
        logger.debug(result)
        return self.__format_response(result)

    def __request_get(self, url, values):
        """
        Wrapper for request() to send request as a GET.
        @param url URL to request.
        @param values Parameters for the request.
        @return request result.
        """
        if py27:
            v = urllib.urlencode(values)
        else:
            v = urllib.parse.urlencode(values)
        return self.__request(url + "?" + v)

    def __request_post(self, url, values, content_type=None):
        """
        Wrapper for request() to send request as a POST.
        @param url URL to request.
        @param values Parameters for the request.
        @return request result.
        """
        if py27:
            return self.__request(url, urllib.urlencode(values), content_type)
        else:
            return self.__request(url, urllib.parse.urlencode(values), content_type)

    def get_devicetrustbydevice(self, device_id, uniq, trusted_state):
        """
        Get device trust by device
        :param device_id is a issue for the device
        :param uniq is a customer identifier
        :param trusted_state is trusted state to set to (not_trusted, trusted, banned)
        :return: request result
        """
        self._validate_param(device_id, "invalid device id: ")
        self._validate_param(uniq, "invalid uniq: ")
        self._validate_state(trusted_state)

        url = self._build_url(self.host, self.DEVICE_TRUST_BY_DEVICE)
        data = {
            'v': self.version,
            'd': device_id,
            'uniq': uniq,
            'ts': trusted_state
        }

        logger.info("get_devicetrustbydevice -> v: %s, d: %s, uniq: %s, trusted state: %s" %
                    (self.version, device_id, uniq, trusted_state))

        return self.__request_post(url, data)

    def get_devicetrustbysession(self, session, uniq, trusted_state):
        """
        Get device trust by session
        :param session that has already had a device collection made
        :param uniq is a customer identifier
        :param trusted_state is trusted state to set to (not_trusted, trusted, banned)
        :return: request result
        """
        self._validate_session(session)
        self._validate_param(uniq, "invalid uniq: ")
        self._validate_state(trusted_state)

        url = self._build_url(self.host, self.DEVICE_TRUST_BY_SESSION)
        data = {
            'v': self.version,
            's': session,
            'uniq': uniq,
            'ts': trusted_state
        }

        logger.info("get_devicetrustbysession -> v: %s, s: %s, uniq: %s, trusted state: %s" %
                    (self.version, session, uniq, trusted_state))

        return self.__request_post(url, data)

    def get_uniques(self, device_id):
        """
        Get a list of UNIQ values for given device ID
        :param device_id is device identifier assigned by Kount
        :return: request result
        """
        self._validate_param(device_id, "invalid device id: ")

        url = self._build_url(self.host, self.GET_UNIQUES_ENDPOINT)
        data = {
            'v': self.version,
            'd': device_id
        }

        logger.info("get_uniques -> v: %s, d: %s" % (self.version, device_id))

        return self.__request_get(url, data)

    def get_devices(self, uniq):
        """
        Get devices
        :param uniq is a customer identifier
        :return: request result
        """
        self._validate_param(uniq, "invalid uniq: ")

        url = self._build_url(self.host, self.GET_DEVICES_ENDPOINT)
        data = {
            'v': self.version,
            'uniq': uniq
        }

        logger.info("get_devices -> v: %s, uniq: %s" % (self.version, uniq))

        return self.__request_get(url, data)

    def get_info(self, session, info=None, velocity=None,
                 decision=None, trusted=None, behaviosec=None,
                 uniq=None, username=None, password=None
                 ):
        """
        Get Info
        :param info should be true if we want device info in result
        :param velocity should be true if we want velocity in result
        :param decision should be true if we want decision in result
        :param trusted should be true if we want trusted in result
        :param behaviosec should be true if we want behaviosec info in result
        :param uniq is a customer identifier
        :param session that has already had a device collection made
        :param password
        :param username
        :return: request result
        """
        self._validate_session(session)

        if not info and not velocity and not decision and not trusted and not behaviosec:
            err_msg = "At least one of the following parameters - " \
                      "info, velocity, decision, trusted, behaviosec should be true"
            raise ValueError(err_msg)

        data = {'v': self.version, 's': session,
                'i': self._calc_data_set_value(info, velocity, decision, trusted, behaviosec)}

        if trusted or behaviosec:
            self._validate_param(uniq, "invalid uniq: ")
            data['uniq'] = uniq

        if behaviosec:
            data['m'] = self.merchant_id

        if velocity or decision:
            self._validate_param(username, "invalid username: ")
            self._validate_param(password, "invalid password: ")
            data = self._prepare_hashes(data, username, password)

        url = self._build_url(self.host, self.INFO_ENDPOINT)

        return self.__request_post(url, data)

    def behaviosec(self, session, uniq, timing, merchant):
        """
        BehavioSec
        :param session that has already had a device collection made
        :param uniq is a customer identifier
        :param timing
        :param merchant id
        :return: request result
        """
        self._validate_session(session)
        self._validate_param(uniq, "invalid uniq: ")
        self._validate_param(self.behavio_host, "invalid behavio host")
        self._validate_param(self.behavio_environment, "invalid environment")

        url = self._build_url(self.behavio_host + '/' + self.behavio_environment, self.BEHAVIOSEC_ENDPOINT)

        data = {
            'uniq': uniq,
            's': session,
            'timing': timing,  # TODO
            'm': merchant
        }

        logger.info("behaviosec -> uniq: %s, s: %s, timing: %s, m: %s" % (uniq, session, timing, merchant))
        return self.__request_post(url, data, 'application/x-www-form-urlencoded')

    def _calc_data_set_value(self, info, velocity, decision, trusted, behaviosec):
        """
        Calculate i
        :param info:
        :param velocity:
        :param decision:
        :param trusted:
        :param behaviosec:
        :return: i
        """
        i = 0
        if info:
            i += self.DATA_SET['info']
        if velocity:
            i += self.DATA_SET['velocity']
        if decision:
            i += self.DATA_SET['decision']
        if trusted:
            i += self.DATA_SET['trusted']
        if behaviosec:
            i += self.DATA_SET['behaviosec']
        return i

    def _prepare_hashes(self, params, username, password):
        """
        Helper, add to params hashed username and password
        :param params:
        :param username:
        :param password:
        :return: modified params
        """
        if all(i for i in [username, password]):
            params['uh'] = self._get_hash(username)
            params['ph'] = self._get_hash(password)
            params['ah'] = self._get_hash("%s:%s" % (username, password))
        return params

    def _build_url(self, host, endpoint):
        if not self.host:
            raise ValueError("invalid host: %s" % self.host)
        return 'https://' + host + endpoint

    @staticmethod
    def _validate_state(state):
        if state not in ['not_trusted', 'trusted', 'banned']:
            raise ValueError("invalid state: %s" % state)

    @staticmethod
    def _validate_session(session):
        if not session or len(session) != 32:
            raise ValueError("invalid session: %s" % session)

    @staticmethod
    def _validate_param(value, err_string):
        if not value:
            raise ValueError(err_string + " %s" % value)
