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
__version__ = "2.1.1"
__maintainer__ = "Kount Access SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

import base64
import hashlib
import urllib
import sys
if sys.version_info[0] == 2:
    import urllib2 as urllibr
    py27 = True
else:
    py27 = False
    import urllib.request as urllibr
import json
import logging
logging.basicConfig()

logger = logging.getLogger('kount.access')


class AccessSDK:
    """
    Class that wraps access to Kount Access's API via python interface.
    """

    # This is the default service version for this SDK - 0210.
    __version__ = '0210'

    def __init__(self, host, merchantId, apiKey, version=None):
        """
        Constructor.
        @param version:
        @param host Kount server to connect.
        @param merchantId Merchant's id.
        @param apiKey Merchant's api key.
        @param version Optional version string to override default.
        """
        self.host = host
        self.merchantId = merchantId
        self.apiKey = apiKey
        self.version = self.__version__
        if version is not None:
            self.version = version

    def __add_param(self, request, additional_params):
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

    def __format_response(self, response):
        """
        Convert the JSON response to a native dictionary.
        @param response: JSON representation of the response.
        @return: Dictionary representation of the response.
        """
        if not py27:
            response = response.decode('utf-8')
        logger.debug(json.loads(response))
        return json.loads(response)

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

    def __get_authorization_header(self):
        """
        Helper for building authorization header
        @return Encoded authorization value.
        """
        m = str(self.merchantId).encode('utf-8')
        a = base64.standard_b64encode(m +  ":".encode('utf-8') + self.apiKey.encode('utf-8'))
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
        if all(i for i in [username, password]):
            params['uh'] = self._get_hash(username)
            params['ph'] = self._get_hash(password)
            params['ah'] = self._get_hash("%s:%s"%(username, password))
        return params

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
        params = self._prepare_params(session, username, password)
        request = {
            'url': 'https://{}/api/{}'.format(self.host, endpoint),
            'params': params
        }
        if additional_params is not None:
            self.__add_param(request, additional_params)
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
        return self.__request_get(request['url'], request['params'])

    def _get_hash(self, value):
        """
        Abstracted in case the hashing process should ever change.
        @param value: Value to hash.
        @return Hashed value.
        """
        if value:
            return hashlib.sha256(str(value).encode('utf-8')).hexdigest()
        else:
            raise ValueError("Invalid value '%s'."% value)

    def __request(self, url, values=None):
        """
        Helper for making web requests and handling response.
        @param url URL to request.
        @param values
        @return request result.
        """
        if values:
            values = values.encode('utf-8')
        request = urllibr.Request(url, values, self.__get_authorization_header())
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

    def __request_post(self, url, values):
        """
        Wrapper for request() to send request as a POST.
        @param url URL to request.
        @param values Parameters for the request.
        @return request result.
        """
        if py27:
            return self.__request(url, urllib.urlencode(values))
        else:
            return self.__request(url, urllib.parse.urlencode(values))
