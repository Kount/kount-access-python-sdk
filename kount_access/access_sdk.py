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


"""
access_sdk module Contains functions for a client to call Kount Access's API Service.
"""
import base64
import hashlib
import urllib
try:
    import urllib2
    py27 = True
except ImportError:
    py27 = False
import json


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
        #self.logger.error(json.loads(response))
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
        return {'Authorization': ('Basic ' + a.decode('utf-8'))}

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
        request = {
            'url': 'https://{}/api/{}'.format(self.host, endpoint),
            'params': {
                'v': self.version,
                's': session,
                'uh': self._get_hash(username),
                'ph': self._get_hash(password),
                'ah': self._get_hash(username + ":" + password)
            }
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
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def __request(self, url, values=None):
        """
        Helper for making web requests and handling response.
        @param url URL to request.
        @param values
        @return request result.
        """
        if py27:
            request = urllib2.Request(url, values, self.__get_authorization_header())
            response = urllib2.urlopen(request)
        else:
            if values:
                values = values.encode('utf-8')
            request = urllib.request.Request(url, values, self.__get_authorization_header())
            response = urllib.request.urlopen(request)
        result = response.read()
        return self.__format_response(result)

    def __request_get(self, url, values):
        """
        Wrapper for request() to send request as a GET.
        @param url URL to request.
        @param values Parameters for the request.
        @return request result.
        """
        if py27:
            return self.__request(url + "?" + urllib.urlencode(values))
        else:
            return self.__request(url + "?" + urllib.parse.urlencode(values))

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
