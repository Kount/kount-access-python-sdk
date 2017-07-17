#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount python sdk project
# https://github.com/Kount/kount-access-python-sdk/)
# Copyright (C) 2017 Kount Inc. All Rights Reserved.
"settings"
from __future__ import (
    absolute_import, unicode_literals, division, print_function)

__author__ = "Kount SDK"
__version__ = "2.1.1"
__maintainer__ = "Kount SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

merchantId = 123456
apiKey = 'YOUR-API-KEY-GOES-HERE'
serverName = 'api-sandbox01.kountaccess.com'
version = '0210'
pswd = 'fake_pass'
u_email = 'fake@email.com'


#~ uncomment this if you'd like to get the API_KEY from the environment
#~ import os
#~ try:
    #~ SALT = os.environ['K_ACCESS']
#~ except KeyError:
    #~ print("The default fake API_KEY set. Required actual one from Kount")

try:
    from .local_settings import *
except ImportError as ie:
    print("The default fake apikey set. Required actual one from Kount. ", ie)
