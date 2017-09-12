# -*- coding: utf-8 -*-
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Kount access python sdk project
# https://github.com/Kount/kount-access-python-sdk/)
# Copyright (C) 2017 Kount Inc. All Rights Reserved.
"test AccessSDK._prepare_params"

from __future__ import absolute_import, unicode_literals, division, print_function
__author__ = "Kount Access SDK"
__version__ = "2.1.1"
__maintainer__ = "Kount Access SDK"
__email__ = "sdkadmin@kount.com"
__status__ = "Development"

import unittest
import itertools
from kount_access.access_sdk import AccessSDK


class TestAccessPrepareParams(unittest.TestCase):
    "test AccessSDK._prepare_params"
    def test_prepare_params(self):
        """test _prepare_params;
        username or password could be null or empty string
        tested (username, password) in:
        [('', ''), ('', test), ('', None), (None, test), (None, None),
            (None, ''), (test, ''), (test, None), (test, test)]"""
        test = 'test'
        version = '0210'
        session_id = '8f18a81cfb6e3179ece7138ac81019aa'
        access = AccessSDK('serverName', 123456, 'API-KEY', version)
        th = access._get_hash(test)
        lst = ['', None, test]
        unique = list(set([x for x in itertools.product(lst, repeat=2)]))
        expected_list = [{'s': session_id, 'v': version},
                         #~ {'v': version, 'ph': (th,),
                         {'v': version, 'ph': th,
                          's': session_id, 'uh': th,
                          'ah': access._get_hash("%s:%s"%(test, test)),}]
        for arg in unique:
            fake_arg = [session_id] + list(arg)
            self.assertIn(access._prepare_params(*fake_arg), expected_list)
        #~ numbers, dict, list, etc. accepted too in .get_data_using_velocity_params
        for fake_arg in [[session_id, {}, 666], [session_id, 'a' * 10000, []],
                         [session_id, {}, []], [session_id, set(), ()]]:
            self.assertEqual(access._prepare_params(*fake_arg), expected_list[0])
        for fake_arg in [[session_id, 2**10, 666], [session_id, {'test': test}, 666],
                         [session_id, 'a' * 10000, 666], [session_id, test, -42],
                         [session_id, set([1, 2]), (1, 2)]]:
            try:
                #~ python 27
                self.assertItemsEqual(access._prepare_params(*fake_arg), expected_list[1])
            except AttributeError:
                #~ python 36
                self.assertEqual(access._prepare_params(*fake_arg).keys(), expected_list[1].keys())


if __name__ == "__main__":
    unittest.main(verbosity=2,)
