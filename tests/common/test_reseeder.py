#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import unittest

from unittest import mock

from src.common.reseeder import force_reseed

class TestForceReseed(unittest.TestCase):

    @mock.patch('fcntl.ioctl', return_value=1)
    def test_exit_code_is_one_if_ioctl_returns_non_zero_value(self, mock_ioctl):
        with self.assertRaises(SystemExit):
            force_reseed()
        mock_ioctl.assert_called()

    @mock.patch('fcntl.ioctl', return_value=0)
    def test_exit_code_is_zero_if_ioctl_returns_zero(self, mock_ioctl):
        self.assertIsNone(force_reseed())
        mock_ioctl.assert_called()


if __name__ == '__main__':
    unittest.main(exit=False)
