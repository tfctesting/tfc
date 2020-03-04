#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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
import os
import subprocess

from tests.utils import cd_unit_test, cleanup


REPOSITORY  = "https://raw.github.com/tfctesting/tfc/master/"
INSTALL_DIR = f'{os.getenv("HOME")}/tfc_installation_test'


class TestDependencyHashes(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    @unittest.skipIf("TRAVIS" not in os.environ and os.environ["TRAVIS"] != "true",
                     "Skipping this test on local system.")
    def test_tcb_installation(self):
        self.assertEqual(0, subprocess.Popen(f"bash install.sh tcb travis", shell=True).wait())

    @unittest.skipIf("TRAVIS" not in os.environ and os.environ["TRAVIS"] != "true",
                     "Skipping this test on local system.")
    def test_relay_installation(self):
        self.assertEqual(0, subprocess.Popen(f"bash install.sh relay travis", shell=True).wait())

    @unittest.skipIf("TRAVIS" not in os.environ and os.environ["TRAVIS"] != "true",
                     "Skipping this test on local system.")
    def test_local_installation(self):
        self.assertEqual(0, subprocess.Popen(f"bash install.sh local travis", shell=True).wait())

    @unittest.skipIf("TRAVIS" not in os.environ and os.environ["TRAVIS"] != "true",
                     "Skipping this test on local system.")
    def test_dev_installation(self):
        self.assertEqual(0, subprocess.Popen(f"bash install.sh dev travis", shell=True).wait())


if __name__ == '__main__':
    unittest.main(exit=False)
