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
import subprocess

from tests.utils import cd_unit_test, cleanup


REPOSITORY = "https://raw.github.com/tfctesting/tfc/master/"


class TestDependencyHashes(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_requirements(self):
        file_name = 'requirements.txt'
        self.assertEqual(0, subprocess.Popen(f"wget --no-cache {REPOSITORY}/{file_name}",                                           shell=True).wait())
        self.assertEqual(0, subprocess.Popen(f"python3.7 -m pip download --no-deps --no-cache-dir -r {file_name} --require-hashes", shell=True).wait())

    def test_requirements_relay(self):
        file_name = 'requirements-relay.txt'
        self.assertEqual(0, subprocess.Popen(f"wget --no-cache {REPOSITORY}/{file_name}",                                           shell=True).wait())
        self.assertEqual(0, subprocess.Popen(f"python3.7 -m pip download --no-deps --no-cache-dir -r {file_name} --require-hashes", shell=True).wait())

    def test_requirements_relay_tails(self):
        file_name = 'requirements-relay-tails.txt'
        self.assertEqual(0, subprocess.Popen(f"wget --no-cache {REPOSITORY}/{file_name}",                                           shell=True).wait())
        self.assertEqual(0, subprocess.Popen(f"python3.7 -m pip download --no-deps --no-cache-dir -r {file_name} --require-hashes", shell=True).wait())

    def test_requirements_setuptools(self):
        file_name = 'requirements-setuptools.txt'
        self.assertEqual(0, subprocess.Popen(f"wget --no-cache {REPOSITORY}/{file_name}",                                           shell=True).wait())
        self.assertEqual(0, subprocess.Popen(f"python3.7 -m pip download --no-deps --no-cache-dir -r {file_name} --require-hashes", shell=True).wait())

    def test_requirements_venv(self):
        file_name = 'requirements-venv.txt'
        self.assertEqual(0, subprocess.Popen(f"wget --no-cache {REPOSITORY}/{file_name}",                                           shell=True).wait())
        self.assertEqual(0, subprocess.Popen(f"python3.7 -m pip download --no-deps --no-cache-dir -r {file_name} --require-hashes", shell=True).wait())


if __name__ == '__main__':
    unittest.main(exit=False)
