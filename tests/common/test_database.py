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

import os
import unittest

from unittest      import mock
from unittest.mock import MagicMock

from src.common.crypto   import auth_and_decrypt, blake2b, encrypt_and_sign
from src.common.database import TFCDatabase, TFCUnencryptedDatabase
from src.common.statics  import DB_WRITE_RETRY_LIMIT, MASTERKEY_DB_SIZE

from tests.mock_classes import MasterKey
from tests.utils        import cd_unit_test, cleanup, tamper_file


class TestTFCDatabase(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.database_name = 'unittest_db'
        self.master_key    = MasterKey()
        self.database      = TFCDatabase(self.database_name, self.master_key)

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    @mock.patch('os.fsync', return_value=MagicMock)
    def test_write_to_file(self, mock_os_fsync):
        # Setup
        data = os.urandom(MASTERKEY_DB_SIZE)

        # Test
        self.assertIsNone(self.database.write_to_file(self.database_name, data))

        with open(self.database_name, 'rb') as f:
            stored_data = f.read()
        self.assertEqual(data, stored_data)

        mock_os_fsync.assert_called()

    def test_verify_file(self):
        # Setup
        pt_bytes = os.urandom(MASTERKEY_DB_SIZE)
        ct_bytes = encrypt_and_sign(pt_bytes, self.master_key.master_key)
        with open(self.database_name, 'wb') as f:
            f.write(ct_bytes)

        # Test valid file content returns True.
        self.assertTrue(self.database.verify_file(self.database_name))

        # Test invalid file content returns False.
        tamper_file(self.database_name, tamper_size=1)
        self.assertFalse(self.database.verify_file(self.database_name))

    def test_ensure_temp_write_raises_critical_error_after_exceeding_retry_limit(self):
        # Setup
        orig_verify_file          = self.database.verify_file
        self.database.verify_file = MagicMock(side_effect=DB_WRITE_RETRY_LIMIT*[False])

        # Test
        with self.assertRaises(SystemExit):
            self.database.store_database(os.urandom(MASTERKEY_DB_SIZE))

        # Teardown
        self.database.verify_file = orig_verify_file

    def test_ensure_temp_write_succeeds_just_before_limit(self):
        # Setup
        orig_verify_file          = self.database.verify_file
        self.database.verify_file = MagicMock(side_effect=(DB_WRITE_RETRY_LIMIT-1)*[False] + [True])

        # Test
        self.assertIsNone(self.database.store_database(os.urandom(MASTERKEY_DB_SIZE)))

        # Teardown
        self.database.verify_file = orig_verify_file

    def test_store_database_encrypts_data_with_master_key_and_replaces_temp_file_and_original_file(self):
        # Setup
        pt_old = os.urandom(MASTERKEY_DB_SIZE)
        ct_old = encrypt_and_sign(pt_old, self.master_key.master_key)
        with open(self.database_name, 'wb') as f:
            f.write(ct_old)

        pt_new = os.urandom(MASTERKEY_DB_SIZE)

        ct_temp = os.urandom(MASTERKEY_DB_SIZE)
        with open(self.database.database_temp, 'wb') as f:
            f.write(ct_temp)

        # Test
        self.assertTrue(os.path.isfile(self.database.database_temp))
        self.assertIsNone(self.database.store_database(pt_new))
        self.assertFalse(os.path.isfile(self.database.database_temp))

        with open(self.database_name, 'rb') as f:
            purp_data = f.read()
        purp_pt = auth_and_decrypt(purp_data, self.master_key.master_key)
        self.assertEqual(purp_pt, pt_new)

    def test_load_database_ignores_invalid_temp_database(self):
        # Setup
        pt_old = os.urandom(MASTERKEY_DB_SIZE)
        ct_old = encrypt_and_sign(pt_old, self.master_key.master_key)
        with open(self.database_name, 'wb') as f:
            f.write(ct_old)

        ct_temp = os.urandom(MASTERKEY_DB_SIZE)
        with open(self.database.database_temp, 'wb') as f:
            f.write(ct_temp)

        # Test
        self.assertTrue(os.path.isfile(self.database.database_temp))
        self.assertEqual(self.database.load_database(), pt_old)
        self.assertFalse(os.path.isfile(self.database.database_temp))

    def test_load_database_prefers_valid_temp_database(self):
        # Setup
        pt_old = os.urandom(MASTERKEY_DB_SIZE)
        ct_old = encrypt_and_sign(pt_old, self.master_key.master_key)
        with open(self.database_name, 'wb') as f:
            f.write(ct_old)

        pt_temp = os.urandom(MASTERKEY_DB_SIZE)
        ct_temp = encrypt_and_sign(pt_temp, self.master_key.master_key)
        with open(self.database.database_temp, 'wb') as f:
            f.write(ct_temp)

        # Test
        self.assertTrue(os.path.isfile(self.database.database_temp))
        self.assertEqual(self.database.load_database(), pt_temp)
        self.assertFalse(os.path.isfile(self.database.database_temp))


class TestTFCUnencryptedDatabase(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.database_name = 'unittest_db'
        self.database      = TFCUnencryptedDatabase(self.database_name)

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    @mock.patch('os.fsync', return_value=MagicMock)
    def test_write_to_file(self, mock_os_fsync):
        # Setup
        data = os.urandom(MASTERKEY_DB_SIZE)

        # Test
        self.assertIsNone(self.database.write_to_file(self.database_name, data))

        with open(self.database_name, 'rb') as f:
            stored_data = f.read()
        self.assertEqual(data, stored_data)

        mock_os_fsync.assert_called()

    def test_verify_file(self):
        # Setup
        data             = os.urandom(MASTERKEY_DB_SIZE)
        checksummed_data = data + blake2b(data)
        with open(self.database_name, 'wb') as f:
            f.write(checksummed_data)

        # Test valid file content returns True.
        self.assertTrue(self.database.verify_file(self.database_name))

        # Test invalid file content returns False.
        tamper_file(self.database_name, tamper_size=1)
        self.assertFalse(self.database.verify_file(self.database_name))

    def test_ensure_temp_write_raises_critical_error_after_exceeding_retry_limit(self):
        # Setup
        orig_verify_file          = self.database.verify_file
        self.database.verify_file = MagicMock(side_effect=DB_WRITE_RETRY_LIMIT*[False])

        # Test
        with self.assertRaises(SystemExit):
            self.database.store_unencrypted_database(os.urandom(MASTERKEY_DB_SIZE))

        # Teardown
        self.database.verify_file = orig_verify_file

    def test_ensure_temp_write_succeeds_just_before_limit(self):
        # Setup
        orig_verify_file          = self.database.verify_file
        self.database.verify_file = MagicMock(side_effect=(DB_WRITE_RETRY_LIMIT-1)*[False] + [True])

        # Test
        self.assertIsNone(self.database.store_unencrypted_database(os.urandom(MASTERKEY_DB_SIZE)))

        # Teardown
        self.database.verify_file = orig_verify_file

    def test_store_unencrypted_database_replaces_temp_file_and_original_file(self):
        # Setup
        data_old = os.urandom(MASTERKEY_DB_SIZE)
        with open(self.database_name, 'wb') as f:
            f.write(data_old)

        data_new = os.urandom(MASTERKEY_DB_SIZE)

        data_temp = os.urandom(MASTERKEY_DB_SIZE)
        with open(self.database.database_temp, 'wb') as f:
            f.write(data_temp)

        # Test
        self.assertTrue(os.path.isfile(self.database.database_temp))
        self.assertIsNone(self.database.store_unencrypted_database(data_new))
        self.assertFalse(os.path.isfile(self.database.database_temp))

        with open(self.database_name, 'rb') as f:
            purp_data = f.read()

        self.assertEqual(purp_data, data_new + blake2b(data_new))

    def test_load_database_ignores_invalid_temp_database(self):
        # Setup
        data_old    = os.urandom(MASTERKEY_DB_SIZE)
        checksummed = data_old + blake2b(data_old)
        with open(self.database_name, 'wb') as f:
            f.write(checksummed)

        data_temp = os.urandom(MASTERKEY_DB_SIZE)
        with open(self.database.database_temp, 'wb') as f:
            f.write(data_temp)

        # Test
        self.assertTrue(os.path.isfile(self.database.database_temp))
        self.assertEqual(self.database.load_database(), data_old)
        self.assertFalse(os.path.isfile(self.database.database_temp))

    def test_load_database_prefers_valid_temp_database(self):
        # Setup
        data_old        = os.urandom(MASTERKEY_DB_SIZE)
        checksummed_old = data_old + blake2b(data_old)
        with open(self.database_name, 'wb') as f:
            f.write(checksummed_old)

        data_temp        = os.urandom(MASTERKEY_DB_SIZE)
        checksummed_temp = data_temp + blake2b(data_temp)
        with open(self.database.database_temp, 'wb') as f:
            f.write(checksummed_temp)

        # Test
        self.assertTrue(os.path.isfile(self.database.database_temp))
        data_purp = self.database.load_database()
        self.assertEqual(data_purp, data_temp)
        self.assertFalse(os.path.isfile(self.database.database_temp))
