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
import sqlite3
import typing

from typing import Iterator, Tuple

import nacl.exceptions

from src.common.crypto     import auth_and_decrypt, blake2b, encrypt_and_sign
from src.common.exceptions import CriticalError
from src.common.misc       import ensure_dir, separate_trailer
from src.common.statics    import BLAKE2_DIGEST_LENGTH, DB_WRITE_RETRY_LIMIT, DIR_USER_DATA

if typing.TYPE_CHECKING:
    from src.common.db_masterkey import MasterKey


class TFCDatabase(object):
    """
    TFC database handles encryption and decryption operations, as well
    as atomicity to ensure database writing always succeeds or fails.
    """

    def __init__(self, database_name: str, master_key: 'MasterKey') -> None:
        """Initialize TFC database."""
        self.database_name = database_name
        self.database_temp = database_name + '_temp'
        self.database_key  = master_key.master_key

    @staticmethod
    def write_to_file(file_name: str, data: bytes) -> None:
        """Write data to file."""
        with open(file_name, 'wb+') as f:
            f.write(data)

            # Write data from program buffer to operating system buffer.
            f.flush()

            # Run the fsync syscall to ensure operating system buffer is
            # synchronized with storage device, i.e. write the data on disk.
            # https://docs.python.org/3/library/os.html#os.fsync
            # http://man7.org/linux/man-pages/man2/fdatasync.2.html
            os.fsync(f.fileno())

    def verify_file(self, database_name: str) -> bool:
        """Verify integrity of file content."""
        with open(database_name, 'rb') as f:
            purp_data = f.read()

        try:
            _ = auth_and_decrypt(purp_data, self.database_key)
            return True
        except nacl.exceptions.CryptoError:
            return False

    def ensure_temp_write(self, ct_bytes: bytes) -> None:
        """Ensure data is written to a temp file."""
        self.write_to_file(self.database_temp, ct_bytes)

        retries = 0
        while not self.verify_file(self.database_temp):
            retries += 1
            if retries >= DB_WRITE_RETRY_LIMIT:
                raise CriticalError(f"Writing to database '{self.database_temp}' failed after {retries} retries.")

            self.write_to_file(self.database_temp, ct_bytes)

    def store_database(self, pt_bytes: bytes) -> None:
        """Encrypt and store data into database."""
        ct_bytes = encrypt_and_sign(pt_bytes, self.database_key)
        ensure_dir(DIR_USER_DATA)
        self.ensure_temp_write(ct_bytes)

        # Replace original file with temp file. (`os.replace` is atomic as per POSIX
        # requirements): https://docs.python.org/3/library/os.html#os.replace
        os.replace(self.database_temp, self.database_name)

    def load_database(self) -> bytes:
        """Load data from database.

        This function first checks if a temporary file exists from
        previous session. The integrity of the temporary file is
        verified with the Poly1305 MAC before the database is
        replaced.

        The function then reads the up-to-date database content
        and decrypts it.
        """
        if os.path.isfile(self.database_temp):
            if self.verify_file(self.database_temp):
                os.replace(self.database_temp, self.database_name)
            else:
                # If temp file is not authentic, the file is most likely corrupt, so
                # we delete it and continue using the old file to ensure atomicity.
                os.remove(self.database_temp)

        with open(self.database_name, 'rb') as f:
            database_data = f.read()

        return auth_and_decrypt(database_data, self.database_key, database=self.database_name)


class TFCUnencryptedDatabase(object):
    """
    The unencrypted database is used for storing login data.
    """

    def __init__(self, database_name: str) -> None:
        """Initialize unencrypted TFC database."""
        self.database_name = database_name
        self.database_temp = database_name + '_temp'

    @staticmethod
    def write_to_file(file_name: str, data: bytes) -> None:
        """Write data to file."""
        with open(file_name, 'wb+') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    @staticmethod
    def verify_file(database_name: str) -> bool:
        """Verify integrity of file content."""
        with open(database_name, 'rb') as f:
            purp_data = f.read()

        purp_data, digest = separate_trailer(purp_data, BLAKE2_DIGEST_LENGTH)

        return blake2b(purp_data) == digest

    def ensure_temp_write(self, data: bytes) -> None:
        """Ensure data is written to a temp file."""
        self.write_to_file(self.database_temp, data)

        retries = 0
        while not self.verify_file(self.database_temp):
            retries += 1
            if retries >= DB_WRITE_RETRY_LIMIT:
                raise CriticalError(f"Writing to database '{self.database_temp}' failed after {retries} retries.")

            self.write_to_file(self.database_temp, data)

    def store_unencrypted_database(self, data: bytes) -> None:
        """Store unencrypted data into database.

        For future integrity check, concatenate the BLAKE2b
        digest of the database content to the database file.
        """
        ensure_dir(DIR_USER_DATA)

        self.ensure_temp_write(data + blake2b(data))

        # Replace original file with temp file. (`os.replace` is atomic as per POSIX
        # requirements): https://docs.python.org/3/library/os.html#os.replace
        os.replace(self.database_temp, self.database_name)

    def load_database(self) -> bytes:
        """Load data from database.

        This function first checks if a temporary file exists from
        previous session. The integrity of the temporary file is
        verified with a BLAKE2b-based checksum before the database is
        replaced.

        The function then reads the up-to-date database content.
        """
        if os.path.isfile(self.database_temp):
            if self.verify_file(self.database_temp):
                os.replace(self.database_temp, self.database_name)
            else:
                # If temp file failed integrity check, the file is most likely corrupt,
                # so we delete it and continue using the old file to ensure atomicity.
                os.remove(self.database_temp)

        with open(self.database_name, 'rb') as f:
            database_data = f.read()

        database_data, digest = separate_trailer(database_data, BLAKE2_DIGEST_LENGTH)

        if blake2b(database_data) != digest:
            raise CriticalError(f"Invalid data in login database {self.database_name}")

        return database_data


class TFCLogDatabase(object):

    def __init__(self, file_name: str) -> None:
        """Create a new TFCLogDatabase object."""
        ensure_dir(DIR_USER_DATA)
        self.file_name = file_name
        self.conn      = sqlite3.connect(self.file_name)
        self.c         = self.conn.cursor()
        self.create_table()

    def __iter__(self) -> Iterator[Tuple[int, bytes]]:
        """Iterate over encrypted log entries."""
        yield from self.c.execute("SELECT * FROM log_entries")

    def create_table(self) -> None:
        """Create new log database."""
        self.c.execute("""CREATE TABLE IF NOT EXISTS log_entries (id INTEGER PRIMARY KEY, log_entry BLOB NOT NULL)""")

    def insert_encrypted_log_entry(self, encrypted_log_entry: bytes) -> None:
        """Insert previously encrypted log entry into the sqlite3 database."""
        params = (encrypted_log_entry,)
        try:
            self.c.execute(f"""INSERT INTO log_entries (log_entry) VALUES (?)""", params)
        except sqlite3.Error:
            # Re-connect to database
            self.conn = sqlite3.connect(self.file_name)
            self.c = self.conn.cursor()
            self.insert_encrypted_log_entry(encrypted_log_entry)
        self.conn.commit()

    def close_database(self) -> None:
        self.c.close()
