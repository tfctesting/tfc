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
import struct
import unittest

from datetime        import datetime
from multiprocessing import Queue
from unittest        import mock
from unittest.mock   import MagicMock

from src.common.db_logs  import write_log_entry
from src.common.encoding import int_to_bytes
from src.common.statics  import *

from src.receiver.packet   import PacketList
from src.receiver.commands import ch_contact_s, ch_master_key, ch_nick, ch_setting, contact_rem, exit_tfc, log_command
from src.receiver.commands import process_command, remove_log, reset_screen, win_activity, win_select, wipe

from tests.mock_classes import ContactList, Gateway, group_name_to_group_id, GroupList, KeyList, MasterKey
from tests.mock_classes import nick_to_pub_key, RxWindow, Settings, WindowList
from tests.utils        import assembly_packet_creator, cd_unittest, cleanup, ignored, nick_to_short_address, tear_queue
from tests.utils        import TFCTestCase


class TestProcessCommand(TFCTestCase):

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.ts           = datetime.now()
        self.settings     = Settings()
        self.master_key   = MasterKey()
        self.group_list   = GroupList()
        self.exit_queue   = Queue()
        self.gateway      = Gateway()
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.contact_list = ContactList(nicks=[LOCAL_ID])
        self.packet_list  = PacketList(self.settings, self.contact_list)
        self.key_list     = KeyList(nicks=[LOCAL_ID])
        self.key_set      = self.key_list.get_keyset(LOCAL_PUBKEY)

        self.args = (self.window_list, self.packet_list, self.contact_list, self.key_list, self.group_list,
                     self.settings, self.master_key, self.gateway, self.exit_queue)

    def tearDown(self):
        cleanup(self.unittest_dir)

    def test_incomplete_command_raises_fr(self):
        packet = assembly_packet_creator(COMMAND, b'test_command', s_header_override=C_L_HEADER, encrypt_packet=True)[0]
        self.assert_fr("Incomplete command.", process_command, self.ts, packet, *self.args)

    def test_invalid_command_header(self):
        packet = assembly_packet_creator(COMMAND, b'invalid_header', encrypt_packet=True)[0]
        self.assert_fr("Error: Received an invalid command.", process_command, self.ts, packet, *self.args)

    def test_process_command(self):
        packet = assembly_packet_creator(COMMAND, LOG_REMOVE, encrypt_packet=True)[0]
        self.assert_fr(f"No log database available.", process_command, self.ts, packet, *self.args)


class TestWinActivity(TFCTestCase):

    def setUp(self):
        self.window_list         = WindowList()
        self.window_list.windows = [RxWindow(name='Alice', unread_messages=4),
                                    RxWindow(name='Bob',   unread_messages=15)]

    @mock.patch('time.sleep', return_value=None)
    def test_function(self, _):
        self.assert_prints(f"""\
                              ┌─────────────────┐                               
                              │ Window activity │                               
                              │    Alice: 4     │                               
                              │     Bob: 15     │                               
                              └─────────────────┘                               
{5*(CURSOR_UP_ONE_LINE+CLEAR_ENTIRE_LINE)}""", win_activity, self.window_list)


class TestWinSelect(unittest.TestCase):

    def setUp(self):
        self.window_list         = WindowList()
        self.window_list.windows = [RxWindow(uid=nick_to_pub_key("Alice"), name='Alice'),
                                    RxWindow(uid=nick_to_pub_key("Bob"), name='Bob')]

    def test_window_selection(self):
        self.assertIsNone(win_select(nick_to_pub_key("Alice"), self.window_list))
        self.assertEqual(self.window_list.active_win.name, 'Alice')

        self.assertIsNone(win_select(nick_to_pub_key("Bob"), self.window_list))
        self.assertEqual(self.window_list.active_win.name, 'Bob')

        self.assertIsNone(win_select(WIN_UID_FILE, self.window_list))
        self.assertEqual(self.window_list.active_win.uid, WIN_UID_FILE)


class TestResetScreen(unittest.TestCase):

    def setUp(self):
        self.cmd_data            = nick_to_pub_key("Alice")
        self.window_list         = WindowList()
        self.window_list.windows = [RxWindow(uid=nick_to_pub_key("Alice"), name='Alice'),
                                    RxWindow(uid=nick_to_pub_key("Bob"), name='Bob')]
        self.window              = self.window_list.get_window(nick_to_pub_key("Alice"))
        self.window.message_log  = [(datetime.now(), 'Hi Bob', nick_to_pub_key("Alice"), ORIGIN_CONTACT_HEADER)]

    @mock.patch('os.system', return_value=None, create_autospec=True)
    def test_screen_reset(self, reset):
        # Ensure there is a message to be removed from the ephemeral message log
        self.assertEqual(len(self.window.message_log), 1)

        reset_screen(self.cmd_data, self.window_list)

        # Test that screen is reset by the command
        reset.assert_called_with(RESET)

        # Test that the ephemeral message log is empty after the command
        self.assertEqual(len(self.window.message_log), 0)


class TestExitTFC(unittest.TestCase):

    def setUp(self):
        self.exit_queue = Queue()

    def tearDown(self):
        tear_queue(self.exit_queue)

    def test_function(self):
        self.assertIsNone(exit_tfc(self.exit_queue))
        self.assertEqual(self.exit_queue.qsize(), 1)


class TestLogCommand(TFCTestCase):

    @mock.patch("getpass.getpass", return_value='test_password')
    def setUp(self, _):
        from src.common.db_masterkey import MasterKey
        self.unittest_dir      = cd_unittest()
        self.cmd_data          = int_to_bytes(1) + nick_to_pub_key("Bob")
        self.ts                = datetime.now()
        self.window_list       = WindowList(nicks=['Alice', 'Bob'])
        self.window            = self.window_list.get_window(nick_to_pub_key("Bob"))
        self.window.type_print = 'contact'
        self.window.name       = 'Bob'
        self.window.type       = WIN_TYPE_CONTACT
        self.contact_list      = ContactList(nicks=['Alice', 'Bob'])
        self.group_list        = GroupList()
        self.settings          = Settings()
        self.master_key        = MasterKey(operation=NC, local_test=True)
        self.args              = (self.ts, self.window_list, self.contact_list,
                                  self.group_list, self.settings, self.master_key)

        time_float = struct.unpack('<L', bytes.fromhex('08ceae02'))[0]
        self.time  = datetime.fromtimestamp(time_float).strftime("%H:%M:%S.%f")[:-4]

    def tearDown(self):
        cleanup(self.unittest_dir)
        with ignored(OSError):
            os.remove('Unittest - Plaintext log (None)')

    def test_print(self):
        self.assert_fr(f"No log database available.", log_command, self.cmd_data, *self.args)

    @mock.patch("getpass.getpass", side_effect=['invalid_password','test_password'])
    @mock.patch('struct.pack',     return_value=bytes.fromhex('08ceae02'))
    def test_export(self, *_):
        # Setup
        for p in assembly_packet_creator(MESSAGE, 'A short message'):
            write_log_entry(p, nick_to_pub_key("Bob"), self.settings, self.master_key, origin=ORIGIN_CONTACT_HEADER)

        # Test
        self.assertIsNone(log_command(self.cmd_data, *self.args))

        with open('Transmitter - Plaintext log (Bob)') as f:
            data = f.read()

        self.assertEqual(data, f"""\
Log file of 1 most recent message(s) sent to contact Bob
════════════════════════════════════════════════════════════════════════════════
{self.time} Bob: A short message
<End of log file>

""")


class TestRemoveLog(TFCTestCase):

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.win_name     = nick_to_pub_key("Alice")
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.master_key   = MasterKey()

    def tearDown(self):
        cleanup(self.unittest_dir)

    def test_remove_log_file(self):
        self.assert_fr(f"No log database available.",
                       remove_log, self.win_name, self.contact_list, self.group_list, self.settings, self.master_key)


class TestChMasterKey(TFCTestCase):

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.ts           = datetime.now()
        self.master_key   = MasterKey()
        self.settings     = Settings()
        self.contact_list = ContactList(nicks=[LOCAL_ID])
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.group_list   = GroupList()
        self.key_list     = KeyList()
        self.args         = (self.ts, self.window_list, self.contact_list, self.group_list, 
                             self.key_list, self.settings, self.master_key)

    def tearDown(self):
        cleanup(self.unittest_dir)

    @mock.patch('getpass.getpass', return_value='a')
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('os.popen',        return_value=MagicMock(read=MagicMock(return_value='foo\nMemFree 200')))
    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 0.01)
    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 1.01)
    def test_master_key_change(self, *_):
        # Setup
        write_log_entry(F_S_HEADER + bytes(PADDING_LENGTH), nick_to_pub_key("Alice"), self.settings, self.master_key)

        # Test
        self.assertEqual(self.master_key.master_key, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertIsNone(ch_master_key(*self.args))
        self.assertNotEqual(self.master_key.master_key, bytes(SYMMETRIC_KEY_LENGTH))

    @mock.patch('getpass.getpass', return_value='a')
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('os.getrandom',    side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_raises_fr(self, *_):
        self.assert_fr("Password change aborted.", ch_master_key, *self.args)


class TestChNick(TFCTestCase):

    def setUp(self):
        self.ts           = datetime.now()
        self.contact_list = ContactList(nicks=['Alice'])
        self.window_list  = WindowList(contact_list=self.contact_list)
        self.group_list   = GroupList()
        self.args         = self.ts, self.window_list, self.contact_list
        self.window       = self.window_list.get_window(nick_to_pub_key("Alice"))
        self.window.type  = WIN_TYPE_CONTACT

    def test_unknown_account_raises_fr(self):
        # Setup
        cmd_data = nick_to_pub_key("Bob") + b'Bob_'

        # Test
        trunc_addr = nick_to_short_address('Bob')
        self.assert_fr(f"Error: Receiver has no contact '{trunc_addr}' to rename.", ch_nick, cmd_data, *self.args)

    def test_nick_change(self):
        # Setup
        cmd_data = nick_to_pub_key("Alice") + b'Alice_'

        # Test
        self.assertIsNone(ch_nick(cmd_data, *self.args))
        self.assertEqual(self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice")).nick, 'Alice_')
        self.assertEqual(self.window.name, 'Alice_')


class TestChSetting(TFCTestCase):

    def setUp(self):
        self.ts           = datetime.now()
        self.window_list  = WindowList()
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.key_list     = KeyList()
        self.settings     = Settings()
        self.gateway      = Gateway()
        self.args         = (self.ts, self.window_list, self.contact_list, self.group_list,
                             self.key_list, self.settings, self.gateway)

    def test_invalid_data_raises_fr(self):
        # Setup
        self.settings.key_list = ['']

        # Test
        cmd_data = b'setting' + b'True'
        self.assert_fr("Error: Received invalid setting data.", ch_setting, cmd_data, *self.args)

    def test_invalid_setting_raises_fr(self):
        # Setup
        self.settings.key_list = ['']

        # Test
        cmd_data = b'setting' + US_BYTE + b'True'
        self.assert_fr("Error: Invalid setting 'setting'.", ch_setting, cmd_data, *self.args)

    def test_databases(self):
        # Setup
        self.settings.key_list = ['max_number_of_group_members', 'max_number_of_contacts']

        # Test
        cmd_data = b'max_number_of_group_members' + US_BYTE + b'30'
        self.assertIsNone(ch_setting(cmd_data, *self.args))

        cmd_data = b'max_number_of_contacts' + US_BYTE + b'30'
        self.assertIsNone(ch_setting(cmd_data, *self.args))

    def test_change_gateway_setting(self):
        # Setup
        self.settings.key_list = ['max_number_of_group_members', 'max_number_of_contacts']

        # Test
        cmd_data = b'serial_baudrate' + US_BYTE + b'115200'
        self.assertIsNone(ch_setting(cmd_data, *self.args))


class TestChContactSetting(TFCTestCase):

    def setUp(self):
        self.ts           = datetime.fromtimestamp(1502750000)
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['test_group', 'test_group2'])
        self.window_list  = WindowList(contact_list=self.contact_list,
                                       group_list=self.group_list)
        self.args         = self.ts, self.window_list, self.contact_list, self.group_list

    def test_invalid_window_raises_fr(self):
        # Setup
        cmd_data          = ENABLE + nick_to_pub_key("Bob")
        header            = CH_LOGGING
        self.contact_list = ContactList(nicks=['Alice'])
        self.window_list  = WindowList(contact_list=self.contact_list,
                                       group_list=self.group_list)
        # Test
        self.assert_fr(f"Error: Found no window for '{nick_to_short_address('Bob')}'.",
                       ch_contact_s, cmd_data, *self.args, header)

    def test_setting_change_contact(self):
        # Setup
        self.window                 = self.window_list.get_window(nick_to_pub_key("Bob"))
        self.window.type            = WIN_TYPE_CONTACT
        self.window.type_print      = 'contact'
        self.window.window_contacts = self.contact_list.contacts
        bob                         = self.contact_list.get_contact_by_address_or_nick("Bob")

        # Test
        for attr, header in [('log_messages', CH_LOGGING),
                             ('notifications', CH_NOTIFY),
                             ('file_reception', CH_FILE_RECV)]:
            for s in [ENABLE, ENABLE, DISABLE, DISABLE]:
                cmd_data = s + nick_to_pub_key("Bob")
                self.assertIsNone(ch_contact_s(cmd_data, *self.args, header))
                self.assertEqual(bob.__getattribute__(attr), (s == ENABLE))

    def test_setting_change_group(self):
        # Setup
        self.window                 = self.window_list.get_window(group_name_to_group_id('test_group'))
        self.window.type            = WIN_TYPE_GROUP
        self.window.type_print      = 'group'
        self.window.window_contacts = self.group_list.get_group('test_group').members

        # Test
        for attr, header in [('log_messages', CH_LOGGING),
                             ('notifications', CH_NOTIFY),
                             ('file_reception', CH_FILE_RECV)]:
            for s in [ENABLE, ENABLE, DISABLE, DISABLE]:
                cmd_data = s + group_name_to_group_id('test_group')
                self.assertIsNone(ch_contact_s(cmd_data, *self.args, header))

                if header in [CH_LOGGING, CH_NOTIFY]:
                    self.assertEqual(self.group_list.get_group('test_group').__getattribute__(attr), (s == ENABLE))

                if header == CH_FILE_RECV:
                    for m in self.group_list.get_group('test_group').members:
                        self.assertEqual(m.file_reception, (s == ENABLE))

    def test_setting_change_all(self):
        # Setup
        self.window                 = self.window_list.get_window(nick_to_pub_key("Bob"))
        self.window.type            = WIN_TYPE_CONTACT
        self.window.type_print      = 'contact'
        self.window.window_contacts = self.contact_list.contacts

        # Test
        for attr, header in [('log_messages', CH_LOGGING),
                             ('notifications', CH_NOTIFY),
                             ('file_reception', CH_FILE_RECV)]:
            for s in [ENABLE, ENABLE, DISABLE, DISABLE]:
                cmd_data = s.upper() + US_BYTE
                self.assertIsNone(ch_contact_s(cmd_data, *self.args, header))

                if header in [CH_LOGGING, CH_NOTIFY]:
                    for c in self.contact_list.get_list_of_contacts():
                        self.assertEqual(c.__getattribute__(attr), (s == ENABLE))
                    for g in self.group_list.groups:
                        self.assertEqual(g.__getattribute__(attr), (s == ENABLE))

                if header == CH_FILE_RECV:
                    for c in self.contact_list.get_list_of_contacts():
                        self.assertEqual(c.__getattribute__(attr), (s == ENABLE))


class TestContactRemove(TFCTestCase):

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.ts           = datetime.now()
        self.window_list  = WindowList()
        self.cmd_data     = nick_to_pub_key("Bob")
        self.settings     = Settings()
        self.master_key   = MasterKey()
        self.args         = self.cmd_data, self.ts, self.window_list

    def tearDown(self):
        cleanup(self.unittest_dir)

    def test_no_contact_raises_fr(self):
        # Setup
        contact_list = ContactList(nicks=['Alice'])
        group_list   = GroupList(groups=[])
        key_list     = KeyList(nicks=['Alice'])

        # Test
        self.assert_fr(f"Receiver has no account '{nick_to_short_address('Bob')}' to remove.",
                       contact_rem, *self.args, contact_list, group_list, key_list, self.settings, self.master_key)

    def test_successful_removal(self):
        # Setup
        contact_list             = ContactList(nicks=['Alice', 'Bob'])
        contact                  = contact_list.get_contact_by_address_or_nick("Bob")
        group_list               = GroupList(groups=['test_group', 'test_group2'])
        key_list                 = KeyList(nicks=['Alice', 'Bob'])
        self.window_list.windows = [RxWindow(type=WIN_TYPE_GROUP)]

        # Test
        self.assert_fr("No log database available.",
                       contact_rem, *self.args, contact_list, group_list, key_list, self.settings, self.master_key)
        self.assertFalse(contact_list.has_pub_key(nick_to_pub_key("Bob")))
        self.assertFalse(key_list.has_keyset(nick_to_pub_key("Bob")))
        for g in group_list:
            self.assertFalse(contact in g.members)


class TestWipe(unittest.TestCase):

    @mock.patch('os.system', return_value=None)
    def test_wipe_command(self, _):
        exit_queue = Queue()
        self.assertIsNone(wipe(exit_queue))
        self.assertEqual(exit_queue.get(), WIPE)


if __name__ == '__main__':
    unittest.main(exit=False)
