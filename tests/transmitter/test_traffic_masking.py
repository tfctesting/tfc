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

import time
import unittest

from src.common.misc import HideRunTime
from src.common.statics import (
    C_N_HEADER,
    PADDING_LENGTH,
    PLACEHOLDER_DATA,
    TM_NOISE_COMMAND_QUEUE,
    TM_NOISE_PACKET_QUEUE,
    TRAFFIC_MASKING,
)

from src.transmitter.traffic_masking import noise_loop

from tests.mock_classes import ContactList, Settings
from tests.utils import gen_queue_dict, tear_queues


class TestHideRunTime(unittest.TestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.settings = Settings()
        self.settings.tm_random_delay = 1
        self.settings.tm_static_delay = 1

    def test_traffic_masking_delay(self) -> None:
        start = time.monotonic()
        with HideRunTime(self.settings, delay_type=TRAFFIC_MASKING):
            pass
        duration = time.monotonic() - start
        self.assertTrue(duration > self.settings.tm_static_delay)

    def test_static_time(self) -> None:
        start = time.monotonic()
        with HideRunTime(self.settings, duration=1):
            pass
        duration = time.monotonic() - start
        self.assertTrue(0.9 < duration < 1.1)


class TestNoiseLoop(unittest.TestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()
        self.contact_list = ContactList(nicks=["Alice"])

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_noise_commands(self) -> None:
        self.assertIsNone(noise_loop(self.queues, unit_test=True))
        packet = self.queues[TM_NOISE_COMMAND_QUEUE].get()
        self.assertEqual(packet, C_N_HEADER + bytes(PADDING_LENGTH))

    def test_noise_packets(self) -> None:
        self.assertIsNone(noise_loop(self.queues, self.contact_list, unit_test=True))
        packet, log_messages, log_as_ph = self.queues[TM_NOISE_PACKET_QUEUE].get()
        self.assertEqual(packet, PLACEHOLDER_DATA)
        self.assertTrue(log_messages)
        self.assertTrue(log_as_ph)


if __name__ == "__main__":
    unittest.main(exit=False)
