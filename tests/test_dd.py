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

import socket
import threading
import time
import unittest

from multiprocessing import Queue
from unittest        import mock
from unittest.mock   import MagicMock

from src.common.statics import *
from dd                 import animate, draw_frame, main, process_arguments, rx_loop, tx_loop

from tests.utils import TFCTestCase


class TestDrawFrame(TFCTestCase):

    def test_left_to_right_oriented_data_diode_frames(self):

        for argv in [SCNCLR, NCDCRL]:

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       →                                        
                                 ────╮   ╭────                                  
                                  Tx │ > │ Rx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=True)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       →                                        
                                 ────╮   ╭────                                  
                                  Tx │   │ Rx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=False)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                      Idle                                      
                                                                                
                                 ────╮   ╭────                                  
                                  Tx │   │ Rx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, IDLE, high=False)

    def test_right_to_left_oriented_data_diode_frames(self):

        for argv in [SCNCRL, NCDCLR]:

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       ←                                        
                                 ────╮   ╭────                                  
                                  Rx │ < │ Tx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=True)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       ←                                        
                                 ────╮   ╭────                                  
                                  Rx │   │ Tx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=False)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                      Idle                                      
                                                                                
                                 ────╮   ╭────                                  
                                  Rx │   │ Tx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, IDLE, high=False)


class TestAnimate(unittest.TestCase):

    @mock.patch('time.sleep', lambda _: None)
    def test_animation(self):
        for arg in [SCNCLR, SCNCRL, NCDCLR, NCDCRL]:
            self.assertIsNone(animate(arg))


class TestRxLoop(unittest.TestCase):

    @mock.patch('multiprocessing.connection.Listener', return_value=MagicMock(
        accept=MagicMock(return_value=MagicMock(
            recv=MagicMock(side_effect=[b'test_data', b'test_data', KeyboardInterrupt, EOFError])))))
    def test_rx_loop(self, _):

        queue = Queue()

        with self.assertRaises(SystemExit):
            rx_loop(queue, RP_LISTEN_SOCKET)

        self.assertEqual(queue.qsize(), 2)
        while queue.qsize() != 0:
            self.assertEqual(queue.get(), b'test_data')


class TestTxLoop(unittest.TestCase):

    @mock.patch('time.sleep',                        lambda _: None)
    @mock.patch('multiprocessing.connection.Client', return_value=MagicMock(side_effect=[socket.error, MagicMock]))
    def test_tx_loop(self, *_):
        # Setup
        queue = Queue()

        def queue_delayer():
            time.sleep(0.01)
            queue.put(b'test_packet')
        threading.Thread(target=queue_delayer).start()

        # Test
        self.assertEqual(queue.qsize(), 1)
        tx_loop(queue, DST_LISTEN_SOCKET, NCDCLR, unit_test=True)
        self.assertEqual(queue.qsize(), 0)


class TestProcessArguments(unittest.TestCase):

    def test_invalid_parameters_exit(self, *_):
        for parameter in ['', 'invalid']:
            with mock.patch("sys.argv", ['dd.py', parameter]):
                with self.assertRaises(SystemExit):
                    process_arguments()

    def test_valid_parameters(self, *_):
        for parameter in [SCNCLR, SCNCRL, NCDCLR, NCDCRL]:
            with mock.patch("sys.argv", ['dd.py', parameter]):
                param, input_socket, output_socket = process_arguments()
                self.assertEqual(param, parameter)
                self.assertIsInstance(input_socket,  int)
                self.assertIsInstance(output_socket, int)


class TestMain(unittest.TestCase):

    @mock.patch('time.sleep', lambda _: None)
    @mock.patch('sys.argv',   ['dd.py', SCNCLR])
    def test_main(self, *_):
        # Setup
        queues = {EXIT_QUEUE: Queue()}

        def queue_delayer():
            time.sleep(0.1)
            queues[EXIT_QUEUE].put(EXIT)
        threading.Thread(target=queue_delayer).start()

        # Test
        with self.assertRaises(SystemExit):
            main(queues=queues)


if __name__ == '__main__':
    unittest.main(exit=False)
