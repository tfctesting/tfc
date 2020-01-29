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

import difflib
import os
import sys
import time
import typing

from multiprocessing import Queue
from typing          import Any, Dict, List, Optional

import tkinter

from src.common.encoding import b58encode
from src.common.misc     import validate_onion_addr, split_string, ignored
from src.common.output   import m_print
from src.common.statics  import (ACCOUNT_CHECK_QUEUE, ACCOUNT_RATIO_LIMIT, ACCOUNT_SEND_QUEUE, B58_PUBLIC_KEY_GUIDE,
                                 ENCODED_B58_PUB_KEY_LENGTH, PUB_KEY_CHECK_QUEUE, PUB_KEY_SEND_QUEUE,
                                 USER_ACCOUNT_QUEUE)

if typing.TYPE_CHECKING:
    AccountQueue = Queue[Optional[str]]
    QueueDict    = Dict[bytes, Queue[Any]]

# Accounts


class GetAccountFromUser(object):
    """Load actual account of contact with Tkinter prompt."""

    def __init__(self, queue: 'AccountQueue', onion_address_user: str) -> None:
        """Create new Tkinter input box."""
        self.queue              = queue
        self.onion_address_user = onion_address_user

        self.root = tkinter.Tk()
        self.root.title("Contact account entry")
        self.root.protocol("WM_DELETE_WINDOW", self.dismiss_window)

        self.error_label = tkinter.Label(self.root, text=None)

        self.instruction = tkinter.Text(self.root, height=3, width=54)
        self.instruction.tag_configure('center', justify='center')
        self.instruction.insert('1.0', "Could not determine the account being added.\n"  # type: ignore
                                       "Please paste the account here to see diffs\n"
                                       "or press Cancel to dismiss this prompt.")
        self.instruction.tag_add('center', '1.0', 'end')  # type: ignore
        self.instruction.pack()

        self.address_entry_box = tkinter.Entry(self.root, width=54)
        self.address_entry_box.pack()

        tkinter.Button(self.root, text='Cancel', command=self.dismiss_window).pack()
        tkinter.Button(self.root, text='Ok',     command=self.evaluate_account).pack()

        self.root.mainloop()

    def evaluate_account(self) -> None:
        """Check if the input is a valid TFC account."""
        purp_acco = self.address_entry_box.get()  # type: ignore
        error_msg = validate_onion_addr(purp_acco, self.onion_address_user)

        if error_msg:
            self.address_entry_box.delete(0, tkinter.END)
            self.error_label.forget()
            self.error_label.configure(text=error_msg)
            self.error_label.pack()
        else:
            self.queue.put(purp_acco)
            self.root.destroy()

    def dismiss_window(self) -> None:
        """Dismiss the account input window."""
        self.queue.put(None)
        self.root.destroy()


def account_checker(queues:   'QueueDict',
                    stdin_fd: int
                    ) -> None:
    """\
    Display diffs between received TFC accounts and accounts
    manually imported to Source Computer."""
    sys.stdin           = os.fdopen(stdin_fd)
    account_list        = []  # type: List[str]
    account_check_queue = queues[ACCOUNT_CHECK_QUEUE]
    account_send_queue  = queues[ACCOUNT_SEND_QUEUE]

    while queues[USER_ACCOUNT_QUEUE].qsize() == 0:
        time.sleep(0.01)
    onion_address_user = queues[USER_ACCOUNT_QUEUE].get()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if account_send_queue.qsize() != 0:
                account = account_send_queue.get()  # type: Optional[str]
                if account is not None and account not in account_list:
                    account_list.append(account)
                continue

            if account_check_queue.qsize() != 0:
                purp_account = account_check_queue.get()  # type: str

                # Determine correct account
                for account in account_list:
                    # Check if accounts are similar enough:
                    ratio = difflib.SequenceMatcher(a=account, b=purp_account).ratio()
                    if ratio >= ACCOUNT_RATIO_LIMIT:
                        break
                else:
                    queue = Queue()  # type: AccountQueue
                    GetAccountFromUser(queue, onion_address_user)
                    account = queue.get()
                    if account is not None and account not in account_list:
                        account_list.append(account)

                if account is not None:
                    show_value_diffs("account", account, purp_account, local_test=True)

                continue

            time.sleep(0.01)


# Public keys

def pub_key_checker(queues:     'QueueDict',
                    local_test: bool
                    ) -> None:
    """\
    Display diffs between received public keys and public keys
    manually imported to Source Computer.
    """
    pub_key_check_queue = queues[PUB_KEY_CHECK_QUEUE]
    pub_key_send_queue  = queues[PUB_KEY_SEND_QUEUE]
    pub_key_dictionary  = dict()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if pub_key_send_queue.qsize() != 0:
                account, pub_key            = pub_key_send_queue.get()
                pub_key_dictionary[account] = b58encode(pub_key, public_key=True)
                continue

            if pub_key_check_queue.qsize() != 0:
                purp_account, purp_pub_key = pub_key_check_queue.get()  # type: bytes, bytes

                if purp_account in pub_key_dictionary:
                    purp_b58_pub_key = purp_pub_key.decode()
                    true_b58_pub_key = pub_key_dictionary[purp_account]

                    show_value_diffs("public key", true_b58_pub_key, purp_b58_pub_key, local_test)

            time.sleep(0.01)


# Diffs

def show_value_diffs(value_type: str,
                     true_value: str,
                     purp_value: str,
                     local_test: bool
                     ) -> None:
    """Compare purported value with correct value."""
    # Pad with underscores to denote missing chars
    while len(purp_value) < ENCODED_B58_PUB_KEY_LENGTH:
        purp_value += '_'

    replace_l = ''
    purported = ''
    for c1, c2 in zip(purp_value, true_value):
        if c1 == c2:
            replace_l += ' '
            purported += c1
        else:
            replace_l += '↓'
            purported += c1

    message_list = [f"Source Computer received an invalid {value_type}.",
                    "See arrows below that point to correct characters."]

    if local_test:
        m_print(message_list + ['', purported, replace_l, true_value], box=True)
    else:
        purported  = ' '.join(split_string(purported,  item_len=7))
        replace_l  = ' '.join(split_string(replace_l,  item_len=7))
        true_value = ' '.join(split_string(true_value, item_len=7))

        m_print(message_list + ['',
                                B58_PUBLIC_KEY_GUIDE,
                                purported,
                                replace_l,
                                true_value,
                                B58_PUBLIC_KEY_GUIDE], box=True)


if __name__ == '__main__':
    queue = Queue()  # type: Queue[Optional[str]]
    GetAccountFromUser(queue, 58*'a')
    print(queue.get_nowait())
