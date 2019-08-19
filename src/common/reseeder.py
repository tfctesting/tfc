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
import fcntl

RNDRESEEDCRNG = 0x5207  # https://godoc.org/golang.org/x/sys/unix

def force_reseed():
    """Force reseed of the LRNG ChaCha20 DNRG.

    This is a utility program that is called by the
    src.common.check_kernel_entropy function once the
    /proc/sys/kernel/random/entropy_avail indicates the input_pool has
    been seeded with 512 bits.
        This function calls the RNDRESEEDCRNG IOCTL which forces
    reseeding of the ChaCha20 DRNG from the input_pool. Reseeding from
    the input_pool ensures the ChaCha20 DRNG is safely seeded before use
    even if the kernel trusts the RDSEED/RDRAND instructions.
    """
    fd = os.open('/dev/urandom', os.O_WRONLY)
    try:
        if fcntl.ioctl(fd, RNDRESEEDCRNG) != 0:
            exit(1)
    finally:
        os.close(fd)

if __name__ == '__main__':
    force_reseed()
