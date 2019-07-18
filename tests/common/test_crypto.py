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

import hashlib
import multiprocessing
import os
import random
import subprocess
import unittest

from string        import ascii_letters, digits
from unittest      import mock
from unittest.mock import MagicMock

import argon2
import nacl.exceptions
import nacl.public
import nacl.utils

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from src.common.crypto  import argon2_kdf, auth_and_decrypt, blake2b, byte_padding, check_kernel_entropy
from src.common.crypto  import check_kernel_version, csprng, encrypt_and_sign, rm_padding_bytes, X448
from src.common.statics import ARGON2_SALT_LENGTH, BLAKE2_DIGEST_LENGTH_MAX, ENTROPY_THRESHOLD, PADDING_LENGTH
from src.common.statics import SYMMETRIC_KEY_LENGTH, TFC_PUBLIC_KEY_LENGTH, XCHACHA20_NONCE_LENGTH

from tests.utils import cd_unit_test, cleanup


class TestBLAKE2b(unittest.TestCase):
    """\
    Because hash values of secure hash functions are unpredictable (i.e.
    indistinguishable from the output of a truly random function), it's
    hard to know whether the algorithm is implemented correctly.

    Known answer test (KAT), a.k.a. test vector, contains the known
    correct output value of the function under some known set of input
    values. With each successful KAT it becomes more and more certain
    that the implementation of the function is correct. On the other
    hand, any failing KAT indicates a problem within the implementation.

    TFC does its best to verify the BLAKE2b implementation is correct by
    using the full suite of BLAKE2b KATs available in the official
    BLAKE2 GitHub repository:

        https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
    """

    def setUp(self) -> None:
        self.unit_test_dir = cd_unit_test()

        kat_file_url  = 'https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2b-kat.txt'
        kat_file_name = 'blake2b-kat.txt'

        # Download the test vector file.
        subprocess.Popen(f'wget {kat_file_url} -O {kat_file_name}', shell=True).wait()

        # Read the test vector file.
        with open(kat_file_name) as f:
            file_data = f.read()

        # Verify the SHA256 hash of the test vector file.
        self.assertEqual(hashlib.sha256(file_data.encode()).hexdigest(),
                         '82fcb3cabe8ff6e1452849e3b2a26a3631f1e2b51beb62ffb537892d2b3e364f')

        # Parse the test vectors to a list of tuples: [(message1, key1, digest1), (message2, key2, digest2), ...]
        self.test_vectors = []

        trimmed_data = file_data[2:-1]             # Remove empty lines from the start and the end of the read data.
        test_vectors = trimmed_data.split('\n\n')  # Each tuple of test vector values is separated by an empty line.

        for test_vector in test_vectors:

            # Each value is hex-encoded, and has a tab-separated name
            # (in, key, hash) prepended to it that must be separated.
            message, key, digest = [bytes.fromhex(line.split('\t')[1]) for line in test_vector.split('\n')]

            self.test_vectors.append((message, key, digest))

        # Transpose the list of tuples to lists of messages, keys, and digests.
        messages, keys, digests = list(map(list, zip(*self.test_vectors)))

        # Verify that messages and digests are unique, and
        # that identical keys are used in every test vector.
        self.assertEqual(len(set(messages)), 256)
        self.assertEqual(len(    keys),      256)
        self.assertEqual(len(set(keys)),       1)
        self.assertEqual(len(set(digests)),  256)

    def tearDown(self) -> None:
        cleanup(self.unit_test_dir)

    def test_blake2b_using_the_official_known_answer_tests(self):
        for message, key, digest in self.test_vectors:
            purported_digest = blake2b(message, key, digest_size=BLAKE2_DIGEST_LENGTH_MAX)
            self.assertEqual(purported_digest, digest)


class TestArgon2KDF(unittest.TestCase):
    """\
    Similar to normal cryptographic hash functions, a password hashing
    function such as the Argon2 also generates unpredictable values
    (secret keys in this case). The IETF test vectors[1] require
    parameters (e.g. the "Secret" and the "Associated data" fields) that
    the argon2_cffi library does not provide. The only available option
    is to generate the test vectors dynamically.
        To do that, this test downloads and compiles the command-line
    utility[2] for the reference implementation of Argon2. Next, the
    test compiles and runs the command-line utility's tests. It then
    generates random (but valid) input parameters, and compares the
    output of the argon2_cffi library to the output of the command-line
    utility under those input parameters.

     [1] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-6.1
     [2] https://github.com/P-H-C/phc-winner-argon2#command-line-utility
    """

    def setUp(self) -> None:
        self.unit_test_dir   = cd_unit_test()
        self.number_of_tests = 256

        file_url  = 'https://github.com/P-H-C/phc-winner-argon2/archive/master.zip'
        file_name = 'phc-winner-argon2-master.zip'

        # Download the Argon2 command-line utility.
        subprocess.Popen(f'wget {file_url} -O {file_name}', shell=True).wait()

        # Verify the SHA256 hash of the zip-file containing the command-line utility.
        file_data = open(file_name, 'rb').read()
        self.assertEqual(hashlib.sha256(file_data).hexdigest(),
                         '2957db15d320b0970a34be9a6ef984b11b2296b1b1f8b051a47e35035c1bc7cf')

        # Unzip, compile, and test the command-line utility.
        subprocess.Popen(f'unzip {file_name}', shell=True).wait()
        os.chdir('phc-winner-argon2-master/')
        subprocess.Popen('make',      shell=True).wait()
        subprocess.Popen('make test', shell=True).wait()

    def tearDown(self) -> None:
        os.chdir('..')
        cleanup(self.unit_test_dir)

    def test_argon2_cffi_using_the_official_command_line_utility(self):

        # Command-line utility's parameter limits.
        MIN_PASSWORD_LENGTH = 1
        MAX_PASSWORD_LENGTH = 127
        MIN_SALT_LENGTH     = 8
        MIN_PARALLELISM     = 1
        MAX_PARALLELISM     = multiprocessing.cpu_count()
        MIN_TIME_COST       = 1
        MIN_MEMORY_COST     = 7
        MIN_KEY_LENGTH      = 4

        # Arbitrary limits set for the test.
        MAX_SALT_LENGTH = 128
        MAX_TIME_COST   = 3
        MAX_MEMORY_COST = 15
        MAX_KEY_LENGTH  = 64

        sys_rand = random.SystemRandom()

        for _ in range(self.number_of_tests):

            # Generate random parameters for the test.
            len_password = sys_rand.randint(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
            len_salt     = sys_rand.randint(MIN_SALT_LENGTH,     MAX_SALT_LENGTH)
            parallelism  = sys_rand.randint(MIN_PARALLELISM,     MAX_PARALLELISM)
            time_cost    = sys_rand.randint(MIN_TIME_COST,       MAX_TIME_COST)
            memory_cost  = sys_rand.randint(MIN_MEMORY_COST,     MAX_MEMORY_COST)
            key_length   = sys_rand.randint(MIN_KEY_LENGTH,      MAX_KEY_LENGTH)

            password = ''.join([sys_rand.choice(ascii_letters + digits) for _ in range(len_password)])
            salt     = ''.join([sys_rand.choice(ascii_letters + digits) for _ in range(len_salt)])

            # Generate a key test vector using the command-line utility.
            output = subprocess.check_output(
                f'echo -n "{password}" | ./argon2 {salt} '
                f'-t {time_cost} '
                f'-m {memory_cost} '
                f'-p {parallelism} '
                f'-l {key_length} '
                f'-d',
                shell=True).decode()  # type: str

            key_test_vector = output.split('\n')[4].split('\t')[-1]

            # Generate a key using the argon2_cffi library.
            purported_key = argon2.low_level.hash_secret_raw(secret=password.encode(),
                                                             salt=salt.encode(),
                                                             time_cost=time_cost,
                                                             memory_cost=2**memory_cost,
                                                             parallelism=parallelism,
                                                             hash_len=key_length,
                                                             type=argon2.Type.D).hex()

            self.assertEqual(purported_key, key_test_vector)


class TestArgon2Wrapper(unittest.TestCase):

    def test_invalid_length_salt_raises_critical_error(self):
        invalid_salts = [salt_length * b'a' for salt_length in [0, ARGON2_SALT_LENGTH-1,
                                                                   ARGON2_SALT_LENGTH+1, 1000]]
        for invalid_salt in invalid_salts:
            with self.assertRaises(SystemExit):
                argon2_kdf('password', invalid_salt)

    def test_argon2_kdf_key_type_and_length(self):
        key = argon2_kdf('password', os.urandom(ARGON2_SALT_LENGTH), time_cost=1, memory_cost=100)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)


class TestX448(unittest.TestCase):
    """\
    Again, since the X448 output (shared secret) is an unpredictable
    value (a random point on the curve), the easiest way to verify the
    correct implementation of the algorithm is with the official test
    vectors:

        https://tools.ietf.org/html/rfc7748#section-6.2

    In addition to the X448 test vectors, there also exists two separate
    sets of test vectors for the internal functionality of X448, namely,
    for scalar multiplication.
        The first set contains known input scalars and input
    u-coordinates that produce known output u-coordinates.
        The second set contains an input scalar and input u-coordinate,
    plus the output values after the scalar multiplication has been
    performed 1,000 and 1,000,000 times:

        https://tools.ietf.org/html/rfc7748#section-5.2

    The pyca/cryptography library does not provide bindings for the
    OpenSSL's X448 internals, but both KATs are done by OpenSSL tests:

        https://github.com/openssl/openssl/blob/master/test/curve448_internal_test.c#L654
        https://github.com/openssl/openssl/blob/master/test/curve448_internal_test.c#L668
    """
    sk_alice = bytes.fromhex(
        '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d'
        'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b')

    pk_alice = bytes.fromhex(
        '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c'
        '22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0')

    sk_bob = bytes.fromhex(
        '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d'
        '6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d')

    pk_bob = bytes.fromhex(
        '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430'
        '27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609')

    shared_secret = bytes.fromhex(
        '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b'
        'b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d')

    def test_generate_private_key_function_returns_private_key_object(self):
        self.assertIsInstance(X448.generate_private_key(), X448PrivateKey)

    def test_deriving_shared_secret_with_an_invalid_size_public_key_raises_critical_error(self):
        private_key         = X448.generate_private_key()
        invalid_public_keys = [key_length * b'a' for key_length in (1, TFC_PUBLIC_KEY_LENGTH-1,
                                                                       TFC_PUBLIC_KEY_LENGTH+1, 1000)]
        for invalid_public_key in invalid_public_keys:
            with self.assertRaises(SystemExit):
                X448.shared_key(private_key, invalid_public_key)

    def test_deriving_zero_shared_secret_raises_critical_error(self):
        """\
        Some experts such as JP Aumasson[1] and Thai Duong[2] have
        argued that X25519 public keys should be validated before use to
        prevent one party from having key control, i.e., being able to
        force the shared secret to a preselected value. This also
        applies to X448.
            It's not clear how this type of attack could be leveraged in
        the context of secure messaging where both the sender and the
        recipient desire confidentiality, and where easier ways to break
        the confidentiality of the conversation exist for both parties.
        However, there is
          a) no harm in doing the check and
          b) no need to trouble ourselves with whether TFC should ensure
             contributory behavior; the pyca/cryptography library
             already checks that the shared secret is not zero. This
             test merely verifies that the check takes place.

         [1] https://research.kudelskisecurity.com/2017/04/25/should-ecdh-keys-be-validated/
         [2] https://vnhacker.blogspot.com/2015/09/why-not-validating-curve25519-public.html
        """
        with self.assertRaises(SystemExit):
            X448.shared_key(X448.generate_private_key(), bytes(TFC_PUBLIC_KEY_LENGTH))

    def test_x448_with_the_official_test_vectors(self):
        sk_alice_ = X448PrivateKey.from_private_bytes(TestX448.sk_alice)
        sk_bob_   = X448PrivateKey.from_private_bytes(TestX448.sk_bob)

        self.assertEqual(X448.derive_public_key(sk_alice_), TestX448.pk_alice)
        self.assertEqual(X448.derive_public_key(sk_bob_),   TestX448.pk_bob)

        shared_secret1 = X448.shared_key(sk_alice_, TestX448.pk_bob)
        shared_secret2 = X448.shared_key(sk_bob_,   TestX448.pk_alice)

        self.assertEqual(shared_secret1, blake2b(TestX448.shared_secret))
        self.assertEqual(shared_secret2, blake2b(TestX448.shared_secret))


class TestXChaCha20Poly1305(unittest.TestCase):
    """\
    Since HChaCha20 is a secure PRG, the XChaCha20 stream cipher derived
    from it is also semantically secure: Under some set of inputs
    (plaintext, associated data, key, and nonce), XChaCha20-Poly1305
    will output a ciphertext and a tag that are indistinguishable from
    the output of a truly random function. So again, the correctness of
    the implementation is best tested using test vectors.

    There are two slightly different test vectors available. Both KATs
    use the same plaintext, associated data, and key. However, both
    KATs use a different nonce, which will result in different
    ciphertext and tag.

    IETF test vectors:
        https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-00#appendix-A.1

    Libsodium test vectors:
        Message: https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L22
        Ad:      https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L28
        Key:     https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L14
        Nonce:   https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L25
        CT+tag:  https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.exp#L1

    To make the verification of the test vectors (listed below) easy,
    they are formatted in the most identical way as is possible.
    """

    ietf_plaintext = bytes.fromhex(
        '4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c'
        '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73'
        '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63'
        '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f'
        '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20'
        '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73'
        '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69'
        '74 2e')

    ietf_ad = bytes.fromhex(
        '50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7')

    ietf_key = bytes.fromhex(
        '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'
        '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f')

    ietf_nonce = bytes.fromhex(
        '40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f'
        '50 51 52 53 54 55 56 57')

    ietf_ciphertext = bytes.fromhex(
        'bd 6d 17 9d 3e 83 d4 3b 95 76 57 94 93 c0 e9 39'
        '57 2a 17 00 25 2b fa cc be d2 90 2c 21 39 6c bb'
        '73 1c 7f 1b 0b 4a a6 44 0b f3 a8 2f 4e da 7e 39'
        'ae 64 c6 70 8c 54 c2 16 cb 96 b7 2e 12 13 b4 52'
        '2f 8c 9b a4 0d b5 d9 45 b1 1b 69 b9 82 c1 bb 9e'
        '3f 3f ac 2b c3 69 48 8f 76 b2 38 35 65 d3 ff f9'
        '21 f9 66 4c 97 63 7d a9 76 88 12 f6 15 c6 8b 13'
        'b5 2e')

    ietf_tag = bytes.fromhex(
        'c0:87:59:24:c1:c7:98:79:47:de:af:d8:78:0a:cf:49'.replace(':', ''))

    nonce_ct_tag_ietf = ietf_nonce + ietf_ciphertext + ietf_tag

    # ---

    libsodium_plaintext = \
        b"Ladies and Gentlemen of the class of '99: If I could offer you " \
        b"only one tip for the future, sunscreen would be it."

    libsodium_ad = bytes([
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7])

    libsodium_key = bytes([
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f])

    libsodium_nonce = bytes([
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53])

    libsodium_ct_tag = bytes([
         0xf8,0xeb,0xea,0x48,0x75,0x04,0x40,0x66
        ,0xfc,0x16,0x2a,0x06,0x04,0xe1,0x71,0xfe
        ,0xec,0xfb,0x3d,0x20,0x42,0x52,0x48,0x56
        ,0x3b,0xcf,0xd5,0xa1,0x55,0xdc,0xc4,0x7b
        ,0xbd,0xa7,0x0b,0x86,0xe5,0xab,0x9b,0x55
        ,0x00,0x2b,0xd1,0x27,0x4c,0x02,0xdb,0x35
        ,0x32,0x1a,0xcd,0x7a,0xf8,0xb2,0xe2,0xd2
        ,0x50,0x15,0xe1,0x36,0xb7,0x67,0x94,0x58
        ,0xe9,0xf4,0x32,0x43,0xbf,0x71,0x9d,0x63
        ,0x9b,0xad,0xb5,0xfe,0xac,0x03,0xf8,0x0a
        ,0x19,0xa9,0x6e,0xf1,0x0c,0xb1,0xd1,0x53
        ,0x33,0xa8,0x37,0xb9,0x09,0x46,0xba,0x38
        ,0x54,0xee,0x74,0xda,0x3f,0x25,0x85,0xef
        ,0xc7,0xe1,0xe1,0x70,0xe1,0x7e,0x15,0xe5
        ,0x63,0xe7,0x76,0x01,0xf4,0xf8,0x5c,0xaf
        ,0xa8,0xe5,0x87,0x76,0x14,0xe1,0x43,0xe6
        ,0x84,0x20])

    nonce_ct_tag_libsodium = libsodium_nonce + libsodium_ct_tag

    def setUp(self) -> None:
        self.assertEqual(self.ietf_plaintext, self.libsodium_plaintext)
        self.assertEqual(self.ietf_ad,        self.libsodium_ad)
        self.assertEqual(self.ietf_key,       self.libsodium_key)

        self.assertNotEqual(self.ietf_nonce,        self.libsodium_nonce)
        self.assertNotEqual(self.nonce_ct_tag_ietf, self.nonce_ct_tag_libsodium)

        self.plaintext = self.ietf_plaintext
        self.ad        = self.ietf_ad
        self.key       = self.ietf_key

    @mock.patch('src.common.crypto.csprng', side_effect=[ietf_nonce, libsodium_nonce])
    def test_encrypt_and_sign_with_the_official_test_vectors(self, mock_csprng):
        self.assertEqual(encrypt_and_sign(self.plaintext, self.key, self.ad), self.nonce_ct_tag_ietf)
        self.assertEqual(encrypt_and_sign(self.plaintext, self.key, self.ad), self.nonce_ct_tag_libsodium)
        mock_csprng.assert_called_with(XCHACHA20_NONCE_LENGTH)

    def test_auth_and_decrypt_with_the_official_test_vectors(self):
        self.assertEqual(auth_and_decrypt(self.nonce_ct_tag_ietf,      self.key, ad=self.ad), self.plaintext)
        self.assertEqual(auth_and_decrypt(self.nonce_ct_tag_libsodium, self.key, ad=self.ad), self.plaintext)

    def test_invalid_size_key_raises_critical_error(self):
        invalid_keys = [key_length * b'a' for key_length in [1, SYMMETRIC_KEY_LENGTH-1,
                                                                SYMMETRIC_KEY_LENGTH+1, 1000]]
        for invalid_key in invalid_keys:
            with self.assertRaises(SystemExit):
                encrypt_and_sign(self.libsodium_plaintext, invalid_key)
            with self.assertRaises(SystemExit):
                auth_and_decrypt(self.nonce_ct_tag_ietf, invalid_key)

    def test_invalid_tag_in_data_from_database_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            auth_and_decrypt(self.nonce_ct_tag_ietf, key=bytes(SYMMETRIC_KEY_LENGTH), database='path/database_filename')

    def test_invalid_tag_in_data_from_contact_raises_nacl_crypto_error(self):
        with self.assertRaises(nacl.exceptions.CryptoError):
            auth_and_decrypt(self.nonce_ct_tag_ietf, key=bytes(SYMMETRIC_KEY_LENGTH))


class TestBytePadding(unittest.TestCase):
    """The requirements of the PKCS#7 padding are as follows:

        1. The size of the padded message must be a multiple of the
           padding size (255 bytes).
        2. If the length of the message to be padded is exactly 255
           bytes, a dummy block must be added.
        3. Removing the padding must not change the original message in
           any way.

    The unit tests of the pyca/cryptography library are available at
        https://github.com/pyca/cryptography/blob/master/tests/hazmat/primitives/test_padding.py
    """

    def test_length_of_the_padded_message_is_divisible_by_padding_length(self):
        padded_bytestrings = set()

        for message_length in range(4*PADDING_LENGTH):
            message = os.urandom(message_length)
            padded  = byte_padding(message)

            self.assertIsInstance(padded, bytes)
            self.assertEqual(len(padded) % PADDING_LENGTH, 0)

            padded_bytestrings.add(len(padded))

        self.assertEqual(padded_bytestrings, {1*PADDING_LENGTH, 2*PADDING_LENGTH,
                                              3*PADDING_LENGTH, 4*PADDING_LENGTH})

    @mock.patch('cryptography.hazmat.primitives.padding.PKCS7',
                return_value=MagicMock(
                    padder=MagicMock(return_value=MagicMock(
                        update=MagicMock(return_value=b''),
                        finalize=MagicMock(return_value=(PADDING_LENGTH+1)*b'a')))))
    def test_invalid_padding_length_raises_critical_error(self, _):
        """\
        This test makes sure TFC detects if the length of the message
        padded by pyca/cryptography library is not correct.
            The MagicMock object replaces the message b'test_string' with
        a message that has an incorrect length of 256 bytes.
        """
        with self.assertRaises(SystemExit):
            byte_padding(b'test_string')

    def test_message_length_one_less_than_padding_size_does_not_add_a_dummy_block(self):
        message = (PADDING_LENGTH-1) * b'a'
        padded  = byte_padding(message)
        self.assertEqual(len(padded), PADDING_LENGTH)

    def test_message_length_equal_to_padding_size_adds_a_dummy_block(self):
        message = PADDING_LENGTH * b'a'
        padded  = byte_padding(message)
        self.assertEqual(len(padded), 2*PADDING_LENGTH)

    def test_removal_of_padding_does_not_alter_the_original_message(self):
        for message_length in range(4*PADDING_LENGTH):
            message = os.urandom(message_length)
            padded  = byte_padding(message)
            self.assertEqual(rm_padding_bytes(padded), message)


class TestCSPRNG(unittest.TestCase):

    entropy = SYMMETRIC_KEY_LENGTH * b'a'

    def test_key_generation(self):
        key = csprng()
        self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)
        self.assertIsInstance(key, bytes)

    @mock.patch('os.getrandom', return_value=entropy)
    def test_function_calls_getrandom_with_correct_parameters_and_hashes_with_blake2b(self, mock_get_random):
        key = csprng()
        mock_get_random.assert_called_with(SYMMETRIC_KEY_LENGTH, flags=0)
        self.assertEqual(key, blake2b(self.entropy))

    def test_function_returns_specified_amount_of_entropy(self):
        for key_size in [16, 24, 32, 56, 64]:
            key = csprng(key_size)
            self.assertEqual(len(key), key_size)

    def test_exceeding_hash_function_max_digest_size_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            csprng(BLAKE2_DIGEST_LENGTH_MAX + 1)

    @mock.patch('os.getrandom', side_effect=[(SYMMETRIC_KEY_LENGTH-1) * b'a',
                                             (SYMMETRIC_KEY_LENGTH+1) * b'a'])
    def test_invalid_entropy_raises_critical_error(self, _):
        with self.assertRaises(SystemExit):
            csprng()
        with self.assertRaises(SystemExit):
            csprng()

    @mock.patch('src.common.crypto.blake2b', side_effect=[(SYMMETRIC_KEY_LENGTH-1) * b'a',
                                                          (SYMMETRIC_KEY_LENGTH+1) * b'a'])
    def test_invalid_blake2b_digest_raises_critical_error(self, _):
        with self.assertRaises(SystemExit):
            csprng()
        with self.assertRaises(SystemExit):
            csprng()

class TestCheckKernelEntropy(unittest.TestCase):

    @mock.patch('time.sleep', return_value=None)
    def test_large_enough_entropy_pool_state_returns_none(self, _):
        with mock.patch('builtins.open', mock.mock_open(read_data=str(ENTROPY_THRESHOLD))):
            self.assertIsNone(check_kernel_entropy())
        with mock.patch('builtins.open', mock.mock_open(read_data=str(ENTROPY_THRESHOLD+1))):
            self.assertIsNone(check_kernel_entropy())

    @mock.patch('time.sleep', return_value=None)
    def test_insufficient_entropy_pool_state_does_not_return(self, _):
        with unittest.mock.patch('builtins.open', unittest.mock.mock_open(read_data=str(ENTROPY_THRESHOLD-1))):
            p = multiprocessing.Process(target=check_kernel_entropy)
            try:
                p.start()
                p.join(timeout=0.1)
                self.assertTrue(p.is_alive())
            finally:
                p.terminate()
                p.join()
                self.assertFalse(p.is_alive())


class TestCheckKernelVersion(unittest.TestCase):

    invalid_versions = ['3.9.11', '3.19.8', '4.7.10']
    valid_versions   = ['4.8.1',  '4.10.1', '5.0.0']

    @mock.patch('os.uname', side_effect=[['', '', f'{i}-0-generic'] for i in invalid_versions])
    def test_invalid_kernel_versions_raise_critical_error(self, _):
        for _ in self.invalid_versions:
            with self.assertRaises(SystemExit):
                check_kernel_version()

    @mock.patch('os.uname', side_effect=[['', '', f'{v}-0-generic'] for v in valid_versions])
    def test_valid_kernel_versions(self, _):
        for _ in self.valid_versions:
            self.assertIsNone(check_kernel_version())


if __name__ == '__main__':
    unittest.main(exit=False)
