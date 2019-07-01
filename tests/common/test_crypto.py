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
import string
import unittest

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
    Because hash values of secure hash functions are unpredictable
    (i.e. indistinguishable from the output of a truly random function),
    it's hard to know whether the algorithm is implemented correctly.

    Known answer test (KAT) (aka test vector) contains known correct
    output value of the function under some known input value. With each
    successful KAT it becomes more and more certain that the
    implementation of the function is correct. On the other hand, any
    failing test indicates a problem within the implementation.

    TFC does its best to verify the BLAKE2b implementation is correct
    by using the full suite of BLAKE2b KATs available in the official
    BLAKE2 GitHub repository:

       https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
    """

    def setUp(self) -> None:
        self.unittest_dir = cd_unit_test()

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

        trimmed_data = file_data[2:-1]             # Remove empty lines from the start and the end of the file.
        test_vectors = trimmed_data.split('\n\n')  # Each tuple of test vectors is separated with an empty line.

        for test_vector in test_vectors:

            # Each value is hex-encoded, and has a tab-separated name
            # (in, key, hash) prepended to it that must be separated.
            message, key, digest = [bytes.fromhex(line.split('\t')[1]) for line in test_vector.split('\n')]

            self.test_vectors.append((message, key, digest))

        # Transpose the list of tuples to lists of messages, keys, and
        # digests, and verify that messages and digests are unique, and
        # that identical keys are used in every test vector.
        messages, keys, digests = list(map(list, zip(*self.test_vectors)))

        self.assertEqual(len(set(messages)), 256)
        self.assertEqual(len(    keys),      256)
        self.assertEqual(len(set(keys)),       1)
        self.assertEqual(len(set(digests)),  256)

    def tearDown(self) -> None:
        cleanup(self.unittest_dir)

    def test_blake2b_known_answer_tests(self):
        for message, key, digest in self.test_vectors:
            purp_digest = blake2b(message, key, digest_size=BLAKE2_DIGEST_LENGTH_MAX)
            self.assertEqual(purp_digest, digest)


class TestArgon2KDF(unittest.TestCase):
    """\
    Similar to normal cryptographic hash functions, a password hashing
    function such as the Argon2 also generates unpredictable values
    (secret keys in this case). The IETF test vectors[1] require
    parameters (e.g. the "Secret" and the "Associated data" fields) that
    the argon2_cffi library does not provide. The only available option
    is to generate the test vectors dynamically.
        To do that, this test downloads and compiles the command-line
    utility[2] for the reference implementation of Argon2. It then
    generates random (but valid) input parameters, and compares the
    output of the argon2_cffi function to the output of the command-line
    utility under those input parameters.

    [1] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-6.1
    [2] https://github.com/P-H-C/phc-winner-argon2#command-line-utility
    """

    def setUp(self) -> None:
        self.unittest_dir    = cd_unit_test()
        self.number_of_tests = 256

        file_url  = 'https://github.com/P-H-C/phc-winner-argon2/archive/master.zip'
        file_name = 'argon2_master.zip'

        # Download the Argon2 command-line utility.
        subprocess.Popen(f'wget {file_url} -O {file_name}', shell=True).wait()

        # Verify the SHA256 hash of the zip-file containing the command-line utility.
        file_data = open(file_name, 'rb').read()
        self.assertEqual(hashlib.sha256(file_data).hexdigest(),
                         '2957db15d320b0970a34be9a6ef984b11b2296b1b1f8b051a47e35035c1bc7cf')

        # Unzip and compile the command-line utility.
        subprocess.Popen(f'unzip {file_name}', shell=True).wait()
        os.chdir('phc-winner-argon2-master/')
        subprocess.Popen('make', shell=True).wait()

    def tearDown(self) -> None:
        os.chdir('..')
        cleanup(self.unittest_dir)

    def test_argon2_cffi_using_the_official_command_line_utility(self):

        # Command-line utility's parameter limits
        MIN_PASSWORD_LENGTH = 1
        MAX_PASSWORD_LENGTH = 127
        MIN_SALT_LENGTH = 8
        MIN_PARALLELISM = 1
        MAX_PARALLELISM = multiprocessing.cpu_count()
        MIN_TIME_COST = 1
        MIN_MEMORY_COST = 7
        MIN_KEY_LENGTH = 4

        # Arbitrary limits set for the test
        MAX_SALT_LENGTH = 128
        MAX_TIME_COST = 3
        MAX_MEMORY_COST = 15
        MAX_KEY_LENGTH = 64

        sys_rand = random.SystemRandom()

        for _ in range(self.number_of_tests):

            # Generate random parameters for the test.
            len_password = sys_rand.randint(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
            len_salt     = sys_rand.randint(MIN_SALT_LENGTH,     MAX_SALT_LENGTH)
            password     = ''.join([sys_rand.choice(string.ascii_letters + string.digits) for _ in range(len_password)])
            salt         = ''.join([sys_rand.choice(string.ascii_letters + string.digits) for _ in range(len_salt)])
            parallelism  = sys_rand.randint(MIN_PARALLELISM, MAX_PARALLELISM)
            time_cost    = sys_rand.randint(MIN_TIME_COST,   MAX_TIME_COST)
            memory_cost  = sys_rand.randint(MIN_MEMORY_COST, MAX_MEMORY_COST)
            key_length   = sys_rand.randint(MIN_KEY_LENGTH,  MAX_KEY_LENGTH)

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

    def test_invalid_salt_length_raises_critical_error(self):
        for salt_length in [0, ARGON2_SALT_LENGTH-1,
                               ARGON2_SALT_LENGTH+1, 1000]:
            with self.assertRaises(SystemExit):
                argon2_kdf('password', salt_length * b'a')

    def test_argon2_kdf_key_type_and_length(self):
        key = argon2_kdf('password', os.urandom(ARGON2_SALT_LENGTH), time_cost=1, memory_cost=100)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)


class TestX448(unittest.TestCase):
    """\
    The X448 shared secret is also an unpredictable value. To test the
    correctness of the OpenSSL implementation and TFC's wrapper, this
    test uses the official X448 test vectors:

        https://tools.ietf.org/html/rfc7748#section-6.2
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

    def test_generate_private_key_returns_private_key_object(self):
        self.assertIsInstance(X448.generate_private_key(), X448PrivateKey)

    def test_deriving_shared_key_with_an_incorrect_public_key_length_raises_critical_error(self):
        private_key = X448PrivateKey.generate()
        public_keys = [key_len * b'a' for key_len in (1, TFC_PUBLIC_KEY_LENGTH-1,
                                                         TFC_PUBLIC_KEY_LENGTH+1, 1000)]
        for public_key in public_keys:
            with self.assertRaises(SystemExit):
                X448.shared_key(private_key, public_key)

    def test_deriving_zero_shared_key_raises_critical_error(self):
        """\
        Some experts such as JP Aumasson[1] and Thai Duong[2] have
        argued that X25519 public keys should be validated before use to
        prevent one party from being able to force the shared key to a
        preselected value. This also applies to X448.
            While it's not clear how this type of attack could be
        leveraged in the context of secure messaging where both parties
        strive for confidentiality, and where easier ways to break the
        confidentiality of the conversation exist, there is
          1) no harm in doing the check and
          2) no need to trouble ourselves with whether it's needed as
             the pyca/cryptography implementation already checks for
             zero shared keys. This test merely verifies that the check
             takes place.

        [1] https://research.kudelskisecurity.com/2017/04/25/should-ecdh-keys-be-validated/
        [2] https://vnhacker.blogspot.com/2015/09/why-not-validating-curve25519-public.html
        """
        with self.assertRaises(SystemExit):
            X448.shared_key(X448PrivateKey.generate(), bytes(TFC_PUBLIC_KEY_LENGTH))

    def test_x448_with_test_vectors(self):
        sk_alice_ = X448PrivateKey.from_private_bytes(TestX448.sk_alice)
        sk_bob_   = X448PrivateKey.from_private_bytes(TestX448.sk_bob)

        self.assertEqual(X448.derive_public_key(sk_alice_), TestX448.pk_alice)
        self.assertEqual(X448.derive_public_key(sk_bob_),   TestX448.pk_bob)

        shared_secret1 = X448.shared_key(sk_alice_, TestX448.pk_bob)
        shared_secret2 = X448.shared_key(sk_bob_,   TestX448.pk_alice)

        self.assertEqual(shared_secret1, blake2b(TestX448.shared_secret))
        self.assertEqual(shared_secret2, blake2b(TestX448.shared_secret))


class TestXChaCha20Poly1305(unittest.TestCase):
    """Libsodium test vectors:
        Message: https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L22
        Ad:      https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L28
        Nonce:   https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L25
        Key:     https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c#L14
        CT+tag:  https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.exp#L1

    IETF test vectors:
        https://tools.ietf.org/html/draft-arciszewski-xchacha-02#appendix-A.1
    """
    plaintext = \
        b"Ladies and Gentlemen of the class of '99: If I could offer you " \
        b"only one tip for the future, sunscreen would be it."

    ad = bytes.fromhex(
        '50515253c0c1c2c3c4c5c6c7')

    nonce = bytes.fromhex(
        '070000004041424344454647'
        '48494a4b4c4d4e4f50515253')

    key = bytes.fromhex(
        '8081828384858687'
        '88898a8b8c8d8e8f'
        '9091929394959697'
        '98999a9b9c9d9e9f')

    ct_tag = bytes.fromhex(
        'f8ebea4875044066'
        'fc162a0604e171fe'
        'ecfb3d2042524856'
        '3bcfd5a155dcc47b'
        'bda70b86e5ab9b55'
        '002bd1274c02db35'
        '321acd7af8b2e2d2'
        '5015e136b7679458'
        'e9f43243bf719d63'
        '9badb5feac03f80a'
        '19a96ef10cb1d153'
        '33a837b90946ba38'
        '54ee74da3f2585ef'
        'c7e1e170e17e15e5'
        '63e77601f4f85caf'
        'a8e5877614e143e6'
        '8420')

    nonce_ct_tag = nonce + ct_tag

    # ---

    ietf_nonce = bytes.fromhex(
        "404142434445464748494a4b4c4d4e4f"
        "5051525354555657")

    ietf_ct = bytes.fromhex(
        "bd6d179d3e83d43b9576579493c0e939"
        "572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39"
        "ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e"
        "3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13"
        "b52e")

    ietf_tag = bytes.fromhex(
        "c0875924c1c7987947deafd8780acf49")

    ietf_nonce_ct_tag = ietf_nonce + ietf_ct + ietf_tag

    @mock.patch('src.common.crypto.csprng', side_effect=[nonce, ietf_nonce])
    def test_encrypt_and_sign_with_official_test_vectors(self, mock_csprng):
        self.assertEqual(encrypt_and_sign(self.plaintext, self.key, self.ad),
                         self.nonce_ct_tag)

        self.assertEqual(encrypt_and_sign(self.plaintext, self.key, self.ad),
                         self.ietf_nonce_ct_tag)

        mock_csprng.assert_called_with(XCHACHA20_NONCE_LENGTH)

    def test_auth_and_decrypt_with_official_test_vectors(self):
        self.assertEqual(auth_and_decrypt(self.nonce_ct_tag, self.key, ad=self.ad),
                         self.plaintext)

        self.assertEqual(auth_and_decrypt(self.ietf_nonce_ct_tag, self.key, ad=self.ad),
                         self.plaintext)

    def test_invalid_key_size_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            encrypt_and_sign(self.plaintext, self.key + b'a')

        with self.assertRaises(SystemExit):
            auth_and_decrypt(self.nonce_ct_tag, self.key + b'a')

    def test_database_decryption_error_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            auth_and_decrypt(self.nonce_ct_tag, key=bytes(SYMMETRIC_KEY_LENGTH), database='path/database_filename')

    def test_error_in_decryption_of_data_from_contact_raises_nacl_crypto_error(self):
        with self.assertRaises(nacl.exceptions.CryptoError):
            auth_and_decrypt(self.nonce_ct_tag, key=bytes(SYMMETRIC_KEY_LENGTH))


class TestBytePadding(unittest.TestCase):
    """Unit tests of the cryptography library are available at
        https://github.com/pyca/cryptography/blob/master/tests/hazmat/primitives/test_padding.py
    """

    def test_padding_length_is_divisible_by_packet_length(self):
        padded_bytestrings = []

        for length in range(1000):
            string = length * b'm'
            padded = byte_padding(string)
            self.assertIsInstance(padded, bytes)
            self.assertEqual(len(padded) % PADDING_LENGTH, 0)

            padded_bytestrings.append(len(padded))
        self.assertNotEqual(len(list(set(padded_bytestrings))), 1)

    def test_packet_length_equal_to_padding_size_adds_dummy_block(self):
        string = PADDING_LENGTH * b'm'
        padded = byte_padding(string)
        self.assertEqual(len(padded), 2*PADDING_LENGTH)

    @mock.patch("cryptography.hazmat.primitives.padding.PKCS7",
                return_value=MagicMock(
                    padder=MagicMock(return_value=MagicMock(
                        update=MagicMock(return_value=b'a'),
                        finalize=MagicMock(return_value=PADDING_LENGTH*b'a')))))
    def test_invalid_padding_length_raises_critical_error(self, _):
        string = b'test_string'
        with self.assertRaises(SystemExit):
            byte_padding(string)


class TestRmPaddingBytes(unittest.TestCase):

    def test_removal_of_padding_does_not_alter_original_string(self):
        for length in range(1000):
            string = os.urandom(length)
            padded = byte_padding(string)
            self.assertEqual(rm_padding_bytes(padded), string)


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
