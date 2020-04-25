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

import hashlib
import os
import shutil
import subprocess

from typing import Dict, List, Optional


WORKING_DIR = '/home/user/tfc'
TESTING_DIR = ''  # Must include slash!

REQ_FILE_DEV   = 'requirements-dev.txt'
REQ_FILE_NET   = 'requirements-relay.txt'
REQ_FILE_SUT   = 'requirements-setuptools.txt'
REQ_FILE_TAILS = 'requirements-relay-tails.txt'
REQ_FILE_TCB   = 'requirements.txt'
REQ_FILE_VENV  = 'requirements-venv.txt'

persistent = False  # When True, uses cached dependencies.
debug      = True   # When True, prints debug messages

# Dependency statics
APIPKG = 'APIPKG'
APPDIRS = 'APPDIRS'
ARGON2_CFFI = 'ARGON2_CFFI'
ATTRS = 'ATTRS'
CERTIFI = 'CERTIFI'
CFFI = 'CFFI'
CHARDET = 'CHARDET'
CLICK = 'CLICK'
COVERAGE = 'COVERAGE'
CRYPTOGRAPHY = 'CRYPTOGRAPHY'
DISTLIB = 'DISTLIB'
EXECNET = 'EXECNET'
FLASK = 'FLASK'
FILELOCK = 'FILELOCK'
IDNA = 'IDNA'
IMPORTLIB_METADATA = 'IMPORTLIB_METADATA'
ITSDANGEROUS = 'ITSDANGEROUS'
JINJA2 = 'JINJA2'
MARKUPSAFE = 'MARKUPSAFE'
MCCABE = 'MCCABE'
MORE_ITERTOOLS = 'MORE_ITERTOOLS'
MYPY = 'MYPY'
MYPY_EXTENSIONS = 'MYPY_EXTENSIONS'
PACKAGING = 'PACKAGING'
PLUGGY = 'PLUGGY'
PY = 'PY'
PYCODESTYLE = 'PYCODESTYLE'
PYCPARSER = 'PYCPARSER'
PYDOCSTYLE = 'PYDOCSTYLE'
PYFLAKES = 'PYFLAKES'
PYLAMA = 'PYLAMA'
PYNACL = 'PYNACL'
PYPARSING = 'PYPARSING'
PYSERIAL = 'PYSERIAL'
PYSOCKS = 'PYSOCKS'
PYTEST = 'PYTEST'
PYTEST_COV = 'PYTEST_COV'
PYTEST_FORKED = 'PYTEST_FORKED'
PYTEST_XDIST = 'PYTEST_XDIST'
REQUESTS = 'REQUESTS'
SETUPTOOLS = 'SETUPTOOLS'
SIX = 'SIX'
SNOWBALLSTEMMER = 'SNOWBALLSTEMMER'
STEM = 'STEM'
TYPED_AST = 'TYPED_AST'
TYPING_EXTENSIONS = 'TYPING_EXTENSIONS'
URLLIB3 = 'URLLIB3'
VIRTUALENV = 'VIRTUALENV'
WCWIDTH = 'WCWIDTH'
WERKZEUG = 'WERKZEUG'
ZIPP = 'ZIPP'

PINNED_FILES = [
    "APPDIRS",
    "ARGON2_CFFI",
    "CERTIFI",
    "CFFI37",
    "CFFI38",
    "CHARDET",
    "CLICK",
    "CRYPTOGRAPHY37",
    "CRYPTOGRAPHY38",
    "DISTLIB",
    "FILELOCK",
    "FLASK",
    "IDNA",
    "IMPORTLIB_METADATA",
    "ITSDANGEROUS",
    "JINJA2",
    "MARKUPSAFE37",
    "MARKUPSAFE38",
    "PYCPARSER",
    "PYNACL",
    "PYSERIAL",
    "PYSOCKS",
    "REQUESTS",
    "SETUPTOOLS",
    "SIX",
    "URLLIB3",
    "VIRTUALENV",
    "WERKZEUG",
    "ZIPP"
]  # type: List[str]


def print_debug(string: str) -> None:
    if debug:
        print(f"Debug: {string}")


def create_file_digest(file_name: str) -> str:
    """Create the SHA512 digest of a dependency file."""
    with open(file_name, 'rb') as f:
        data = f.read()
    digest = hashlib.sha512(data).hexdigest()
    return digest


def create_and_change_to_download_directory():
    """Create download directory for the dependencies."""
    if TESTING_DIR:
        os.chdir(WORKING_DIR)
        try:
            os.mkdir(TESTING_DIR)
        except FileExistsError:
            if not persistent:
                shutil.rmtree(TESTING_DIR)
                os.mkdir(TESTING_DIR)
                os.chdir(TESTING_DIR)
        os.chdir(TESTING_DIR)


class Dependency(object):
    """A dependency object represents one dependency installed with PIP."""

    def __init__(self,
                 uid:              str,
                 stylized_name:    str,
                 pip_name:         str,
                 description_dict: Optional[Dict[str, str]] = None,
                 manual_py37_url:  Optional[str] = None,
                 manual_py38_url:  Optional[str] = None,
                 sub_dependencies: Optional[List[str]] = None
                 ) -> None:
        self.uid              = uid
        self.stylized_name    = stylized_name
        self.pip_name         = pip_name
        self.description_dict = description_dict
        self.manual_py37_url  = manual_py37_url
        self.manual_py38_url  = manual_py38_url
        self.sub_dependencies = sub_dependencies

        self.latest_file_name_py37  = None  # type: Optional[str]
        self.latest_file_name_py38  = None  # type: Optional[str]
        self.latest_version         = None  # type: Optional[str]
        self.latest_digest_py37     = None  # type: Optional[str]
        self.latest_digest_py38     = None  # type: Optional[str]

    def fetch_attributes(self) -> None:
        """Download packages from PyPI and parse attributes."""
        self.setup()

        if self.manual_py37_url is None:
            subprocess.Popen(f"python3.7 -m pip download {self.pip_name} --no-deps", shell=True).wait()
        else:
            subprocess.Popen(f"wget {self.manual_py37_url}", shell=True).wait()

        self.latest_file_name_py37 = os.listdir('.')[0]
        self.latest_digest_py37    = create_file_digest(self.latest_file_name_py37)
        self.latest_version        = self.get_latest_version_from_file_name(self.latest_file_name_py37)
        assert len(os.listdir('.')) == 1

        if self.manual_py38_url is None:
            subprocess.Popen(f"python3.8 -m pip download {self.pip_name} --no-deps", shell=True).wait()
        else:
            subprocess.Popen(f"wget {self.manual_py38_url}", shell=True).wait()

        if len(os.listdir('.')) == 2:
            os.remove(self.latest_file_name_py37)
            self.latest_file_name_py38 = os.listdir('.')[0]
            self.latest_digest_py38    = create_file_digest(self.latest_file_name_py38)
            assert self.get_latest_version_from_file_name(self.latest_file_name_py38) == self.latest_version

        self.teardown()

    def generate_dev_string(self, file_name: str) -> str:
        """Generate requirements-dev.txt string for dependency."""
        requirements_string = ''
        if self.description_dict is not None:
            if file_name in self.description_dict.keys():
                description = self.description_dict[file_name]
                requirements_string += f"\n# {description}\n"
        requirements_string += f"{self.pip_name}>={self.latest_version}\n"
        return requirements_string

    def generate_production_string(self, file_name: str, max_spacing: int) -> str:
        """Generate requirements-file string for dependency."""
        requirements_string = ''
        if self.description_dict is not None:
            if file_name in self.description_dict.keys():
                description         = self.description_dict[file_name]
                requirements_string = f"\n# {description}\n"

        name_and_version = f"{self.pip_name}=={self.latest_version}"
        spacing          = (max_spacing - len(name_and_version)) * ' '

        requirements_string += name_and_version
        requirements_string += spacing
        requirements_string += '  --hash=sha512:'
        requirements_string += self.latest_digest_py37

        if self.latest_digest_py38 is not None:
            requirements_string += ' \\\n'
            requirements_string += max_spacing * ' '
            requirements_string += '  --hash=sha512:'
            requirements_string += self.latest_digest_py38
        requirements_string += '\n'

        return requirements_string

    def setup(self):
        os.mkdir(self.uid)
        os.chdir(self.uid)

    def teardown(self):
        os.chdir('..')
        shutil.rmtree(self.uid)

    @staticmethod
    def get_latest_version_from_file_name(file_name: str) -> str:
        """Parse latest dependency version from file name."""
        for extension in ['.tar.gz', '.zip']:
            if file_name.endswith(extension):
                trunc_len = len(extension)
                return file_name.split('-', 2)[1][:-trunc_len]
        return file_name.split('-', 2)[1]


class RequirementsFile(object):
    """RequirementsFile object contains list of dependencies and their hashes."""

    def __init__(self,
                 file_name:       str,
                 dependency_dict: Dict[str, Dependency],
                 dependencies:    List[str]
                 ) -> None:
        self.file_name       = file_name
        self.dependency_dict = dependency_dict
        self.dependencies    = dependencies

    def generate_file(self):
        with open(f"{self.file_name}", 'w+') as f:

            dependency_uid_list = []
            for dependency_uid in self.dependencies:
                dependency_uid_list.append(dependency_uid)
                dependency = self.dependency_dict[dependency_uid]
                self.check_sub_dependencies(dependency_uid_list, dependency)

            if len(dependency_uid_list) > 1:
                f.writelines("# Sub-dependencies are listed below dependencies\n")

            dependency_list = [self.dependency_dict[d] for d in dependency_uid_list]
            max_spacing     = max([len(f"{d.pip_name}=={d.latest_version}") for d in dependency_list])

            for dependency_uid in dependency_uid_list:
                dependency = self.dependency_dict[dependency_uid]

                if self.file_name == REQ_FILE_DEV:
                    f.writelines(dependency.generate_dev_string(self.file_name))
                else:
                    f.writelines(dependency.generate_production_string(self.file_name, max_spacing))

    def check_sub_dependencies(self, dependency_uid_list: List[str], dependency: Dependency):
        """Add subdependencies of dependency to list of dependency UIDs."""

        if dependency.sub_dependencies is not None:
            for sub_dependency_uid in dependency.sub_dependencies:
                if sub_dependency_uid not in dependency_uid_list:
                    dependency_uid_list.append(sub_dependency_uid)

                sub_dependency = self.dependency_dict[sub_dependency_uid]

                # Recursive search of deeper sub-dependencies
                self.check_sub_dependencies(dependency_uid_list, sub_dependency)


def update_installer_file_names(dependency_dict):
    # Read install.sh
    with open(f"{WORKING_DIR}/install.sh") as f:
        data = f.read().splitlines()

    for file_name_uid in PINNED_FILES:
        if file_name_uid.endswith('37'):
            file_name_uid_ = file_name_uid[:-2]
            dependency = dependency_dict[file_name_uid_]
            new_file_name = dependency.latest_file_name_py37
        elif file_name_uid.endswith('38'):
            file_name_uid_ = file_name_uid[:-2]
            dependency = dependency_dict[file_name_uid_]
            new_file_name = dependency.latest_file_name_py38
        else:
            dependency = dependency_dict[file_name_uid]
            new_file_name = dependency.latest_file_name_py37

        for index, line in enumerate(data):
            if line.startswith(file_name_uid + '='):
                old_file_name = line.split('=')[1]

                if old_file_name != new_file_name:
                    new_line = '='.join([file_name_uid, new_file_name])
                    data[index] = new_line
                    break

    # Write new file name from memory to install.sh
    with open(f'{WORKING_DIR}/install.sh', 'w+') as f:
        for line in data:
            f.write(line + '\n')


def update_installer_digests(dependency_dict):
    # Read install.sh
    with open(f'{WORKING_DIR}/install.sh') as f:
        data = f.read().splitlines()

    # Change dependency digest in memory
    for index, line in enumerate(data):
        if line.startswith('DIGEST_'):

            identifier, old_digest = line.split('=')
            trunc_identifier = identifier[len('DIGEST_'):]

            dependency = dependency_dict[trunc_identifier]  # type: Dependency
            new_digest = dependency.latest_digest_py37

            if old_digest != new_digest:
                new_line = '='.join([identifier, new_digest])
                data[index] = new_line

    # Write new digest from memory to install.sh
    with open(f'{WORKING_DIR}/install.sh', 'w+') as f:
        for line in data:
            f.write(line + '\n')


def main() -> None:

    create_and_change_to_download_directory()

    dependency_dict = {
        APIPKG:             Dependency(uid=APIPKG,             stylized_name='apipkg',             pip_name='apipkg',             sub_dependencies=None),
        APPDIRS:            Dependency(uid=APPDIRS,            stylized_name='appdirs',            pip_name='appdirs',            sub_dependencies=None),
        ARGON2_CFFI:        Dependency(uid=ARGON2_CFFI,        stylized_name='argon2-cffi',        pip_name='argon2-cffi',        sub_dependencies=[CFFI, SIX],
                                       description_dict={REQ_FILE_DEV: 'Argon2 Password Hashing Function (Derives keys that protect persistent user data)',
                                                         REQ_FILE_TCB: 'Argon2 Password Hashing Function (Derives keys that protect persistent user data)'}),
        ATTRS:              Dependency(uid=ATTRS,              stylized_name='attrs',              pip_name='attrs',              sub_dependencies=None),
        CERTIFI:            Dependency(uid=CERTIFI,            stylized_name='Certifi',            pip_name='certifi',            sub_dependencies=None),
        CFFI:               Dependency(uid=CFFI,               stylized_name='CFFI',               pip_name='cffi',               sub_dependencies=[PYCPARSER]),
        CHARDET:            Dependency(uid=CHARDET,            stylized_name='chardet',            pip_name='chardet',            sub_dependencies=None),
        CLICK:              Dependency(uid=CLICK,              stylized_name='Click',              pip_name='click',              sub_dependencies=None),
        COVERAGE:           Dependency(uid=COVERAGE,           stylized_name='Coverage.py',        pip_name='coverage',           sub_dependencies=None),
        CRYPTOGRAPHY:       Dependency(uid=CRYPTOGRAPHY,       stylized_name='cryptography',       pip_name='cryptography',       sub_dependencies=[CFFI, SIX],
                                       description_dict={REQ_FILE_DEV:   'cryptography (pyca) (Provides X448 key exchange)',
                                                         REQ_FILE_TCB:   'cryptography (pyca) (Handles TCB-side X448 key exchange)',
                                                         REQ_FILE_NET:   'cryptography (pyca) (Handles URL token derivation)',
                                                         REQ_FILE_TAILS: 'cryptography (pyca) (Handles URL token derivation)'},
                                       manual_py37_url="https://files.pythonhosted.org/packages/58/95/f1282ca55649b60afcf617e1e2ca384a2a3e7a5cf91f724cf83c8fbe76a1/cryptography-2.9.2-cp35-abi3-manylinux1_x86_64.whl",
                                       manual_py38_url="https://files.pythonhosted.org/packages/3c/04/686efee2dcdd25aecf357992e7d9362f443eb182ecd623f882bc9f7a6bba/cryptography-2.9.2-cp35-abi3-manylinux2010_x86_64.whl"),
        DISTLIB:            Dependency(uid=DISTLIB,            stylized_name='distlib',            pip_name='distlib',            sub_dependencies=None),
        EXECNET:            Dependency(uid=EXECNET,            stylized_name='execnet',            pip_name='execnet',            sub_dependencies=[APIPKG]),
        FILELOCK:           Dependency(uid=FILELOCK,           stylized_name='py-filelock',        pip_name='filelock',           sub_dependencies=None),
        FLASK:              Dependency(uid=FLASK,              stylized_name='Flask',              pip_name='Flask',              sub_dependencies=[CLICK, ITSDANGEROUS, JINJA2, WERKZEUG],
                                       description_dict={REQ_FILE_DEV:   'Flask (Onion Service web server that serves TFC public keys and ciphertexts to contacts)',
                                                         REQ_FILE_NET:   'Flask (Onion Service web server that serves TFC public keys and ciphertexts to contacts)',
                                                         REQ_FILE_TAILS: 'Flask (Onion Service web server that serves TFC public keys and ciphertexts to contacts)'}),
        IDNA:               Dependency(uid=IDNA,               stylized_name='IDNA',               pip_name='idna',               sub_dependencies=None),
        IMPORTLIB_METADATA: Dependency(uid=IMPORTLIB_METADATA, stylized_name='importlib_metadata', pip_name='importlib-metadata', sub_dependencies=[ZIPP]),
        ITSDANGEROUS:       Dependency(uid=ITSDANGEROUS,       stylized_name='ItsDangerous',       pip_name='itsdangerous',       sub_dependencies=None),
        JINJA2:             Dependency(uid=JINJA2,             stylized_name='Jinja2',             pip_name='Jinja2',             sub_dependencies=[MARKUPSAFE]),
        MARKUPSAFE:         Dependency(uid=MARKUPSAFE,         stylized_name='MarkupSafe',         pip_name='MarkupSafe',         sub_dependencies=None),
        MCCABE:             Dependency(uid=MCCABE,             stylized_name='McCabe',             pip_name='mccabe',             sub_dependencies=None),
        MORE_ITERTOOLS:     Dependency(uid=MORE_ITERTOOLS,     stylized_name='More Itertools',     pip_name='more-itertools',     sub_dependencies=None),
        MYPY:               Dependency(uid=MYPY,               stylized_name='mypy',               pip_name='mypy',               sub_dependencies=[MYPY_EXTENSIONS, TYPED_AST, TYPING_EXTENSIONS],
                                       description_dict={REQ_FILE_DEV: 'mypy (Static type checking tool)'}),
        MYPY_EXTENSIONS:    Dependency(uid=MYPY_EXTENSIONS,    stylized_name='Mypy Extensions',    pip_name='mypy-extensions',    sub_dependencies=None),
        PACKAGING:          Dependency(uid=PACKAGING,          stylized_name='packaging',          pip_name='packaging',          sub_dependencies=[PYPARSING, SIX]),
        PLUGGY:             Dependency(uid=PLUGGY,             stylized_name='pluggy',             pip_name='pluggy',             sub_dependencies=[IMPORTLIB_METADATA]),
        PY:                 Dependency(uid=PY,                 stylized_name='py',                 pip_name='py',                 sub_dependencies=None),
        PYCODESTYLE:        Dependency(uid=PYCODESTYLE,        stylized_name='pycodestyle',        pip_name='pycodestyle',        sub_dependencies=None),
        PYCPARSER:          Dependency(uid=PYCPARSER,          stylized_name='pycparser',          pip_name='pycparser',          sub_dependencies=None),
        PYDOCSTYLE:         Dependency(uid=PYDOCSTYLE,         stylized_name='pydocstyle',         pip_name='pydocstyle',         sub_dependencies=[SNOWBALLSTEMMER]),
        PYFLAKES:           Dependency(uid=PYFLAKES,           stylized_name='Pyflakes',           pip_name='pyflakes',           sub_dependencies=None),
        PYLAMA:             Dependency(uid=PYLAMA,             stylized_name='Pylama',             pip_name='pylama',             sub_dependencies=[MCCABE, PYCODESTYLE, PYDOCSTYLE, PYFLAKES],
                                       description_dict={REQ_FILE_DEV: 'PyLama (Code audit tool for Python)'}),
        PYNACL:             Dependency(uid=PYNACL,             stylized_name='PyNaCl',             pip_name='PyNaCl',             sub_dependencies=[CFFI, SIX],
                                       description_dict={REQ_FILE_DEV:   'PyNaCl (pyca) (Handles TCB-side XChaCha20-Poly1305 symmetric encryption and Derives TFC account from Onion Service private key)',
                                                         REQ_FILE_NET:   'PyNaCl (pyca) (Derives TFC account from Onion Service private key)',
                                                         REQ_FILE_TAILS: 'PyNaCl (pyca) (Derives TFC account from Onion Service private key)',
                                                         REQ_FILE_TCB:   'PyNaCl (pyca) (Handles TCB-side XChaCha20-Poly1305 symmetric encryption)'}),
        PYPARSING:          Dependency(uid=PYPARSING,          stylized_name='PyParsing',          pip_name='pyparsing',          sub_dependencies=None),
        PYSERIAL:           Dependency(uid=PYSERIAL,           stylized_name='pySerial',           pip_name='pyserial',           sub_dependencies=None,
                                       description_dict={REQ_FILE_DEV:   'pySerial (Connects the Source/Destination Computer to the Networked Computer)',
                                                         REQ_FILE_NET:   'pySerial (Connects the Source/Destination Computer to the Networked Computer)',
                                                         REQ_FILE_TAILS: 'pySerial (Connects the Source/Destination Computer to the Networked Computer)',
                                                         REQ_FILE_TCB:   'pySerial (Connects the Source/Destination Computer to the Networked Computer)'}),
        PYSOCKS:            Dependency(uid=PYSOCKS,            stylized_name='PySocks',            pip_name='PySocks',            sub_dependencies=None,
                                       description_dict={REQ_FILE_DEV:   'PySocks (Routes Requests library through SOCKS5 proxy making Onion Service connections possible)',
                                                         REQ_FILE_NET:   'PySocks (Routes Requests library through SOCKS5 proxy making Onion Service connections possible)',
                                                         REQ_FILE_TAILS: 'PySocks (Routes Requests library through SOCKS5 proxy making Onion Service connections possible)'}),
        PYTEST:             Dependency(uid=PYTEST,             stylized_name='pytest',             pip_name='pytest',             sub_dependencies=[ATTRS, IMPORTLIB_METADATA, MORE_ITERTOOLS, PACKAGING, PLUGGY, PY, WCWIDTH],
                                       description_dict={REQ_FILE_DEV: 'pytest (Test framework)'}),
        PYTEST_COV:         Dependency(uid=PYTEST_COV,         stylized_name='pytest-cov',         pip_name='pytest-cov',         sub_dependencies=[COVERAGE, PYTEST],
                                       description_dict={REQ_FILE_DEV: 'pytest-cov (Pytest plugin for measuring coverage)'}),
        PYTEST_FORKED:      Dependency(uid=PYTEST_FORKED,      stylized_name='pytest-forked',      pip_name='pytest-forked',      sub_dependencies=[PYTEST]),
        PYTEST_XDIST:       Dependency(uid=PYTEST_XDIST,       stylized_name='xdist',              pip_name='pytest-xdist',       sub_dependencies=[EXECNET, PYTEST, PYTEST_FORKED, SIX],
                                       description_dict={REQ_FILE_DEV: 'xdist (Pytest distributed testing plugin)'}),
        REQUESTS:           Dependency(uid=REQUESTS,           stylized_name='Requests',           pip_name='requests',           sub_dependencies=[CERTIFI, CHARDET, IDNA, URLLIB3],
                                       description_dict={REQ_FILE_DEV:   "Requests (Connects to the contact's Tor Onion Service)",
                                                         REQ_FILE_NET:   "Requests (Connects to the contact's Tor Onion Service)",
                                                         REQ_FILE_TAILS: "Requests (Connects to the contact's Tor Onion Service)"}),
        SETUPTOOLS:         Dependency(uid=SETUPTOOLS,         stylized_name='Setuptools',         pip_name='setuptools',         sub_dependencies=None),
        SIX:                Dependency(uid=SIX,                stylized_name='six',                pip_name='six',                sub_dependencies=None),
        SNOWBALLSTEMMER:    Dependency(uid=SNOWBALLSTEMMER,    stylized_name='snowballstemmer',    pip_name='snowballstemmer',    sub_dependencies=None),
        STEM:               Dependency(uid=STEM,               stylized_name='Stem',               pip_name='stem',               sub_dependencies=None,
                                       description_dict={REQ_FILE_DEV:   'Stem (Connects to Tor and manages Onion Services)',
                                                         REQ_FILE_NET:   'Stem (Connects to Tor and manages Onion Services)',
                                                         REQ_FILE_TAILS: 'Stem (Connects to Tor and manages Onion Services)'}),
        TYPED_AST:          Dependency(uid=TYPED_AST,          stylized_name='Typed AST',          pip_name='typed-ast',          sub_dependencies=None),
        TYPING_EXTENSIONS:  Dependency(uid=TYPING_EXTENSIONS,  stylized_name='Typing Extensions',  pip_name='typing-extensions',  sub_dependencies=None),
        URLLIB3:            Dependency(uid=URLLIB3,            stylized_name='urllib3',            pip_name='urllib3',            sub_dependencies=None),
        VIRTUALENV:         Dependency(uid=VIRTUALENV,         stylized_name='virtualenv',         pip_name='virtualenv',         sub_dependencies=[APPDIRS, DISTLIB, FILELOCK, IMPORTLIB_METADATA, SIX],
                                       description_dict={REQ_FILE_VENV: 'Virtual environment (Used to create an isolated Python environment for TFC dependencies)'}),
        WCWIDTH:            Dependency(uid=WCWIDTH,            stylized_name='wcwidth',            pip_name='wcwidth',            sub_dependencies=None),
        WERKZEUG:           Dependency(uid=WERKZEUG,           stylized_name='Werkzeug',           pip_name='Werkzeug',           sub_dependencies=None),
        ZIPP:               Dependency(uid=ZIPP,               stylized_name='zipp',               pip_name='zipp',               sub_dependencies=None)
    }

    for dependency_uid in dependency_dict.keys():
        dependency = dependency_dict[dependency_uid]
        dependency.fetch_attributes()

    requirements = RequirementsFile(file_name=REQ_FILE_TCB,
                                    dependency_dict=dependency_dict,
                                    dependencies=[PYSERIAL,
                                                  ARGON2_CFFI,
                                                  CRYPTOGRAPHY,
                                                  PYNACL,
                                                  SETUPTOOLS
                                                  ])

    requirements_r = RequirementsFile(file_name=REQ_FILE_NET,
                                      dependency_dict=dependency_dict,
                                      dependencies=[PYSERIAL,
                                                    STEM,
                                                    PYSOCKS,
                                                    REQUESTS,
                                                    FLASK,
                                                    CRYPTOGRAPHY,
                                                    PYNACL,
                                                    SETUPTOOLS
                                                    ])

    requirements_rt = RequirementsFile(file_name=REQ_FILE_TAILS,
                                       dependency_dict=dependency_dict,
                                       dependencies=[PYSERIAL,
                                                     # STEM,  # Not needed ATM
                                                     PYSOCKS,
                                                     REQUESTS,
                                                     FLASK,
                                                     CRYPTOGRAPHY,
                                                     PYNACL,
                                                     SETUPTOOLS
                                                     ])

    requirements_setuptools = RequirementsFile(file_name=REQ_FILE_SUT,
                                               dependency_dict=dependency_dict,
                                               dependencies=[SETUPTOOLS])

    requirements_venv = RequirementsFile(file_name=REQ_FILE_VENV,
                                         dependency_dict=dependency_dict,
                                         dependencies=[VIRTUALENV])

    requirements_dev = RequirementsFile(file_name=REQ_FILE_DEV,
                                        dependency_dict=dependency_dict,
                                        dependencies=[ARGON2_CFFI,
                                                      CRYPTOGRAPHY,
                                                      FLASK,
                                                      MYPY,
                                                      PYLAMA,
                                                      PYNACL,
                                                      PYSERIAL,
                                                      PYSOCKS,
                                                      PYTEST,
                                                      PYTEST_COV,
                                                      PYTEST_XDIST,
                                                      REQUESTS,
                                                      SETUPTOOLS,
                                                      STEM
                                                      ])

    requirements.generate_file()
    requirements_r.generate_file()
    requirements_rt.generate_file()
    requirements_setuptools.generate_file()
    requirements_venv.generate_file()
    requirements_dev.generate_file()

    update_installer_file_names(dependency_dict)
    update_installer_digests(dependency_dict)


if __name__ == '__main__':
    main()
