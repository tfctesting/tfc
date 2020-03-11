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

from typing import Dict, Tuple


update_dir = 'update_dir'
repo_path  = '/home/maqp/tfctesting'  # (no slash at end!)
print_up_to_dates = False

# Dependency tree in reverse order
package_file_name_start_dict = {

    # argon2_cffi
    'six': ('six-', 'SIX'),
        'pycparser': ('pycparser-', 'PYCPARSER'),
    'cffi': ('cffi-', 'CFFI'),
    'argon2-cffi': ('argon2_cffi-', 'ARGON2_CFFI'),

    # cryptography (pyca)
    # 'six': ('six-', 'SIX'),
    #     'pycparser': ('pycparser-', 'PYCPARSER'),
    # 'cffi': ('cffi-', 'CFFI'),
    # 'cryptography': ('cryptography-', 'CRYPTOGRAPHY'),  # Cryptography has wheel selection issues, its updated manually

    # Flask
        'Werkzeug': ('Werkzeug-', 'WERKZEUG'),
            'MarkupSafe': ('MarkupSafe-', 'MARKUPSAFE'),
        'Jinja2': ('Jinja2-', 'JINJA2'),
        'itsdangerous': ('itsdangerous-', 'ITSDANGEROUS'),
        'click': ('click-', 'CLICK'),
    'Flask': ('Flask-', 'FLASK'),

    # mypy static type checking tool
        'typing-extensions': ('typing_extensions-', 'NOT_IN_USE'),
        'typed-ast': ('typed_ast-', 'NOT_IN_USE'),
        'mypy-extensions': ('mypy_extensions-', 'NOT_IN_USE'),
    'mypy': ('mypy-', 'NOT_IN_USE'),

    # PyLama
        'pyflakes': ('pyflakes-', 'NOT_IN_USE'),
            'snowballstemmer': ('snowballstemmer-', 'NOT_IN_USE'),
        'pydocstyle': ('pydocstyle-', 'NOT_IN_USE'),
        'pycodestyle': ('pycodestyle-', 'NOT_IN_USE'),
        'mccabe': ('mccabe-', 'NOT_IN_USE'),
    'pylama': ('pylama-', 'NOT_IN_USE'),

    # PyNaCl (pyca)
        'setuptools': ('setuptools-', 'SETUPTOOLS'),
    'PyNaCl': ('PyNaCl-', 'PYNACL'),

    # pyserial
    'pyserial': ('pyserial-', 'PYSERIAL'),

    # PySocks
    'PySocks': ('PySocks-', 'PYSOCKS'),

    # pytest
        'wcwidth': ('wcwidth-', 'NOT_IN_USE'),
        'py': ('py-', 'NOT_IN_USE'),
                'zipp': ('zipp-', 'NOT_IN_USE'),
            'importlib-metadata': ('importlib_metadata-', 'NOT_IN_USE'),
        'pluggy': ('pluggy-', 'NOT_IN_USE'),
            # 'six': ('six-', 'NOT_IN_USE'),
            'pyparsing': ('pyparsing-', 'NOT_IN_USE'),
        'packaging': ('packaging-', 'NOT_IN_USE'),
        'more-itertools': ('more_itertools-', 'NOT_IN_USE'),
        #     'zipp': ('zipp-', 'NOT_IN_USE'),
        # 'importlib-metadata': ('importlib_metadata-', 'NOT_IN_USE'),
        'attrs': ('attrs-', 'NOT_IN_USE'),
    'pytest': ('pytest-', 'NOT_IN_USE'),

    # pytest-cov
    # 'pytest': ('pytest-', 'NOT_IN_USE'),
    'coverage': ('coverage-', 'NOT_IN_USE'),
    'pytest-cov': ('pytest_cov-', 'NOT_IN_USE'),

    # xdist: pytest distributed testing plugin
        # 'six': ('six-', 'NOT_IN_USE'),
        # 'pytest': ('pytest-', 'NOT_IN_USE'),
        'pytest-forked': ('pytest_forked-', 'NOT_IN_USE'),
        # 'pytest': ('pytest-', 'NOT_IN_USE'),
            'apipkg': ('apipkg-', 'NOT_IN_USE'),
        'execnet': ('execnet-', 'NOT_IN_USE'),
    'pytest-xdist': ('pytest_xdist-', 'NOT_IN_USE'),

    # Requests
    'urllib3': ('urllib3-', 'URLLIB3'),
    'idna': ('idna-', 'IDNA'),
    'chardet': ('chardet-', 'CHARDET'),
    'certifi': ('certifi-', 'CERTIFI'),
    'requests': ('requests-', 'REQUESTS'),

    # Stem
    'stem': ('stem-', 'NOT_IN_USE'),

    # Virtualenv
    # 'six': ('six-', 'SIX'),
    #     'zipp': ('zipp-', 'ZIPP'),
    # 'importlib-metadata': ('importlib_metadata-', 'IMPORTLIB_METADATA'),
    'filelock': ('filelock-', 'FILELOCK'),
    'distlib': ('distlib-', 'DISTLIB'),
    'appdirs': ('appdirs-', 'APPDIRS'),
    'virtualenv': ('virtualenv-', 'VIRTUALENV'),
}  # type: Dict[str, Tuple[str, str]]


def move_to_temp_update_dir():
    """Move to clean temporary directory for the update."""
    try:
        os.mkdir(update_dir)
    except FileExistsError:
        shutil.rmtree(update_dir)
        os.mkdir(update_dir)
    os.chdir(update_dir)


def get_file_sha512_digest(file_name: str) -> str:
    """Get SHA512-digest of file."""
    with open(file_name, 'rb') as f:
        data = f.read()
        return hashlib.sha512(data).hexdigest()


def change_dependency_file_name_in_installer(package_name: str, new_file_name: str) -> None:
    """Change name of the dependency file."""
    # Read install.sh
    with open(f'{repo_path}/install.sh') as f:
        data = f.read().splitlines()

    # Change file name in memory
    static = package_file_name_start_dict[package_name][1]

    for index, line in enumerate(data):
        if line.startswith(static + '='):
            old_file_name = line.split('=')[1]
            if old_file_name != new_file_name:
                new_line = '='.join([static, new_file_name])
                data[index] = new_line
                print(f"install.sh:                   Updated {package_name}'s file name to '{new_file_name}'")
                break
    else:
        if print_up_to_dates:
            print(f"install.sh:                   Up-to-date f name for {package_name}")

    # Write new file name from memory to install.sh
    with open(f'{repo_path}/install.sh', 'w+') as f:
        for line in data:
            f.write(line + '\n')


def update_dependency_digest_in_installer(package_name: str, new_digest: str) -> None:
    """Update SHA512 hash of dependency in installer."""
    # Read install.sh
    with open(f'{repo_path}/install.sh') as f:
        data = f.read().splitlines()

    # Change dependency digest in memory
    static = package_file_name_start_dict[package_name][1]

    for index, line in enumerate(data):
        if line.startswith('    compare_digest') and line.endswith('${%s}' % static):
            line_data  = line.split(' ')
            old_digest = line_data[5]

            if old_digest != new_digest:
                line_data[5] = new_digest
                new_line     = ' '.join(line_data)
                data[index]  = new_line
                print(f"install:sh:                   Updated digest for {package_name} to '{new_digest}'")
    else:
        if print_up_to_dates:
            print(f"install.sh:                   Up-to-date digest for {package_name}")

    # Write new digest from memory to install.sh
    with open(f'{repo_path}/install.sh', 'w+') as f:
        for line in data:
            f.write(line + '\n')


def update_dependency_version_in_requirements_files(package_name: str, new_digest: str) -> None:

    for requirement_file in ['requirements.txt',
                             'requirements-relay.txt',
                             'requirements-relay-tails.txt',
                             'requirements-setuptools.txt',
                             'requirements-venv.txt']:

        with open(f'{repo_path}/{requirement_file}') as f:
            requirements_data = f.read().splitlines()
        with open(f'{repo_path}/install.sh') as f:
            installer_data = f.read().splitlines()

        final_index    = None
        old_version    = None
        latest_version = None
        old_digest     = None

        # Find package name, old version and old digest from requirements file.
        for line_index, line in enumerate(requirements_data):
            fields = line.split(' ')

            # Filter unnecessary requirements file lines
            if fields[0].startswith('#') or fields[0].startswith(' ') or fields[0] =='':
                continue

            purp_package_name, old_version = fields[0].split('==')

            if purp_package_name != package_name:
                continue

            final_index = line_index
            old_digest  = fields[-1].split(':')[1]
            break

        # Read updated install.sh for file name and parse new version from it.
        for line in installer_data:
            installer_static = package_file_name_start_dict[package_name][1]
            if line.startswith(f"{installer_static}="):
                pinned_file_name = line.split('=')[1]
                latest_version   = pinned_file_name.split('-')[1].strip('.zip')
                break

        # Check that version and digest are correct
        if final_index is not None \
                and old_version is not None \
                and latest_version is not None \
                and old_digest is not None:
            if old_version != latest_version or old_digest != new_digest:

                old_line = requirements_data[final_index]
                new_line = old_line\
                    .replace(old_digest, new_digest) \
                    .replace(old_version, latest_version)
                requirements_data[final_index] = new_line

                with open(f'{repo_path}/{requirement_file}', 'w+') as f:
                    for line in requirements_data:
                        f.write(line + '\n')

                spacing = (28-len(requirement_file)) * ' '
                if old_version != latest_version:
                    print(f"{requirement_file}:{spacing} Updated {package_name}'s version to '{latest_version}'")
                if old_digest != new_digest:
                    print(f"{requirement_file}:{spacing} Updated {package_name}'s digest  to '{new_digest}'")

            else:
                if print_up_to_dates:
                    spacing = (28-len(requirement_file)) * ' '
                    print(f"{requirement_file}:{spacing} Up-to-date vers.  for {package_name}")
                    print(f"{requirement_file}:{spacing} Up-to-date digest for {package_name}")


def update_dependency_in_requirements_dev_file() -> None:
    """Update digestless dependency in requirements-dev.txt"""

    with open(f'{repo_path}/requirements-dev.txt') as f:
        requirements_data = f.read().splitlines()

    for package_name in package_file_name_start_dict.keys():
        file_start_str = package_file_name_start_dict[package_name][0]
        file_name      = [f for f in os.listdir('.') if f.startswith(file_start_str)][0]
        latest_version = file_name.split('-')[1].strip('.zip').strip('tar.gz')

        for index, line in enumerate(requirements_data):
            if line.startswith('#') or ">=" not in line:
                continue
            package, old_version = line.split(">=")
            if package != package_name:
                continue

            if latest_version != old_version:
                requirements_data[index] = f"{package}>={latest_version}"
                print(f"requirements-dev.txt:         Updated {package} to at use at least {latest_version}")
        else:
            if print_up_to_dates:
                print(f"requirements-dev.txt:         Up-to-date minimum version for {package_name}")

    with open(f'{repo_path}/requirements-dev.txt', 'w+') as f:
        for line in requirements_data:
            f.write(line + '\n')


def update_dependency(package_name: str) -> None:
    file_start_str    = package_file_name_start_dict[package_name][0]
    try:
        new_file_name     = [filename for filename in os.listdir('.') if filename.startswith(file_start_str)][0]
    except IndexError:
        print(f"Error: Could not find file name for package '{package_name}'.")
        exit(1)
    new_sha512_digest = get_file_sha512_digest(new_file_name)

    change_dependency_file_name_in_installer(package_name, new_file_name)
    update_dependency_digest_in_installer(package_name, new_sha512_digest)
    update_dependency_version_in_requirements_files(package_name, new_sha512_digest)


def main():
    os.chdir(repo_path+'/')
    move_to_temp_update_dir()
    for dep in package_file_name_start_dict.keys():
        subprocess.Popen(f"python3.7 -m pip download {dep.lower()}", shell=True).wait()

    for dep in package_file_name_start_dict.keys():
        update_dependency(dep)

    update_dependency_in_requirements_dev_file()

    os.chdir(repo_path+'/')
    shutil.rmtree(update_dir)

    print("\nUpdates completed. Remember to check for cryptography updates "
          "manually due to inconsistent manylinux wheel problem!\n")


if __name__ == '__main__':
    main()
