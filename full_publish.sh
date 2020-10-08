#!/usr/bin/env bash

# TFC - Onion-routed, endpoint secure messaging system
# Copyright (C) 2013-2020  Markus Ottela
#
# This file is part of TFC.
#
# TFC is free software: you can redistribute it and/or modify it under the terms
# of the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with TFC. If not, see <https://www.gnu.org/licenses/>.
#
# --------------------------------------------------------------------------------

set -e

# Change to working directory
cd /home/user/tfc/

# Update dependencies
python3.7 /home/user/tfc/auto_dependency_updater.py

# Run tests on Python 3.7 and 3.8
minor_versions="7 8"
for minor_v in ${minor_versions}; do
    interpreter=python3.${minor_v}
    venv_name=venv_tfc_py3${minor_v}

    # Test requirements-files with pinned hashes
    requirements_files="requirements.txt requirements-relay.txt requirements-relay-tails.txt requirements-setuptools.txt"
    for req_file in ${requirements_files}; do

        # Setup
        rm -rf req_test
        mkdir req_test
        cd req_test

        # Test
        ${interpreter} -m virtualenv ${venv_name}
        . /home/user/tfc/req_test/${venv_name}/bin/activate
        ${interpreter} -m pip install  -r "/home/user/tfc/${req_file}" --require-hashes  --no-cache-dir
        ${interpreter} -m pip download -r "/home/user/tfc/${req_file}" --require-hashes  --no-cache-dir  # Check that downloading also works
        deactivate

        # Teardown
        cd ..
        rm -rf req_test

    done

    echo 'Req tests complete'

    rm -rf ${venv_name}
    find . -type f -name "*.py[co]" -delete -or -type d -name "__pycache__" -delete

    ${interpreter} -m pip install -r "/home/user/tfc/requirements-venv.txt" --require-hashes
    ${interpreter} -m virtualenv ${venv_name} --system-site-packages

    # Install up-to-date dependencies
    . /home/user/tfc/${venv_name}/bin/activate
    ${interpreter} -m pip install --no-cache-dir -r "/home/user/tfc/requirements-dev.txt"

    # Run type checks
    rm -rf /home/user/tfc/.mypy_cache 2>/dev/null;
    ${interpreter} -m mypy {tfc,relay,dd}.py --ignore-missing-imports --strict
    rm -rf /home/user/tfc/.mypy_cache 2>/dev/null;

    # Run unit tests
    if ((minor_v == 7)); then
        rm -rf /home/user/tfc/.pytest_cache 2>/dev/null;
        ${interpreter} -m pytest --cov=src --cov-report=html -d --tx 8*popen//python=${interpreter} tests/
    fi
    rm -rf /home/user/tfc/.pytest_cache 2>/dev/null;

    # Run style checks
    cd src/
    ${interpreter} -m pylama -i E122,E272,E221,E202,E271,E701,E251,E201,E222,E231,E127,E131,E128,E125,E501,W0611,C901
    cd ..

    # Cleanup
    deactivate
    rm -rf ${venv_name}
    find . -type f -name "*.py[co]" -delete -or -type d -name "__pycache__" -delete
done

# Update normal virtualenv too
rm -rf venv_tfc
python3.7 -m virtualenv venv_tfc --system-site-packages
python3.7 -m pip install --no-cache-dir -r "/home/user/tfc/requirements-dev.txt" --no-cache-dir

# Update digests
rm -f install.sh.asc SHA512.list
find . -type f -exec sha512sum "{}" + > SHA512.list
python3.7 hash_replacer.py
rm -f SHA512.list

# Sign installer
gpg --detach-sign --armor install.sh

echo 'Publish script completed successfully.'