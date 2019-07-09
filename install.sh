#!/usr/bin/env bash

# TFC - Onion-routed, endpoint secure messaging system
# Copyright (C) 2013-2019  Markus Ottela
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


function compare_digest {
    # Compare the SHA512 digest of TFC file against the digest pinned in
    # this installer.
    if sha512sum /opt/tfc/$2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        echo OK - Pinned SHA512 hash matched file /opt/tfc/$2$3
    else
        echo Error: /opt/tfc/$2$3 had invalid SHA512 hash
        exit 1
    fi
}


function verify_tcb_requirements_files {
# To minimize the time TCB installer configuration stays online, only
# the requirements files are authenticated between downloads.
    compare_digest a52d96aa42f4aa00958e3778d8048f31ae64d7b602a4998d88ff4649328df3c53b73e529a6e672058c609ff31009d71e98838a634c4b71550742c6cdc6c3cfbb '' requirements.txt
    compare_digest 68939117a092fa4aff34e678d554bf9c86da84f9c757cc2db2932379bac0c10becbedd05a7ba8869672cd66c4160e55d843290063f550d634d4e8484b6d180b3 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest e4f81f752001dbd04d46314ea6d8867393c3ad5ed85c2d3e336a8018913446f5855525e0ca03671ab8d26d8af1fe16416c8f5a163cad795867284a726adfeb31 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 651fccf97f1a1a3541078a19191b834448cb0c3256c6c2822989b572d67bc4b16932edea226ecf0cbd792fc6a11f4db841367d3ecd93efa67b27eaee0cc04cb7 '' LICENSE-3RD-PARTY
    compare_digest ee7ba1068bf2ef5a2d71f3827ad850d8f021117b8d8f15181f05acf6876905260e6196c86955342ca979923c8e99d7254e1854d11b81ed7e9c6b590d959da027 '' relay.py
    compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
    compare_digest 55d0bcd6ba90ba5a7e433366d1a2b688c4c93f9a4bb9a6859934c0375190d1540916cfcbfe7a6220c828e2fd26ae0bb21a3c15fff1a419eac8e23879b4078b20 '' requirements-relay.txt
    compare_digest 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png
    compare_digest c335b6c9b5a6f1a28b16269e27ac1b7cba63ab87c436b23f8eee447c27d2b0b5d43d7fbb46cfc975226ef301be42bace2897df81df2bb1b0fb55a5662a938f30 '' tfc.py
    compare_digest c6a61b3050624874cabc28cc51e947aa1ba629b0fd62564466b902cc433c08be6ae64d53bb2f33158e198c60ef2eb7c38b0bee1a64ef9659d101dee07557ddc7 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest e0c7038b0ebb22cdfcf224b1f7e3cc6dde1a6ae10d41464963fef986421cb0decd7caf37e3bc7f51e59a0f22956e29c2baccd52d60c5c7971a46cd4aaa56916f launchers/ TFC-Local-test.desktop
    compare_digest 7a24710a6560c246776e95670350c7bede99fb241ed6fa5670259584c06c6659688fea45b462937f61fcbf7731af71ecb0618c2af0266e998b891a0bc0252c54 launchers/ TFC-RP.desktop
    compare_digest b288fc75048536adca9b585e238b6b327f31feebeb98bf1593a48cf5aa9ae7f43dbd619825d8f769b5e2d5439a7ad537bc6c540815e7700c0f4f311bf9bea3ea launchers/ TFC-RP-Tails.desktop
    compare_digest 615763e9efe5261e90db37f574af3bfce8c6e585e486e83a133869ad60ab1394ffe8047203e803a2d379240c43883a23a093eb3ae1077a9f4cc61a6fea8bd5c6 launchers/ TFC-RxP.desktop
    compare_digest c76cabbb129a386acd9bc4a02b277eb4bd56bd4eec784df93383799ae11780225c4f5af24a5464e8e0d35274f7b100581c2311411773cbbf487af7d523d19e2a launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest 5c9cd3a13d46090f1c3686c91df8603302fb5e547140c8edd32b9dbe60b300f091b5921da9dd0b8131642673f766e99290b30ca9a4c43ac8435261102db9c8b1 src/common/ crypto.py
    compare_digest 0b830ad6705f90dc8e554c8b06f31054d9222d3b35db92470eaf3f9af935aae3107b61142ea68129943e4227a45dfe26a87f23e9dd95a7794ae65c397bd35641 src/common/ db_contacts.py
    compare_digest bad54588b3e713caf94aba3216090410f77f92064aecfea004a33487a21f9fffcf5d05782b91104c27ec499e38196881a76d6002ec1149816d8c53560182fba9 src/common/ db_groups.py
    compare_digest 46e503af15fb7a1ea8387fa8f22674d0926eda0d879d43f99076ca967295d5e3727a411aa11c4bb4d832783c5daa9f4b7ef4491b90112c1be405910d269abaf4 src/common/ db_keys.py
    compare_digest 68b2c7761623ff9e4ce596e170c8e1ce2b6129bbbbb9fc9e48a120974d30db6e471bb5d514f5dc8d7edc8e0abcb0cd0c2b4e5da739f4d98c6fa8c8e07af0d8ef src/common/ db_logs.py
    compare_digest a19ed5c4a6590d4d62dfff03980d450844c1d9b1ef5f16764e129cb21e3a6d62a28a3ec9dc4a144fe31ea6cb5b9f79dcfba8dad9105bdc8de3542d11720ee924 src/common/ db_masterkey.py
    compare_digest 5befbe864e2b09125be2b04cdfee8d13e7616715fc20a0fa06da270e34b555602b2df825fd429059056b2beb1497c50dafdc682d59a43a483837445861647e9d src/common/ db_onion.py
    compare_digest 404aa061de5a33b910cce126ff55ff28999ea981a971cbd2d198cfb3cf6d186646cc02727ddd8312bfedf5662b2302d46af92175682891f288b06d7c18f1819f src/common/ db_settings.py
    compare_digest 13c203b565880ab83f8b54fa2474c17c9b5cea890a1839666515600f876bdf749132b63e48e56d3d43a7042e29acb7d14fd2aa0f5f448622f5eaf8bd933c6b01 src/common/ encoding.py
    compare_digest 043a5518a6afb2f3e5c445d26d7f0a3bbcd80cc26679b17fc3342671759cfc9e3f23ba68e4479c795c7455cec73fe7b332febde29944c1e1f69455780ca1f036 src/common/ exceptions.py
    compare_digest ab65b4d22fa2bda80d94f63557e93bbb1db4288ed5a3f2ecb9ea301a894afce3c49ca3f60581ebd1a8bcb532df9f2c9cbc5965dfe73cfcac8781fc2bbcd8ca98 src/common/ gateway.py
    compare_digest 618cbaccb4f50bc6e551cd13570693d4d53cfdfdc00b7ff42ff9fd14f0dadf7a15c9bc32c8e53801aca42348826568a2aa9117bdbf79bbcc4217a07c94c9efd3 src/common/ input.py
    compare_digest 14f9a5f06443b50251272939b92eaf287fecfb4e3c9882254f13757259d9d791ac1e66c46fd0475d1e3161ff27f16ad7b4de04ac564500cae60d27a631d42e36 src/common/ misc.py
    compare_digest 6c1f317f3e271efc37cb506ec7b6e9e9225ed834613ca9a3f98bdc14ba7b8402766f9e184aa698dfc2dc1875dc1f13e0df8d91f982cc68c9ff2ba478163b96a1 src/common/ output.py
    compare_digest c4d97b497b341f0e7865a4e27a2a2ffd3b3c5a7bfbf72f4676f6b65d6ba66a2adb8fed563f88fa25cef555f0042290ef0ae4cbeed1697a2e19a3b8cff0b9ef1b src/common/ path.py
    compare_digest 7debb29d0f582a4f1e38e4676b10ef0437bb437911e9d5f41130f57a50072dfec103c0842b690057578de6ac58575af4b587d2c3f67c7215c8f03319d23debe7 src/common/ reed_solomon.py
    compare_digest 05a9e42d3860e90858723bcfc246284ca9a7b3a23b16d425f29e77a74f074233230801ae8de7a9040b7ac4acf3570b52aebbe6d02368c4241b33d040411aaea6 src/common/ statics.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest bce9f7cc76826515c9d1568b2cc348986f077d17efa5cd70bdc513a6cf54e5e93853c374bb19f4d35cdeb69beb4715494c08e799ae51d09bd6081d4c3c679559 src/receiver/ commands.py
    compare_digest 760edaa44ff6175612b02f95b02b291ae369733a18cc5f87d525b46bcebc35c8a2d169a47962417eab434cf26ea6d5bfcd8894153fae668bb4a8cf2ceb8871f0 src/receiver/ commands_g.py
    compare_digest 5a728d57c954a1616848fa4839058f28de8960686efa2670549fe98b0b08b28fb99dcc1d15c5fe405615ea69f708845005cd596cfca5345bdde3a33aead2be8c src/receiver/ files.py
    compare_digest 2b39ab5653d8ef52395b6761f6aeaec131bcc66b81f9db708e01871e6ba268f860015cee7aa2a7586ad3592cc6884adbf0340de523b19d89eec449a3c16d1040 src/receiver/ key_exchanges.py
    compare_digest 65307a0ea2c9ae69859cc8ef62a5d7e45c27bdf5a4ec44db704df143ce3630fdc077fafc7fd4cfc0cd922f350f49f0aa0a880192c40c614b6d3117804ea683ae src/receiver/ messages.py
    compare_digest b33a7696b31265027bb137aacd80845d4fefbd112144f3e01cfe4e083e5b6575fcdab387ae9d2435dd1c82bf0cf31b55f934cd12256a7ac78b4b13cc3d593987 src/receiver/ output_loop.py
    compare_digest 7a81a142d21ebf8779fa0fec9aeef922d21bd6d57643061722d91047ecafeea7f0bfdd3a2919251a83a02cecbef909756fdb62881d5d2a844c3daba0e7069bf5 src/receiver/ packet.py
    compare_digest 01b0ce92b4ab8f37eed55356a65f4d25ffff590955b5ca124dbb541bdec6968e8235242bf47ad5c2bfe57a30d54cf494d9f3836e3d53a73748f203ff68381c14 src/receiver/ receiver_loop.py
    compare_digest 17ab4e845274ac6901902537cbea19841de56b5d6e92175599d22b74a3451ecafa3681420e2fcc7f53f6b2ebb7994e5903aabb63a5403fbf7fb892509bb5d11c src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest 95be5f0e84ad7197fd63cb699ef84fdb5b20b1dd71dd4542d9c1428dc63dcb5e48303b86a7f25e999f03fe0800f99b38dab2051cb1c9f787f1e07ab337bd0ae6 src/relay/ client.py
    compare_digest 327fc0b969b57998eea85237e4a97852b25f617631ffc6f6b885cfe6a98c92a9c8a01fbfe43c195b58f12b6e086c3575276e3e46380abe460ac91bacb4c24dc4 src/relay/ commands.py
    compare_digest c8212c618ef15e02545c04a3070f46b3d95ecb9a8061e0e129d3d75ddb383eba5a21c13d6c29bdb19936d8b33fcb266de7366ad56ce7dee6e692a2f08aa23bd2 src/relay/ onion.py
    compare_digest a18aa0ca4ffff7be99721c094ae44a95ed407e5e4cb25016ce14bf9fca7fef950d0b0460fd91689f2003aeb7f8385cb4f88a5f2e3f7f4ba7b88634412853d888 src/relay/ server.py
    compare_digest e03b2896049d6c4f98cc9b52ae43a32078ffe93f6a18848fb96cf4051752872ad20463754fad61244e914b2082839d8297f0d3357e20c8dd22881e885bfbd32a src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest bc359eb3d79e803f64060f10ec1bef76d4bf7e722fe300881c57f88a63516e681cacf12bfc9fa8494188614b6885eeb203f173d9e8860e861b8e89d117138d80 src/transmitter/ commands.py
    compare_digest c6304590a38c1e43a1cd3bfcab0c08bea06cf984397b6d70265f445ab3f42857dcbf5d5519081d876f9d4ca72a47819fe5c7676943d5af6778184125ac0e702a src/transmitter/ commands_g.py
    compare_digest d5ad53e3ba7ae32e0c6255f5fca3a60c267b028d7dfb2f2e28768c2f8824b0ad25afc7edc3a5d6d69bb76986ff8d81549d50d71d8b46ca6a0a9dc37324ae027a src/transmitter/ contact.py
    compare_digest dffc059fc25cbfb17beb9f83fc2d52ce043e9b923580ccf655933cf66fefcf6e18bcb923d7cb42a7d547126f938ff867a7638ffd13c14953b4a2d700f8f0d5c4 src/transmitter/ files.py
    compare_digest 061d7f3c4f737afafacc65bea744ac9bad16c6b064ab6281a3ab2079b18d984afa00b93e3861209425f78807e335925d824e018e80523b5380ac5244b8f5b8c2 src/transmitter/ input_loop.py
    compare_digest 2a909550e923c8712d571a05adc6ea409e97c6e7ffabae4997b084a43c38c8c60391a7497652bdcca85a99b4700aeda1a33fec4a5d4ac7d2f2ce8d301ee47699 src/transmitter/ key_exchanges.py
    compare_digest 1249ba23d30031ec8c1b42e999e52bc0903a0ad00c317d27d51c8d650b3343c9475319db6e0f2f16dfae39a942e01eeaae8eb862d541957b1f51690b1eb0f202 src/transmitter/ packet.py
    compare_digest 93f874a8d97312ab4be10e803ba5b0432a40cf2c05541775c7117aa68c18e78e52e814d38639b33e87dc33df1773e04dc2c789e61e08c12d9c15512dd9e5d4d3 src/transmitter/ sender_loop.py
    compare_digest bcad5d4b9932f1b35b2c74dc083233af584012cacdd1d2cb04b28115b4e224118ce220252754ae532df0adcc6c343b1913f711cf3bd94da9c4cd3eaf23e4b196 src/transmitter/ traffic_masking.py
    compare_digest ccbda8415c23b23cc10cda57fb6b32df71e6510f3cb94c7f932b40adcf5f0abdd9842c48a992d56c95755e3024aebd7ecb05f69eb18f3c41656d94cfeabb38fa src/transmitter/ user_input.py
    compare_digest 4c5b9c877474257d078723d32533ba614d72bad7b108588f49fae6c26dcb2c49994b256b5457caee0e5ab4628f728b25a54551ce778b585cbb8b1f8c947dc7e6 src/transmitter/ windows.py
}


# PIP dependency file names
ARGON2=argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
ASN1CRYPTO=asn1crypto-0.24.0-py2.py3-none-any.whl
CERTIFI=certifi-2019.6.16-py2.py3-none-any.whl
CFFI=cffi-1.12.3-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.7-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.0.3-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.10.1-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.0-py3-none-any.whl
REQUESTS=requests-2.22.0-py2.py3-none-any.whl
SIX=six-1.12.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.3-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.6.1-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.15.4-py2.py3-none-any.whl


function process_tcb_dependencies {
    # Manage TCB dependencies in batch. The command that uses the files
    # is passed to the function as a parameter.
    sudo $1 /opt/tfc/${SIX}
    sudo $1 /opt/tfc/${PYCPARSER}
    sudo $1 /opt/tfc/${CFFI}
    sudo $1 /opt/tfc/${ARGON2}
    sudo $1 /opt/tfc/${PYNACL}
    sudo $1 /opt/tfc/${PYSERIAL}
    sudo $1 /opt/tfc/${ASN1CRYPTO}
    sudo $1 /opt/tfc/${CRYPTOGRAPHY}
}


function process_tails_dependencies {
    # Manage Tails dependencies in batch. The command that uses the
    # files is passed to the function as a parameter.

    # Pyserial
    t_sudo $1 /opt/tfc/${PYSERIAL}

    # Stem
    t_sudo $1 /opt/tfc/${STEM}

    # PySocks
    t_sudo $1 /opt/tfc/${PYSOCKS}

    # Requests
    t_sudo $1 /opt/tfc/${URLLIB3}
    t_sudo $1 /opt/tfc/${IDNA}
    t_sudo $1 /opt/tfc/${CHARDET}
    t_sudo $1 /opt/tfc/${CERTIFI}
    t_sudo $1 /opt/tfc/${REQUESTS}

    # Flask
    t_sudo $1 /opt/tfc/${WERKZEUG}
    t_sudo $1 /opt/tfc/${MARKUPSAFE}
    t_sudo $1 /opt/tfc/${JINJA2}
    t_sudo $1 /opt/tfc/${ITSDANGEROUS}
    t_sudo $1 /opt/tfc/${CLICK}
    t_sudo $1 /opt/tfc/${FLASK}

    # Cryptography
    t_sudo $1 /opt/tfc/${SIX}
    t_sudo $1 /opt/tfc/${ASN1CRYPTO}
    t_sudo $1 /opt/tfc/${PYCPARSER}
    t_sudo $1 /opt/tfc/${CFFI}
    t_sudo $1 /opt/tfc/${CRYPTOGRAPHY}
}


function remove_common_files {
    # Remove files that become unnecessary after installation.
    $1 rm -r /opt/tfc/.git/
    $1 rm -r /opt/tfc/launchers/
    $1 rm -r /opt/tfc/tests/
    $1 rm    /opt/tfc/.coveragerc
    $1 rm    /opt/tfc/.travis.yml
    $1 rm    /opt/tfc/install.sh
    $1 rm    /opt/tfc/install.sh.asc
    $1 rm    /opt/tfc/pubkey.asc
    $1 rm    /opt/tfc/pytest.ini
    $1 rm    /opt/tfc/README.md
    $1 rm    /opt/tfc/requirements.txt
    $1 rm    /opt/tfc/requirements-dev.txt
    $1 rm    /opt/tfc/requirements-relay.txt
    $1 rm    /opt/tfc/requirements-venv.txt
    $1 rm -f /opt/install.sh
    $1 rm -f /opt/install.sh.asc
    $1 rm -f /opt/pubkey.asc
}


function steps_before_network_kill {
    # These steps are identical in TCB/Relay/Local test configurations.
    # This makes it harder to distinguish from network traffic when the
    # user is installing TFC for Source or Destination computer: By the
    # time `kill_network` is run, it's too late to compromise the TCB.
    # Hopefully this forces adversaries to attempt compromise of more
    # endpoints during installation, which increases their chances of
    # getting caught.
    dpkg_check
    check_rm_existing_installation

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk net-tools -y
    sudo torsocks git clone https://github.com/tfctesting/tfc.git /opt/tfc

    verify_tcb_requirements_files
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/
}


function install_tcb {
    # Install TFC for Source/Destination Computer.
    #
    # The installer configuration first downloads all necessary files.
    # It then disconnects the computer from network, before completing
    # the rest of the installation steps.
    steps_before_network_kill

    kill_network

    verify_files
    create_user_data_dir

    sudo python3.7 -m pip install /opt/tfc/${VIRTUALENV}
    sudo python3.7 -m virtualenv /opt/tfc/venv_tcb --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    process_tcb_dependencies "python3.7 -m pip install"
    deactivate

    sudo mv /opt/tfc/tfc.png                   /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-TxP.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/TFC-RxP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_common_files      "sudo"
    process_tcb_dependencies "rm"
    sudo rm -r /opt/tfc/src/relay/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/relay.py
    sudo rm    /opt/tfc/${VIRTUALENV}

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


function install_local_test {
    # Install TFC for local testing on a single computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    sudo torsocks apt install terminator -y

    install_virtualenv
    sudo python3.7 -m virtualenv /opt/tfc/venv_tfc --system-site-packages

    . /opt/tfc/venv_tfc/bin/activate
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements.txt       --require-hashes
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                                /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-Local-test.desktop       /usr/share/applications/
    sudo mv /opt/tfc/launchers/terminator-config-local-test /opt/tfc/
    modify_terminator_font_size "sudo" "/opt/tfc/terminator-config-local-test"

    # Remove unnecessary files
    remove_common_files      "sudo"
    process_tcb_dependencies "rm"
    sudo rm /opt/tfc/${VIRTUALENV}

    install_complete "Installation of TFC for local testing is now complete."
}


function install_developer {
    # Install TFC development configuration.
    #
    # This configuration will install TFC into `$HOME/tfc/`. This allows
    # you (the user) to easily make edits to the source between runs.
    # Note that it also means, that any malicious program with
    # user-level privileges is also able to modify the source files. For
    # more secure use on a single computer, select the local testing
    # install configuration.
    dpkg_check

    create_user_data_dir

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk terminator -y

    torsocks git clone https://github.com/tfctesting/tfc.git $HOME/tfc

    torsocks python3.7 -m pip install -r $HOME/tfc/requirements-venv.txt --require-hashes
    python3.7 -m virtualenv $HOME/tfc/venv_tfc --system-site-packages

    . $HOME/tfc/venv_tfc/bin/activate
    torsocks python3.7 -m pip install -r $HOME/tfc/requirements.txt       --require-hashes
    torsocks python3.7 -m pip install -r $HOME/tfc/requirements-relay.txt --require-hashes
    torsocks python3.7 -m pip install -r $HOME/tfc/requirements-dev.txt
    deactivate

    sudo cp $HOME/tfc/tfc.png                   /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-Dev.desktop /usr/share/applications/
    sudo sed -i "s|\$HOME|${HOME}|g"            /usr/share/applications/TFC-Dev.desktop
    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"
    chmod a+rwx -R $HOME/tfc/

    # Remove unnecessary files
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


function install_relay_ubuntu {
    # Install TFC Relay configuration on Networked Computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    install_virtualenv
    sudo python3.7 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                  /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_common_files      "sudo"
    process_tcb_dependencies "rm"
    sudo rm -r /opt/tfc/src/receiver/
    sudo rm -r /opt/tfc/src/transmitter/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/tfc.py
    sudo rm    /opt/tfc/${VIRTUALENV}

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


function install_relay_tails {
    # Install TFC Relay configuration on Networked Computer running
    # Tails live distro (https://tails.boum.org/).
    check_tails_tor_version

    read_sudo_pwd

    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip python3-setuptools -y || true  # Ignore error in case packets can not be persistently installed

    git clone https://github.com/tfctesting/tfc.git $HOME/tfc
    t_sudo mv $HOME/tfc/ /opt/tfc/

    verify_tcb_requirements_files
    verify_files
    create_user_data_dir

    t_sudo python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay.txt --require-hashes -d /opt/tfc/

    process_tails_dependencies "python3.7 -m pip install"

    t_sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    t_sudo mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/

    remove_common_files        "t_sudo"
    process_tails_dependencies "rm"
    t_sudo rm -r /opt/tfc/src/receiver/
    t_sudo rm -r /opt/tfc/src/transmitter/
    t_sudo rm    /opt/tfc/dd.py
    t_sudo rm    /opt/tfc/tfc.py

    install_complete "Installation of the TFC Relay configuration is now complete."
}


function t_sudo {
    # Execute command as root on Tails.
    echo ${sudo_pwd} | sudo -S $@
}


function install_relay {
    # Determine the Networked Computer OS for Relay Program installation.
    if [[ "$(lsb_release -a 2>/dev/null | grep Tails)" ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


function install_virtualenv {
    # Determine if OS is debian and install virtualenv as sudo so that
    # the user (who should be on sudoers list) can see virtualenv on
    # when the installer sets up virtual environment to /opt/tfc/.
    distro=$(lsb_release -d | awk -F"\t" '{print $2}')

    if [[ "$distro" =~ ^Debian* ]]; then
        sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    else
        torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    fi
}


function read_sudo_pwd {
    # Cache the sudo password so that Debian doesn't keep asking for it
    # during the installation (it won't be stored on disk).
    read -s -p "[sudo] password for ${USER}: " sudo_pwd
    until (t_sudo echo '' 2>/dev/null)
    do
        echo -e '\nSorry, try again.'
        read -s -p "[sudo] password for ${USER}: " sudo_pwd
    done
    echo
}


function check_tails_tor_version {
    # Check that the Tails distro is running Tor 0.3.5 or newer.
    included=($(tor --version |awk '{print $3}' |head -c 5))
    required="0.3.5"

    if ! [[ "$(printf '%s\n' "$required" "$included" | sort -V | head -n1)" = "$required" ]]; then
        clear
        echo -e "\nError: This Tails includes Tor $included but Tor $required is required. Exiting.\n" 1>&2
        exit 1
    fi
}


function kill_network {
    # Kill network interfaces to protect the TCB from remote compromise.
    for interface in /sys/class/net/*; do
        name=`basename ${interface}`
        if [[ $name != "lo" ]]; then
            echo "Disabling network interface ${name}"
            sudo ifconfig ${name} down
        fi
    done

    clear
    c_echo ''
    c_echo " This computer needs to be air gapped. The installer has "
    c_echo "disabled network interfaces as the first line of defense."
    c_echo ''
    c_echo "Disconnect the Ethernet cable and press any key to continue."
    read -n 1 -s -p ''
    echo -e '\n'
}


function add_serial_permissions {
    # Enable serial interface for user-level programs.
    clear
    c_echo ''
    c_echo "Setting serial permissions. If available, please connect the"
    c_echo "USB-to-serial/TTL adapter now and press any key to continue."
    read -n 1 -s -p ''
    echo -e '\n'
    sleep 3  # Wait for USB serial interfaces to register

    # Add user to the dialout group to allow serial access after reboot
    sudo adduser ${USER} dialout

    # Add temporary permissions for serial interfaces until reboot
    arr=($(ls /sys/class/tty | grep USB)) || true
    for i in "${arr[@]}"; do
        sudo chmod 666 /dev/${i}
    done

    if [[ -e /dev/ttyS0 ]]; then
        sudo chmod 666 /dev/ttyS0
    fi
}


function c_echo {
    # Justify printed text to the center of the terminal.
    printf "%*s\n" $(( ( $(echo $1 | wc -c ) + 80 ) / 2 )) "$1"
}


function check_rm_existing_installation {
    # Remove TFC installation directory if TFC is already installed.
    if [[ -d "/opt/tfc" ]]; then
        if [[ ${sudo_pwd} ]]; then
            t_sudo rm -r /opt/tfc  # Tails
        else
            sudo rm -r /opt/tfc    # *buntu
        fi
    fi
}


function create_user_data_dir {
    # Backup TFC user data directory if it exists and has files in it.
    if [[ -d "$HOME/tfc" ]]; then
        if ! [[ -z "$(ls -A $HOME/tfc/)" ]]; then
            mv $HOME/tfc $HOME/tfc_userdata_backup_at_$(date +%Y-%m-%d_%H-%M-%S)
        fi
    fi
    mkdir -p $HOME/tfc 2>/dev/null
}


function modify_terminator_font_size {
    # Adjust terminator font size for local testing configurations.
    #
    # The default font sizes in terminator config file are for 1920px
    # wide screens. The lowest resolution (width) supported is 1366px.
    width=$(get_screen_width)

    if (( $width < 1600 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 8/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 7/g'   $2  # Data diode config
    elif (( $width < 1920 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 9/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 8.5/g' $2  # Data diode config
    fi
}


function get_screen_width {
    # Output the width of the screen resolution.
    xdpyinfo | grep dimensions | sed -r 's/^[^0-9]*([0-9]+).*$/\1/'
}


function install_complete {
    # Notify the user that the installation is complete.
    clear
    c_echo ''
    c_echo "$*"
    c_echo ''
    c_echo "Press any key to close the installer."
    read -n 1 -s -p ''
    echo ''

    kill -9 $PPID
}


function dpkg_check {
    # Check if the software manager is busy, and if, wait until it
    # completes.
    i=0
    tput sc
    while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
        case $(($i % 4)) in
            0 ) j="." ;;
            1 ) j="o" ;;
            2 ) j="O" ;;
            3 ) j="o" ;;
        esac
        tput rc
        echo -en "\rWaiting for other software managers to finish..$j"
        sleep 0.5
        ((i=i+1))
    done
    echo ''
}


function arg_error {
    # Print help message if the user launches the installer with missing
    # or invalid argument.
    clear
    echo -e "\nUsage: bash install.sh [OPTION]\n"
    echo    "Mandatory arguments"
    echo    "  tcb      Install Transmitter/Receiver Program (*buntu 19.04+)"
    echo    "  relay    Install Relay Program                (*buntu 19.04+ / Tails (Debian Buster+))"
    echo -e "  local    Install insecure local testing mode  (*buntu 19.04+)\n"
    exit 1
}


function root_check {
    # Check that the installer was not launched as root.
    if [[ !$EUID -ne 0 ]]; then
        clear
        echo -e "\nError: This installer must not be run as root. Exiting.\n" 1>&2
        exit 1
    fi
}


function architecture_check {
    # Check that the OS is 64-bit, and not 32-bit.
    if ! [[ "$(uname -m 2>/dev/null | grep x86_64)" ]]; then
        clear
        echo -e "\nError: Invalid system architecture. Exiting.\n" 1>&2
        exit 1
    fi
}


set -e
architecture_check
root_check
sudo_pwd=''

case $1 in
    tcb   ) install_tcb;;
    relay ) install_relay;;
    local ) install_local_test;;
    dev   ) install_developer;;
    *     ) arg_error;;
esac
