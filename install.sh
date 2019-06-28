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
    compare_digest 9d18d052fc7eb0837f00f618b391ec47951fe130c8a420db841499d335cbd83122df3138c69e2b0ebc1505d1834e670cac28ccfed0c3f3441e23824266991623 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 651fccf97f1a1a3541078a19191b834448cb0c3256c6c2822989b572d67bc4b16932edea226ecf0cbd792fc6a11f4db841367d3ecd93efa67b27eaee0cc04cb7 '' LICENSE-3RD-PARTY
    compare_digest 1b6c5aa953c331c4f5669ca714945163ab2966b05f8d259c725334fdc917711f22bde5eb4fd15ee375981a4ba61b3ed7b11f99b3ce86f818450572d4c5e21895 '' relay.py
    compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
    compare_digest 55d0bcd6ba90ba5a7e433366d1a2b688c4c93f9a4bb9a6859934c0375190d1540916cfcbfe7a6220c828e2fd26ae0bb21a3c15fff1a419eac8e23879b4078b20 '' requirements-relay.txt
    compare_digest 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png
    compare_digest e937ba36345960a67bae8369d261a0ca8dc4cf891b46435e0da72aee48d4155c8a057ab0ba2f80c819318fa418bd16ff00ecaba8695608841cbb2b1bf900704e '' tfc.py
    compare_digest c6a61b3050624874cabc28cc51e947aa1ba629b0fd62564466b902cc433c08be6ae64d53bb2f33158e198c60ef2eb7c38b0bee1a64ef9659d101dee07557ddc7 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest a6eb44dd2ab51bc310daf88dbe3d3ca2585e3bd4e8520cbf2f2867adbc2ce7a394b0d9666f2093dbedf1a5e36619c443133a7c18c899c2747858cc0ae6f64bb3 launchers/ TFC-Local-test.desktop
    compare_digest de490c82aa3ee6349c04bdbb1a088bfd3a2b13b9dac031ebbd40b684db3312d6ecb2b129caa3a84b497f349962f730b9234ccd0664a28f61adeaf949e68c1b29 launchers/ TFC-RP.desktop
    compare_digest 2631d34e2a59771ffad95a6283ee2dbb32a426c5eabf62f783e2f2ab46381332c547298c297263596ec7c244301e792bef5c32e621b90fe68badb47a2d42f08c launchers/ TFC-RP-Tails.desktop
    compare_digest a9c566090dae46fd28d695e4329b6277646767a438735f5f33f073ca6a781052a9a5e0c0d25361e838d1bbf0ad11a1683e64ab1646c7231db4c4bed8005a288e launchers/ TFC-RxP.desktop
    compare_digest d8ecc62e8ed2c495325910c490d18542218e59343765f72d77f56742e4f8af3d7b00b23ef5818b1db6373e1bf408f66ca77ac6e33a7c887abbef0094d3c41ddb launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest 64a658eb375aa867a3e36e6176af811247400746a521e7d775b5066f7c6c23134c3c025f3508de3931b65e6693f0d374aaa5d355b4e8c187d1e8bf392d9cc322 src/common/ crypto.py
    compare_digest a325657fb3494d86c8824894e02df0d43ab48c1a85d11c18a305ad40a97766ad45035d60d9bcadeb5ea8f3a71d4b69a8c224b8d433c86d81dece351627bd77ef src/common/ db_contacts.py
    compare_digest 4489dbc12e30ce066cc5cb7e0898b276b01c0e589e110f230abe3d2ccddf25fcae7b0d157e4b801f76e537f5ab527fe5899a015371250b855d8066c6085f3b3b src/common/ db_groups.py
    compare_digest a71345dea4e9fcbe7131e3692ec5687e706e069f7aada56856837675fec7b2ee393ae4221fe8fd08f5c359a5f506dbced04586f9b908a27d2f81c99fa42d3b23 src/common/ db_keys.py
    compare_digest b7abfebfbef8d64d26bc41f4b66681d65aee365c0b93541d53aa2d7e5e1ce6a4fbcc98b6ffb894a41ed51831e41dd6bc204f2bf08b8bed12796476a379b0f259 src/common/ db_logs.py
    compare_digest a19ed5c4a6590d4d62dfff03980d450844c1d9b1ef5f16764e129cb21e3a6d62a28a3ec9dc4a144fe31ea6cb5b9f79dcfba8dad9105bdc8de3542d11720ee924 src/common/ db_masterkey.py
    compare_digest 5befbe864e2b09125be2b04cdfee8d13e7616715fc20a0fa06da270e34b555602b2df825fd429059056b2beb1497c50dafdc682d59a43a483837445861647e9d src/common/ db_onion.py
    compare_digest 404aa061de5a33b910cce126ff55ff28999ea981a971cbd2d198cfb3cf6d186646cc02727ddd8312bfedf5662b2302d46af92175682891f288b06d7c18f1819f src/common/ db_settings.py
    compare_digest 13c203b565880ab83f8b54fa2474c17c9b5cea890a1839666515600f876bdf749132b63e48e56d3d43a7042e29acb7d14fd2aa0f5f448622f5eaf8bd933c6b01 src/common/ encoding.py
    compare_digest 043a5518a6afb2f3e5c445d26d7f0a3bbcd80cc26679b17fc3342671759cfc9e3f23ba68e4479c795c7455cec73fe7b332febde29944c1e1f69455780ca1f036 src/common/ exceptions.py
    compare_digest 6c14b5e2beb69817ef4db932519239422374bfeaa891383d09e7b456805dc305372565ced7244d7d75311c824186089b81c143f6ced69916999ec7f23cc3b49e src/common/ gateway.py
    compare_digest 56639c5be9e89abb3305bda4d96fddd74490f125a68ae5cf1de2e0d4dee7bf04b114ce1e52b540484b89493aca772122cbb253ea15a78381a56c29c6a50edff9 src/common/ input.py
    compare_digest 87671c61f659cb1ca85abbd33116fd704767e93d51749ddae1f8cd34c24f24cb08c655e560084d593b8864ebcbdfe6899341118b2631d93fbc56e20ea7c512a7 src/common/ misc.py
    compare_digest ba14034b99e42b60e1fd68d44562534058a50a1ffced3d4460bb69d806f076bf2086b07817d5d59d2124da6ab2b5ade4529dc49b5d3554a60dd1de56daaf3e9d src/common/ output.py
    compare_digest a62724cb2e2ac0f63371fc0dc4be5541c9d9eaf1c8441c69001485f9057bbea16f31b9093ad6f9f6b4d1ed5a70136b8881bb7c09c63b2631a6ce052b2e914253 src/common/ path.py
    compare_digest 9c05675ecd3a8a436d24469adbb5ce821632e4fae95452d06ffad92b692a9950d1a0bf4e5875b2f0f6e6fa592fd25f11382ff2354b78d19a84a720aa324005ef src/common/ reed_solomon.py
    compare_digest 8509f7fbc4f6e1b08213fd54e5b523ac340ad439c4d0021f8feaa44482ce10921bb5338b927d109650a593891001915d24618f972dedb9fd142dd9868bb02cb3 src/common/ statics.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest 4340c76dcef1ae31eb6c75784a60bdccb9083592931a2b8ae33f35a78a23c0c3fe85f6b1c286b215025639109ac77046bf62dda0ad71fc8debdf66a09d5cabf5 src/receiver/ commands.py
    compare_digest 760edaa44ff6175612b02f95b02b291ae369733a18cc5f87d525b46bcebc35c8a2d169a47962417eab434cf26ea6d5bfcd8894153fae668bb4a8cf2ceb8871f0 src/receiver/ commands_g.py
    compare_digest 5a728d57c954a1616848fa4839058f28de8960686efa2670549fe98b0b08b28fb99dcc1d15c5fe405615ea69f708845005cd596cfca5345bdde3a33aead2be8c src/receiver/ files.py
    compare_digest ed73dece8ccd6f71874ffb8d1e2bdae13621ff7bc44f656b84053dcc199773c9c0533ef12d87f17b7b16551fafef6356cb237b9771487ddceed5763b63059eae src/receiver/ key_exchanges.py
    compare_digest 65307a0ea2c9ae69859cc8ef62a5d7e45c27bdf5a4ec44db704df143ce3630fdc077fafc7fd4cfc0cd922f350f49f0aa0a880192c40c614b6d3117804ea683ae src/receiver/ messages.py
    compare_digest 36e8eefcf4b749310e9bfaea2e2c45c93af0e9f82a9bb157feb82079d5e116dda546845af366678f3138314254009bedc9e34afb36fd7bece08459d07fdfd019 src/receiver/ output_loop.py
    compare_digest 748ae971dc3324a8f00fd36b9a119d7c17427f8fc65c522f25c0197b45b257b4f658d332f330c13dbfa1530791d792cf2beb58dc78030bcfa279926246593ecd src/receiver/ packet.py
    compare_digest ee1119685f7659f4fe5ecc70bdbb618d266bc15283adc784b6e47603be0a74fda8704d5c579eba060154a274b0952fcd1d302d243ca76dac9f2c2c34ab70cf74 src/receiver/ receiver_loop.py
    compare_digest 27cc4f8048b1f7d5e5dee0216d279701258eb468b8452fddfd3402c2eed4bb78673d8f1320412bf2bac43a5a23af07517a90fcca5446621773f8c54cefdfe3e3 src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest cb2981e88bf1afb7936125b9e84e2518b0cd332c63c667e55e35dfb88982aa3b8f95165b20349819a36600c9ac58651a8a4a5d26f78f7f1025cf485a55b5cf9c src/relay/ client.py
    compare_digest 34298c5978c00c04f6504019c666d73d49c8d8ecdcbfff646dbf22506e2cac1d6e827da4cf45c27bbd786e5723565c54c7f365805e4cb26616b6106737038d35 src/relay/ commands.py
    compare_digest adcfab07937641076d7c710d0b2a55c870d6f47500e61b18086e84f35d523f1b8f256de9eb805515de8dc77f509548b4e949683fd0ed98b716265e3ff27d8cab src/relay/ onion.py
    compare_digest 85eb7b13ac38fcb34d901a080c41258d9e635fba9223c60ebcfe9b0351a336219394f38096ddb1b4816b780cd73ed4a9b87418cac0e7c444a599421a6f64f683 src/relay/ server.py
    compare_digest 7f86bb8073dd10894230969a1d29146f12176bd770a64bac279bf2159dbd61c06cec48a9cdf37e46af80f458428102b0c1daaecbd076b8de73724311baa42a54 src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest 2b51b539ea54cad9af07221fe352ddd5134e37e34fe393b8238310194849c7cd99311830b543333beb551c6e67def7309aa23e955671e3df5638ea393c9683e5 src/transmitter/ commands.py
    compare_digest 9fe441f21fb496f4fcf58c8398b2e2bd13e1f10588d46e56b9c38f05a57405ab3263d932c420ac33ae55c9565164d09888f8f5f27579d15411ae185247435d7f src/transmitter/ commands_g.py
    compare_digest 07f2ecc641354aa36fdebfaa7367f521bedb1032914419267b6d7177458acd1dad7b2f051525b6835d94882580a4c1a2ad31e530a0d8dcd79ccd535281ef3955 src/transmitter/ contact.py
    compare_digest dffc059fc25cbfb17beb9f83fc2d52ce043e9b923580ccf655933cf66fefcf6e18bcb923d7cb42a7d547126f938ff867a7638ffd13c14953b4a2d700f8f0d5c4 src/transmitter/ files.py
    compare_digest 319a6f33ca0571768b78008c9c746b84df1aeeb9dd13fe663e4143c4af524dafc6ae83923b84430b08f4b598dffa09c1a1a5095e7571a25c0fd811428772ff26 src/transmitter/ input_loop.py
    compare_digest 950e535439e2e13fa458fcdb1694606f62d89307f66e17286db8d7c5d8467f98195bc7483b0eb37e2a7106fb88b8409a9f179bb9c1a537f1ece3a667657f026d src/transmitter/ key_exchanges.py
    compare_digest fdcdd252e17c0857372c754a5d825db17040ff9cae45d08730df45e015fa8e5a4002b6e8d5bf06e6e42f6a95eaf604fa1b4ba3cc1c1903382dd9b979e055e820 src/transmitter/ packet.py
    compare_digest a007d6322448942cbe7843aeee64ec6df712c9a9f406f48613ce36b6752f37a119a3eab0a6d1f8fde6d5f72821d1ea12608839280f6f4aee0263c46e7af8b710 src/transmitter/ sender_loop.py
    compare_digest ddf7f009c3563d80e4a07e5ee985efa0643a899a77509a5326c46c81d64f419afee48e0e972ff5d1f6ee01bbdfc12d265f7de92cbe4308751e19c27bf445d90d src/transmitter/ traffic_masking.py
    compare_digest ccbda8415c23b23cc10cda57fb6b32df71e6510f3cb94c7f932b40adcf5f0abdd9842c48a992d56c95755e3024aebd7ecb05f69eb18f3c41656d94cfeabb38fa src/transmitter/ user_input.py
    compare_digest a3b88629e4668a2bd92f4723135947d4b97d78714a5c7de2f875fbf1a8152680e1128c41c12585b511d37611eac1723e91ae5941524b5f9cff580f3b8832ba61 src/transmitter/ windows.py
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

    torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
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

    torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
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
