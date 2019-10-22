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

# PIP dependency file names
ARGON2=argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
CERTIFI=certifi-2019.9.11-py2.py3-none-any.whl
CFFI=cffi-1.13.1-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.8-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.1.1-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.10.3-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.1-py3-none-any.whl
REQUESTS=requests-2.22.0-py2.py3-none-any.whl
SETUPTOOLS=setuptools-41.4.0-py2.py3-none-any.whl
SIX=six-1.12.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.6-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.7.7-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.16.0-py2.py3-none-any.whl


function compare_digest {
    # Compare the SHA512 digest of TFC file against the digest pinned in
    # this installer.
    if sha512sum /opt/tfc/$2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        echo OK - Pinned SHA512 hash matched file /opt/tfc/$2$3
    else
        echo Error: /opt/tfc/$2$3 had an invalid SHA512 hash
        exit 1
    fi
}


function verify_tcb_requirements_files {
    # To minimize the time TCB installer configuration stays online, only
    # the requirements files are authenticated between downloads.
    compare_digest fda79e90f90c0bcec5bed194d787d1370de9779ce3c9cbe82f17d09bcbf47e3ab25a97d67951d8b8a7e2cf1db1ad2dd2d883e7f46b909cf2f962c3a6f261df8b '' requirements.txt
    compare_digest 97558ed189976ccd54e3a25bcf639f1944aa43f4a4f42ff5ef2cf22349a7b649272e91746041b4e04b2f33adf1fab8818c339b1cc58f9353af3e5ac76cb1ec0b '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest e4f81f752001dbd04d46314ea6d8867393c3ad5ed85c2d3e336a8018913446f5855525e0ca03671ab8d26d8af1fe16416c8f5a163cad795867284a726adfeb31 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 7e519d20fef24e25e88ec4a9c03abadf513b084e05038f17c62ca7899c2f9174a953caa0bfbd3b61e455e243513cdab737c22a34d73ebab07b65d3ce99100f0a '' LICENSE-3RD-PARTY
    compare_digest 84a4e5b287ba4f600fc170913f5bdcd3db67c6d75a57804331a04336a9931c7ce9c58257ad874d3f197c097869438bb1d2932f06f5762c44f264617681eab287 '' relay.py
    compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
    compare_digest 1e77b356754c7050ad608b94609e8724899c2f7480aea3f6047f0e097a5dd01acc0089d6d85512c3cef0ba51878bf941a6962cc3ec17e1e5d68d1b129a05c799 '' requirements-relay.txt
    compare_digest 052b4d2dddd1c55aedc121c44bd0a0fc362f556816729f80361b23fe36050c54f8566abd7aa21b028d33fea512de190be60afb5548744cbdb33cd1301ace380a '' requirements-relay-tails.txt
    compare_digest 4a44501e21d463ff8569a1665b75c2e4d8de741d445dc3e442479cbb7282646045129233bd7313df4b9c2e64ec86b7615a8196ae2b3350de933731926d39bbda '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest a7b8090855295adfc22528b2f89bed88617b5e990ffe58e3a42142a9a4bea6b1b67c757c9b7d1eafeec22eddee9f9891b44afffa52d31ce5d050f08a1734874d '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest c6a61b3050624874cabc28cc51e947aa1ba629b0fd62564466b902cc433c08be6ae64d53bb2f33158e198c60ef2eb7c38b0bee1a64ef9659d101dee07557ddc7 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest a5611269e2f69a452840ae13d888bd80d6f8e5e78fdab0cb666440491d8431e6c326dc57a52df7d9e68ecd139376606c9f6c945207f2427bb21c114fe26c0af7 launchers/ TFC-Local-test.desktop
    compare_digest 9263737fca4773672515e0f4708e147b634bd09c8d068966806bb77d3b38dcf60b1f933846f9a649e795760ff141a31dc2b58fad38ef2afbaedb33d2f479a29b launchers/ TFC-RP.desktop
    compare_digest 9263737fca4773672515e0f4708e147b634bd09c8d068966806bb77d3b38dcf60b1f933846f9a649e795760ff141a31dc2b58fad38ef2afbaedb33d2f479a29b launchers/ TFC-RP-Tails.desktop
    compare_digest 113d1f8f6bc03009ef1ccfe1aed8a90bdecb54e66bd91ed815bbd83cb695419a25c614de8287475d3beab832cfcaf6d549c06832f2ea098d29ff049d7cd91da7 launchers/ TFC-RxP.desktop
    compare_digest 1f4d4e216039b63f2579eef17dc18df5e2f1e65f09e619b62adb8dceb128de6ffe5784ea0ff1dc846af21e1ce641bc612df51e37e205fee210f94dd87b86f467 launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest 7aa858161581e344fddbbe14c747903148870c6cea88bbed503bfc3e8a785f6878df2d5cad3c418f90472250cd5acb64bcf6f8e19674b649fb0e7b9fac77fdda src/common/ crypto.py
    compare_digest 0b830ad6705f90dc8e554c8b06f31054d9222d3b35db92470eaf3f9af935aae3107b61142ea68129943e4227a45dfe26a87f23e9dd95a7794ae65c397bd35641 src/common/ db_contacts.py
    compare_digest bad54588b3e713caf94aba3216090410f77f92064aecfea004a33487a21f9fffcf5d05782b91104c27ec499e38196881a76d6002ec1149816d8c53560182fba9 src/common/ db_groups.py
    compare_digest 46e503af15fb7a1ea8387fa8f22674d0926eda0d879d43f99076ca967295d5e3727a411aa11c4bb4d832783c5daa9f4b7ef4491b90112c1be405910d269abaf4 src/common/ db_keys.py
    compare_digest f5310f50c850405fdffe818b52be04fbf50d171199f62f1cc126448fe950eca0c8472a8846ae2d1cedad272bd35111e03f8fb5e60d786e13c1ca438f28642421 src/common/ db_logs.py
    compare_digest b6d8d88af58b8f13ca0768a9f05c79850017cf3ade59b931c08cb74b0cd2d082884bd952e704f39b383fbea8024314715ea2abdfe4ad78531c067e0e43a231ad src/common/ db_masterkey.py
    compare_digest 5befbe864e2b09125be2b04cdfee8d13e7616715fc20a0fa06da270e34b555602b2df825fd429059056b2beb1497c50dafdc682d59a43a483837445861647e9d src/common/ db_onion.py
    compare_digest 4f6a51fb56126d075886ef74ffb5408e12d2aa9cbaaffb8d646e8b7d891af31a0b74797d39716fa299ed9a3e5598b13f5862d0088de4516e09e19b3388e4f0fc src/common/ db_settings.py
    compare_digest b1c149138ae31619b3235e141a7e9fa9d6f424fa2a17e9447f40cfb845153bdc52ed03490b6502ec811af7ab3ea9fa5ed775f1f654583189141d82602028a870 src/common/ encoding.py
    compare_digest f7ff99c8a5f84b892b959fe391cdfe416d103a5a4d25fcd46842f768583a5b241036ee9c4b6713a938e8234f5af82a770ffe28975292d162b6d5bea69a120ad8 src/common/ exceptions.py
    compare_digest 9984086a39e8ce2f6d8760be4575c514aa82e2379577124ac94f8bf271a26284e420f2987b282b1afcc40532463419512818f16ff696f259090ff89cd38a002a src/common/ gateway.py
    compare_digest 618cbaccb4f50bc6e551cd13570693d4d53cfdfdc00b7ff42ff9fd14f0dadf7a15c9bc32c8e53801aca42348826568a2aa9117bdbf79bbcc4217a07c94c9efd3 src/common/ input.py
    compare_digest 748d70273bbe71550e0a7aa6fde19c6aee87c935f466550a23d280551cf963b8d10d34e3c17b0694eab406e4a44250a0ddb4dca56f0eb0d789b0ea1603db9db8 src/common/ misc.py
    compare_digest b6c05c8fdbe90dd4b6e358bcaa0becc3a33536f6e1bee4fee0f3f797be3cf8b85fdd1a0a8cb87a2ca7263399ae88ac1754cc050678c537f00b8303720e05809b src/common/ output.py
    compare_digest c4d97b497b341f0e7865a4e27a2a2ffd3b3c5a7bfbf72f4676f6b65d6ba66a2adb8fed563f88fa25cef555f0042290ef0ae4cbeed1697a2e19a3b8cff0b9ef1b src/common/ path.py
    compare_digest b591972b9f7c35be74b3e35ca0b6c8bca350f48f1f2ffb26b08659c6c6b2c6c7f654a7b8a1f505ada8f3e5ed9c6861aedac346768458b8cd71b4a5c8477fc7df src/common/ reed_solomon.py
    compare_digest 90ccd8e5ed8ab5e591777b65d20d2bfcacefda38ba5ea2f5079c3bd40ab280415757dc71e0df5d9b80aea6f9818956e36b9b8cc75e9ad1a54727ec2680f64e44 src/common/ statics.py
    compare_digest 339b402790cb3002841a1212d4dc24b07236b65baf68e3a8caf8d61bfd48af12887564be449ae49cfe5d7b88107a73e01a05053e3789398fbd560ef89f14afd4 src/common/ word_list.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest 42159ab4d20d0da6fee878238f75bea916e9cd8be85979fa17e0902311473e415873efa980984d624454da02ad22caa794152693a4f1cbe9953c54b9a7c8a6a8 src/receiver/ commands.py
    compare_digest 760edaa44ff6175612b02f95b02b291ae369733a18cc5f87d525b46bcebc35c8a2d169a47962417eab434cf26ea6d5bfcd8894153fae668bb4a8cf2ceb8871f0 src/receiver/ commands_g.py
    compare_digest d3b70099efb0b966f1071da4a4f2b9ef0a4ae4a232c5bebf3cfd8f8e63b91d0152adcb43df10ff010b357a3ee6061cb3a8ece47e34af0a4767e76d5b008718eb src/receiver/ files.py
    compare_digest bc0382f99d05d88fd06706d15c5242da69157a2175ef2901d7feb1b5ccf06d4017d3a4ffaeee72bbc5be4d6a19c3c7bef1b65ea3214f97c7b2c571baec7c9b1a src/receiver/ key_exchanges.py
    compare_digest df5af59342c8cbfa1ffbbdeadfc47da850601aa5fe7d21a857d0a4125dfff4b0984734f2e7ee589fe3b0642258923bb8efcd9f2e79ef06797f3218d34dc1266d src/receiver/ messages.py
    compare_digest c6156888ec4203bbdd589794181d1ab301953cce48355cd08b6226c983e34d72573e9df00fb116cd9a3f3bc191244c91a4206db6876bc386d1d2344092c9ec7f src/receiver/ output_loop.py
    compare_digest e98eda35146aafcede340e363df3fbec7e9429a091e97b1e2262cebd267654680ea23db5dd16d68d39d2d32e058827e315e752d09bc8c0f748c88fa95ad520bb src/receiver/ packet.py
    compare_digest 01b0ce92b4ab8f37eed55356a65f4d25ffff590955b5ca124dbb541bdec6968e8235242bf47ad5c2bfe57a30d54cf494d9f3836e3d53a73748f203ff68381c14 src/receiver/ receiver_loop.py
    compare_digest f5d7f6f790f8cc4a6337bdb2930620903cb5fe5271971816dde822e2c30b07fed5f7c625401f207e97da084e4985cf73b2a7394c4c52d11609313f5bd3930bad src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest b1027823ef0f99d5746fb82d13ab65d203b9fb66125c6d607570de13c9ad474e8dc805ace215619615f4eda6d76889b76bbab5ef13dc1ee4b5207c826b616e36 src/relay/ client.py
    compare_digest 6f0f916f7c879c0383e8dc39593385de8f1ab2f7ba99f59b7fcbee947f8fcfae0935a98dcd8de1db3a600a0d8469a369ea38915fe2932c00b6756fb4944c938d src/relay/ commands.py
    compare_digest 346001eff31e3f13ce2bb08d05696e49e9321812298352b21a0b95b4ea8f8f63ec1d10545c0743d40a4d6695f114c8ada79b2e4e1860482302c12b9802828db6 src/relay/ onion.py
    compare_digest a18aa0ca4ffff7be99721c094ae44a95ed407e5e4cb25016ce14bf9fca7fef950d0b0460fd91689f2003aeb7f8385cb4f88a5f2e3f7f4ba7b88634412853d888 src/relay/ server.py
    compare_digest d8bd141c9a41364744e78b606361393771bb52399ca3354c232f722374fc4b1e03baec91248ddcfd28b73d4d82bc03089c0c61dfb67d70df7068f91636d16c1a src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest bb471267d37c73b37f3695bd3f28929612fe2074f7303b77f40cba0be84e975e3498402cbba2b402e45e35e81512ed2f67629cf0584536f36903b326d35cf557 src/transmitter/ commands.py
    compare_digest 39c691823cb0d496aa0462d417f9c1576070c857d79e97a412990d9b58750c19b4090ab94feaa5e7ea35f0eb337eb8d74fce81592b573acc832888b5b2483272 src/transmitter/ commands_g.py
    compare_digest 9504026240d11036872f9c0b644d8249e364d4d303e339262d53bc0b9fe12e4ac36ea4d720fab2c916d3525c53928a6e782180529caf316298ffa84f2815f97d src/transmitter/ contact.py
    compare_digest dffc059fc25cbfb17beb9f83fc2d52ce043e9b923580ccf655933cf66fefcf6e18bcb923d7cb42a7d547126f938ff867a7638ffd13c14953b4a2d700f8f0d5c4 src/transmitter/ files.py
    compare_digest beb07be42303a77e339bed65befcfebdf577cdb02f187bc0abf642bd8aeda998911efa4fc04a55729867d52b1f30af9326cfda657d599e6678af133019a1404b src/transmitter/ input_loop.py
    compare_digest 032589074552c0a97a09ca7e141e563fd99a74a31c203edec3098144178f65eaf4f029b5097e6c09097adacc4549275648ff59fea6b03553b84b3e1506c02850 src/transmitter/ key_exchanges.py
    compare_digest 2dc93e66500ce0fbb06873255c6b42e0ed2f54bdf4d54f118ded6ff93e0dc05ae2fa6f124f30c0afb97281dd9c8e017712920472909641b61c4123eecd13d92e src/transmitter/ packet.py
    compare_digest 93f874a8d97312ab4be10e803ba5b0432a40cf2c05541775c7117aa68c18e78e52e814d38639b33e87dc33df1773e04dc2c789e61e08c12d9c15512dd9e5d4d3 src/transmitter/ sender_loop.py
    compare_digest bcad5d4b9932f1b35b2c74dc083233af584012cacdd1d2cb04b28115b4e224118ce220252754ae532df0adcc6c343b1913f711cf3bd94da9c4cd3eaf23e4b196 src/transmitter/ traffic_masking.py
    compare_digest ccbda8415c23b23cc10cda57fb6b32df71e6510f3cb94c7f932b40adcf5f0abdd9842c48a992d56c95755e3024aebd7ecb05f69eb18f3c41656d94cfeabb38fa src/transmitter/ user_input.py
    compare_digest 4c5b9c877474257d078723d32533ba614d72bad7b108588f49fae6c26dcb2c49994b256b5457caee0e5ab4628f728b25a54551ce778b585cbb8b1f8c947dc7e6 src/transmitter/ windows.py
}


function process_tcb_dependencies {
    # Manage TCB dependencies in batch. The command that uses the files
    # is passed to the function as a parameter.
    sudo $1 /opt/tfc/${SIX}
    sudo $1 /opt/tfc/${PYCPARSER}
    sudo $1 /opt/tfc/${CFFI}
    sudo $1 /opt/tfc/${ARGON2}
    sudo $1 /opt/tfc/${SETUPTOOLS}
    sudo $1 /opt/tfc/${PYNACL}
    sudo $1 /opt/tfc/${PYSERIAL}
    sudo $1 /opt/tfc/${CRYPTOGRAPHY}
}


function process_tails_dependencies {
    # Manage Tails dependencies in batch. The command that uses the
    # files is passed to the function as a parameter.

    t_sudo -E $1 /opt/tfc/${PYSERIAL}
    # t_sudo -E $1 /opt/tfc/${STEM}
    t_sudo -E $1 /opt/tfc/${PYSOCKS}

    # Requests
    t_sudo -E $1 /opt/tfc/${URLLIB3}
    t_sudo -E $1 /opt/tfc/${IDNA}
    t_sudo -E $1 /opt/tfc/${CHARDET}
    t_sudo -E $1 /opt/tfc/${CERTIFI}
    t_sudo -E $1 /opt/tfc/${REQUESTS}

    # Flask
    t_sudo -E $1 /opt/tfc/${WERKZEUG}
    t_sudo -E $1 /opt/tfc/${MARKUPSAFE}
    t_sudo -E $1 /opt/tfc/${JINJA2}
    t_sudo -E $1 /opt/tfc/${ITSDANGEROUS}
    t_sudo -E $1 /opt/tfc/${CLICK}
    t_sudo -E $1 /opt/tfc/${FLASK}

    # Cryptography
    t_sudo -E $1 /opt/tfc/${SIX}
    t_sudo -E $1 /opt/tfc/${PYCPARSER}
    t_sudo -E $1 /opt/tfc/${CFFI}
    t_sudo -E $1 /opt/tfc/${CRYPTOGRAPHY}

    # PyNaCl
    t_sudo -E $1 /opt/tfc/${PYNACL}
}


function move_tails_dependencies {
    # Move Tails dependencies in batch.
    t_sudo mv $HOME/${VIRTUALENV} /opt/tfc/
    t_sudo mv $HOME/${PYSERIAL} /opt/tfc/
    # t_sudo mv $HOME/${STEM}     /opt/tfc/
    t_sudo mv $HOME/${PYSOCKS}  /opt/tfc/

    # Requests
    t_sudo mv $HOME/${URLLIB3}  /opt/tfc/
    t_sudo mv $HOME/${IDNA}     /opt/tfc/
    t_sudo mv $HOME/${CHARDET}  /opt/tfc/
    t_sudo mv $HOME/${CERTIFI}  /opt/tfc/
    t_sudo mv $HOME/${REQUESTS} /opt/tfc/

    # Flask
    t_sudo mv $HOME/${WERKZEUG}     /opt/tfc/
    t_sudo mv $HOME/${MARKUPSAFE}   /opt/tfc/
    t_sudo mv $HOME/${JINJA2}       /opt/tfc/
    t_sudo mv $HOME/${ITSDANGEROUS} /opt/tfc/
    t_sudo mv $HOME/${CLICK}        /opt/tfc/
    t_sudo mv $HOME/${FLASK}        /opt/tfc/

    # Cryptography
    t_sudo mv $HOME/${SIX}          /opt/tfc/
    t_sudo mv $HOME/${PYCPARSER}    /opt/tfc/
    t_sudo mv $HOME/${CFFI}         /opt/tfc/
    t_sudo mv $HOME/${CRYPTOGRAPHY} /opt/tfc/

    # PyNaCl
    t_sudo mv $HOME/${PYNACL} /opt/tfc/
}


function verify_tails_dependencies {
    # Tails doesn't allow downloading over PIP to /opt/tfc, so we
    # first download to $HOME, move the files to /opt/tfc, and then
    # perform additional hash verification
    compare_digest e80eb04615d1dcd2546bd5ceef5408bbb577fa0dd725bc69f20dd7840518af575f0b41e629e8164fdaea398628813720a6f70a42e7748336601391605b79f542 '' ${VIRTUALENV}
    compare_digest 8333ac2843fd136d5d0d63b527b37866f7d18afc3bb33c4938b63af077492aeb118eb32a89ac78547f14d59a2adb1e5d00728728275de62317da48dadf6cdff9 '' ${PYSERIAL}
    # compare_digest a275f59bba650cb5bb151cf53fb1dd820334f9abbeae1a25e64502adc854c7f54c51bc3d6c1656b595d142fc0695ffad53aab3c57bc285421c1f4f10c9c3db4c '' ${STEM}
    compare_digest 313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12 '' ${PYSOCKS}

    # Requests
    compare_digest 719cfa3841d0fe7c7f0a1901b8029df6685825da7f510ba61f095df64f115fae8bfa4118fa7536231ed8187cdf3385cb2d52e53c1b35b8f4aa42f7117cc4d447 '' ${URLLIB3}
    compare_digest fb07dbec1de86efbad82a4f73d98123c59b083c1f1277445204bef75de99ca200377ad2f1db8924ae79b31b3dd984891c87d0a6344ec4d07a0ddbbbc655821a3 '' ${IDNA}
    compare_digest bfae58c8ea19c87cc9c9bf3d0b6146bfdb3630346bd954fe8e9f7da1f09da1fc0d6943ff04802798a665ea3b610ee2d65658ce84fe5a89f9e93625ea396a17f4 '' ${CHARDET}
    compare_digest 06e8e1546d375e528a1486e1dee4fda3e585a03ef23ede85d1dad006e0eda837ebade1edde62fdc987a7f310bda69159e94ec36b79a066e0e13bbe8bf7019cfc '' ${CERTIFI}
    compare_digest 9186ce4e39bb64f5931a205ffc9afac61657bc42078bc4754ed12a2b66a12b7a620583440849fc2e161d1061ac0750ddef4670f54916931ace1e9abd2a9fb09c '' ${REQUESTS}

    # Flask
    compare_digest 3905022d0c398856b30d2ed6bae046c1532e87f56a0a40060030c18124c6c9c98976d9429e2ab03676c4ce75be4ea915ffc2719e04e4b4912a96e498dcd9eb89 '' ${WERKZEUG}
    compare_digest 69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec '' ${MARKUPSAFE}
    compare_digest 658d069944c81f9d8b2e90577a9d2c844b4c6a26764efefd7a86f26c05276baf6c7255f381e20e5178782be1786b7400cab12dec15653e7262b36194228bf649 '' ${JINJA2}
    compare_digest 891c294867f705eb9c66274bd04ac5d93140d6e9beea6cbf9a44e7f9c13c0e2efa3554bdf56620712759a5cd579e112a782d25f3f91ba9419d60b2b4d2bc5b7c '' ${ITSDANGEROUS}
    compare_digest 6b30987349df7c45c5f41cff9076ed45b178b444fca1ab1965f4ae33d1631522ce0a2868392c736666e83672b8b20e9503ae9ce5016dce3fa8f77bc8a3674130 '' ${CLICK}
    compare_digest bd49cb364307569480196289fa61fbb5493e46199620333f67617367278e1f56b20fc0d40fd540bef15642a8065e488c24e97f50535e8ec143875095157d8069 '' ${FLASK}

    # Cryptography
    compare_digest 326574c7542110d2cd8071136a36a6cffc7637ba948b55e0abb7f30f3821843073223301ecbec1d48b8361b0d7ccb338725eeb0424696efedc3f6bd2a23331d3 '' ${SIX}
    compare_digest 7f830e1c9066ee2d297a55e2bf6db4bf6447b6d9da0145d11a88c3bb98505755fb7986eafa6e06ae0b7680838f5e5d6a6d188245ca5ad45c2a727587bac93ab5 '' ${PYCPARSER}
    compare_digest fdefd3f63f56adff50723d6a88dc6db816d3d8a31b563599d2a3633ba796f6f70d5a9430510852b3d62b97357f8764f17eeab74b13df16c7cc34e1671a82373b '' ${CFFI}
    compare_digest d8ddabe127ae8d7330d219e284de68b37fa450a27b4cf05334e9115388295b00148d9861c23b1a2e5ea9df0c33a2d27f3e4b25ce9abd3c334f1979920b19c902 '' ${CRYPTOGRAPHY}

    # PyNaCl
    compare_digest c4017c38b026a5c531b15839b8d61d1fae9907ba1960c2f97f4cd67fe0827729346d5186a6d6927ba84f64b4cbfdece12b287aa7750a039f4160831be871cea3 '' ${PYNACL}
}


function install_tails_setuptools {
    # Download setuptools package for Tails and then authenticate and install it.
    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-setuptools.txt  --require-hashes -d $HOME/
    t_sudo mv $HOME/${SETUPTOOLS} /opt/tfc/
    compare_digest a27b38d596931dfef81d705d05689b7748ce0e02d21af4a37204fc74b0913fa7241b8135535eb7749f09af361cad90c475af98493fef11c4ad974780ee01243d '' ${SETUPTOOLS}
    t_sudo python3.7 -m pip install /opt/tfc/${SETUPTOOLS}
    t_sudo -E rm /opt/tfc/${SETUPTOOLS}
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
    $1 rm    /opt/tfc/requirements-relay-tails.txt
    $1 rm    /opt/tfc/requirements-setuptools.txt
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
    sudo torsocks apt install git gnome-terminal libssl-dev python3-pip python3-tk net-tools -y
    sudo torsocks git clone --depth 1 https://github.com/tfctesting/tfc.git /opt/tfc

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
    sudo rm    /opt/tfc/tfc.yml
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
    sudo rm /opt/tfc/tfc.yml
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
    sudo torsocks apt install git libssl-dev python3-pip python3-tk terminator -y

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
    sudo rm    /opt/tfc/tfc.yml
    sudo rm    /opt/tfc/${VIRTUALENV}

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


function install_relay_tails {
    # Install TFC Relay configuration on Networked Computer running
    # Tails live distro (https://tails.boum.org/).
    check_tails_tor_version
    read_sudo_pwd

    # Apt dependencies
    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip -y || true  # Ignore error in case packets can not be persistently installed

    torsocks git clone --depth 1 https://github.com/tfctesting/tfc.git $HOME/tfc
    t_sudo mv $HOME/tfc/ /opt/tfc/
    t_sudo chown -R root /opt/tfc/

    verify_tcb_requirements_files
    verify_files

    create_user_data_dir

    install_tails_setuptools

    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt        --require-hashes -d $HOME/
    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay-tails.txt --require-hashes -d $HOME/

    move_tails_dependencies
    verify_tails_dependencies

    t_sudo python3.7 -m pip install /opt/tfc/${VIRTUALENV}
    t_sudo python3.7 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    process_tails_dependencies "python3.7 -m pip install"
    deactivate

    # Complete setup
    t_sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    t_sudo mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/
    t_sudo mv /opt/tfc/tfc.yml                        /etc/onion-grater.d/

    remove_common_files        "t_sudo"
    process_tails_dependencies "rm"

    t_sudo rm /opt/tfc/${VIRTUALENV}
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
    if [[ "$(cat /etc/os-release 2>/dev/null | grep Tails)" ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


function install_virtualenv {
    # Determine if the OS needs to have the virtualenv installed as sudo
    # so that the user (who should be on sudoers list) can see virtualenv
    # when the installer sets up virtual environment to /opt/tfc/.
    distro=$(lsb_release -d | awk -F"\t" '{print $2}')

    if [[ "$distro" =~ ^Debian* ]]; then
        sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    elif [[ "$distro" =~ Eoan* ]]; then
        sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    elif [[ "$distro" =~ PureOS* ]]; then
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

    sleep 1
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
        exit_with_message "This installer must not be run as root."
    fi
}


function sudoer_check {
    # Check that the user who launched the installer is on the sudoers list.

    # Tails allows sudo without the user `amnesia` being on sudoers list.
    if ! [[ "$(lsb_release -a 2>/dev/null | grep Tails)" ]]; then
        return
    fi

    sudoers=$(getent group sudo |cut -d: -f4 | tr "," "\n")
    user_is_sudoer=false

    for sudoer in ${sudoers}; do
        if [[ ${sudoer} == ${USER} ]]; then
            user_is_sudoer=true
            break
        fi
    done

    if ! ${user_is_sudoer}; then
        exit_with_message "User ${USER} must be on the sudoers list."
    fi
}


function architecture_check {
    # Check that the OS is 64-bit, and not 32-bit.
    if ! [[ "$(uname -m 2>/dev/null | grep x86_64)" ]]; then
        exit_with_message "Invalid system architecture."
    fi
}


function exit_with_message {
    # Print error message and exit the installer with flag 1.
    clear
    echo ''
    c_echo "Error: $* Exiting." 1>&2
    echo ''
    exit 1
}


set -e
architecture_check
root_check
sudoer_check
sudo_pwd=''

case $1 in
    tcb   ) install_tcb;;
    relay ) install_relay;;
    local ) install_local_test;;
    dev   ) install_developer;;
    *     ) arg_error;;
esac
