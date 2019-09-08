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
ASN1CRYPTO=asn1crypto-0.24.0-py2.py3-none-any.whl
CERTIFI=certifi-2019.6.16-py2.py3-none-any.whl
CFFI=cffi-1.12.3-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.7-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.1.1-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.10.1-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.0-py3-none-any.whl
REQUESTS=requests-2.22.0-py2.py3-none-any.whl
SETUPTOOLS=setuptools-41.2.0-py2.py3-none-any.whl
SIX=six-1.12.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.3-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.7.5-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.15.6-py2.py3-none-any.whl


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
    compare_digest c3f27d766f2795bf0c87ddb0cec43f1f9919c2cf20db5eff62e818d67436f1520b6001bf9e7649c5508e62b221c02039b6cb29f7393ba1dbacf9a442cb3bb8b2 '' requirements.txt
    compare_digest 26e05619aeb1b39ea9d7a44e425ad33c83337ef3d04bd8dafdea6d725a0dfc8f896220bce74446edc9ed49811db8725340ae786d7c7e67b0f775f09377306625 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest e4f81f752001dbd04d46314ea6d8867393c3ad5ed85c2d3e336a8018913446f5855525e0ca03671ab8d26d8af1fe16416c8f5a163cad795867284a726adfeb31 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 651fccf97f1a1a3541078a19191b834448cb0c3256c6c2822989b572d67bc4b16932edea226ecf0cbd792fc6a11f4db841367d3ecd93efa67b27eaee0cc04cb7 '' LICENSE-3RD-PARTY
    compare_digest 84a4e5b287ba4f600fc170913f5bdcd3db67c6d75a57804331a04336a9931c7ce9c58257ad874d3f197c097869438bb1d2932f06f5762c44f264617681eab287 '' relay.py
    compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
    compare_digest 04a73ead3a4e4e61647588eb744f60bfab20983da9c26f3224dafe9bb7a78897841be8cdd26bf68857c0da2e169fc949a67af79de5d972158c40a945c15b3af4 '' requirements-relay.txt
    compare_digest 6e11d4928b23a0af977360b7ebb206888a6fcfd204be057c6210488494b828e1f372e6d180fc479c73c45dedf78bd7767bda8c4263ca0bb1c05432bf9de3b213 '' requirements-relay-tails.txt
    compare_digest 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png
    compare_digest a7b8090855295adfc22528b2f89bed88617b5e990ffe58e3a42142a9a4bea6b1b67c757c9b7d1eafeec22eddee9f9891b44afffa52d31ce5d050f08a1734874d '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest c6a61b3050624874cabc28cc51e947aa1ba629b0fd62564466b902cc433c08be6ae64d53bb2f33158e198c60ef2eb7c38b0bee1a64ef9659d101dee07557ddc7 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest fed9f056541afe1822ec41bce315fc6ce94652318088ecc905ddc657a15525d740ca83ff335e5090b9e3844027a706990da72a754ffa3dcd255b21e263597c78 launchers/ TFC-Local-test.desktop
    compare_digest 011a64aa7790253b008f0adfe940108dc94c08adec9b3a42efd1ac0d6405a82d828b3d416736ad64235b6b90ef2f6712fc10a70d8e97870670e5b84cf25fe54e launchers/ TFC-RP.desktop
    compare_digest 011a64aa7790253b008f0adfe940108dc94c08adec9b3a42efd1ac0d6405a82d828b3d416736ad64235b6b90ef2f6712fc10a70d8e97870670e5b84cf25fe54e launchers/ TFC-RP-Tails.desktop
    compare_digest 270153a45e5426db326ba2144ca454bb57ddf8f53731c1948ee8fa33dedcb98e32e19506b0fa923e5a7f6fca9a5b67338216c19417e52289726721efe12abd98 launchers/ TFC-RxP.desktop
    compare_digest 691d0cc4f03bd9c2874711ba97e347e705e4eadf53c5b14562e7e1a419ae892a9ce156b6e5a26945bde72c0b3e56ec6ca2d24fb3bf23848fb44808b7681e4141 launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest 92c7f788c41984cf75ad879e281f73a1a334dd759b858be11f91481a0e754e2db1527c9d3ab369aad7b8cf139492d5809c0c0542e46ff27637ee5b4b655b726f src/common/ crypto.py
    compare_digest 0b830ad6705f90dc8e554c8b06f31054d9222d3b35db92470eaf3f9af935aae3107b61142ea68129943e4227a45dfe26a87f23e9dd95a7794ae65c397bd35641 src/common/ db_contacts.py
    compare_digest bad54588b3e713caf94aba3216090410f77f92064aecfea004a33487a21f9fffcf5d05782b91104c27ec499e38196881a76d6002ec1149816d8c53560182fba9 src/common/ db_groups.py
    compare_digest 46e503af15fb7a1ea8387fa8f22674d0926eda0d879d43f99076ca967295d5e3727a411aa11c4bb4d832783c5daa9f4b7ef4491b90112c1be405910d269abaf4 src/common/ db_keys.py
    compare_digest 68b2c7761623ff9e4ce596e170c8e1ce2b6129bbbbb9fc9e48a120974d30db6e471bb5d514f5dc8d7edc8e0abcb0cd0c2b4e5da739f4d98c6fa8c8e07af0d8ef src/common/ db_logs.py
    compare_digest 1a3783e6ea5643bc799b9745d0a8abb82f9e814ca01da3414df86faaa007aaa21609a88e07c8947e43567a787f114db57143f10585053e92f96807858adec96a src/common/ db_masterkey.py
    compare_digest 5befbe864e2b09125be2b04cdfee8d13e7616715fc20a0fa06da270e34b555602b2df825fd429059056b2beb1497c50dafdc682d59a43a483837445861647e9d src/common/ db_onion.py
    compare_digest 328375464a5064829621fb8154c94cf15a1e7564122d99f03c9e578dcd6d6f264a671412b738b4971a6e505062673df40cc89f7b67c7ef2a761236c3f1247e93 src/common/ db_settings.py
    compare_digest 1e28086030d316a212053683dd204f05fbde48e94a913fa3c545b16d7e5842750b01af60e5b08771cce85e65a8394ad6208330a36e0ed8449a1a5e72b3fac285 src/common/ encoding.py
    compare_digest f7ff99c8a5f84b892b959fe391cdfe416d103a5a4d25fcd46842f768583a5b241036ee9c4b6713a938e8234f5af82a770ffe28975292d162b6d5bea69a120ad8 src/common/ exceptions.py
    compare_digest 6cbdbf90e4e427a645a3a8bafe40cf13b4d7c13e30836b8c23323b7f0f0d8ea10f0f6ec011d7f7a026e1cac156e125428fd0755c5321b108be09e07d62450a8e src/common/ gateway.py
    compare_digest 618cbaccb4f50bc6e551cd13570693d4d53cfdfdc00b7ff42ff9fd14f0dadf7a15c9bc32c8e53801aca42348826568a2aa9117bdbf79bbcc4217a07c94c9efd3 src/common/ input.py
    compare_digest 14f9a5f06443b50251272939b92eaf287fecfb4e3c9882254f13757259d9d791ac1e66c46fd0475d1e3161ff27f16ad7b4de04ac564500cae60d27a631d42e36 src/common/ misc.py
    compare_digest b6c05c8fdbe90dd4b6e358bcaa0becc3a33536f6e1bee4fee0f3f797be3cf8b85fdd1a0a8cb87a2ca7263399ae88ac1754cc050678c537f00b8303720e05809b src/common/ output.py
    compare_digest c4d97b497b341f0e7865a4e27a2a2ffd3b3c5a7bfbf72f4676f6b65d6ba66a2adb8fed563f88fa25cef555f0042290ef0ae4cbeed1697a2e19a3b8cff0b9ef1b src/common/ path.py
    compare_digest 9e9db25e73e0abb312b540d7601be7dfecae8d0aef6497feb2570f9ddf788fa0e261e276ed5a40e75fee0e0c6e86ccf3b05c110846fde804c302d4aa80a930e5 src/common/ reed_solomon.py
    compare_digest da6e0fbc5ac066067e8c38fcf2e6cd75a51f0caf19b697ee31bb4cca9f051d6033c8a885588bab35c44355640c0ace88e934aec99b40d2ac722fcece10ff296e src/common/ statics.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest e7444d665319a76f98798b6726a6b4f5dc53deda2daf32e1c84d018a5998264a5344f58d4a85dcfbda3b1179bad977b430a335d7f23c4416be6755ad62cad2c3 src/receiver/ commands.py
    compare_digest 760edaa44ff6175612b02f95b02b291ae369733a18cc5f87d525b46bcebc35c8a2d169a47962417eab434cf26ea6d5bfcd8894153fae668bb4a8cf2ceb8871f0 src/receiver/ commands_g.py
    compare_digest d3b70099efb0b966f1071da4a4f2b9ef0a4ae4a232c5bebf3cfd8f8e63b91d0152adcb43df10ff010b357a3ee6061cb3a8ece47e34af0a4767e76d5b008718eb src/receiver/ files.py
    compare_digest b3b0a61f3aba200e06bb2c6e05a067931be37ccfbc0768167a9d8651f7a8f6ea47871dcb5d63cf238f040d6c482fc45967a5a2ccbadb1308ec76b287b88fa3a6 src/receiver/ key_exchanges.py
    compare_digest df5af59342c8cbfa1ffbbdeadfc47da850601aa5fe7d21a857d0a4125dfff4b0984734f2e7ee589fe3b0642258923bb8efcd9f2e79ef06797f3218d34dc1266d src/receiver/ messages.py
    compare_digest c6156888ec4203bbdd589794181d1ab301953cce48355cd08b6226c983e34d72573e9df00fb116cd9a3f3bc191244c91a4206db6876bc386d1d2344092c9ec7f src/receiver/ output_loop.py
    compare_digest e98eda35146aafcede340e363df3fbec7e9429a091e97b1e2262cebd267654680ea23db5dd16d68d39d2d32e058827e315e752d09bc8c0f748c88fa95ad520bb src/receiver/ packet.py
    compare_digest 01b0ce92b4ab8f37eed55356a65f4d25ffff590955b5ca124dbb541bdec6968e8235242bf47ad5c2bfe57a30d54cf494d9f3836e3d53a73748f203ff68381c14 src/receiver/ receiver_loop.py
    compare_digest 6c35f718f8f9f7f01866233894a5f9a341e523dcddf05851292a1db927bccfba0da0d2db840cea31355a4df59e73244090ea8cbac4c14de773776b98bad9cf1d src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest 0e6b79d0fca3c47f3b8710e3d41d9ccc3274e38f21c80ba3271dc684369b68243e5f3301475b16773bb5716f0e6cef2379d8c173692a2fbafe98574e86e965e5 src/relay/ client.py
    compare_digest 6f0f916f7c879c0383e8dc39593385de8f1ab2f7ba99f59b7fcbee947f8fcfae0935a98dcd8de1db3a600a0d8469a369ea38915fe2932c00b6756fb4944c938d src/relay/ commands.py
    compare_digest 2891e53c2abf18d7d137a60ad75ae9990e335c8be4d4e9aee870bcbda9260d726d0b182cc558694c0e6bf872ca11820cedb2dff32a11ce59765f07e166fcd86c src/relay/ onion.py
    compare_digest a18aa0ca4ffff7be99721c094ae44a95ed407e5e4cb25016ce14bf9fca7fef950d0b0460fd91689f2003aeb7f8385cb4f88a5f2e3f7f4ba7b88634412853d888 src/relay/ server.py
    compare_digest e03b2896049d6c4f98cc9b52ae43a32078ffe93f6a18848fb96cf4051752872ad20463754fad61244e914b2082839d8297f0d3357e20c8dd22881e885bfbd32a src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest bb471267d37c73b37f3695bd3f28929612fe2074f7303b77f40cba0be84e975e3498402cbba2b402e45e35e81512ed2f67629cf0584536f36903b326d35cf557 src/transmitter/ commands.py
    compare_digest b861e16a6fbe2a93bf9f2dcf3f7f42d3f3ebf240aeaa2d752169a6807e2371eaaaf6230e0a71e6fe1e41e7ce5eb0515e8ec95bed5a7a7a263f42d715d23c399c src/transmitter/ commands_g.py
    compare_digest 9504026240d11036872f9c0b644d8249e364d4d303e339262d53bc0b9fe12e4ac36ea4d720fab2c916d3525c53928a6e782180529caf316298ffa84f2815f97d src/transmitter/ contact.py
    compare_digest dffc059fc25cbfb17beb9f83fc2d52ce043e9b923580ccf655933cf66fefcf6e18bcb923d7cb42a7d547126f938ff867a7638ffd13c14953b4a2d700f8f0d5c4 src/transmitter/ files.py
    compare_digest 061d7f3c4f737afafacc65bea744ac9bad16c6b064ab6281a3ab2079b18d984afa00b93e3861209425f78807e335925d824e018e80523b5380ac5244b8f5b8c2 src/transmitter/ input_loop.py
    compare_digest 6465a819b1a449145fdb676819446761d8faa96921623433b12b9386b781d7964368c0f2cd5fe48aad5beda3cdc0f6496e95ae89650addd91619c5984979584c src/transmitter/ key_exchanges.py
    compare_digest 1249ba23d30031ec8c1b42e999e52bc0903a0ad00c317d27d51c8d650b3343c9475319db6e0f2f16dfae39a942e01eeaae8eb862d541957b1f51690b1eb0f202 src/transmitter/ packet.py
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
    sudo $1 /opt/tfc/${ASN1CRYPTO}
    sudo $1 /opt/tfc/${CRYPTOGRAPHY}
}


function process_tails_dependencies {
    # Manage Tails dependencies in batch. The command that uses the
    # files is passed to the function as a parameter.

    t_sudo -E $1 /opt/tfc/${PYSERIAL}
    t_sudo -E $1 /opt/tfc/${STEM}
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
    t_sudo -E $1 /opt/tfc/${SETUPTOOLS}
    t_sudo -E $1 /opt/tfc/${SIX}
    t_sudo -E $1 /opt/tfc/${ASN1CRYPTO}
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
    t_sudo mv $HOME/${STEM}     /opt/tfc/
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
    t_sudo mv $HOME/${SETUPTOOLS}   /opt/tfc/
    t_sudo mv $HOME/${SIX}          /opt/tfc/
    t_sudo mv $HOME/${ASN1CRYPTO}   /opt/tfc/
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
    compare_digest 42141b21e096571329da88383bc977509608c0992b12c7d19cc2dae5c70efb7c0220abcd4f61d23d3133ea9ea47a15dbed8a15bd081049af9827272bcec02507 '' ${VIRTUALENV}
    compare_digest 8333ac2843fd136d5d0d63b527b37866f7d18afc3bb33c4938b63af077492aeb118eb32a89ac78547f14d59a2adb1e5d00728728275de62317da48dadf6cdff9 '' ${PYSERIAL}
    compare_digest a275f59bba650cb5bb151cf53fb1dd820334f9abbeae1a25e64502adc854c7f54c51bc3d6c1656b595d142fc0695ffad53aab3c57bc285421c1f4f10c9c3db4c '' ${STEM}
    compare_digest 5bbffb2714a04fb53417058703d8112c5e5dca768df627e64618e8ab8a36a8bdbc27f5d6852f39cff6b8fb4c9a5d13909f86eeb5fe9741ba42bdc985685e5d51 '' ${PYSOCKS}

    # Requests
    compare_digest 46d144af3633080b9ec8a642ab855b401b8224edb839c237639998b004f19b8cb191155c57e633954cf70b100d6d8b21105cd280acd1ea975aef1dec9a4a5860 '' ${URLLIB3}
    compare_digest fb07dbec1de86efbad82a4f73d98123c59b083c1f1277445204bef75de99ca200377ad2f1db8924ae79b31b3dd984891c87d0a6344ec4d07a0ddbbbc655821a3 '' ${IDNA}
    compare_digest bfae58c8ea19c87cc9c9bf3d0b6146bfdb3630346bd954fe8e9f7da1f09da1fc0d6943ff04802798a665ea3b610ee2d65658ce84fe5a89f9e93625ea396a17f4 '' ${CHARDET}
    compare_digest d81fe3a75ea611466d5ece7788f47c7946a4226bf4622c2accfd28c1e37b817e748609710c176c51ef2621cbc7ee200dd8d8106e738f1ef7cb96d7f2f82539cc '' ${CERTIFI}
    compare_digest 9186ce4e39bb64f5931a205ffc9afac61657bc42078bc4754ed12a2b66a12b7a620583440849fc2e161d1061ac0750ddef4670f54916931ace1e9abd2a9fb09c '' ${REQUESTS}

    # Flask
    compare_digest 70c09ba678e06b7631cd9a2e4c40225f56eb2f3fa76246234e40a8de809aeee2904630817843a16ae446497c5e1e462889e92bbc6ca342e4f9e8efbad4b0a70c '' ${WERKZEUG}
    compare_digest 69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec '' ${MARKUPSAFE}
    compare_digest 04860c7ff7086f051368787289f75198eec3357c7da7565dc5045353122650a887e063b1a5297578ddefcc77bfdfe3d9a23c868cb3e7f18a0b5f1c475e29339e '' ${JINJA2}
    compare_digest 891c294867f705eb9c66274bd04ac5d93140d6e9beea6cbf9a44e7f9c13c0e2efa3554bdf56620712759a5cd579e112a782d25f3f91ba9419d60b2b4d2bc5b7c '' ${ITSDANGEROUS}
    compare_digest 6b30987349df7c45c5f41cff9076ed45b178b444fca1ab1965f4ae33d1631522ce0a2868392c736666e83672b8b20e9503ae9ce5016dce3fa8f77bc8a3674130 '' ${CLICK}
    compare_digest bd49cb364307569480196289fa61fbb5493e46199620333f67617367278e1f56b20fc0d40fd540bef15642a8065e488c24e97f50535e8ec143875095157d8069 '' ${FLASK}

    # Cryptography
    compare_digest 125341f0c22e11d2bd24c453b22e8fd7fd71605ee7a44eb61228686326eaca2e8f35b7ad4d0eacde4865f4d8cb8acb5cb5e3ff2856e756632b71af2f0dbdbee9 '' ${SETUPTOOLS}
    compare_digest 326574c7542110d2cd8071136a36a6cffc7637ba948b55e0abb7f30f3821843073223301ecbec1d48b8361b0d7ccb338725eeb0424696efedc3f6bd2a23331d3 '' ${SIX}
    compare_digest 8d9bc344981079ac6c00e71e161c34b6f403e575bbfe1ad06e30a3bcb33e0db317bdcb7aed2d18d510cb1b3ee340a649f7f77a00d271fcf3cc388e6655b67533 '' ${ASN1CRYPTO}
    compare_digest 7f830e1c9066ee2d297a55e2bf6db4bf6447b6d9da0145d11a88c3bb98505755fb7986eafa6e06ae0b7680838f5e5d6a6d188245ca5ad45c2a727587bac93ab5 '' ${PYCPARSER}
    compare_digest 69a2d725395a1a3585556cb44b62c49bd7f88f41ff194b60d4b9b591c4878a907c0770ef4052b588eaa9d420a53cbeb6b13237fff4054bf26ba5deaa84e25afa '' ${CFFI}
    compare_digest 1285c3f5181da41bace4f9fd5ce5fc4bfba71143b39a4f3d8bab642db65bec9556b1965b1c2990236fed9d6b156bf81e6c0642d1531eadf7b92379c25cc4aeac '' ${CRYPTOGRAPHY}

    # PyNaCl
    compare_digest c4017c38b026a5c531b15839b8d61d1fae9907ba1960c2f97f4cd67fe0827729346d5186a6d6927ba84f64b4cbfdece12b287aa7750a039f4160831be871cea3 '' ${PYNACL}
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
    sudo torsocks apt install git libssl-dev python3-pip python3-tk net-tools -y
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
