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

# PIP dependency file names
ARGON2=argon2_cffi-19.2.0-cp34-abi3-manylinux1_x86_64.whl
CERTIFI=certifi-2019.11.28-py2.py3-none-any.whl
CFFI=cffi-1.13.2-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.8-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.1.1-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.11.0-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.1-py3-none-any.whl
REQUESTS=requests-2.22.0-py2.py3-none-any.whl
SETUPTOOLS=setuptools-45.1.0-py3-none-any.whl
SIX=six-1.14.0-py2.py3-none-any.whl
# STEM=stem-1.8.0.tar.gz
URLLIB3=urllib3-1.25.7-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.7.9-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.16.1-py2.py3-none-any.whl


function compare_digest {
    # Compare the SHA512 digest of TFC file against the digest pinned in
    # this installer.
    if sha512sum "/opt/tfc/${2}${3}" | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        echo "OK - Pinned SHA512 hash matched file /opt/tfc/${2}${3}"
    else
        echo "Error: /opt/tfc/${2}${3} had an invalid SHA512 hash"
        exit 1
    fi
}


function verify_tcb_requirements_files {
    # To minimize the time TCB installer configuration stays online, only
    # the requirements files are authenticated between downloads.
    compare_digest 8cb58c52af4481bc0be13dcda4db00456f7522934f185c216dcfe3ded794e5a35ecf7fa3e6417d7cbb477c0b3c59606a1c858b0b17d46ba6453ed71522fd976e '' requirements.txt
    compare_digest 4f7372efb604ca5d45f8f8d76d0b840f68c5e2401b09b9824d6a0fc34291ceffbd0ebf516735e2ac5244681628ed2bd6fca1405f0c6d463bf869061bd6f6cd29 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest 1d9ee816a00eb66a96cf2a6484f37037e90eb8865d68b02de9c01d7ee6fa735cbbd2279099fe8adfb4dda5d9c0a2da649a5f530dba1f0c44471838995abcebb2 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 4a239b91b2626375255fbf4202a4bf49ea248832b65d69e00530d7cec88e489466508aeb1ff8c8ef0f138819500c4fde2010207ebe3e289c36bc201df55d3c47 '' LICENSE-3RD-PARTY
    compare_digest 95b6422cae6c643de278de98b1b1f959d296498dcd64cc674717b05238d81707a70be2fc24ff1fbe6173e7df057abf5c8aa9304cdb3c8ae0e8cf6824c34cdfe4 '' relay.py
    compare_digest 4c6e646f2a28c2535f4f1c7da8cff2447fb21a8fc01af5ea4af5ffeec9f7af717d06a882913fcad427832f20dfc8b91162aea9ee20e3a90570a23e983b1a7c65 '' requirements-dev.txt
    compare_digest 1276cf7dbfea9b59ef3730a47e79090330dea7ed4137336edc095423cd35dbe5a55ce3c28a801fea193833d18d06a8b3c8b1fceb4df71b33717d863cc896b3e9 '' requirements-relay.txt
    compare_digest fcb793f4bea82fdf60706b948b1e0363d7a361814056ac339df5f0a27f6b955f8098b069883ebfeea4e87467bc77f73443006dd521b88df561ef4ded60f7e1ee '' requirements-relay-tails.txt
    compare_digest 89e82f1f1b1a4d9f3d1432c2988c00f70d2cc1b5e670f50666d189817115bac7b1e15331dc243d1f0364d7d283a9d25c9982ee7ba90563b29bdf41986e734b50 '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest 4e659a97f7f4b8ba816b111446e5795460db8def5db380bd05ede96042170796def1f4cdc4f6afc7062079fca584ac09010a6222d6835403777d6acba91add8c '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest ba16a9b9a197d7a916609bcd1f1ad8a076ad55c0b3f04510e8f19dfea35be9cf4a036481b3a03deb5932d5e9a90c4ca9f6e28d0127549681d756b4eda3c5c6e0 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest 105867d11f0055c4ea549bc95881e0a38ab0f08b4964c55cc710b9f8a4b074185840e92f5b3ea327bfc914a6597ee3c95d25ce931368bcfdf6ec807c7bf49332 launchers/ TFC-Local-test.desktop
    compare_digest b3c83861fd868ad6b9605c1e641e76d33d8d8cf39c300caff1fb5f7b8333d92e76583c611c7cb747525b0e911369cd4106cac743e16b30e51ec37684999d6166 launchers/ TFC-RP.desktop
    compare_digest b3c83861fd868ad6b9605c1e641e76d33d8d8cf39c300caff1fb5f7b8333d92e76583c611c7cb747525b0e911369cd4106cac743e16b30e51ec37684999d6166 launchers/ TFC-RP-Tails.desktop
    compare_digest 6c169a1746ec289b2eda98e2bb12ef0cd6c8206e70b0433e194cb4f9bbe9eea83ac06262d3c4b8b5ae1a04c0ac4be2c34ff97b11053734b030664bbe2355b2fa launchers/ TFC-RxP.desktop
    compare_digest a325bf7b1c2e3dc4f8f40c67db15df1ce8e7e0b96b4224afc6ede84031f7e799d4ea41f6a44b75dab92a22a9cf4c60154a108b9737a5dac6af0c2abca8b6786e launchers/ TFC-TxP.desktop

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/ __init__.py
    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/common/ __init__.py
    compare_digest 1185e70d293efcde095dc546ea1fc228a031769cf81f1b8d3baee87e2c828bf1353c80613a4c641a4fa6f2e7839e3a8f91f7263ff7608e8d95c6f4d476d401d9 src/common/ crypto.py
    compare_digest c4459dbd67a0abddf7323b7254dfad79ec9f5789cc99fa666a4a03b32509994f56cecb0ea3a0f694df5387bdfa28ac6b9de32243b0f63b5839bbb3ae748f3280 src/common/ database.py
    compare_digest 99bb26974918c1fe23c001d39296653b5dda678fbde1d3470bfb2d62ccc73d31f782adc74666f53389cf8560215e098350dcac7cd66c297712564460c50c4302 src/common/ db_contacts.py
    compare_digest 032ccacc86f62bbd1eafb645730679a1023841f53c6391b700e6562ba33321f0ef81d36f3fa02752b189cb795677d209404fffa7de6ebf042bd3ff418e056b9a src/common/ db_groups.py
    compare_digest 38fed0ace4cc1032b9d52d80c2a94252a0001b11ed7a7d7dc27fff66ed1e10309ee07b345556775958389d83cb976cd151df2d717b5c7dbe6d312778ecb06408 src/common/ db_keys.py
    compare_digest 9145cc54445727ce55d18e8ca2279c7e924678e2eba891ade369e9a8580bb836612745c1e5d95c2bdfde223cfe877824bb7d685cceb0815b58d326a1b1f5354f src/common/ db_logs.py
    compare_digest 4d7c6d383d79c2ba11bea894a0e9ba5aec07bd952196da7ee2b006a0bf8908825d434a5973aa65adcc7f1cf87e9996b2699d8cfc914657093004f571e9ea41ef src/common/ db_masterkey.py
    compare_digest 325298cd6cb7e68d27681c18f29e635f46222e34015ba3c8fe55e6718e6907b4257bbe12d71fd344b557aff302ae9d7fca2b581b4208e59ac7923e57aca23fe5 src/common/ db_onion.py
    compare_digest 66fba9810a2f9f7ef93d41a279a319c3cb45f1bea1ad798c3b3bbc35aa2b5ba5ff63ec2c392faf4db1d430d2e24bb718cb8b67c27f096d420915a6af3e3b06ee src/common/ db_settings.py
    compare_digest 60fb4c922af286307865b29f0cadab53a5a575a9f820cd5ad99ea116c841b54dd1d1be1352bf7c3ab51d2fd223077217bcda1b442d44d2b9f1bf614e15c4a14d src/common/ encoding.py
    compare_digest 1b58f97ffb19683a84588a7a0b2e92cf0ffa134cad18205a9a8fb0bfddaa57e3b2d650f69c88659857d8c310d8df33db91327b25e87d4e7f9d503275ddfb89f5 src/common/ exceptions.py
    compare_digest be7d2d35a0c43578cd5ffe7ad4940d582a47968688037fd54e971f3850e2d87be0d18e7623a2ca1e67981a859d525e2c7cf51dd0d7e0873cee1736ca97502ec5 src/common/ gateway.py
    compare_digest c8d339a0728148ea1ad99d2680446618f79d34ad9c7334f8e7d57c74dd3b855c7566d7f806adde882fc8bebd9e52acec95bf2d16f6ce5d876378bbb55db2895b src/common/ input.py
    compare_digest e8ae996925e6651c003ad7defbc1341ef1dd8539150a6edbdd79ee0ba2b2959f06afd8048d98e4244d103aea69d89856d4e909243e31d92147b89497b919291d src/common/ misc.py
    compare_digest 6ffdf92210f258978ea946440a3607f714ded5b75c6deaf1fc49d0f0f62c51b0b8c010c4c4da0ce42a3f738f923e764201794dde56a98d5189658ca2b1aaf9dd src/common/ output.py
    compare_digest 08443cfe633bb552d6bb55e48d81423db4a4099f9febc73ec6ee85ee535bc543720f199ac8b600b718e9af7247fb96ef4b9991b0416cf7186fd75a149365dd36 src/common/ path.py
    compare_digest 557a59675e7887f140603f799a53898d0920938d9df6c7058ab868b3edeb7cab5fe8aa900eeed7025362767171470e5ab9979f23cc8901e64cebbd3c2b85b10c src/common/ reed_solomon.py
    compare_digest 5dcc772c69bba283083f0a3b11e1b36b6776ff1973659033b8ae7c8ff2506bcfdb62f7b9ac2d46a3fb7b42f59c59867edc5cfdda11ed16c7e2e22a75fcc660ff src/common/ statics.py
    compare_digest a57d5525a570a78d15c75e79702289cf8571c1b3c142fae57f32bf3ed8bb784c7f63ce2e805d295b4a505fdeaf9d59094ebe67d8979c92dc11e2534474505b0e src/common/ word_list.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/receiver/ __init__.py
    compare_digest a4aeb64c2adb0d435e52f8de33aaff1ec135ca6b551c813fa53281087e8e62a0db9ad0ac595bca17391ee80cba9dfef9790b39d0877b0497bab3871f167ee9cd src/receiver/ commands.py
    compare_digest 6dd0d73fe240f974bb92e850c5f38e97ee8d632fbb3a53abc3160b4e29f9b2b076b8b5d20dc7f7231c01c978ea67b55740ac17dc74bf05e6811d2e35e34056fb src/receiver/ commands_g.py
    compare_digest 060e35c046dc48d67ae234ffb7e7d607de45d3076a42a1860893024e2a3f41d7e77c280ce67da271c35b6a31e34bcd6e4b892687dcfa808685d35292060c99a2 src/receiver/ files.py
    compare_digest 611744c93b1d16d0341bba679e3d9963a08fc5c55eaf20c3281fc21da591006c69004499813b485f6f1ccc6f3c7eb5efb8d7f3f1099d30295607f023b8a8eed1 src/receiver/ key_exchanges.py
    compare_digest 5c45405ba4025489ea55a39fba4503e08a93b8e2a273b5bb4fa1a57d3f674997c8b3a31a216a2d03bc0a919b59c32a92a57116385fd608016f3cc9e74061f273 src/receiver/ messages.py
    compare_digest 5903e0fec9dd816adf0f3bd69ed01cd0cd2ac8e9f0c1cb5c97a8d12a8a48e1b6b3efc88a0eab807b42c9c41f49cc0dd4bb82160edfc19f7fde939f572d55b000 src/receiver/ output_loop.py
    compare_digest 25b49765e149f5e072df2aa70c125478d1c9621886527201bf0d7718db557f2991823d980274f53abf93269f5aa1096b3e56fae94ecaa974ef31b0cb7907fde7 src/receiver/ packet.py
    compare_digest 002c960023393bec10da3de6d9a218c8e2c27da1635fd1a7f99e02a9a28792428a2c0e6cd030d1cc1fac1124c58f397f63d60b7af4c384367a8c293978125539 src/receiver/ receiver_loop.py
    compare_digest da8ff22a1ece42c780328c84722ae42c2dced69dd87f2fb2d09fd517d3ee98f3777c448922b2b06a5839347e075a5598e6c770a544fdf801e664ba5ad06b684d src/receiver/ windows.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/relay/ __init__.py
    compare_digest 3bf2a0c8916ad19ba91046868dccf81c7fe65efa23f767bb9d0a02b4e8fa668b66fd45a0cc309b22b72a1639b4462a61559b4e479e3ab3d9054847f8e3ac8f86 src/relay/ client.py
    compare_digest aebfdb969adf63ee5d53e968fb2709a448ff4b55d84058ce3f988a355531207b652f24bafed79e5f8a21d5a71f6c31e5df5110e4359fb7ab4cff33d481bd79f6 src/relay/ commands.py
    compare_digest 64674ffa28c1ba3626cd5415e1c1656637e83c33c02fa84f36b281c82cf812f6a96c0a829e0acffd4fdd162138637ec0b9dc883d2604aeb2aad1ac0b1f2c6713 src/relay/ onion.py
    compare_digest 0273508b0c2f95ba5e710a9c8201fa6915881305a02de9c3e165b6f78912d559ed8fa4edb0ca07cbf1843a0cee4b377c073dbfc3eb6600bbdb163228ac1f1742 src/relay/ server.py
    compare_digest 789244e14856cc0efb81b2a13855166bf8532c510b17883b1204afaa1b1abfa44a9a77e63bc052de7a9a82676d6c646a9c336d3dd410f3b5bf7b32213ef4fb5a src/relay/ tcb.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/transmitter/ __init__.py
    compare_digest 8331943fd11bf59a3f9d91c28f13bc77826a66713dee5df0f1c69d81273a4fd9aeb8ab1a3d7fa93adfe8edd871157f77bfafb9f76194666f2a79fe7e53fb9942 src/transmitter/ commands.py
    compare_digest 72c072d39033a9e670c8621bcda44a066e7490eba0bb9cbfbded248a40a77f406c3fae875f6ff72d912e01703fb1b7570eeacba6ac51563a11aba8e1e31549dc src/transmitter/ commands_g.py
    compare_digest 98eaf672530a58aeb8d6b241923fd23e8d19026c65dde652e8c2d02fcd82ce1f389c586aa8bd155ce752bbdb215ab77deb32f2da9b0a56da864064f07dd4cc19 src/transmitter/ contact.py
    compare_digest f2fefbc2acbad441cb997969d6b39fbe26813abc781f5b6caaa08f1eb4c52c05b2bd4cbc341cb75ea07f7a4931d9b1145bef2fb352376a72442f7a71299fb595 src/transmitter/ files.py
    compare_digest 110665f962eb827a9f636cc823837222a7bed4a429d4e10eb90c7bf5ba7bd5900aa1ecc4d4b485927a276d5727e18fe9e78f75ab8bd4ff67f039bb633fe505ec src/transmitter/ input_loop.py
    compare_digest e5a08585d9d87d01aa295ebbdbb625ecb1bdad9ec3aac63f66accef995e44ea84f714f8786facd737e6f75517ef250ddf603683d76cb51bc5e3ff247c50d63bb src/transmitter/ key_exchanges.py
    compare_digest 766b1efa548f2da49272870fa5f89b8aacdf65b737b908f7064209f2f256c4d4875228ad087ac4957a292a82ed5936a40b9ae7553bfae2eae739f0c4579eb21a src/transmitter/ packet.py
    compare_digest 263ee3f6ae9183808b2c3652fecbf0327a26f299b88c962d3a20fcbfcfac1b73ca3ecf1bbbe4c7c39384b5bf8a06d5193152d13f21573f523bde7335a864f067 src/transmitter/ sender_loop.py
    compare_digest cdcb21128f71134ae49f3e99bf2a6dce5ec88766ecf6d91be89200ef282f7bd326c9805ba8f2d73d3fa12a8e05da20630874b5bbf9e18085d47ad5063098eaf8 src/transmitter/ traffic_masking.py
    compare_digest eb77c6206cab63ffdb47bbcb8b76a55100636d893e234a048221d83e9ce07b76ccfcc93b506d9fb48d6f8823135e5697f3e56aed8e95f23990d8dfc1cece325e src/transmitter/ user_input.py
    compare_digest c98461d1807f585092be0440426bbd7082f3bbadc6b80c7be4402fe38d0ec898b90ad331ca93d047ff4237be0b724562445d7cda4f957aa18f79b6ae654139f0 src/transmitter/ window_mock.py
    compare_digest 7822acf6c3306b2189e0544aeb3d94fdf1f9b2668be772cc044535c907f135c09ca846786fecb072d46a349d267cd1499d4088a511defe75b312610d8f36e55e src/transmitter/ windows.py
}


function process_tcb_dependencies {
    # Manage TCB dependencies in batch. The command that uses the files
    # is passed to the function as a parameter.
    sudo $1 "/opt/tfc/${SIX}"
    sudo $1 "/opt/tfc/${PYCPARSER}"
    sudo $1 "/opt/tfc/${CFFI}"
    sudo $1 "/opt/tfc/${ARGON2}"
    sudo $1 "/opt/tfc/${SETUPTOOLS}"
    sudo $1 "/opt/tfc/${PYNACL}"
    sudo $1 "/opt/tfc/${PYSERIAL}"
    sudo $1 "/opt/tfc/${CRYPTOGRAPHY}"
}


function process_tails_dependencies {
    # Manage Tails dependencies in batch. The command that uses the
    # files is passed to the function as a parameter.

    t_sudo -E $1 "/opt/tfc/${PYSERIAL}"
    # t_sudo -E $1 "/opt/tfc/${STEM}"
    t_sudo -E $1 "/opt/tfc/${PYSOCKS}"

    # Requests
    t_sudo -E $1 "/opt/tfc/${URLLIB3}"
    t_sudo -E $1 "/opt/tfc/${IDNA}"
    t_sudo -E $1 "/opt/tfc/${CHARDET}"
    t_sudo -E $1 "/opt/tfc/${CERTIFI}"
    t_sudo -E $1 "/opt/tfc/${REQUESTS}"

    # Flask
    t_sudo -E $1 "/opt/tfc/${WERKZEUG}"
    t_sudo -E $1 "/opt/tfc/${MARKUPSAFE}"
    t_sudo -E $1 "/opt/tfc/${JINJA2}"
    t_sudo -E $1 "/opt/tfc/${ITSDANGEROUS}"
    t_sudo -E $1 "/opt/tfc/${CLICK}"
    t_sudo -E $1 "/opt/tfc/${FLASK}"

    # Cryptography
    t_sudo -E $1 "/opt/tfc/${SIX}"
    t_sudo -E $1 "/opt/tfc/${PYCPARSER}"
    t_sudo -E $1 "/opt/tfc/${CFFI}"
    t_sudo -E $1 "/opt/tfc/${CRYPTOGRAPHY}"

    # PyNaCl
    t_sudo -E $1 "/opt/tfc/${PYNACL}"
}


function move_tails_dependencies {
    # Move Tails dependencies in batch.
    t_sudo mv "$HOME/${VIRTUALENV}" "/opt/tfc/"
    t_sudo mv "$HOME/${PYSERIAL}"   "/opt/tfc/"
    # t_sudo mv "$HOME/${STEM}"       "/opt/tfc/"
    t_sudo mv "$HOME/${PYSOCKS}"    "/opt/tfc/"

    # Requests
    t_sudo mv "$HOME/${URLLIB3}"  "/opt/tfc/"
    t_sudo mv "$HOME/${IDNA}"     "/opt/tfc/"
    t_sudo mv "$HOME/${CHARDET}"  "/opt/tfc/"
    t_sudo mv "$HOME/${CERTIFI}"  "/opt/tfc/"
    t_sudo mv "$HOME/${REQUESTS}" "/opt/tfc/"

    # Flask
    t_sudo mv "$HOME/${WERKZEUG}"     "/opt/tfc/"
    t_sudo mv "$HOME/${MARKUPSAFE}"   "/opt/tfc/"
    t_sudo mv "$HOME/${JINJA2}"       "/opt/tfc/"
    t_sudo mv "$HOME/${ITSDANGEROUS}" "/opt/tfc/"
    t_sudo mv "$HOME/${CLICK}"        "/opt/tfc/"
    t_sudo mv "$HOME/${FLASK}"        "/opt/tfc/"

    # Cryptography
    t_sudo mv "$HOME/${SIX}"          "/opt/tfc/"
    t_sudo mv "$HOME/${PYCPARSER}"    "/opt/tfc/"
    t_sudo mv "$HOME/${CFFI}"         "/opt/tfc/"
    t_sudo mv "$HOME/${CRYPTOGRAPHY}" "/opt/tfc/"

    # PyNaCl
    t_sudo mv "$HOME/${PYNACL}" "/opt/tfc/"
}


function verify_tails_dependencies {
    # Tails doesn't allow downloading over PIP to /opt/tfc, so we
    # first download to $HOME, move the files to /opt/tfc, and then
    # perform additional hash verification
    compare_digest f4e7148f1de50fa2e69061e72db211085fc2f44007de4d18ee02a20d34bca30a00d2fe56ff6f3132e696c3f6efd4151863f26dac4c1d43e87b597c47a51c52ad '' ${VIRTUALENV}
    compare_digest 8333ac2843fd136d5d0d63b527b37866f7d18afc3bb33c4938b63af077492aeb118eb32a89ac78547f14d59a2adb1e5d00728728275de62317da48dadf6cdff9 '' ${PYSERIAL}
    # compare_digest a275f59bba650cb5bb151cf53fb1dd820334f9abbeae1a25e64502adc854c7f54c51bc3d6c1656b595d142fc0695ffad53aab3c57bc285421c1f4f10c9c3db4c '' ${STEM}
    compare_digest 313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12 '' ${PYSOCKS}

    # Requests
    compare_digest f6a78508cb87050e176005a088118f8ad87b17cf541457d949e5712c356f8c4de7e7516ba066e5c4bb9ced5c7e7590ba7e07d4ae7fc7190487bf27f1bb9d0668 '' ${URLLIB3}
    compare_digest fb07dbec1de86efbad82a4f73d98123c59b083c1f1277445204bef75de99ca200377ad2f1db8924ae79b31b3dd984891c87d0a6344ec4d07a0ddbbbc655821a3 '' ${IDNA}
    compare_digest bfae58c8ea19c87cc9c9bf3d0b6146bfdb3630346bd954fe8e9f7da1f09da1fc0d6943ff04802798a665ea3b610ee2d65658ce84fe5a89f9e93625ea396a17f4 '' ${CHARDET}
    compare_digest 06e8e1546d375e528a1486e1dee4fda3e585a03ef23ede85d1dad006e0eda837ebade1edde62fdc987a7f310bda69159e94ec36b79a066e0e13bbe8bf7019cfc '' ${CERTIFI}
    compare_digest 9186ce4e39bb64f5931a205ffc9afac61657bc42078bc4754ed12a2b66a12b7a620583440849fc2e161d1061ac0750ddef4670f54916931ace1e9abd2a9fb09c '' ${REQUESTS}

    # Flask
    compare_digest 3905022d0c398856b30d2ed6bae046c1532e87f56a0a40060030c18124c6c9c98976d9429e2ab03676c4ce75be4ea915ffc2719e04e4b4912a96e498dcd9eb89 '' ${WERKZEUG}
    compare_digest 69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec '' ${MARKUPSAFE}
    compare_digest 13af0d7e5abe1f99c61cef7841f3ce6ad559ec7bd3f7e50546e9a1b27e754badee9a75bed64caee34ca87cfb1047529084e73246a3ae92d2ab5dfcc5c291c7c6 '' ${JINJA2}
    compare_digest 891c294867f705eb9c66274bd04ac5d93140d6e9beea6cbf9a44e7f9c13c0e2efa3554bdf56620712759a5cd579e112a782d25f3f91ba9419d60b2b4d2bc5b7c '' ${ITSDANGEROUS}
    compare_digest 6b30987349df7c45c5f41cff9076ed45b178b444fca1ab1965f4ae33d1631522ce0a2868392c736666e83672b8b20e9503ae9ce5016dce3fa8f77bc8a3674130 '' ${CLICK}
    compare_digest bd49cb364307569480196289fa61fbb5493e46199620333f67617367278e1f56b20fc0d40fd540bef15642a8065e488c24e97f50535e8ec143875095157d8069 '' ${FLASK}

    # Cryptography
    compare_digest 387d94f37a74e2d86ac0a41f482638dd9aec9e94215ffc50f314eb2f8e0cfc2f15afc3e508ea37a4fbcca7e4bcfc65efa1e5cab5f8094ccedc18bee2b0f2e3a8 '' ${SIX}
    compare_digest 7f830e1c9066ee2d297a55e2bf6db4bf6447b6d9da0145d11a88c3bb98505755fb7986eafa6e06ae0b7680838f5e5d6a6d188245ca5ad45c2a727587bac93ab5 '' ${PYCPARSER}
    compare_digest b8753a0435cc7a2176f8748badc074ec6ffab6698d6be42b1770c85871f85aa7cf60152a8be053c3031b234a286c5cef07267cb812accb704783d74a2675ed3b '' ${CFFI}
    compare_digest 184003c89fee74892de25c3e5ec366faea7a5f1fcca3c82b0d5e5f9f797286671a820ca54da5266d6f879ab342c97e25bce9db366c5fb1178690cd5978d4d622 '' ${CRYPTOGRAPHY}  # manylinux1
    # compare_digest d8ddabe127ae8d7330d219e284de68b37fa450a27b4cf05334e9115388295b00148d9861c23b1a2e5ea9df0c33a2d27f3e4b25ce9abd3c334f1979920b19c902 '' ${CRYPTOGRAPHY}  # manylinux2010

    # PyNaCl
    compare_digest c4017c38b026a5c531b15839b8d61d1fae9907ba1960c2f97f4cd67fe0827729346d5186a6d6927ba84f64b4cbfdece12b287aa7750a039f4160831be871cea3 '' ${PYNACL}
}


function install_tails_setuptools {
    # Download setuptools package for Tails and then authenticate and install it.
    torsocks python3.7 -m pip download --no-cache-dir -r "/opt/tfc/requirements-setuptools.txt" --require-hashes --no-deps -d "${HOME}/"
    t_sudo mv "$HOME/${SETUPTOOLS}" "/opt/tfc/"
    compare_digest 761e4c8df239b8d173513b08959b387c1059e3e023ba6b3f6250fade518d6ef29f287ab90dd35d02bb681b410a050b30b2ed44849638b6f98831f4290a4ccd15 '' ${SETUPTOOLS}
    t_sudo python3.7 -m pip install "/opt/tfc/${SETUPTOOLS}"
    t_sudo -E rm "/opt/tfc/${SETUPTOOLS}"
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
    sudo torsocks python3.7 -m pip download --no-cache-dir -r "/opt/tfc/requirements-venv.txt" --require-hashes --no-deps -d /opt/tfc/
    sudo torsocks python3.7 -m pip download --no-cache-dir -r "/opt/tfc/requirements.txt"      --require-hashes --no-deps -d /opt/tfc/
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

    sudo python3.7 -m pip install "/opt/tfc/${VIRTUALENV}"
    sudo python3.7 -m virtualenv  "/opt/tfc/venv_tcb" --system-site-packages --never-download

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
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements.txt       --require-hashes --no-deps
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes --no-deps
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

    torsocks git clone https://github.com/tfctesting/tfc.git "${HOME}/tfc"

    torsocks python3.7 -m pip install -r "${HOME}/tfc/requirements-venv.txt" --require-hashes --no-deps

    python3.7 -m virtualenv "${HOME}/tfc/venv_tfc" --system-site-packages

    . "${HOME}/tfc/venv_tfc/bin/activate"
    torsocks python3.7 -m pip install -r "${HOME}/tfc/requirements-dev.txt"
    deactivate

    sudo cp "${HOME}/tfc/tfc.png"                   "/usr/share/pixmaps/"
    sudo cp "${HOME}/tfc/launchers/TFC-Dev.desktop" "/usr/share/applications/"
    sudo sed -i "s|\$HOME|${HOME}|g"                "/usr/share/applications/TFC-Dev.desktop"
    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"
    chmod a+rwx -R "${HOME}/tfc/"

    # Remove unnecessary files
    sudo rm -f "/opt/install.sh"
    sudo rm -f "/opt/install.sh.asc"
    sudo rm -f "/opt/pubkey.asc"

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
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv /opt/tfc/tfc.png                  /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_common_files      "sudo"
    process_tcb_dependencies "rm"
    sudo rm -r "/opt/tfc/src/receiver/"
    sudo rm -r "/opt/tfc/src/transmitter/"
    sudo rm    "/opt/tfc/dd.py"
    sudo rm    "/opt/tfc/tfc.py"
    sudo rm    "/opt/tfc/tfc.yml"
    sudo rm    "/opt/tfc/${VIRTUALENV}"

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

    torsocks git clone --depth 1 https://github.com/tfctesting/tfc.git "${HOME}/tfc"
    t_sudo mv "${HOME}/tfc/ /opt/tfc/"
    t_sudo chown -R root /opt/tfc/

    verify_tcb_requirements_files
    verify_files

    create_user_data_dir

    install_tails_setuptools

    torsocks python3.7 -m pip download --no-cache-dir -r "/opt/tfc/requirements-venv.txt"        --require-hashes --no-deps -d "${HOME}/"
    torsocks python3.7 -m pip download --no-cache-dir -r "/opt/tfc/requirements-relay-tails.txt" --require-hashes --no-deps -d "${HOME}/"

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

    t_sudo rm    "/opt/tfc/${VIRTUALENV}"
    t_sudo rm -r "/opt/tfc/src/receiver/"
    t_sudo rm -r "/opt/tfc/src/transmitter/"
    t_sudo rm    "/opt/tfc/dd.py"
    t_sudo rm    "/opt/tfc/tfc.py"

    install_complete "Installation of the TFC Relay configuration is now complete."
}


function t_sudo {
    # Execute command as root on Tails.
    echo "${sudo_pwd}" | sudo -S $@
}


function install_relay {
    # Determine the Networked Computer OS for Relay Program installation.
    if [[ $(grep "Tails" /etc/os-release 2>/dev/null) ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


function install_virtualenv {
    # Some distros want virtualenv installed as sudo and other do
    # not. Install both to improve the chances of compatibility.
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes --no-deps
    torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes --no-deps
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
        name=$(basename "${interface}")
        if [[ $name != "lo" ]]; then
            echo "Disabling network interface ${name}"
            sudo ifconfig "${name}" down
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
    sudo adduser "${USER}" dialout

    # Add temporary permissions for serial interfaces until reboot
    arr=($(ls /sys/class/tty | grep USB)) || true
    for i in "${arr[@]}"; do
        sudo chmod 666 "/dev/${i}"
    done

    if [[ -e /dev/ttyS0 ]]; then
        sudo chmod 666 "/dev/ttyS0"
    fi
}


function c_echo {
    # Justify printed text to the center of the terminal.
    printf "%*s\n" "$(( ( $(echo "${1}" | wc -c ) + 80 ) / 2 ))" "${1}"
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
        if ! [[ -z "$(ls -A "${HOME}/tfc/")" ]]; then
            mv "${HOME}/tfc" "${HOME}/tfc_userdata_backup_at_$(date +%Y-%m-%d_%H-%M-%S)"
        fi
    fi
    mkdir -p "${HOME}/tfc" 2>/dev/null
}


function modify_terminator_font_size {
    # Adjust terminator font size for local testing configurations.
    #
    # The default font sizes in terminator config file are for 1920px
    # wide screens. The lowest resolution (width) supported is 1366px.
    width=$(get_screen_width)

    if (( width < 1600 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 8/g'     "${2}"  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 7/g'   "${2}"  # Data diode config
    elif (( width < 1920 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 9/g'     "${2}"  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 8.5/g' "${2}"  # Data diode config
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
        case $((i % 4)) in
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
    echo    "  tcb      Install Transmitter/Receiver Program (*buntu 19.10+ / Debian 10 / PureOS 9.0+ )"
    echo    "  relay    Install Relay Program                (*buntu 19.10+ / Debian 10 / PureOS 9.0+ / Tails 4.0+)"
    echo -e "  local    Install insecure local testing mode  (*buntu 19.10+ / Debian 10 / PureOS 9.0+ )\n"
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
