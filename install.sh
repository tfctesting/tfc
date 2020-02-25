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

APPDIRS=appdirs-1.4.3-py2.py3-none-any.whl
ARGON2=argon2_cffi-19.2.0-cp34-abi3-manylinux1_x86_64.whl
CERTIFI=certifi-2019.11.28-py2.py3-none-any.whl
CFFI=cffi-1.14.0-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.8-cp34-abi3-manylinux1_x86_64.whl
DISTLIB=distlib-0.3.0.zip
FILELOCK=filelock-3.0.12-py3-none-any.whl
FLASK=Flask-1.1.1-py2.py3-none-any.whl
IDNA=idna-2.9-py2.py3-none-any.whl
IMPORTLIB_METADATA=importlib_metadata-1.5.0-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.11.1-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.1-py3-none-any.whl
REQUESTS=requests-2.23.0-py2.py3-none-any.whl
SETUPTOOLS=setuptools-45.2.0-py3-none-any.whl
SIX=six-1.14.0-py2.py3-none-any.whl
# STEM=stem-1.8.0.tar.gz
URLLIB3=urllib3-1.25.8-py2.py3-none-any.whl
VIRTUALENV=virtualenv-20.0.5-py2.py3-none-any.whl
WERKZEUG=Werkzeug-1.0.0-py2.py3-none-any.whl
ZIPP=zipp-3.0.0-py3-none-any.whl


# Functions with pinned hashes

function verify_tails_dependencies {
    # Tails doesn't allow downloading over PIP to /opt/tfc, so we
    # first download to $HOME, move the files to /opt/tfc, and then
    # perform the  hash verification
    compare_digest f4e7148f1de50fa2e69061e72db211085fc2f44007de4d18ee02a20d34bca30a00d2fe56ff6f3132e696c3f6efd4151863f26dac4c1d43e87b597c47a51c52ad '' ${VIRTUALENV}
    compare_digest b79e9fa76eadee595fe47ea7efd35c4cc72f058a9ed16a95cfa4d91a52c330efba50df7a9926900bbced229cca7bbfb05bbf0a8ee1d46bac2362c98ab9a5154d '' ${APPDIRS}
    compare_digest 6f910a9607569c9023a19aee35be15cf8521ec7c07c5d478e6d555a301d024a2ee1db48562707b238a72c631d75d9dc154d38b39ed51746b66c938ac40671e60 '' ${DISTLIB}
    compare_digest a6e7e35921ce8f2f8e79a296ea79a9c3515ff6dd7e777d7892fe4988594f1b3a442a68ffb89cf64530b90a32ceeea00e4ab9069bb697629ab4eb7262c68d1b0f '' ${SIX}
    compare_digest 53e51d4b75c1df19fcb6b32e57fa73ffcb00eede86fee7ac9634f02661360538a74d3546b65a641b68ee84c0d78293fe03d09b65cb85359780822b56f813b926 '' ${IMPORTLIB_METADATA}
    compare_digest d13edd50779bca9842694e0da157ca1fdad9d28166771275049f41dea4b8d8466fc5604b610b6ad64552cdf4c1d3cada9977ca37c6b775c4cc92f333709e8ea3 '' ${FILELOCK}
    compare_digest b1970b23f7c3f51da5e1b7825d4e6062b62bf2e908148f4b84eb70ba47e44b2873caba86536b23289fb986f04c9d617faa10541f5c25ad3885057d5920fdb98b '' ${ZIPP}

    compare_digest 8333ac2843fd136d5d0d63b527b37866f7d18afc3bb33c4938b63af077492aeb118eb32a89ac78547f14d59a2adb1e5d00728728275de62317da48dadf6cdff9 '' ${PYSERIAL}
    # compare_digest a275f59bba650cb5bb151cf53fb1dd820334f9abbeae1a25e64502adc854c7f54c51bc3d6c1656b595d142fc0695ffad53aab3c57bc285421c1f4f10c9c3db4c '' ${STEM}
    compare_digest 313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12 '' ${PYSOCKS}

    # Requests
    compare_digest f7fd3b54b7c555c0e74eb445e543763d233b5c6f8021ccf46a45d452c334953276d43ecd8f3d0eafefa35103a7d1874e291216fc9a41362eb6f1250a2a670f16 '' ${URLLIB3}
    compare_digest be96b782728404acec374f446b11811f8e76d5ed42d4673a07e883220f5ba2a099a8124cda5898c3f5da7d92b87b36127e8fd42e9edb240b587a380ed73cce93 '' ${IDNA}
    compare_digest bfae58c8ea19c87cc9c9bf3d0b6146bfdb3630346bd954fe8e9f7da1f09da1fc0d6943ff04802798a665ea3b610ee2d65658ce84fe5a89f9e93625ea396a17f4 '' ${CHARDET}
    compare_digest fe5b05c29c1e1d9079150aaea28b09d84f0dd15907e276ccabb314433cfaac948a9615e10d6d01cbd537f99eed8072fbda7cb901e932fbab4f1286ae8c50471b '' ${CERTIFI}
    compare_digest 98e4c9435434b8f63fc37a21133adbbfeb471bfb8b40d60f04bded5cbe328c14a22527d54ab2a55a81d93110d627bacc26943e55ec338b7bed8708b55e15fff3 '' ${REQUESTS}

    # Flask
    compare_digest 82a0f1776820d07e929daa60bfa0a3e746464b0f2923376330f8ae5abf535bcb756c7384757b2ff8e0076f299fe85d96ef34b3a8eede21c11df9aba8cc58cb77 '' ${WERKZEUG}
    compare_digest 69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec '' ${MARKUPSAFE}
    compare_digest 461bbd517560f1c4dbf7309bdf0cf33b468938fddfa2c3385fab07343269732d8ce68d8827148645113267d48e7d67b03f1663cc64839dd1fcec723ea606aaf4 '' ${JINJA2}
    compare_digest 891c294867f705eb9c66274bd04ac5d93140d6e9beea6cbf9a44e7f9c13c0e2efa3554bdf56620712759a5cd579e112a782d25f3f91ba9419d60b2b4d2bc5b7c '' ${ITSDANGEROUS}
    compare_digest 6b30987349df7c45c5f41cff9076ed45b178b444fca1ab1965f4ae33d1631522ce0a2868392c736666e83672b8b20e9503ae9ce5016dce3fa8f77bc8a3674130 '' ${CLICK}
    compare_digest bd49cb364307569480196289fa61fbb5493e46199620333f67617367278e1f56b20fc0d40fd540bef15642a8065e488c24e97f50535e8ec143875095157d8069 '' ${FLASK}

    # Cryptography
    compare_digest 7f830e1c9066ee2d297a55e2bf6db4bf6447b6d9da0145d11a88c3bb98505755fb7986eafa6e06ae0b7680838f5e5d6a6d188245ca5ad45c2a727587bac93ab5 '' ${PYCPARSER}
    compare_digest 5b315a65fc8f40622ceef35466546620aaca9dd304f5491a845239659b4066469c5fb3f1683c382eb57f8975caf318e5d88852e3dbb049cde193c9189b88c9c0 '' ${CFFI}
    compare_digest 184003c89fee74892de25c3e5ec366faea7a5f1fcca3c82b0d5e5f9f797286671a820ca54da5266d6f879ab342c97e25bce9db366c5fb1178690cd5978d4d622 '' ${CRYPTOGRAPHY}  # manylinux1
    # compare_digest d8ddabe127ae8d7330d219e284de68b37fa450a27b4cf05334e9115388295b00148d9861c23b1a2e5ea9df0c33a2d27f3e4b25ce9abd3c334f1979920b19c902 '' ${CRYPTOGRAPHY}  # manylinux2010

    # PyNaCl
    compare_digest c4017c38b026a5c531b15839b8d61d1fae9907ba1960c2f97f4cd67fe0827729346d5186a6d6927ba84f64b4cbfdece12b287aa7750a039f4160831be871cea3 '' ${PYNACL}
}


function install_tails_setuptools {
    # Download setuptools package for Tails and then authenticate and install it.
    torsocks python3.7 -m pip download --no-cache-dir -r "/opt/tfc/requirements-setuptools.txt" --require-hashes --no-deps -d "${HOME}/"
    t_sudo mv "$HOME/${SETUPTOOLS}" "/opt/tfc/"
    compare_digest de1ac45cb52e8a28322048e6a2b95015aa6826c49679349a1b579cb46b95cb2ffd62242c861c2fe3e059c0c55d4fdb4384c51b964ca2634b2843263543f8842a '' ${SETUPTOOLS}
    t_sudo python3.7 -m pip install "/opt/tfc/${SETUPTOOLS}"
    t_sudo -E rm "/opt/tfc/${SETUPTOOLS}"
}


function verify_tcb_requirements_files {
    # To minimize the time TCB installer configuration stays online, only
    # the requirements files are authenticated between downloads.
    compare_digest eca1997b9abf71010f4373e17e87b1131e72c7395d6d8a86182ffb52b208f4058b3d59f33f022023ce3e6c5f53884d682a985e9908ff2c2958817b3427cfd19d '' requirements.txt
    compare_digest 90c71b5bb2728ca7054467e56f86ce2d0730d10e8e2be12fca613f74ccbf5af555d88b48d4089426bbd26f1a1dfb4cbe98585d937a7b90a9a701405c3ba4fb45 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest 1d9ee816a00eb66a96cf2a6484f37037e90eb8865d68b02de9c01d7ee6fa735cbbd2279099fe8adfb4dda5d9c0a2da649a5f530dba1f0c44471838995abcebb2 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 4a239b91b2626375255fbf4202a4bf49ea248832b65d69e00530d7cec88e489466508aeb1ff8c8ef0f138819500c4fde2010207ebe3e289c36bc201df55d3c47 '' LICENSE-3RD-PARTY
    compare_digest a6dad2efad1390944c5f00249fba40ddaff244ffabc60e837344ce3587a91559a792ac78455fb1a1e3b516d95ffbbfebab7b2d2d878c3700c5eed8483bc9e994 '' relay.py
    compare_digest 563f4acff5fd30e27cc3a318c1867d8d9cabe1d6ee48a369c31e55d8312ec69ccdd430b51f88cbc3e072a6bfc0681112c3b7001244cbbdd37ca33490d888916b '' requirements-dev.txt
    compare_digest 038aacbab88ba9465d20995e5286734eb67c173a2b4166e26e267d55f41f834962a2d8d6365156637fafaed5e6e688c7cd2246210b336de215f73957d284127f '' requirements-relay.txt
    compare_digest 5fd48bb377c826639d1a2f75cc72c5b34d6c2f5683a9e655878c049708a73471949847e0156f8524706d629bdb1d82998fa7f75819874949c34e5a3cc64f61e0 '' requirements-relay-tails.txt
    compare_digest 1432c2f098b1e656a597cbcfcceef00e2cda1897242f2a9316182fffff55bd64ea974534756200ec878741cd8de12b46b4b05a39ed550ad3997d111a6176f16f '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest 2e6be3bfab2aa1c46d5ea43ca0e4f9aac7b3f8bb0a2e09b733bd840729270d0b7f075df4cd23220590b4a9bdd6657ca3f4a8cf1542c584ae61df7c16913ae7b8 '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest e96471894b177d65639a3cc68e85bf609334ecaaa806009467d0e5e45d8ed4fcb4a43b8fce842458e18b0da9362a895948d45109a020a667986998f5c0055294 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest 9a40d97bd9fe1324b5dd53079c49c535ae307cbb28a0bc1371067d03c72e67ddeed368c93352732c191c26dcdc9ac558868e1df9dfd43a9b01ba0a8681064ab3 launchers/ TFC-Local-test.desktop
    compare_digest 62ada11d5513d2d196184b207a82dd14c7ad78af3f7b43c4de64162c8784c2996fa999f36fc6e2c7f1b823df43497725b05f0b52489e9a9e1d9bddbe2ce7910f launchers/ tfc-qubes-receiver
    compare_digest 72e04fe07ac400ca70da59d196119db985d9e74b99b0fd735be20a534bd10084287a52aee46c6467703fe5e14609729db229112d53ce3156838c80b4f159df0a launchers/ tfc-qubes-relay
    compare_digest 89e23c4d9e7d4402d7dde3d905fe0c3a3fd5ff8c09c33033f95d203ae9f1f53fa26d20c913820ff16764e9b6e0d558f8f332f9657b2e92eb77134576e683e1a9 launchers/ tfc-qubes-transmitter
    compare_digest c5dfa3e4c94c380b0fcf613f57b5879a0d57d593b9b369da3afde37609a9fb11051d71832285d3372f3df6c5dbe96d00a39734fbddf138ab0c04d0f1f752826f launchers/ TFC-RP.desktop
    compare_digest ac0c94a8488bd46e1f6716be706a328cf5a5ec25798c32cc10cc16f9a2080e13efaa13d930b7277694c63de4bd039c783a16d07cb06a495e3c723998783818b9 launchers/ TFC-RP-Qubes.desktop
    compare_digest c5dfa3e4c94c380b0fcf613f57b5879a0d57d593b9b369da3afde37609a9fb11051d71832285d3372f3df6c5dbe96d00a39734fbddf138ab0c04d0f1f752826f launchers/ TFC-RP-Tails.desktop
    compare_digest d109dc200709d9565a076d7adcc666e6ca4b39a2ed9eff0bb7f0beff2d13b368cc008a0bbb9a639e27f6881b3f8a18a264861be98a5b96b67686904ba70e70f2 launchers/ TFC-RxP.desktop
    compare_digest 2cd6d86b3118554154e8a784e169b9c64114f022a32cd5a462d2ad44fc582a836bb16bbca52a393fd46bbd67480e3298be21d59e798067f50ddae34dcac84403 launchers/ TFC-RxP-Qubes.desktop
    compare_digest aa1c23f195bcf158037c075157f12564d92090ed29d9b413688cf0382f016fad4f59cf9755f74408829c444cd1a2db56c481a1b938c6e3981e6a73745c65f406 launchers/ TFC-TxP.desktop
    compare_digest ee18f44c043bf3f2dbb26c181bddf75c4a34183fa6f9d1f9ef234ced98b335fcdcfff72a5221bd9312ce37309a1af9f2ff15bc0736dc6a822c84aace8c8add14 launchers/ TFC-TxP-Qubes.desktop

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/ __init__.py
    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/common/ __init__.py
    compare_digest b2e708608b18e4512910a4a54a6493cb0ef83627a8b6eb76b599661abfb0dfb76963ba9d482e0d207d697d682ff5a79a00e3be14140c9e1405a092b188c80466 src/common/ crypto.py
    compare_digest dd30ee2bdcab64bd62c3d41ff238a4e35fcb950a5b33d43b9758306cda4ab3d9d1a86399a58b70ac78fb2b39649de830b57965e767e7d958839cd9169bc5317d src/common/ database.py
    compare_digest 99bb26974918c1fe23c001d39296653b5dda678fbde1d3470bfb2d62ccc73d31f782adc74666f53389cf8560215e098350dcac7cd66c297712564460c50c4302 src/common/ db_contacts.py
    compare_digest 032ccacc86f62bbd1eafb645730679a1023841f53c6391b700e6562ba33321f0ef81d36f3fa02752b189cb795677d209404fffa7de6ebf042bd3ff418e056b9a src/common/ db_groups.py
    compare_digest 38fed0ace4cc1032b9d52d80c2a94252a0001b11ed7a7d7dc27fff66ed1e10309ee07b345556775958389d83cb976cd151df2d717b5c7dbe6d312778ecb06408 src/common/ db_keys.py
    compare_digest 4d9436a5381b81425c13b43829a1c2dac62a2210ebd5a80b3bb8445aa3b6509b33af58e14cb9803c330d81aa429341382c13170d6770cd1726698a274980978e src/common/ db_logs.py
    compare_digest a5ae2f153716e1e8aef845290ed4dd3b63a97cc54527ec2ffc09e13945e6159f39dc13202299b1485a17720bc45bda2b42edc797c4c0d0b076df8884aaef7261 src/common/ db_masterkey.py
    compare_digest 325298cd6cb7e68d27681c18f29e635f46222e34015ba3c8fe55e6718e6907b4257bbe12d71fd344b557aff302ae9d7fca2b581b4208e59ac7923e57aca23fe5 src/common/ db_onion.py
    compare_digest 63451ece46802c1e4d0ddb591fda951c00b40ed2e0f37ffc9e5310adb687f0db4980d8593ce1ed5c7b5ca9274be33b2666ae9165aa002d99ecf69b0ec620cc1b src/common/ db_settings.py
    compare_digest 60fb4c922af286307865b29f0cadab53a5a575a9f820cd5ad99ea116c841b54dd1d1be1352bf7c3ab51d2fd223077217bcda1b442d44d2b9f1bf614e15c4a14d src/common/ encoding.py
    compare_digest ccd522408ad2e8e21f01038f5f49b9d82d5288717f1a1acf6cda278c421c05472827ee5928fbf56121c2dfc4f2cc49986e32c493e892bd6ae584be38ba381edd src/common/ exceptions.py
    compare_digest 33b8c271b1ef959a04d8e411985175f3317e8f00cc0b8de8b3dcbd33044d5df7152b369bb30fab774cc1512acdf2c316c5463fc8fdde6334c77de756e72360eb src/common/ gateway.py
    compare_digest b01aa02c1985c7c1f7d95678d2422561a06342378306936c35c077938c133b8f60a63952bdc9005210d31e68addd88b86a45f82626c40beff07e785fdc2aa115 src/common/ input.py
    compare_digest a9528e955193050e073dccacea6045c3c31cfa783dc6b9d7982445599ccdd338424b8131eb7fad950901a0a4763f9a6e9ff6df3d12d7cd7a13883edd3d45a86f src/common/ misc.py
    compare_digest 8b479b3a7c1c4fdaf4c4f8d4a4436231933ebb1da47a5a07a596037b20db7d5aa7e8a1d107d4ec973603551f28833ff404c177b9977d654f3b38a915d16a33bb src/common/ output.py
    compare_digest 08443cfe633bb552d6bb55e48d81423db4a4099f9febc73ec6ee85ee535bc543720f199ac8b600b718e9af7247fb96ef4b9991b0416cf7186fd75a149365dd36 src/common/ path.py
    compare_digest 39e48b0b55f4f1a48bc558f47b5f7c872583f3f3925fd829de28710024b000fcb03799cb36da3a31806143bc3cbb98e5d357a8d62674c23e1e8bf957aece79f6 src/common/ reed_solomon.py
    compare_digest a23f7208f7e4a2bcb72af70a2c5ed9015979447244c67e1868bbbb4085c59dd39ecd295c1c025ef151cb670adea3c14702f55ff94cb866eb9a51d69bc03a1ecd src/common/ statics.py
    compare_digest a57d5525a570a78d15c75e79702289cf8571c1b3c142fae57f32bf3ed8bb784c7f63ce2e805d295b4a505fdeaf9d59094ebe67d8979c92dc11e2534474505b0e src/common/ word_list.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/receiver/ __init__.py
    compare_digest ccc8d6bf2b10cf4ccb51a014ff7f251e527196f1172ab9b4da48b01ddcb9a64c15358f03424b76babd1ce2dd20147d847d2e1292fb0d76135c2ba10e182ec14b src/receiver/ commands.py
    compare_digest 6dd0d73fe240f974bb92e850c5f38e97ee8d632fbb3a53abc3160b4e29f9b2b076b8b5d20dc7f7231c01c978ea67b55740ac17dc74bf05e6811d2e35e34056fb src/receiver/ commands_g.py
    compare_digest 320bc36df51efb138c173d9fcef7a8ee7de06bcee672e75512d2a9e07eef5006068650e76d4dc741b4cf180cb8ee46560f941753539e377d0d4e534d0f6c629b src/receiver/ files.py
    compare_digest 73e42247c7eb5d70f9cb12b6b8f65df91473d8c7425365d9d4005d14e8a0b5555dc78915a9334aaf56d9d1c0f8d0ffba765a848b391fcd11f3525211ee8090e1 src/receiver/ key_exchanges.py
    compare_digest 6ebd6c0638525997949783b7623ce9a78683169e95f572ea65dcec52da150b0473a25e928862cab34eac44b0e0991a0969c5252c03cf4dc8f49d1aa9809b43bd src/receiver/ messages.py
    compare_digest eabe1695cd0fe04346e49ed91b64a11ad74ff60b636333140f9a3c6745b9c408d77aae8f45256b5d74b241324a5d429249b2be6c732205ab729a38049b8631f7 src/receiver/ output_loop.py
    compare_digest 25b49765e149f5e072df2aa70c125478d1c9621886527201bf0d7718db557f2991823d980274f53abf93269f5aa1096b3e56fae94ecaa974ef31b0cb7907fde7 src/receiver/ packet.py
    compare_digest 002c960023393bec10da3de6d9a218c8e2c27da1635fd1a7f99e02a9a28792428a2c0e6cd030d1cc1fac1124c58f397f63d60b7af4c384367a8c293978125539 src/receiver/ receiver_loop.py
    compare_digest da8ff22a1ece42c780328c84722ae42c2dced69dd87f2fb2d09fd517d3ee98f3777c448922b2b06a5839347e075a5598e6c770a544fdf801e664ba5ad06b684d src/receiver/ windows.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/relay/ __init__.py
    compare_digest 0d035e3f3b6f1a4569ad1c0bd06de346a98424b1234b3ba97d7e558d174a7cbef803eb7e6f83d0b0b943667f5b37ac260202a3c0a1d364f74a85112cdaf60398 src/relay/ client.py
    compare_digest c7457a0b21383c9d803f3854bbbd616943132a775641d8cada0c5fbd0d756910679d44a748b79291149758e2650e1bee4450b0c51ceb9f8bd680cfc6a5635407 src/relay/ commands.py
    compare_digest b41faf02d99f523556c54ec3c5a23396ec43a660814aa5af73cf577695a6fe528b0d165259fed494a18bfc7234fdd73a3edc8f27bf4d6245268b8e4a6bbc708a src/relay/ diffs.py
    compare_digest 0bc1912af4d45ff72fbd7c43a09ab48ea3a780bb096226011525924820ba0ba1f396937fb191e5e18ec87dee14ccd3b505192e16e835d46088e4b50c941125f5 src/relay/ onion.py
    compare_digest dad7cb0985c55699dd7b702bbae73763736ebb8b1bab8c2772d938eab8a8c3041b3574e209da455209af81a7b38e8e84691e8e44e0dfad50408c606b20f0c8c8 src/relay/ server.py
    compare_digest 72335d62250abceaa6e84b3c054e889f4921d87e72ae751f48c0b522ac1361bac217830ffe0f31f5b1fb959157eb8a737ab34415cbf384a7a8833c08d4f8ddc3 src/relay/ tcb.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/transmitter/ __init__.py
    compare_digest 20b128c1aa0353db8f20f4274632454f8ead9e8e3ec59876673a1b2c270c66c8ab1af2252e83d95e15c95e6d8e56ef4d8708fda5afeedef583f3b297d92d38c1 src/transmitter/ commands.py
    compare_digest 2af2cd801fc83f882c65e031b5bd6f5c2c30b32dc0bb538953021b1f520714723d39b2a2462a6718cbb3efea1b645767b50d468978bb802dacf8b73535a2975f src/transmitter/ commands_g.py
    compare_digest 31267d2049e4e9a88301e0d851e11c8e3db0bbb96c4509c10a3528c29ab679a49db8430cca1529ccd71556e273f4937d3bf7e0c2e1a165a8d36729ed284a4f19 src/transmitter/ contact.py
    compare_digest f2fefbc2acbad441cb997969d6b39fbe26813abc781f5b6caaa08f1eb4c52c05b2bd4cbc341cb75ea07f7a4931d9b1145bef2fb352376a72442f7a71299fb595 src/transmitter/ files.py
    compare_digest 110665f962eb827a9f636cc823837222a7bed4a429d4e10eb90c7bf5ba7bd5900aa1ecc4d4b485927a276d5727e18fe9e78f75ab8bd4ff67f039bb633fe505ec src/transmitter/ input_loop.py
    compare_digest 7a05e0a751acbb1189912d811ad7627722132f8812f82bf8432eed4b461da0d8570b579fe890f258eab1fd7b96b642a8aac18463efd77a8e5b7e6d392925f748 src/transmitter/ key_exchanges.py
    compare_digest 766b1efa548f2da49272870fa5f89b8aacdf65b737b908f7064209f2f256c4d4875228ad087ac4957a292a82ed5936a40b9ae7553bfae2eae739f0c4579eb21a src/transmitter/ packet.py
    compare_digest b8cfc11ae235c8cddbbd4003f8f95504456d9b2d6b6cc09bd538c09132bc737b6f070bdbc8d697e9ddfc5854546575526fa26c813f9f6bff7dc32fcdbb337753 src/transmitter/ sender_loop.py
    compare_digest cdcb21128f71134ae49f3e99bf2a6dce5ec88766ecf6d91be89200ef282f7bd326c9805ba8f2d73d3fa12a8e05da20630874b5bbf9e18085d47ad5063098eaf8 src/transmitter/ traffic_masking.py
    compare_digest eb77c6206cab63ffdb47bbcb8b76a55100636d893e234a048221d83e9ce07b76ccfcc93b506d9fb48d6f8823135e5697f3e56aed8e95f23990d8dfc1cece325e src/transmitter/ user_input.py
    compare_digest 489f869176da0040b6f06327544f5eb72863a748a4799c66198a09402df6d54d842e9af27af51faaeed9d0661133eeaebb9918bd1bcd50950c182ba4b1e5fc74 src/transmitter/ window_mock.py
    compare_digest 09c536d43b37103b6340293efa67345f54da6563ea65441546161066d735b4dfad9eaea9c58452de3413b72b28a923d2efb851ac740ba09ada45368bb64b9f15 src/transmitter/ windows.py
}


# ----------------------------------------------------------------------------------------

# Dependency batch processing

function process_tcb_dependencies {
    # Manage TCB dependencies in batch. The command that uses
    # the files is passed to the function as a parameter.
    sudo $1 "/opt/tfc/${PYCPARSER}"
    sudo $1 "/opt/tfc/${CFFI}"
    sudo $1 "/opt/tfc/${ARGON2}"
    sudo $1 "/opt/tfc/${SETUPTOOLS}"
    sudo $1 "/opt/tfc/${PYNACL}"
    sudo $1 "/opt/tfc/${PYSERIAL}"
    sudo $1 "/opt/tfc/${CRYPTOGRAPHY}"
}


function process_virtualenv_dependencies {
    # Manage Virtualenv dependencies in batch. The command that
    # uses the files is passed to the function as a parameter.
    sudo $1 "/opt/tfc/${ZIPP}"
    sudo $1 "/opt/tfc/${FILELOCK}"
    sudo $1 "/opt/tfc/${IMPORTLIB_METADATA}"
    sudo $1 "/opt/tfc/${SIX}"
    sudo $1 "/opt/tfc/${DISTLIB}"
    sudo $1 "/opt/tfc/${APPDIRS}"
    sudo $1 "/opt/tfc/${VIRTUALENV}"
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


function process_tails_venv_dependencies {
    # Process Tails Virtualenv dependencies in batch.
    t_sudo -E $1 "/opt/tfc/${ZIPP}"
    t_sudo -E $1 "/opt/tfc/${FILELOCK}"
    t_sudo -E $1 "/opt/tfc/${IMPORTLIB_METADATA}"
    t_sudo -E $1 "/opt/tfc/${SIX}"
    t_sudo -E $1 "/opt/tfc/${DISTLIB}"
    t_sudo -E $1 "/opt/tfc/${APPDIRS}"
    t_sudo -E $1 "/opt/tfc/${VIRTUALENV}"
}


function move_tails_dependencies {
    # Move Tails dependencies in batch.
    t_sudo mv "$HOME/${VIRTUALENV}"         "/opt/tfc/"
    t_sudo mv "$HOME/${APPDIRS}"            "/opt/tfc/"
    t_sudo mv "$HOME/${DISTLIB}"            "/opt/tfc/"
    t_sudo mv "$HOME/${FILELOCK}"           "/opt/tfc/"
    t_sudo mv "$HOME/${IMPORTLIB_METADATA}" "/opt/tfc/"
    t_sudo mv "$HOME/${SIX}"                "/opt/tfc/"
    t_sudo mv "$HOME/${ZIPP}"               "/opt/tfc/"

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


# Common tasks

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


# ----------------------------------------------------------------------------------------

# Installation configurations for Debian/PureOS/Ubuntu

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

    process_virtualenv_dependencies "python3.7 -m pip install"
    sudo python3.7 -m virtualenv  "/opt/tfc/venv_tcb" --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    process_tcb_dependencies "python3.7 -m pip install"
    deactivate

    sudo mv /opt/tfc/tfc.png                   /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-TxP.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/TFC-RxP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm"
    sudo rm -r /opt/tfc/src/relay/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/relay.py
    sudo rm    /opt/tfc/tfc.yml

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
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
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm"
    sudo rm -r "/opt/tfc/src/receiver/"
    sudo rm -r "/opt/tfc/src/transmitter/"
    sudo rm    "/opt/tfc/dd.py"
    sudo rm    "/opt/tfc/tfc.py"
    sudo rm    "/opt/tfc/tfc.yml"

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


# Installation configuration for Tails

function install_relay_tails {
    # Install TFC Relay configuration on Networked Computer running
    # Tails live distro (https://tails.boum.org/).
    read_sudo_pwd

    # Apt dependencies
    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip python3-tk -y || true  # Ignore error in case packets can not be persistently installed

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

    process_tails_venv_dependencies "python3.7 -m pip install"
    t_sudo python3.7 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    process_tails_dependencies "python3.7 -m pip install"
    deactivate

    # Complete setup
    t_sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    t_sudo mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/
    t_sudo mv /opt/tfc/tfc.yml                        /etc/onion-grater.d/

    remove_common_files             "t_sudo"
    process_tails_venv_dependencies "rm"
    process_tails_dependencies      "rm"
    t_sudo rm -r "/opt/tfc/src/receiver/"
    t_sudo rm -r "/opt/tfc/src/transmitter/"
    t_sudo rm    "/opt/tfc/dd.py"
    t_sudo rm    "/opt/tfc/tfc.py"

    install_complete "Installation of the TFC Relay configuration is now complete."
}


# Installation configurations for Qubes OS

function install_qubes_src {
    # Qubes Source Computer VM installation configuration for Debian 10 domains.
    steps_before_network_kill
    qubes_src_firewall_config

    verify_files
    create_user_data_dir

    process_virtualenv_dependencies "python3.7 -m pip install"
    sudo python3.7 -m virtualenv  "/opt/tfc/venv_tcb" --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    process_tcb_dependencies "python3.7 -m pip install"
    deactivate

    sudo mv /opt/tfc/tfc.png                         /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-TxP-Qubes.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/tfc-qubes-transmitter /usr/bin/tfc-transmitter

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm"
    sudo rm -r /opt/tfc/src/relay/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/relay.py
    sudo rm    /opt/tfc/tfc.yml

    install_complete_qubes
}


function install_qubes_dst {
    # Qubes Destination Computer VM installation configuration for Debian 10 domains.
    steps_before_network_kill
    qubes_dst_firewall_config

    verify_files
    create_user_data_dir

    process_virtualenv_dependencies "python3.7 -m pip install"
    sudo python3.7 -m virtualenv  "/opt/tfc/venv_tcb" --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    process_tcb_dependencies "python3.7 -m pip install"
    deactivate

    sudo mv /opt/tfc/tfc.png                         /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RxP-Qubes.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/tfc-qubes-receiver    /usr/bin/tfc-receiver

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm"
    sudo rm -r /opt/tfc/src/relay/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/relay.py
    sudo rm    /opt/tfc/tfc.yml

    install_complete_qubes
}


function install_qubes_net {
    # Qubes Networked Computer VM installation configuration for Debian 10 domains.
    steps_before_network_kill
    qubes_net_firewall_config

    verify_files
    create_user_data_dir

    process_virtualenv_dependencies "python3.7 -m pip install"
    sudo python3.7 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RP-Qubes.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/tfc-qubes-relay      /usr/bin/tfc-relay

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    sudo rm -r "/opt/tfc/src/receiver/"
    sudo rm -r "/opt/tfc/src/transmitter/"
    sudo rm    "/opt/tfc/dd.py"
    sudo rm    "/opt/tfc/tfc.py"
    sudo rm    "/opt/tfc/tfc.yml"

    install_complete_qubes
}


# Qubes firewall configurations

function qubes_src_firewall_config {
    # Edit Source Computer VM firewall rules to block all incoming connections, and to
    # only allow UDP packets to Networked Computer's TFC port.

    src_ip=$(sudo ifconfig eth0 | grep "inet" | cut -d: -f2 | awk '{print $2}')
    net_ip=$(get_ip "Networked Computer VM")

    # Add firewall rules that take effect immediately
    sudo iptables --flush
    sudo iptables -t filter -P INPUT DROP
    sudo iptables -t filter -P OUTPUT DROP
    sudo iptables -t filter -P FORWARD DROP
    sudo iptables -I OUTPUT -s ${src_ip} -d ${net_ip} -p udp --dport 2063 -j ACCEPT

    # Create backup of the current rc.config file just in case
    sudo mv /rw/config/rc.local{,.backup."$(date +%Y-%m-%d-%H_%M_%S)"}

    # Make firewall rules persistent
    echo "iptables --flush"                                                           | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P INPUT DROP"                                           | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P OUTPUT DROP"                                          | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P FORWARD DROP"                                         | sudo tee -a /rw/config/rc.local
    echo "iptables -I OUTPUT -s ${src_ip} -d ${net_ip} -p udp --dport 2063 -j ACCEPT" | sudo tee -a /rw/config/rc.local
    sudo chmod a+x /rw/config/rc.local
}


function qubes_dst_firewall_config {
    # Edit Destination Computer VM's firewall rules to block all outgoing connections, and
    # to only allow UDP packets from Networked Computer VM to Receiver Programs' port.

    net_ip=$(get_ip "Networked Computer VM")
    dst_ip=$(sudo ifconfig eth0 | grep "inet" | cut -d: -f2 | awk '{print $2}')

    # Add firewall rules that take effect immediately
    sudo iptables --flush
    sudo iptables -t filter -P INPUT DROP
    sudo iptables -t filter -P OUTPUT DROP
    sudo iptables -t filter -P FORWARD DROP
    sudo iptables -I INPUT -s ${net_ip} -d ${dst_ip} -p udp --dport 2064 -j ACCEPT

    # Create backup of the current rc.config file just in case
    sudo mv /rw/config/rc.local{,.backup."$(date +%Y-%m-%d-%H_%M_%S)"}

    # Make firewall rules persistent
    echo "iptables --flush"                                                          | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P INPUT DROP"                                          | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P OUTPUT DROP"                                         | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P FORWARD DROP"                                        | sudo tee -a /rw/config/rc.local
    echo "iptables -I INPUT -s ${net_ip} -d ${dst_ip} -p udp --dport 2064 -j ACCEPT" | sudo tee -a /rw/config/rc.local
    sudo chmod a+x /rw/config/rc.local
}


function qubes_net_firewall_config {
    # Edit Networked Computer VM's firewall rules to accept UDP packets from Source
    # Computer VM to the Relay Program's port.

    src_ip=$(get_ip "Source Computer VM")
    net_ip=$(sudo ifconfig eth0 | grep "inet" | cut -d: -f2 | awk '{print $2}')
    dst_ip=$(get_ip "Destination Computer VM")

    # Add firewall rules that take effect immediately
    sudo iptables -t filter -P INPUT DROP
    sudo iptables -t filter -P OUTPUT ACCEPT
    sudo iptables -t filter -P FORWARD DROP
    sudo iptables -I INPUT -s ${src_ip} -d ${net_ip} -p udp --dport 2063 -j ACCEPT  # Whitelist UDP packets to Relay Program's port
    sudo iptables -I OUTPUT -d ${dst_ip} ! --dport 2064 -j DROP                     # Blacklist all packets without destination port 2064
    sudo iptables -I OUTPUT -d ${dst_ip} -p ! udp -j DROP                           # Blacklist all non-UDP packets to DST VM
    sudo iptables -I OUTPUT -s ! ${net_ip} -d ${dst_ip} -j DROP                     # Blacklist all packets to DST VM that do not originate from NET VM
    sudo iptables -I OUTPUT -d ${src_ip} -p all -j DROP                             # Blacklist all packets to SRC VM

    # Create backup of the current rc.config file just in case
    sudo cp /rw/config/rc.local{,.backup."$(date +%Y-%m-%d-%H_%M_%S)"}

    # Make firewall rules persistent
    echo "iptables -t filter -P INPUT DROP"                                          | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P OUTPUT ACCEPT"                                       | sudo tee -a /rw/config/rc.local
    echo "iptables -t filter -P FORWARD DROP"                                        | sudo tee -a /rw/config/rc.local
    echo "iptables -I INPUT -s ${src_ip} -d ${net_ip} -p udp --dport 2063 -j ACCEPT" | sudo tee -a /rw/config/rc.local
    echo "iptables -I OUTPUT -d ${dst_ip} ! --dport 2064 -j DROP"                    | sudo tee -a /rw/config/rc.local
    echo "iptables -I OUTPUT -d ${dst_ip} -p ! udp -j DROP"                          | sudo tee -a /rw/config/rc.local
    echo "iptables -I OUTPUT -s ! ${net_ip} -d ${dst_ip} -j DROP"                    | sudo tee -a /rw/config/rc.local
    echo "iptables -I OUTPUT -d ${src_ip} -p all -j DROP"                            | sudo tee -a /rw/config/rc.local
    sudo chmod a+x /rw/config/rc.local
}


# Tiling terminal emulator configurations for single OS

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


# ----------------------------------------------------------------------------------------

# Installation utilities

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


function get_ip {
    # Get IP address from the user.
    ip=$(zenity --entry --title="TFC Installer" --text="Enter the IP-address of the $1:")
    if [[ ${ip} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo ${ip}
        return
    else
        zenity --info --title='TFC installer' --text='Invalid IP'
        get_ip
    fi
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


# Printing functions

function c_echo {
    # Justify printed text to the center of the terminal.
    printf "%*s\n" "$(( ( $(echo "${1}" | wc -c ) + 80 ) / 2 ))" "${1}"
}


function exit_with_message {
    # Print error message and exit the installer with flag 1.
    clear
    echo ''
    c_echo "Error: $* Exiting." 1>&2
    echo ''
    exit 1
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


function install_complete_qubes {
    # Notify the user that the installation is complete.
    clear
    c_echo ''
    c_echo "Installation of TFC on this Qube is now complete."
    c_echo ''
    c_echo "Press any key to close the installer."
    read -n 1 -s -p ''
    clear

    kill -9 $PPID
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
    echo    "  qsrc     Install Transmitter Program          (Qubes 4.0.3)"
    echo    "  qdst     Install Receiver Program             (Qubes 4.0.3)"
    echo -e "  qnet     Install Relay Program                (Qubes 4.0.3)\n"
    exit 1
}


# Pre-install checks

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


function architecture_check {
    # Check that the OS is 64-bit, and not 32-bit.
    if ! [[ "$(uname -m 2>/dev/null | grep x86_64)" ]]; then
        exit_with_message "Invalid system architecture."
    fi
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


# Main routine

set -e
architecture_check
root_check
sudoer_check
sudo_pwd=''

case $1 in
    tcb    ) install_tcb;;
    relay  ) install_relay;;
    local  ) install_local_test;;
    qsrc   ) install_qubes_src;;
    qdst   ) install_qubes_dst;;
    qnet   ) install_qubes_net;;
    dev    ) install_developer;;
    *      ) arg_error;;
esac
