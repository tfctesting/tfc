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

# Installer configuration

INSTALL_DIR="/opt/tfc"


# ----------------------------------------------------------------------------------------

# PIP dependency file names

APPDIRS=appdirs-1.4.4-py2.py3-none-any.whl
ARGON2_CFFI=argon2_cffi-20.1.0-cp35-abi3-manylinux1_x86_64.whl
CERTIFI=certifi-2020.6.20-py2.py3-none-any.whl
CFFI37=cffi-1.14.3-cp37-cp37m-manylinux1_x86_64.whl
CFFI38=cffi-1.14.3-cp38-cp38-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=click-7.1.2-py2.py3-none-any.whl
CRYPTOGRAPHY37=cryptography-3.2.1-cp35-abi3-manylinux1_x86_64.whl
CRYPTOGRAPHY38=cryptography-3.2.1-cp35-abi3-manylinux2010_x86_64.whl
DISTLIB=distlib-0.3.1-py2.py3-none-any.whl
FILELOCK=filelock-3.0.12-py3-none-any.whl
FLASK=Flask-1.1.2-py2.py3-none-any.whl
IDNA=idna-2.10-py2.py3-none-any.whl
IMPORTLIB_METADATA=importlib_metadata-2.0.0-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.11.2-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.20-py2.py3-none-any.whl
PYNACL=PyNaCl-1.4.0-cp35-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.1-py3-none-any.whl
REQUESTS=requests-2.24.0-py2.py3-none-any.whl
SETUPTOOLS=setuptools-50.3.2-py3-none-any.whl
SIX=six-1.15.0-py2.py3-none-any.whl
URLLIB3=urllib3-1.25.11-py2.py3-none-any.whl
VIRTUALENV=virtualenv-20.1.0-py2.py3-none-any.whl
WERKZEUG=Werkzeug-1.0.1-py2.py3-none-any.whl
ZIPP=zipp-3.4.0-py3-none-any.whl


# ----------------------------------------------------------------------------------------

# Pinned Tails dependencies

DIGEST_PYSERIAL=8333ac2843fd136d5d0d63b527b37866f7d18afc3bb33c4938b63af077492aeb118eb32a89ac78547f14d59a2adb1e5d00728728275de62317da48dadf6cdff9
DIGEST_PYSOCKS=313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12

# Virtualenv
DIGEST_ZIPP=bf6090e22c45b53691b25abf98d2f98562762bba00133f378601f2e115729da44d6d11ac7f2738926960a8d0ea6f694ea594d644d0d9ca81fc8e55396cc8d556
DIGEST_FILELOCK=d13edd50779bca9842694e0da157ca1fdad9d28166771275049f41dea4b8d8466fc5604b610b6ad64552cdf4c1d3cada9977ca37c6b775c4cc92f333709e8ea3
DIGEST_IMPORTLIB_METADATA=09ec4c718781e3ba6ed8024a094081ce530f30c1aa7df8f10729d64f17839bcc35dc3c94218209dbb6d133f3052d33cebe282bf7b53ba9646d1653ce62cdae3b
DIGEST_SIX=0416d59434623604de755601c919722c2b800042612a2a7b221ecd3ccf556aca3a78f0f926fd640032a3d74d153457628a89c25065dfcdbb96892d5bf7279904
DIGEST_DISTLIB=ac65d35a5309ec22db5b1e9ab6c20014084feab11e86e81bee6d0bfcc65940dfdcaa2711ac1e98c1ef179b110a4ea03dbaf042b894d3051da9d339c534664e00
DIGEST_APPDIRS=8e6c1ea544013ea2567cda2d8b8c7b441bc50ac689aa7f95de67e3795aa083e9592c687d74fdbb37f5a75e0beab398fe47df5bced14ee9c204cfe5ecc364ef44
DIGEST_VIRTUALENV=f6db0b9d758ea5b1c244aeb3af77597bfba940e13efa3cee80508b3e9923e1691e65bc16a5d83812f1ec83dc04e7b47cea032998253fec450ed2aa80378b663c

# Requests
DIGEST_URLLIB3=6889f032f9f87494c06c0a28d6868e23db68909a2ad6d37ac199198ed2313e4f65fd26900ff05828138e412d9a7a5b2463b6c28e71689c0a5a42ebcbae01ed5b
DIGEST_IDNA=7b7be129e1a99288aa74a15971377cb17bee1618843c03c8f782e287d0f3ecf3b8f26e3ea736444eb358f1d6079131a7eb291446f3279874eb8e00b624d9471c
DIGEST_CHARDET=bfae58c8ea19c87cc9c9bf3d0b6146bfdb3630346bd954fe8e9f7da1f09da1fc0d6943ff04802798a665ea3b610ee2d65658ce84fe5a89f9e93625ea396a17f4
DIGEST_CERTIFI=960f1cbe72443230ecba527b5bc4bb8a45a33feb646b0ad01dcb606b9ec3729d27dff5cfa04655d92efd4dec691d61c62d80f8fd39a82fc21528727eeb5c9991
DIGEST_REQUESTS=64c49592455abbcd1168f5e1908a8db77bbeb373264b1cf6db8a1fefe65f9a0879e30066d34b041e7f013c7fc1ccdd87b91bc637f2a53972be45bb984364fa0d

# Flask
DIGEST_WERKZEUG=8f05b3632d00b1a9c3d85f46dccc7eb55c032bc8cc7b688219865487c96127ecccdd44f9724159299d14db98c1951b552b478811d292d93aa2d12817c88c8527
DIGEST_MARKUPSAFE=69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec
DIGEST_JINJA2=715456e053af748fd04b7357f61c4fe457f511b4802180b01164b647081c7de30f2d5215de4ed2a6a83cd4241e03bcf0d247ddf13dc3878962539855b80344d2
DIGEST_ITSDANGEROUS=891c294867f705eb9c66274bd04ac5d93140d6e9beea6cbf9a44e7f9c13c0e2efa3554bdf56620712759a5cd579e112a782d25f3f91ba9419d60b2b4d2bc5b7c
DIGEST_CLICK=bf12d793b0c29ed36d9ba1ce058ea3eb4a2ba528e0e0266f1573d2a66504e935b553671e2b8bf9ebd75aaed2e8d9d36b41cc260dcdecba329ea87c3b1b54a69c
DIGEST_FLASK=3bcd417e5b93590944ebdba05ff4ae37aab31aadcda2e4514d8be275d52877191ffbc58d89ea603900afe39264c899fc1e4fd77cd5e24880c03601551d8f1aac

# Cryptography
DIGEST_PYCPARSER=06dc9cefdcde6b97c96d0452a77db42a629c48ee545edd7ab241763e50e3b3c56d21f9fcce4e206817aa1a597763d948a10ccc73572490d739c89eea7fede0a1
DIGEST_CFFI=d906b00752bce5634b309574a3edd5fbb737cb90df351cedcb7c264f3a5b93e28bdd16af1ff69eeddce745b1ada93d97c0b7fb73e04e6973fd7631850cba5f87
DIGEST_CRYPTOGRAPHY=14500ff61f10e01281c5b1437de4a594b3fd16253f2911c15736a1e75cc77511c4adb5fdd35c3acb154219a37fe748704593eca4093a08738c1e04d0c663612a

# PyNaCl
DIGEST_SETUPTOOLS=a8d25a299e06ed353963d1c2da7961e4a177e556ce0483750958d74d6f29dafe992f459f694c2465576ce7fc2eff0260a8b2bbb8e5ae9d7c32147ac6af6a7098
DIGEST_PYNACL=bf1bb46d23419cb375bcf620a37b5e9ce925cb0dd55eadf851a4bbb9039c8846ed13ae33966436a96655ea41ad1fc282f9139a958fd55ea10597fd3859635a2f


# ----------------------------------------------------------------------------------------

# Functions with pinned hashes

function verify_tcb_requirements_files {
    # To minimize the time TCB installer configuration stays online,
    # only the requirements files are authenticated between downloads.
    compare_digest 2b88094a3889989ba497d6c89536b803aa761f93687312a4c05ce090784f4f2ef4c6025b1eb38cec71fde10f0b24bbbf171e5602c265ba1377a64a3809f28572 '' requirements.txt
    compare_digest ddb4926855e0e798cc41e6a1f84136d9ab743112a8a5b300bd59c76b57cf9833ee3ecfe8a56c501aeee7f8809281e16609d7c501fa7b528a94f81f834659efcf '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest 1d9ee816a00eb66a96cf2a6484f37037e90eb8865d68b02de9c01d7ee6fa735cbbd2279099fe8adfb4dda5d9c0a2da649a5f530dba1f0c44471838995abcebb2 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 8db25eafc66308f1fe8223c39bc5fb025ae111ebce3eae5601c907fa7a2654f68395af4f355ff0ff03775e79cda8dfccddaf7d68555bfe065d9469ca04a288f9 '' LICENSE-3RD-PARTY
    compare_digest 7cad2202e4cc940627e31577162c38f44022ddb138a51f52d0ac3747e264e065919df2b646020851d8973cc76a2873a72ceabcbe93c39911ebbfa7c867f01675 '' relay.py
    compare_digest 6d1993b629e38818084500baed6d959d332ab6fe19213fc2cf078d1a0b59423cc05b2be839935836d27c63ed73c93c8b51cceddbf1d5415593b691bb0ed1a9dc '' requirements-dev.txt
    compare_digest a76db3ede1bdcce853f7a9d1fc45a588d183c17da63652628bb5102ad14a7c2c51443a562bf0995045ff322199e2b1365acb0fd8e882d623a31751a8d5d7926c '' requirements-relay.txt
    compare_digest 98ad61622b70192927fe520a52c6f2d056c18a454249bf7d599f4872e740043f274aa0488f0e482b9c5f97df65b4a47375cc0abcd7122d594f8f640de3dcc64d '' requirements-relay-tails.txt
    compare_digest 728eaadd78cb3e75b9c1386cca047c056ebcb1c68842cabf346e355fc7e81c3222ebf3009769d37cfa6c793b5e73b5d06641c8cd672f730e8f2558261f77328a '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest c746fa981fcdc1b21cbe7117ed186ef7757d120cb96fbe8500b8b5f7f4effebe71360ae5c1cc2bf873818002544d9aeba26990b93723a79c6bbcd647552a7ca0 '' tfc.py
    compare_digest 62f26d2805570ee70fad3a076579a554008e7d9f2c9ff310f3bb5876d361cc03dbae7ab63b144ac215a35f920ac56d359481352805a356479d622ab00da15f7f '' tfc.yml
    compare_digest c4d95b0385f474eee4ef8c25c579d5303a14ecbd90258d5cbd9c4d32531cec45008fa5fa0593c1babaeaf446e20b5ff5fcc8c7cc0384790be93e56065dc5dce5 '' uninstall.sh

    compare_digest dd2dc76c186e718cd6eb501985f3f8c639d303e44186c5f21ca8e8cf6a25b329c573ca489eda80877be51ccaa6b72b4e763060d0f0f27c0217e8c6b1016d75ca launchers/ terminator-config-local-test
    compare_digest 64fca605fff0722677e74f376f18b17d4fe07096294de16042860e91cc055c2ca33037a61aa1a9b9dde33d803b63f595e8d9cc20a5c36e952c145dc9fbb6e528 launchers/ TFC-Local-test.desktop
    compare_digest fc193b64793fec001365e4c055e0f7894d3993e1a7dbcfd6dc63a8a04a9bb1c28fc455173243f5f7c2385b86b63f122ac6c6fe2c720a9ee92834fa76dbcc1672 launchers/ tfc-qubes-receiver
    compare_digest 4aeeffde5b6f7d27a44a3ab9b8470b59b357f7532dd3c21de78d8ded0415e0dd49cbb8eb10b5b658a8cf32dbc4afbf2663a9bf1dec0e0ee3c443f4fcb9a2990d launchers/ tfc-qubes-relay
    compare_digest 4098d69e5632db7a465b03bda89dcd9817aadb903cfc0a1deb76739fbb627fc6abffd092c922c9ee8f6c3368a142c56583d25787219cfe11e37467193e49fa85 launchers/ tfc-qubes-transmitter
    compare_digest 7a2673087fa278749dcc06310a59e9159e101c0ac4faa4003587071b7df732f5b6cde001df71ee01082f099018d3d1acfdb89300361f72852646dc1ea7081fc0 launchers/ TFC-RP.desktop
    compare_digest 6ac845238824f0ede5b6db6403e9096f0f16050195f179b759cb21249259491363f37b178301ffb50ad1a4919a32a44318c43eae48ac12404de72e33aa672a85 launchers/ TFC-RP-Qubes.desktop
    compare_digest 7a2673087fa278749dcc06310a59e9159e101c0ac4faa4003587071b7df732f5b6cde001df71ee01082f099018d3d1acfdb89300361f72852646dc1ea7081fc0 launchers/ TFC-RP-Tails.desktop
    compare_digest 34ee06aee9b471d7823c8c05c6ccf7a99716231aaaee11e1993281e7bfce2617c378594a402768247c482390f26241829ed99d2134912a94b9fae880448951b7 launchers/ TFC-RxP.desktop
    compare_digest b84115bcbc76753e1702da3eccf81a3fca65cb09d085904c2ec660b9d1a539409d181603ab08c1fef2716d3bb41c686602d9bbe6611f17725eeb6fa52422ac61 launchers/ TFC-RxP-Qubes.desktop
    compare_digest 6661c1181b0eda5773425849bd58d0118936f9285db295ad998b98c96c8c72e3a8e897e70eea4d06d288bf33bc66548d8774ed5afcb75e4eee7d64b40303b12f launchers/ TFC-TxP.desktop
    compare_digest 823ec5061fb7d4a4234ce30c0054c8006d63a1ef719f8c41fad8855c8d096fba59139601f73a9e878a18c5f3377b8de1e80a69e735137bb42f7bae9c4360d6af launchers/ TFC-TxP-Qubes.desktop

    compare_digest b5393d094dce97a8e12a36438c56e92da8dc01555aa18a85b138411d18a3e47384a2dc56b184f8d18745db55495d6f2e22e4aa0038a5b2917856a1ba13fca06a qubes/ service.sh
    compare_digest 070fb411f13dac93a8e11be5a97857f00d05e312f152736f2e9757397bc045cc235212121458c773daf1251e512e37836525dcda394dabc78879e71159f79850 qubes/ writer.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/ __init__.py
    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/common/ __init__.py
    compare_digest 654cc2aa00b91697c3dc1894c4f7726d151e2c2fc92922aa760008c6f55645129a546e0fa38c39e2c72d10720b7a8d67253bfcddddc01dde4a99fdc40143ffad src/common/ crypto.py
    compare_digest e1f77d17164d6879695adb0ad9d32c61f7447f36db73e398e161956140a142c40a9972970d89873d2febd4dc1c2b57ddd838eccd3437fa28c83285a0179aeb45 src/common/ database.py
    compare_digest dfef16b30d75bbe270c4b7df1369b3eeb2347b931e7bb3a974965cc916a6ffb20aaa40d14532ecb4a8cabdb71598fb53d86589aa475dbb02030bdf9489d71429 src/common/ db_contacts.py
    compare_digest 7c0214208857174b43092eaf61d14c16e60d6ebb68ba25b260f84546ce39f1fed8b21aceb58833920c8d939304b313c0ad95c554210ae3d5d0547143f7dd704c src/common/ db_groups.py
    compare_digest c49231429824d8133de7efad667c2bdde694a6c7a2e34e3b015ddb8cf59a150574cdd7099aaad02a4993a1669cd631f5af4cc611fac7d538d3ecd141d9295d0d src/common/ db_keys.py
    compare_digest 59affc49355ee6c3be47fde56434142ec87ce49554194744b67fa7f7f9e24e9008fe23ad5ee196b74adc49a1daf555d42762630e44be5b55294f7bd223b77883 src/common/ db_logs.py
    compare_digest 82286a267814ba58fee37477a44ecd87090ce4878535bd98f626ef9b853965f6f18d082109713856ef19c80ec892fc26ad4a5c08775a0a0ca65134a9d3ed86d5 src/common/ db_masterkey.py
    compare_digest 325298cd6cb7e68d27681c18f29e635f46222e34015ba3c8fe55e6718e6907b4257bbe12d71fd344b557aff302ae9d7fca2b581b4208e59ac7923e57aca23fe5 src/common/ db_onion.py
    compare_digest 4ef757ba877ee6b74632af3a0d3567c9483a62b9063ec0e7fe7b6abc7e82b490ec52279198f0be22866595dae1948bb1ef9ef556c88b3c320c5316fd59fc0743 src/common/ db_settings.py
    compare_digest 60fb4c922af286307865b29f0cadab53a5a575a9f820cd5ad99ea116c841b54dd1d1be1352bf7c3ab51d2fd223077217bcda1b442d44d2b9f1bf614e15c4a14d src/common/ encoding.py
    compare_digest ccd522408ad2e8e21f01038f5f49b9d82d5288717f1a1acf6cda278c421c05472827ee5928fbf56121c2dfc4f2cc49986e32c493e892bd6ae584be38ba381edd src/common/ exceptions.py
    compare_digest 5a146b3cfee9e703453a25bbbf347a87c3422ccefcd9083697d9ebdcf476b7be725518060fa09ea7ff98757b2b3c0ee687cb7b5c24a9938d6d9f17a7fc00505c src/common/ gateway.py
    compare_digest d4021175fba75649fa1b8b65116b0acc98cedccd2a012986037a78e799908329694ee6f4c50617f92f5df279cfe5e719e38cada5f3775a8ea912a541f1dbf438 src/common/ input.py
    compare_digest 8045671a2d180271ea873e91e478a0b3ba766cda195a0755060ba14fb50d089b7007b6134c002e8d25255e47376c2e394c76a7593e68ea45f1cc1f8e109869e9 src/common/ misc.py
    compare_digest 6329bbdc9d24c1342d0996009a8cd4d852d5a800cbf6a582c047c0fc13e6ca9be28251b783325adffca100d2a372616088cedff2441cc103b8c18540828445ef src/common/ output.py
    compare_digest c96d7cb1b76650a49accc3ea007254e73e2e697895790ff6c14351520f4a7b1baec76d6055e3bddb14a687c0641fd15e361c93737afe7a8924b420ca67c31140 src/common/ path.py
    compare_digest 39e48b0b55f4f1a48bc558f47b5f7c872583f3f3925fd829de28710024b000fcb03799cb36da3a31806143bc3cbb98e5d357a8d62674c23e1e8bf957aece79f6 src/common/ reed_solomon.py
    compare_digest 04127f6615143806cee59140b325021fcccc3852d0f2eb6fda84f55268ddc5f4b22af2120a44b3d17e88024807236c97e1a2b60d7dd2c5abf91c521f32b68796 src/common/ statics.py
    compare_digest a57d5525a570a78d15c75e79702289cf8571c1b3c142fae57f32bf3ed8bb784c7f63ce2e805d295b4a505fdeaf9d59094ebe67d8979c92dc11e2534474505b0e src/common/ word_list.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/receiver/ __init__.py
    compare_digest ccc8d6bf2b10cf4ccb51a014ff7f251e527196f1172ab9b4da48b01ddcb9a64c15358f03424b76babd1ce2dd20147d847d2e1292fb0d76135c2ba10e182ec14b src/receiver/ commands.py
    compare_digest 6dd0d73fe240f974bb92e850c5f38e97ee8d632fbb3a53abc3160b4e29f9b2b076b8b5d20dc7f7231c01c978ea67b55740ac17dc74bf05e6811d2e35e34056fb src/receiver/ commands_g.py
    compare_digest 46be945df548416ec306054cdd2026b7f0057489bb2ded4e7d99b7b8f5bdb3208acbc8e5bc39617aa1d94a7e90b38a70321882e1753883389b0780ab58d9ed12 src/receiver/ files.py
    compare_digest acfa0b7ac684b5a2747e1db315386ada28cf077c5fbedfc13a89d9912682b5020ae8da98fc65aef7fcbe3e3180184a7f787eba10b5617666bc43f4e4ba40231c src/receiver/ key_exchanges.py
    compare_digest 6ebd6c0638525997949783b7623ce9a78683169e95f572ea65dcec52da150b0473a25e928862cab34eac44b0e0991a0969c5252c03cf4dc8f49d1aa9809b43bd src/receiver/ messages.py
    compare_digest eabe1695cd0fe04346e49ed91b64a11ad74ff60b636333140f9a3c6745b9c408d77aae8f45256b5d74b241324a5d429249b2be6c732205ab729a38049b8631f7 src/receiver/ output_loop.py
    compare_digest b5f64d5c00681912be163120e465409f015a52b39fd66850d43bf9ee07302370b92b84b145683ad1ffa12d53a79c26477f2b971428aef2bc2882532cc5cbe251 src/receiver/ packet.py
    compare_digest 002c960023393bec10da3de6d9a218c8e2c27da1635fd1a7f99e02a9a28792428a2c0e6cd030d1cc1fac1124c58f397f63d60b7af4c384367a8c293978125539 src/receiver/ receiver_loop.py
    compare_digest fd125c2092c217c74f1e070ba266a807c6bebea54cea2b41488ab4ecc48c91e7f60fbdc16c152704c66916ee06cecdda1a20b8c350d22a1148d83a17f8b414b8 src/receiver/ windows.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/relay/ __init__.py
    compare_digest 0ab86ddcfc7a28e7945e302918e384c2570d8b19942bb7c1b300d5913f77b184aae36612819ec85f0ef5b4a3b21d22aa710f218fc229c1317f04a11782e832e5 src/relay/ client.py
    compare_digest c7457a0b21383c9d803f3854bbbd616943132a775641d8cada0c5fbd0d756910679d44a748b79291149758e2650e1bee4450b0c51ceb9f8bd680cfc6a5635407 src/relay/ commands.py
    compare_digest a5752def8b79a3d7e3cf960f8cbdbbc2b115a864ad4312b439e134a86712781e19af584f1b9f984bd8a7a47e308405630b6a652fce9e920c3f7730a21ae762fd src/relay/ diffs.py
    compare_digest 0bc1912af4d45ff72fbd7c43a09ab48ea3a780bb096226011525924820ba0ba1f396937fb191e5e18ec87dee14ccd3b505192e16e835d46088e4b50c941125f5 src/relay/ onion.py
    compare_digest 42acbe9557c848eea66ea6b9db71b3c3ac5b2da7710f7dc79f70f8b4952e582c8953d8fb38eab82be9b8b15db6a3f3fc882ef8d65adbe5ccdf26f55ef54d4758 src/relay/ server.py
    compare_digest ee0bdbf39053e34d5e6597004ffc4a3831835238631368d29e301094a45551c6ff64b4d8cd9a8e8f7b6cf3fcfddd21e3dd275c0dee7cbc0503584b6991f923f5 src/relay/ tcb.py

    compare_digest 3ee90ee305382d80da801f047a6e58e5b763f9f6bc08dce531d5c620f2748c6bba59a1528eee5d721decb8e724f53b28fc7609f5b20472f679f554b78b5d4cc6 src/transmitter/ __init__.py
    compare_digest 20b128c1aa0353db8f20f4274632454f8ead9e8e3ec59876673a1b2c270c66c8ab1af2252e83d95e15c95e6d8e56ef4d8708fda5afeedef583f3b297d92d38c1 src/transmitter/ commands.py
    compare_digest 2af2cd801fc83f882c65e031b5bd6f5c2c30b32dc0bb538953021b1f520714723d39b2a2462a6718cbb3efea1b645767b50d468978bb802dacf8b73535a2975f src/transmitter/ commands_g.py
    compare_digest 31267d2049e4e9a88301e0d851e11c8e3db0bbb96c4509c10a3528c29ab679a49db8430cca1529ccd71556e273f4937d3bf7e0c2e1a165a8d36729ed284a4f19 src/transmitter/ contact.py
    compare_digest f2fefbc2acbad441cb997969d6b39fbe26813abc781f5b6caaa08f1eb4c52c05b2bd4cbc341cb75ea07f7a4931d9b1145bef2fb352376a72442f7a71299fb595 src/transmitter/ files.py
    compare_digest 110665f962eb827a9f636cc823837222a7bed4a429d4e10eb90c7bf5ba7bd5900aa1ecc4d4b485927a276d5727e18fe9e78f75ab8bd4ff67f039bb633fe505ec src/transmitter/ input_loop.py
    compare_digest 89407e887d0cba4d993c0ee60412ea1ecfdedd8bbb0c73417bb71847733f85dbe1dab2997f65824ae58b4b5278bb0866a2a04bb8273228ca1bbbc1068eec7c04 src/transmitter/ key_exchanges.py
    compare_digest 766b1efa548f2da49272870fa5f89b8aacdf65b737b908f7064209f2f256c4d4875228ad087ac4957a292a82ed5936a40b9ae7553bfae2eae739f0c4579eb21a src/transmitter/ packet.py
    compare_digest 0ed708842241e8b3a76371ea2857f8d6f035424a6a22af097a288d941c37e5d7142d2fa47e4e12cedbf0a06dab94222ff37a00292762660acb0d51f911acfb7a src/transmitter/ sender_loop.py
    compare_digest c102bb337ade562e0d9aedc0910f70f14652e2eba004a632bfb0ba8dddf147ab271d3ae544c4d9f3b2fcd3830646d9ad28255717d017cb91b3463829069360ba src/transmitter/ traffic_masking.py
    compare_digest eb77c6206cab63ffdb47bbcb8b76a55100636d893e234a048221d83e9ce07b76ccfcc93b506d9fb48d6f8823135e5697f3e56aed8e95f23990d8dfc1cece325e src/transmitter/ user_input.py
    compare_digest 489f869176da0040b6f06327544f5eb72863a748a4799c66198a09402df6d54d842e9af27af51faaeed9d0661133eeaebb9918bd1bcd50950c182ba4b1e5fc74 src/transmitter/ window_mock.py
    compare_digest 09c536d43b37103b6340293efa67345f54da6563ea65441546161066d735b4dfad9eaea9c58452de3413b72b28a923d2efb851ac740ba09ada45368bb64b9f15 src/transmitter/ windows.py
}


# ----------------------------------------------------------------------------------------

# Dependency batch processing

function process_virtualenv_dependencies {
    # Manage Virtualenv dependencies in batch.
    sudo $1 "${INSTALL_DIR}/${ZIPP}"
    sudo $1 "${INSTALL_DIR}/${FILELOCK}"
    sudo $1 "${INSTALL_DIR}/${IMPORTLIB_METADATA}"
    sudo $1 "${INSTALL_DIR}/${SIX}"
    sudo $1 "${INSTALL_DIR}/${DISTLIB}"
    sudo $1 "${INSTALL_DIR}/${APPDIRS}"
    sudo $1 "${INSTALL_DIR}/${VIRTUALENV}"
}


function process_tails_venv_dependencies {
    # Process Tails Virtualenv dependencies in batch.
    t_sudo -E $1 "${INSTALL_DIR}/${ZIPP}"
    t_sudo -E $1 "${INSTALL_DIR}/${FILELOCK}"
    t_sudo -E $1 "${INSTALL_DIR}/${IMPORTLIB_METADATA}"
    t_sudo -E $1 "${INSTALL_DIR}/${SIX}"
    t_sudo -E $1 "${INSTALL_DIR}/${DISTLIB}"
    t_sudo -E $1 "${INSTALL_DIR}/${APPDIRS}"
    t_sudo -E $1 "${INSTALL_DIR}/${VIRTUALENV}"
}


function process_tcb_dependencies {
    # Manage TCB dependencies in batch.
    sudo $1 "${INSTALL_DIR}/${PYCPARSER}"
    sudo $1 "${INSTALL_DIR}/${CFFI}"
    sudo $1 "${INSTALL_DIR}/${ARGON2_CFFI}"
    sudo $1 "${INSTALL_DIR}/${SETUPTOOLS}"
    sudo $1 "${INSTALL_DIR}/${PYNACL}"
    sudo $1 "${INSTALL_DIR}/${PYSERIAL}"
    sudo $1 "${INSTALL_DIR}/${CRYPTOGRAPHY}"
}


function verify_tails_dependencies {
    compare_digest ${DIGEST_PYSERIAL} '' ${PYSERIAL}
    compare_digest ${DIGEST_PYSOCKS}  '' ${PYSOCKS}

    # Virtualenv
    compare_digest ${DIGEST_ZIPP}               '' ${ZIPP}
    compare_digest ${DIGEST_FILELOCK}           '' ${FILELOCK}
    compare_digest ${DIGEST_IMPORTLIB_METADATA} '' ${IMPORTLIB_METADATA}
    compare_digest ${DIGEST_SIX}                '' ${SIX}
    compare_digest ${DIGEST_DISTLIB}            '' ${DISTLIB}
    compare_digest ${DIGEST_APPDIRS}            '' ${APPDIRS}
    compare_digest ${DIGEST_VIRTUALENV}         '' ${VIRTUALENV}

    # Requests
    compare_digest ${DIGEST_URLLIB3}  '' ${URLLIB3}
    compare_digest ${DIGEST_IDNA}     '' ${IDNA}
    compare_digest ${DIGEST_CHARDET}  '' ${CHARDET}
    compare_digest ${DIGEST_CERTIFI}  '' ${CERTIFI}
    compare_digest ${DIGEST_REQUESTS} '' ${REQUESTS}

    # Flask
    compare_digest ${DIGEST_WERKZEUG}     '' ${WERKZEUG}
    compare_digest ${DIGEST_MARKUPSAFE}   '' ${MARKUPSAFE}
    compare_digest ${DIGEST_JINJA2}       '' ${JINJA2}
    compare_digest ${DIGEST_ITSDANGEROUS} '' ${ITSDANGEROUS}
    compare_digest ${DIGEST_CLICK}        '' ${CLICK}
    compare_digest ${DIGEST_FLASK}        '' ${FLASK}

    # Cryptography
    compare_digest ${DIGEST_PYCPARSER}    '' ${PYCPARSER}
    compare_digest ${DIGEST_CFFI}         '' ${CFFI37}
    compare_digest ${DIGEST_CRYPTOGRAPHY} '' ${CRYPTOGRAPHY37}

    # PyNaCl
    compare_digest ${DIGEST_PYNACL} '' ${PYNACL}
}


function move_tails_dependencies {
    # Move Tails dependencies in batch.
    t_sudo mv "$HOME/${PYSERIAL}" "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${PYSOCKS}"  "${INSTALL_DIR}/"

    # Virtualenv
    t_sudo mv "$HOME/${ZIPP}"               "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${FILELOCK}"           "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${IMPORTLIB_METADATA}" "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${SIX}"                "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${DISTLIB}"            "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${APPDIRS}"            "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${VIRTUALENV}"         "${INSTALL_DIR}/"

    # Requests
    t_sudo mv "$HOME/${URLLIB3}"  "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${IDNA}"     "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${CHARDET}"  "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${CERTIFI}"  "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${REQUESTS}" "${INSTALL_DIR}/"

    # Flask
    t_sudo mv "$HOME/${WERKZEUG}"     "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${MARKUPSAFE}"   "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${JINJA2}"       "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${ITSDANGEROUS}" "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${CLICK}"        "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${FLASK}"        "${INSTALL_DIR}/"

    # Cryptography
    t_sudo mv "$HOME/${PYCPARSER}"      "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${CFFI37}"         "${INSTALL_DIR}/"
    t_sudo mv "$HOME/${CRYPTOGRAPHY37}" "${INSTALL_DIR}/"

    # PyNaCl
    t_sudo mv "$HOME/${PYNACL}" "${INSTALL_DIR}/"
}

function process_tails_dependencies {
    # Manage Tails dependencies in batch.
    t_sudo -E $1 "${INSTALL_DIR}/${PYSERIAL}"
    t_sudo -E $1 "${INSTALL_DIR}/${PYSOCKS}"

    # Requests
    t_sudo -E $1 "${INSTALL_DIR}/${URLLIB3}"
    t_sudo -E $1 "${INSTALL_DIR}/${IDNA}"
    t_sudo -E $1 "${INSTALL_DIR}/${CHARDET}"
    t_sudo -E $1 "${INSTALL_DIR}/${CERTIFI}"
    t_sudo -E $1 "${INSTALL_DIR}/${REQUESTS}"

    # Flask
    t_sudo -E $1 "${INSTALL_DIR}/${WERKZEUG}"
    t_sudo -E $1 "${INSTALL_DIR}/${MARKUPSAFE}"
    t_sudo -E $1 "${INSTALL_DIR}/${JINJA2}"
    t_sudo -E $1 "${INSTALL_DIR}/${ITSDANGEROUS}"
    t_sudo -E $1 "${INSTALL_DIR}/${CLICK}"
    t_sudo -E $1 "${INSTALL_DIR}/${FLASK}"

    # Cryptography
    t_sudo -E $1 "${INSTALL_DIR}/${PYCPARSER}"
    t_sudo -E $1 "${INSTALL_DIR}/${CFFI37}"
    t_sudo -E $1 "${INSTALL_DIR}/${CRYPTOGRAPHY37}"

    # PyNaCl
    t_sudo -E $1 "${INSTALL_DIR}/${PYNACL}"
}


function install_tails_setuptools {
    # Download setuptools package for Tails, and move it to /opt/tfc so it can't be edited.
    # Once the package has been authenticated, install it and then remove the install file.
    torsocks python3 -m pip download --no-cache-dir -r "${INSTALL_DIR}/requirements-setuptools.txt" --require-hashes --no-deps -d "${HOME}/"
    t_sudo mv "$HOME/${SETUPTOOLS}" "${INSTALL_DIR}/"
    compare_digest ${DIGEST_SETUPTOOLS} '' ${SETUPTOOLS}
    t_sudo python3 -m pip install "${INSTALL_DIR}/${SETUPTOOLS}"
    t_sudo -E rm "${INSTALL_DIR}/${SETUPTOOLS}"
}


# Common tasks

function remove_common_files {
    # Remove files that become unnecessary after installation.
    $1 rm -r ${INSTALL_DIR}/.git/
    $1 rm -r ${INSTALL_DIR}/launchers/
    $1 rm -r ${INSTALL_DIR}/tests/
    $1 rm    ${INSTALL_DIR}/.coveragerc
    $1 rm    ${INSTALL_DIR}/.travis.yml
    $1 rm    ${INSTALL_DIR}/install.sh
    $1 rm    ${INSTALL_DIR}/install.sh.asc
    $1 rm    ${INSTALL_DIR}/pubkey.asc
    $1 rm    ${INSTALL_DIR}/README.md
    $1 rm    ${INSTALL_DIR}/requirements.txt
    $1 rm    ${INSTALL_DIR}/requirements-dev.txt
    $1 rm    ${INSTALL_DIR}/requirements-relay.txt
    $1 rm    ${INSTALL_DIR}/requirements-relay-tails.txt
    $1 rm    ${INSTALL_DIR}/requirements-setuptools.txt
    $1 rm    ${INSTALL_DIR}/requirements-venv.txt
    $1 rm -f /opt/install.sh
    $1 rm -f /opt/install.sh.asc
    $1 rm -f /opt/pubkey.asc
}


function steps_before_network_kill {
    # These steps are identical in TCB/Relay/Local test configurations.
    # This makes it harder to distinguish from network traffic when the
    # user is installing TFC for Source or Destination Computer: By the
    # time `kill_network` is run, it's too late to compromise the TCB.
    # Hopefully this forces adversaries to attempt compromise of more
    # endpoints during installation, which increases their chances of
    # getting caught.
    dpkg_check
    check_rm_existing_installation

    sudo torsocks apt update
    sudo torsocks apt install git gnome-terminal libssl-dev python3-pip python3-tk net-tools -y
    sudo torsocks git clone --depth 1 https://github.com/tfctesting/tfc.git ${INSTALL_DIR}

    verify_tcb_requirements_files
    sudo torsocks python3 -m pip download --no-cache-dir -r "${INSTALL_DIR}/requirements-venv.txt" --require-hashes --no-deps -d ${INSTALL_DIR}/
    sudo torsocks python3 -m pip download --no-cache-dir -r "${INSTALL_DIR}/requirements.txt"      --require-hashes --no-deps -d ${INSTALL_DIR}/
}


# ----------------------------------------------------------------------------------------

# Installation configurations for Debian/PureOS/Ubuntu/LMDE

function install_tcb {
    # Install TFC for Source/Destination Computer.
    steps_before_network_kill

    kill_network

    verify_files
    create_user_data_dir

    process_virtualenv_dependencies "python3 -m pip install"
    sudo python3 -m virtualenv  "${INSTALL_DIR}/venv_tcb" --system-site-packages --never-download

    . ${INSTALL_DIR}/venv_tcb/bin/activate
    process_tcb_dependencies "python3 -m pip install"
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                   /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-TxP.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RxP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm -f"
    sudo rm -r "${INSTALL_DIR}/src/relay/"
    sudo rm -r "${INSTALL_DIR}/qubes/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/relay.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


function install_relay {
    # Install TFC Relay configuration on Networked Computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    install_virtualenv
    sudo python3 -m virtualenv ${INSTALL_DIR}/venv_relay --system-site-packages

    . ${INSTALL_DIR}/venv_relay/bin/activate
    sudo torsocks python3 -m pip install -r ${INSTALL_DIR}/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                  /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm -f"
    sudo rm -r "${INSTALL_DIR}/src/receiver/"
    sudo rm -r "${INSTALL_DIR}/src/transmitter/"
    sudo rm -r "${INSTALL_DIR}/qubes/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/tfc.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


# Installation configuration for Tails

function install_relay_tails {
    # Install TFC Relay configuration on Networked Computer
    # running Tails live distro (https://tails.boum.org/).
    read_sudo_pwd

    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip python3-tk -y || true  # Ignore error in case packets can not be persistently installed

    torsocks git clone --depth 1 https://github.com/tfctesting/tfc.git "${HOME}/tfc"
    t_sudo mv "${HOME}/tfc/ ${INSTALL_DIR}/"
    t_sudo chown -R root ${INSTALL_DIR}/

    verify_tcb_requirements_files
    verify_files

    create_user_data_dir

    install_tails_setuptools

    # Tails doesn't allow downloading over PIP to /opt/tfc, so we first download
    # to $HOME, move the files to /opt/tfc, and then perform the hash verification
    torsocks python3 -m pip download --no-cache-dir -r "${INSTALL_DIR}/requirements-venv.txt"        --require-hashes --no-deps -d "${HOME}/"
    torsocks python3 -m pip download --no-cache-dir -r "${INSTALL_DIR}/requirements-relay-tails.txt" --require-hashes --no-deps -d "${HOME}/"
    move_tails_dependencies
    verify_tails_dependencies

    process_tails_venv_dependencies "python3 -m pip install"
    t_sudo python3 -m virtualenv ${INSTALL_DIR}/venv_relay --system-site-packages

    . ${INSTALL_DIR}/venv_relay/bin/activate
    process_tails_dependencies "python3 -m pip install"
    deactivate

    t_sudo mv ${INSTALL_DIR}/tfc.png                        /usr/share/pixmaps/
    t_sudo mv ${INSTALL_DIR}/launchers/TFC-RP-Tails.desktop /usr/share/applications/
    t_sudo mv ${INSTALL_DIR}/tfc.yml                        /etc/onion-grater.d/

    # Remove unnecessary files
    remove_common_files             "t_sudo"
    process_tails_venv_dependencies "rm"
    process_tails_dependencies      "rm"
    t_sudo rm -r "${INSTALL_DIR}/src/receiver/"
    t_sudo rm -r "${INSTALL_DIR}/src/transmitter/"
    t_sudo rm -r "${INSTALL_DIR}/qubes/"
    t_sudo rm    "${INSTALL_DIR}/dd.py"
    t_sudo rm    "${INSTALL_DIR}/tfc.py"

    install_complete "Installation of the TFC Relay configuration is now complete."
}


# Installation configurations for Qubes OS (https://www.qubes-os.org/)

function install_qubes_src {
    # Qubes Source VM installation configuration for Debian 10 domains.
    create_user_data_dir

    steps_before_network_kill

    verify_files

    process_virtualenv_dependencies "python3 -m pip install"
    sudo python3 -m virtualenv "${INSTALL_DIR}/venv_tcb" --system-site-packages --never-download

    . ${INSTALL_DIR}/venv_tcb/bin/activate
    process_tcb_dependencies "python3 -m pip install"
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                         /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-TxP-Qubes.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/tfc-qubes-transmitter /usr/bin/tfc-transmitter

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm -f"
    sudo rm -r "${INSTALL_DIR}/src/relay/"
    sudo rm -r "${INSTALL_DIR}/qubes/"  # Listening service only needed on NET/DST
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/relay.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    install_complete_qubes
}


function install_qubes_dst {
    # Qubes Destination VM installation configuration for Debian 10 domains.
    create_user_data_dir

    steps_before_network_kill

    verify_files

    # Configure listening service for qrexec RPC
    sudo ln -sf /opt/tfc/qubes/service.sh /etc/qubes-rpc/tfc.NetworkerDestination
    sudo chmod a+x /opt/tfc/qubes/writer.py
    sudo chmod a+x /opt/tfc/qubes/service.sh

    process_virtualenv_dependencies "python3 -m pip install"
    sudo python3 -m virtualenv "${INSTALL_DIR}/venv_tcb" --system-site-packages --never-download

    . ${INSTALL_DIR}/venv_tcb/bin/activate
    process_tcb_dependencies "python3 -m pip install"
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                         /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RxP-Qubes.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/tfc-qubes-receiver    /usr/bin/tfc-receiver

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm -f"
    sudo rm -r "${INSTALL_DIR}/src/relay/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/relay.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    install_complete_qubes
}


function install_qubes_net {
    # Qubes Networked VM installation configuration for Debian 10 domains.
    create_user_data_dir

    steps_before_network_kill

    verify_files

    # Configure listening service for qrexec RPC
    sudo ln -sf /opt/tfc/qubes/service.sh /etc/qubes-rpc/tfc.SourceNetworker
    sudo chmod a+x /opt/tfc/qubes/writer.py
    sudo chmod a+x /opt/tfc/qubes/service.sh

    process_virtualenv_dependencies "python3 -m pip install"
    sudo python3 -m virtualenv ${INSTALL_DIR}/venv_relay --system-site-packages

    . ${INSTALL_DIR}/venv_relay/bin/activate
    sudo torsocks python3 -m pip install -r ${INSTALL_DIR}/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                        /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RP-Qubes.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/tfc-qubes-relay      /usr/bin/tfc-relay

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm -f"
    sudo rm -r "${INSTALL_DIR}/src/receiver/"
    sudo rm -r "${INSTALL_DIR}/src/transmitter/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/tfc.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    install_complete_qubes
}

# Tiling terminal emulator configurations for single OS

function install_local_test {
    # Install TFC for local testing on a single computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    sudo torsocks apt install terminator -y

    install_virtualenv
    sudo python3 -m virtualenv ${INSTALL_DIR}/venv_tfc --system-site-packages

    . ${INSTALL_DIR}/venv_tfc/bin/activate
    sudo torsocks python3 -m pip install -r ${INSTALL_DIR}/requirements.txt       --require-hashes --no-deps
    sudo torsocks python3 -m pip install -r ${INSTALL_DIR}/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                                /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-Local-test.desktop       /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/terminator-config-local-test ${INSTALL_DIR}/
    modify_terminator_font_size "sudo" "${INSTALL_DIR}/terminator-config-local-test"

    # Remove unnecessary files
    remove_common_files             "sudo"
    process_virtualenv_dependencies "rm"
    process_tcb_dependencies        "rm -f"
    sudo rm -r "${INSTALL_DIR}/qubes/"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

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
    # install configuration, or preferably use the Qubes configuration.
    dpkg_check

    create_user_data_dir

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-tk terminator -y

    torsocks git clone https://github.com/tfctesting/tfc.git "${HOME}/tfc"

    torsocks python3 -m pip install -r "${HOME}/tfc/requirements-venv.txt" --require-hashes --no-deps

    python3 -m virtualenv "${HOME}/tfc/venv_tfc" --system-site-packages

    . "${HOME}/tfc/venv_tfc/bin/activate"
    torsocks python3 -m pip install -r "${HOME}/tfc/requirements-dev.txt"
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
    # Compare the SHA512 digest of TFC file against the digest pinned in this installer.
    purp_digest=$(sha512sum "${INSTALL_DIR}/${2}${3}" | awk '{print $1}')
    if echo ${purp_digest} | cmp -s <(echo "$1"); then
        echo "OK - Pinned SHA512 hash matched file ${INSTALL_DIR}/${2}${3}"
    else
        echo "Error: ${INSTALL_DIR}/${2}${3} had an invalid SHA512 hash:"
        echo "${purp_digest}"
        echo "Expected following hash:"
        echo "${1}"
        exit 1
    fi
}


function t_sudo {
    # Execute command as root on Tails.
    echo "${sudo_pwd}" | sudo -S $@
}


function install_virtualenv {
    # Some distros want virtualenv installed as sudo and other don't.
    # Install as both users to improve the chances of compatibility.
    sudo torsocks python3 -m pip install -r ${INSTALL_DIR}/requirements-venv.txt --require-hashes --no-deps
    torsocks      python3 -m pip install -r ${INSTALL_DIR}/requirements-venv.txt --require-hashes --no-deps
}


function read_sudo_pwd {
    # Cache the sudo password so that Debian doesn't keep asking
    # for it during the installation (it won't be stored on disk).
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
        if [[ ${name} != "lo" ]]; then
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
    # Adjust terminator font size for tiling terminal emulator configurations.
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
    # Notify the user that the installation for Qubes VM is complete.
    clear
    c_echo ''
    c_echo "Installation of TFC on this Qube is now complete."
    c_echo ''
    c_echo "Press any key to close the installer."
    read -r -n 1 -s -p ''
    clear

    kill -9 $PPID
}


function arg_error {
    # Print help message if the user launches the
    # installer with missing or invalid argument.
    clear
    echo -e "\nUsage: bash install.sh [OPTION]\n"
    echo    "Mandatory arguments"
    echo    "  tcb      Install Transmitter/Receiver Program (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20)"
    echo    "  relay    Install Relay Program                (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20 / Tails 4.0+)"
    echo -e "  local    Install insecure local testing mode  (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20)\n"
    echo    "  qsrc     Install Transmitter Program          (Qubes 4.0.3)"
    echo    "  qdst     Install Receiver Program             (Qubes 4.0.3)"
    echo -e "  qnet     Install Relay Program                (Qubes 4.0.3)\n"
    exit 1
}


# Pre-install checks

function check_rm_existing_installation {
    # Remove TFC installation directory if TFC is already installed.
    if [[ -d "${INSTALL_DIR}" ]]; then
        if [[ ${sudo_pwd} ]]; then
            t_sudo rm -r ${INSTALL_DIR}  # Tails
        else
            sudo rm -r ${INSTALL_DIR}    # Debian etc.
        fi
    fi
}


function dpkg_check {
    # Check if the software manager is busy, and if, wait until it completes.
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


function python_version_check {
    # Check Python version and select file names based on it.
    python_minor_version=$(python3 -c 'import sys; version=sys.version_info[:3]; print("{1}".format(*version))')

    if (( python_minor_version == 7 )); then
        CFFI=${CFFI37}
        CRYPTOGRAPHY=${CRYPTOGRAPHY37}
    elif (( python_minor_version == 8 )); then
        CFFI=${CFFI38}
        CRYPTOGRAPHY=${CRYPTOGRAPHY38}
    else
        exit_with_message "Invalid Python version (3.${python_minor_version}). Only 3.7 and 3.8 are supported."
    fi
}


# Main routine

set -e
architecture_check
root_check
sudoer_check
python_version_check
sudo_pwd=''

case $1 in
    tcb    ) install_tcb;;
    relay  ) install_relay;;
    tails  ) install_relay_tails;;
    local  ) install_local_test;;
    qsrc   ) install_qubes_src;;
    qdst   ) install_qubes_dst;;
    qnet   ) install_qubes_net;;
    dev    ) install_developer;;
    *      ) arg_error;;
esac
