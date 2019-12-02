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
ARGON2=argon2_cffi-19.2.0-cp34-abi3-manylinux1_x86_64.whl
CERTIFI=certifi-2019.11.28-py2.py3-none-any.whl
CFFI=cffi-1.13.2-cp37-cp37m-manylinux1_x86_64.whl
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
SETUPTOOLS=setuptools-42.0.2-py2.py3-none-any.whl
SIX=six-1.13.0-py2.py3-none-any.whl
# STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.7-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.7.8-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.16.0-py2.py3-none-any.whl


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
    compare_digest b2ac8925070d9f304aac6c7500a752b3907b236fe796b5fd82491d02ce9a8b6e2f739a5efd175a2205ecc9241d5e0465a748ad373e8e2a1346eb4f674cf16e65 '' requirements.txt
    compare_digest 1c95643d28addf2e8a631b7ec54b2c03cdbe8135695aa5c74b7729bbd272d8590fa3ac03ced5034429c2a3012334713924a83550ff835bc1d0fff77cf43500f6 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest 1bd383c8ff277e8bddf806c8c0c34777c4f621a3e3bd48dcc07a0141d2c042ec0f822d103312b226e6133d13f792d8e704c7d9c2a12cdb305d042019d76d5f24 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 7e519d20fef24e25e88ec4a9c03abadf513b084e05038f17c62ca7899c2f9174a953caa0bfbd3b61e455e243513cdab737c22a34d73ebab07b65d3ce99100f0a '' LICENSE-3RD-PARTY
    compare_digest e81bb00e894a14419365b43ecf45443a4fed9ab0332c468066840e8ba17e2e099ff0dc1346c98fbb9d979093afaec4323d53a35d7ffdaca1fe41a4e797a07f29 '' relay.py
    compare_digest cef01f168a92975a2e1fb7d514e60fb95995f51d750596f08fdb62c27912e7d6502e1ab5e1cf5dd621c77f5f1423240f75c7269d45eecf5a56a40ba863360f5d '' requirements-dev.txt
    compare_digest 6d3c903bc74f5d1f2d20072a73aaac9b3c5f55de6a844f627a1e9d2b3522ecd7516d8637a52ccddb74bb8a854703bc28ec0349049a0e3c9cc59838dfdd22b328 '' requirements-relay.txt
    compare_digest fd6073d05c3dc24b44fe1a3b24fcbc6d3b4ffff44d7a96cb5f99c4e431bf7ebe6838fde80384f18fce75bc4f2be752a446bc2cb5bb0335de80366d60eccfdfcc '' requirements-relay-tails.txt
    compare_digest c9ac159bb9a7969ab152ea192f3c7597f852493b088bd1801fc36aee8870e319459509abb253915f4d9bfb4f9482d2b0f004fbccce2d41305557ded33cf8c19e '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest a6776ed2f82b8afec830c7cfb57473ea15656445ca14f3cea5065f8775ea7829f36a3212462b0c72bf6ec002cff2e309e788a5ca43c742d03d98b6d5691bbaaf '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest 50bb3db478184b954480069e40e47167f28f13e55aa87961eed36804c612a8c25e9ab0c0505cf5d36d790051ccfb465a2d7641ab3efb659503b634541d07e9c2 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest 6e1c1082b7850e55fe19fb2ebe0f622dea16e038072adcfe1347305324d10b97bbc443d7ed1ff3ee141d647b4561874c7736ba449c1e8e34dccd4be9dab5db8b launchers/ TFC-Local-test.desktop
    compare_digest 6a6469b5b11cb081e1f9e2848cb328d92f283f94f977f8e89984fa115fbeb719e6b094c9de0c1ff5a4f5f3fd66d3ca71bce1a3a5e4ca3ae454557ad261f8acf6 launchers/ TFC-RP.desktop
    compare_digest 6a6469b5b11cb081e1f9e2848cb328d92f283f94f977f8e89984fa115fbeb719e6b094c9de0c1ff5a4f5f3fd66d3ca71bce1a3a5e4ca3ae454557ad261f8acf6 launchers/ TFC-RP-Tails.desktop
    compare_digest 4b387996983b6b900a53aedaba0a542eb89416fed0e99ed845680e41748bbad65956c5d4662dfce4b5519412a10404e6c995464c26c74298e0db37f55b3dcd2c launchers/ TFC-RxP.desktop
    compare_digest 54b1ff5b89f12548594f65f20b4bd615f6659cdf47188be720c05d3126b8efb13e86257e4f2a1728fca758613519805da66eea3dee01215d389d9d9af6944f4d launchers/ TFC-TxP.desktop

    compare_digest 2e9a7e53ed381f7c75499fa84c4e5c1d29d891fb5ebde5f404ded73689e8794327604876955b98c40c2e711fb4869edebf1f06d8b17ed92a02e28938091bd958 src/ __init__.py
    compare_digest 2e9a7e53ed381f7c75499fa84c4e5c1d29d891fb5ebde5f404ded73689e8794327604876955b98c40c2e711fb4869edebf1f06d8b17ed92a02e28938091bd958 src/common/ __init__.py
    compare_digest b6ed487f95631e2fb72f88e27cc612090f79a232e1984c3da0bb6a6cc0205b7843eec2525135503a1f363ebcd41acf46255103e0ba6a91cbb926a6525dd8f1c9 src/common/ crypto.py
    compare_digest 70e6a3638e3b5953153b4ab70aed16763bae68c0a5d9284057cdd8dcce2491a5caf2061e9d40083e7cfe4eec7c7625ff5127a532661bcc02c27026821397e49b src/common/ database.py
    compare_digest 1a4ca913dcd30418d0340f8c34e51fce4949e2d16149c7f7b41a02c536066cb24d4168de5ba64086c1299f5b6ad10b35fa1c16037fecd2e4576094c106294806 src/common/ db_contacts.py
    compare_digest 2478f5dfb1f0b0493a6692294aae064f2b26671d84006a926e0b7e71e1d70995f3406a22ab12e3fca909ae448218a9e5cd6b9802c2df310e32573efc767303b5 src/common/ db_groups.py
    compare_digest 0034b85241f50caf3998cee0a27ae555efb1b0b7fd15733319f1c717aea5d3a4f15f7bc2bef844232ec61c2e97f18b32c024a8c5b90b73b777299d1bc8ae4459 src/common/ db_keys.py
    compare_digest 2b2a766fbc461e633e31db71aca392d6220e28c6ce5108597a67bff4fe47b73f91c5a1f143e65ac80878d3944aca9c0bab7deb8bc5c885f8324c8aadb5b4cbca src/common/ db_logs.py
    compare_digest 228b9572a18eed02841ae4fb3b828ccae199392e220efc5da5aa87cdb0d8902182f2e9bdced70cca539f38fbc02431e777d08d6675e0465bf35977617fb469b8 src/common/ db_masterkey.py
    compare_digest b46670b84d392cb748e76554a4ed72dd8c020ee843d4d9b6d1f4d54ea2c77ca783b4ff9fd0dcca7100bfdb4661ca1248f786b50b5230dc76e8f200d352989758 src/common/ db_onion.py
    compare_digest d1f515510067eddd8056c643de90aca23016ebc7b22d4818faf0d2f7d495c3aed002c507e749e375f1381ca3c5a00819751d3912eb1cffc222ae476f7e5d7cf2 src/common/ db_settings.py
    compare_digest 5ba06fd066cbcb055a6c14683bd3b424b41a135213501d604929b2ddb667c34a9ab25fb74fb8cd5d3c8a709cf3747c0e7f06b3a8ef80f7e5ad02ed7e87dabff5 src/common/ encoding.py
    compare_digest c4211e1e167dab9f1738ff169006ba7943b3ab35988a13a2bae78ca31c510ebc2b631bba4a997d5037ff8ebcc9441f45e238e5844dea276df760076e4b194fb5 src/common/ exceptions.py
    compare_digest b61971d3fb94ddba38638c8e0d661f59b386b1548aa50eb8ead17deff2662c3130e872dbf30ede40c444af3209408dfbf1e321f63efb7d5f88561aa23668dc95 src/common/ gateway.py
    compare_digest 45471974fe553d516e81b1548d93e38f92caf2104963827a04988c1627afb08429ef3abc82e2400e8706a0071fa2b4d5255f8ebfca607ff25fffa6bc1c9658c5 src/common/ input.py
    compare_digest d53ec3852c32479b669f27ecddbfc570195f8f62fad7c93078cd80da3ad04b08bea73dd00c9943df693947af5fcb88208d5bfe48d3901535709645c8bc8a2286 src/common/ misc.py
    compare_digest c30a5df2a0eadfce97d2df1f142ce8ab0064a9de5231f855df0da95ef2e5378fbcb4373ca03efb6d43c598fe0d36bb3703124ce1ff77d035fc7a4cc54bb5b7e0 src/common/ output.py
    compare_digest 8ec304fa3bf13f42815747fdf956cb3203edae6a08d41ae77a6732688b9c08753961128708d1eb0a29faa6e9d649c120650153d7076e443d9c33f1c756998776 src/common/ path.py
    compare_digest 81f8eb2a6a399d38ba7dc4a85b5ab7a0c8292672eaa2008f160e2af85a8835581ac88874f552761eb93e127773cce5f8a638a7c706b56af4754b51a55d9abfff src/common/ reed_solomon.py
    compare_digest a412d6f1004f9515dc07519b27b6ed860380a7a328ada27eda99a282082e71c7ddf4a4e6ad8aabb9db3ec38dac2ab09ca56b2c69e2ee35e53867d9d4b5bb0b99 src/common/ statics.py
    compare_digest 0ca623e729844bb569eab70c12c6f31c74e342bb131faec37bbcb8db9c3b2eb806357937f6ae764604d8a4482ba95fe1cf61cd1e6ceea4882189f38f8a93db4d src/common/ word_list.py

    compare_digest 2e9a7e53ed381f7c75499fa84c4e5c1d29d891fb5ebde5f404ded73689e8794327604876955b98c40c2e711fb4869edebf1f06d8b17ed92a02e28938091bd958 src/receiver/ __init__.py
    compare_digest b0e1942f1c54ef704505ed0a2f33c9f645ea41546f6c5c48b82d78096da7fbac7fdba640f24cc763310996a17521d4c0d9c588643bd1e1e1d28005f61984a253 src/receiver/ commands.py
    compare_digest 7be8ac8ae366b772b4f0f3499062cff287613be05fbd702b900e2468d1b871be1e968024fe563446305bd199b3da8dae0159c0e7e8e8a0b8fbb049eee69732fc src/receiver/ commands_g.py
    compare_digest 8a7492989e501f8eff4bb9a5eeb5d25ed6a41070f45028fe9fbff197867070fe45070f8855cce0c507a6427aa77579d098ee12287a0929c12b84218cdd865d3c src/receiver/ files.py
    compare_digest df826c54579700b8b4c9ec060ce890e2fbd4bb03a79b0fc1e19eb04f7156b614a99f4c4e9687fe7c947b66c0606cb165a7d95379555a6b8771c99bd260c4bedd src/receiver/ key_exchanges.py
    compare_digest ead1a9e825305f79ac5661489d098cd22d371a28f5ea839a5c1549fb5dc5e8616d043687998d2ee0323df6f4781e02187a9ad46b9874c3ba55090cc9c0f4a596 src/receiver/ messages.py
    compare_digest 7fa407094b8f1c0240959030f206ab335b05df5bb8bd2c98537a5e8f6e8a883e99437ee6ee62e62f07e3620106ef327288b4eb1338c81a07a3ca5b39d900f71b src/receiver/ output_loop.py
    compare_digest 3456150d75db55c0f37b349af3f9f8bab47f5f149d29fa6a9dc99e4b939d9ee265fd6b384286f6452032fd92778f016c9c14e73de623d7d8ea242a669644223c src/receiver/ packet.py
    compare_digest e4ae6ed01255a6a1d849e738145093e667c4f2b76081401a78e0ae6199bc19132e8c23c2585352313b7fd23fc8ef57ac88bac7ae12195bc95ff9c7a14a81248e src/receiver/ receiver_loop.py
    compare_digest 56352964f279d7095f3cacab4b1d1851ad205d6a0acc3bb2f663ff0bed5a85ae2c3980e084cbd395393b796cfbc6c5d410beda1bf05ec30e5dcc748e83b0ed71 src/receiver/ windows.py

    compare_digest 2e9a7e53ed381f7c75499fa84c4e5c1d29d891fb5ebde5f404ded73689e8794327604876955b98c40c2e711fb4869edebf1f06d8b17ed92a02e28938091bd958 src/relay/ __init__.py
    compare_digest ff0fc39929b8c40341d2347779ad5151be8ef5e386a1d999521054a6515eb5d14209fc5b0bdde8ce49c903fe660ae516a05ef0b038f17b23d33337ad25270305 src/relay/ client.py
    compare_digest 38ff6d27c8bf3b45edeed372b5a1845f390cda8112da57b71720bec7ff2a5a64cdd290e41df31ee98bde9ab09d5e7f508adc0278d704078805bd12a89b2bf54c src/relay/ commands.py
    compare_digest 4734902bcfeaf6bb2adb69de6e2bf8f9cef187e5251993ec67e86e19c3d992c085347f0c7c3505a5fb557be1da8e9025d2a6f8bbf4e97efee8d0c3d112855ee6 src/relay/ onion.py
    compare_digest 1ceba51a5ca914976d6177074070979b7c3894d632a98afb63473eabf14bbaded7d70bf5a967c79eadeaba4e9bdcfdf5f31be49251edf2d1e0a519c05ab04267 src/relay/ server.py
    compare_digest db55be695feb19e576bd75bb027a982fd1f4925a22c58a56b8ebb3fe525b4231b542cfdd2548218cfda55c89e1d3e07a139221b53d2905e163a9980d9e0176be src/relay/ tcb.py

    compare_digest 2e9a7e53ed381f7c75499fa84c4e5c1d29d891fb5ebde5f404ded73689e8794327604876955b98c40c2e711fb4869edebf1f06d8b17ed92a02e28938091bd958 src/transmitter/ __init__.py
    compare_digest 17e49f6c29fb3c9b76a3aaed92d183d6f23115df900fc6c903e4a9b987d4470de695f9e02e69c5fb71911c988ab425268858a17829952e85935e5fe56ad56476 src/transmitter/ commands.py
    compare_digest 253e8a754263fdfcb57abf0217477eab00387f543e0ba9d502dc40e7c7606eda898b227060cdaf081dbd214c482160f9244873ca2a913f5f8b20f187894ae292 src/transmitter/ commands_g.py
    compare_digest 5efbb9bf14a75793b83908c96975d2b57a2e8bb9fc2ca7d64811dbbdf9cc9a8a99c1ea5f691f3d080aec688d7f348920746d4f1e6c19ce40cda963ea622fa232 src/transmitter/ contact.py
    compare_digest 8b22fcec147d8dfe8eb2308d4c2ed10b3ebabd8d588ec57276595b41ae2b605478f2a09404264b477541f4ac0415a9c123b59f52a1602b568f5c3db66342c956 src/transmitter/ files.py
    compare_digest 812525414f2df9efa219107eae4787f32b4b543614023e8eec0cef331008a4eecbfd3b449c81b842a98927c6da7ee7a60115eaca94f0ce8463cd46bc0890c2b5 src/transmitter/ input_loop.py
    compare_digest 0eb31260d015519962cdb0a25165638709d1cf44846e0886da1b079ad190e0672ec4f5fd5fe703576836bf27801a2090b2367234ab2c422882cdc8e0bbcafa0a src/transmitter/ key_exchanges.py
    compare_digest 9c4de27dede7292396cb29ca0ab811f0cf95e84096e2bd72a1d23a37a72a624f98258db4d6043eb8a9389f67234e72e24a0d64840854359dee1340b9fc8c1180 src/transmitter/ packet.py
    compare_digest 00748cb52be0cb77f098c44ceedcbf2c89bf1669d8b307bfd793c6c0b79f2132ff66623c0abe28a674ebda9bca943ca2e6a0430acf4025e8b5ed9b5efb0ae906 src/transmitter/ sender_loop.py
    compare_digest 9ea30785b8459e342ac71666012251c76a16a55f059cfdc7b8ad6c74fc7aae69965adf4382654bf686d9acb79b525a3513ddcf6a49bb6459caea124c5fb69eea src/transmitter/ traffic_masking.py
    compare_digest 1f082487590125de9ddeefe696be062ce5bc3fc1f82c3117dab3de2349dca5f859c7aaa3f626d8fe306d5b64c34bfdb1b0b50a0d7f4ed156f1043d35cdb2b618 src/transmitter/ user_input.py
    compare_digest 48903f96e2e45a6463893595aa3bd2335fcfa1561d461c51decc4cb9d700419c27b48d928e0f124336669628892c214609b2a929bc7dee2e40302735bc722418 src/transmitter/ windows.py
}


function process_tcb_dependencies {
    # Manage TCB dependencies in batch. The command that uses the files
    # is passed to the function as a parameter.
    sudo "${1} /opt/tfc/${SIX}"
    sudo "${1} /opt/tfc/${PYCPARSER}"
    sudo "${1} /opt/tfc/${CFFI}"
    sudo "${1} /opt/tfc/${ARGON2}"
    sudo "${1} /opt/tfc/${SETUPTOOLS}"
    sudo "${1} /opt/tfc/${PYNACL}"
    sudo "${1} /opt/tfc/${PYSERIAL}"
    sudo "${1} /opt/tfc/${CRYPTOGRAPHY}"
}


function process_tails_dependencies {
    # Manage Tails dependencies in batch. The command that uses the
    # files is passed to the function as a parameter.

    t_sudo -E "$1 /opt/tfc/${PYSERIAL}"
    # t_sudo -E "$1 /opt/tfc/${STEM}"
    t_sudo -E "$1 /opt/tfc/${PYSOCKS}"

    # Requests
    t_sudo -E "$1 /opt/tfc/${URLLIB3}"
    t_sudo -E "$1 /opt/tfc/${IDNA}"
    t_sudo -E "$1 /opt/tfc/${CHARDET}"
    t_sudo -E "$1 /opt/tfc/${CERTIFI}"
    t_sudo -E "$1 /opt/tfc/${REQUESTS}"

    # Flask
    t_sudo -E "$1 /opt/tfc/${WERKZEUG}"
    t_sudo -E "$1 /opt/tfc/${MARKUPSAFE}"
    t_sudo -E "$1 /opt/tfc/${JINJA2}"
    t_sudo -E "$1 /opt/tfc/${ITSDANGEROUS}"
    t_sudo -E "$1 /opt/tfc/${CLICK}"
    t_sudo -E "$1 /opt/tfc/${FLASK}"

    # Cryptography
    t_sudo -E "$1 /opt/tfc/${SIX}"
    t_sudo -E "$1 /opt/tfc/${PYCPARSER}"
    t_sudo -E "$1 /opt/tfc/${CFFI}"
    t_sudo -E "$1 /opt/tfc/${CRYPTOGRAPHY}"

    # PyNaCl
    t_sudo -E "$1 /opt/tfc/${PYNACL}"
}


function move_tails_dependencies {
    # Move Tails dependencies in batch.
    t_sudo mv "$HOME/${VIRTUALENV} /opt/tfc/"
    t_sudo mv "$HOME/${PYSERIAL}   /opt/tfc/"
    # t_sudo mv "$HOME/${STEM}       /opt/tfc/"
    t_sudo mv "$HOME/${PYSOCKS}    /opt/tfc/"

    # Requests
    t_sudo mv "$HOME/${URLLIB3}  /opt/tfc/"
    t_sudo mv "$HOME/${IDNA}     /opt/tfc/"
    t_sudo mv "$HOME/${CHARDET}  /opt/tfc/"
    t_sudo mv "$HOME/${CERTIFI}  /opt/tfc/"
    t_sudo mv "$HOME/${REQUESTS} /opt/tfc/"

    # Flask
    t_sudo mv "$HOME/${WERKZEUG}     /opt/tfc/"
    t_sudo mv "$HOME/${MARKUPSAFE}   /opt/tfc/"
    t_sudo mv "$HOME/${JINJA2}       /opt/tfc/"
    t_sudo mv "$HOME/${ITSDANGEROUS} /opt/tfc/"
    t_sudo mv "$HOME/${CLICK}        /opt/tfc/"
    t_sudo mv "$HOME/${FLASK}        /opt/tfc/"

    # Cryptography
    t_sudo mv "$HOME/${SIX}          /opt/tfc/"
    t_sudo mv "$HOME/${PYCPARSER}    /opt/tfc/"
    t_sudo mv "$HOME/${CFFI}         /opt/tfc/"
    t_sudo mv "$HOME/${CRYPTOGRAPHY} /opt/tfc/"

    # PyNaCl
    t_sudo mv "$HOME/${PYNACL} /opt/tfc/"
}


function verify_tails_dependencies {
    # Tails doesn't allow downloading over PIP to /opt/tfc, so we
    # first download to $HOME, move the files to /opt/tfc, and then
    # perform additional hash verification
    compare_digest 4483bdd81d63cc38e0003cd3cba995f3e21d506e2f6a64bc98a673f1ef5ccd56e8e1109ec049c9394a538b879ea47dbafa0c575cdc02eedb1b9172e8fc045ca6 '' ${VIRTUALENV}
    compare_digest 8333ac2843fd136d5d0d63b527b37866f7d18afc3bb33c4938b63af077492aeb118eb32a89ac78547f14d59a2adb1e5d00728728275de62317da48dadf6cdff9 '' ${PYSERIAL}
    # compare_digest a275f59bba650cb5bb151cf53fb1dd820334f9abbeae1a25e64502adc854c7f54c51bc3d6c1656b595d142fc0695ffad53aab3c57bc285421c1f4f10c9c3db4c '' ${STEM}
    compare_digest 313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12 '' ${PYSOCKS}

    # Requests
    compare_digest f6a78508cb87050e176005a088118f8ad87b17cf541457d949e5712c356f8c4de7e7516ba066e5c4bb9ced5c7e7590ba7e07d4ae7fc7190487bf27f1bb9d0668 '' ${URLLIB3}
    compare_digest fb07dbec1de86efbad82a4f73d98123c59b083c1f1277445204bef75de99ca200377ad2f1db8924ae79b31b3dd984891c87d0a6344ec4d07a0ddbbbc655821a3 '' ${IDNA}
    compare_digest bfae58c8ea19c87cc9c9bf3d0b6146bfdb3630346bd954fe8e9f7da1f09da1fc0d6943ff04802798a665ea3b610ee2d65658ce84fe5a89f9e93625ea396a17f4 '' ${CHARDET}
    compare_digest fe5b05c29c1e1d9079150aaea28b09d84f0dd15907e276ccabb314433cfaac948a9615e10d6d01cbd537f99eed8072fbda7cb901e932fbab4f1286ae8c50471b '' ${CERTIFI}
    compare_digest 9186ce4e39bb64f5931a205ffc9afac61657bc42078bc4754ed12a2b66a12b7a620583440849fc2e161d1061ac0750ddef4670f54916931ace1e9abd2a9fb09c '' ${REQUESTS}

    # Flask
    compare_digest 3905022d0c398856b30d2ed6bae046c1532e87f56a0a40060030c18124c6c9c98976d9429e2ab03676c4ce75be4ea915ffc2719e04e4b4912a96e498dcd9eb89 '' ${WERKZEUG}
    compare_digest 69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec '' ${MARKUPSAFE}
    compare_digest 658d069944c81f9d8b2e90577a9d2c844b4c6a26764efefd7a86f26c05276baf6c7255f381e20e5178782be1786b7400cab12dec15653e7262b36194228bf649 '' ${JINJA2}
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
    t_sudo mv "$HOME/${SETUPTOOLS} /opt/tfc/"
    compare_digest dd18da86ba566a7abde86890f6fa7c5a4dee34970927ef883a07a44ca8992713f9c2c4c87538d18d7bbf19073f1cc7887b150474375f24a0938cef5db097c841 '' ${SETUPTOOLS}
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

    torsocks python3.7 -m pip install -r "{$HOME}/tfc/requirements-venv.txt" --require-hashes --no-deps

    python3.7 -m virtualenv "${HOME}/tfc/venv_tfc" --system-site-packages

    . "${HOME}/tfc/venv_tfc/bin/activate"
    torsocks python3.7 -m pip install -r "${HOME}/tfc/requirements-dev.txt"
    deactivate

    sudo cp "${HOME}/tfc/tfc.png                   /usr/share/pixmaps/"
    sudo cp "${HOME}/tfc/launchers/TFC-Dev.desktop /usr/share/applications/"
    sudo sed -i "s|\$HOME|${HOME}|g"              "/usr/share/applications/TFC-Dev.desktop"
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

    t_sudo rm /opt/tfc/${VIRTUALENV}
    t_sudo rm -r /opt/tfc/src/receiver/
    t_sudo rm -r /opt/tfc/src/transmitter/
    t_sudo rm    /opt/tfc/dd.py
    t_sudo rm    /opt/tfc/tfc.py

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
        name=$("basename ${interface}")
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
