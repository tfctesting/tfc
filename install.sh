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


compare_digest () {
    # Compare the SHA512 digest of TFC file against the digest pinned in
    # this installer.
    if sha512sum /opt/tfc/$2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        echo OK - Pinned SHA512 hash matched file /opt/tfc/$2$3
    else
        echo Error: /opt/tfc/$2$3 had invalid SHA512 hash
        exit 1
    fi
}


verify_tcb_requirements_files () {
# To minimize the time TCB installer configuration stays online, only
# the requirements files are authenticated between downloads.
compare_digest a52d96aa42f4aa00958e3778d8048f31ae64d7b602a4998d88ff4649328df3c53b73e529a6e672058c609ff31009d71e98838a634c4b71550742c6cdc6c3cfbb '' requirements.txt
compare_digest 68939117a092fa4aff34e678d554bf9c86da84f9c757cc2db2932379bac0c10becbedd05a7ba8869672cd66c4160e55d843290063f550d634d4e8484b6d180b3 '' requirements-venv.txt
}


verify_files () {
# Verify the authenticity of the rest of the TFC files.
compare_digest 9d18d052fc7eb0837f00f618b391ec47951fe130c8a420db841499d335cbd83122df3138c69e2b0ebc1505d1834e670cac28ccfed0c3f3441e23824266991623 '' dd.py
compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
compare_digest 04bc1b0bf748da3f3a69fda001a36b7e8ed36901fa976d6b9a4da0847bb0dcaf20cdeb884065ecb45b80bd520df9a4ebda2c69154696c63d9260a249219ae68a '' LICENSE-3RD-PARTY
compare_digest a490b12ea5e3920b3091838be3956756dba9833b5b155d90a4daff4543fd1e783d08997707eda6542c631569a3adf3ba2038f382795e808ec3a7c12c8c80a6aa '' relay.py
compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
compare_digest 55d0bcd6ba90ba5a7e433366d1a2b688c4c93f9a4bb9a6859934c0375190d1540916cfcbfe7a6220c828e2fd26ae0bb21a3c15fff1a419eac8e23879b4078b20 '' requirements-relay.txt
compare_digest 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png
compare_digest d30e4ea7758a2fa3b704f61b0bec3c78af7830f5b1518473bf629660de4c5138df043a2542f174d790b4bda282edb1f8b536913bb9d9f62fb0c6faf87f255ee0 '' tfc.py
compare_digest 7a3d7b58081c0cd8981f9c7f058b7f35384e43b44879f242ebf43f94cec910bab0e40bd2f7fc1a2f7b87ebc8098357f43b5cede8948bd684be4c6d2deaf1a409 '' uninstall.sh

compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
compare_digest 310c55b863114e33ca61765aea87fb32bafa177bc68bde8538a0b13edcabb5282ee53e6feb9fa753431ae3271d9803f5e5f50a1708c8fa69b09f60e09501de53 launchers/ TFC-Local-test.desktop
compare_digest de490c82aa3ee6349c04bdbb1a088bfd3a2b13b9dac031ebbd40b684db3312d6ecb2b129caa3a84b497f349962f730b9234ccd0664a28f61adeaf949e68c1b29 launchers/ TFC-RP.desktop
compare_digest 2631d34e2a59771ffad95a6283ee2dbb32a426c5eabf62f783e2f2ab46381332c547298c297263596ec7c244301e792bef5c32e621b90fe68badb47a2d42f08c launchers/ TFC-RP-Tails.desktop
compare_digest a9c566090dae46fd28d695e4329b6277646767a438735f5f33f073ca6a781052a9a5e0c0d25361e838d1bbf0ad11a1683e64ab1646c7231db4c4bed8005a288e launchers/ TFC-RxP.desktop
compare_digest d8ecc62e8ed2c495325910c490d18542218e59343765f72d77f56742e4f8af3d7b00b23ef5818b1db6373e1bf408f66ca77ac6e33a7c887abbef0094d3c41ddb launchers/ TFC-TxP.desktop

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
compare_digest c79ac27cebf910353789beb802d32d98608552afcb7ca8004bf5c87e04e7f9749a340f6d1889b65a7785453d9395de3fa5ad74aaa24c142828a62ea1289725a9 src/common/ crypto.py
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
compare_digest 73e17831c1bd7a5ce749f6270f01db67c1756b43589b1ba885bf63f79ab10d2d4868ee09790d932cacfa857a6d3493e3a3f02f0bac488658368750b9c6515091 src/common/ statics.py

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
compare_digest a62c0bbc655d58d16a4dbc4bb0526a773ad0532d345c9abcecd65e710abd0f0f6037d75fc6e5388697bfa0f70038aaa5f4c3a8ca34d35eaa201f4196a0c0c5f8 src/relay/ client.py
compare_digest 0f36460f2db74f4f8872c213f30e9611c8d94d0d7280e03bd5a26899bb9ec3adbe28b34c6af63e29465fde5dbc6235cdbb9460991d7c23c5a28e51313ba82423 src/relay/ commands.py
compare_digest 9e1364e05c7ba9acc65cf7926c94ece8e440e65f21f40affeeade9541c82a15cee47c962bc5478babcc9147dfbaf89276cfeb53547512883cb7fcb14d0f5e496 src/relay/ onion.py
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
compare_digest a22b4eb71fa2b56d61a27193987b5755bc5eeec8011d99ea7813c830a4cb38f8934fb70acf4b1dd0980dbb4a30e0ec5945cfb869fb40e74c4f0ecd12f129b040 src/transmitter/ windows.py
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


process_tcb_dependencies () {
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


steps_before_network_kill () {
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


install_tcb () {
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
    sudo rm -r /opt/tfc/.git/
    sudo rm -r /opt/tfc/launchers/
    sudo rm -r /opt/tfc/src/relay/
    sudo rm -r /opt/tfc/tests/
    sudo rm    /opt/tfc/install.sh
    sudo rm    /opt/tfc/install.sh.asc
    sudo rm    /opt/tfc/pubkey.asc
    sudo rm    /opt/tfc/README.md
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/relay.py
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-dev.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/${VIRTUALENV}
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc
    process_tcb_dependencies "rm"

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


install_local_test () {
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
    sudo rm -r /opt/tfc/.git/
    sudo rm -r /opt/tfc/launchers/
    sudo rm -r /opt/tfc/tests/
    sudo rm    /opt/tfc/install.sh
    sudo rm    /opt/tfc/install.sh.asc
    sudo rm    /opt/tfc/pubkey.asc
    sudo rm    /opt/tfc/README.md
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-dev.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/${VIRTUALENV}
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc
    process_tcb_dependencies "rm"

    install_complete "Installation of TFC for local testing is now complete."
}


install_developer () {
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

    cd $HOME
    torsocks git clone https://github.com/tfctesting/tfc.git
    cd $HOME/tfc/

    torsocks python3.7 -m pip install -r requirements-venv.txt --require-hashes
    python3.7 -m virtualenv venv_tfc --system-site-packages

    . $HOME/tfc/venv_tfc/bin/activate
    torsocks python3.7 -m pip install -r requirements.txt       --require-hashes
    torsocks python3.7 -m pip install -r requirements-relay.txt --require-hashes
    torsocks python3.7 -m pip install -r requirements-dev.txt
    deactivate

    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"

    sudo cp $HOME/tfc/tfc.png                   /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-Dev.desktop /usr/share/applications/
    sudo sed -i "s|\$HOME|${HOME}|g"            /usr/share/applications/TFC-Dev.desktop

    chmod a+rwx -R $HOME/tfc/

    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


install_relay_ubuntu () {
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

    sudo rm -r /opt/tfc/.git/
    sudo rm -r /opt/tfc/launchers/
    sudo rm -r /opt/tfc/src/receiver/
    sudo rm -r /opt/tfc/src/transmitter/
    sudo rm -r /opt/tfc/tests/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/install.sh
    sudo rm    /opt/tfc/install.sh.asc
    sudo rm    /opt/tfc/pubkey.asc
    sudo rm    /opt/tfc/README.md
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-dev.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/tfc.py
    sudo rm    /opt/tfc/${VIRTUALENV}
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc
    process_tcb_dependencies "rm"

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


install_relay_tails () {
    # Install TFC Relay configuration on Networked Computer running
    # Tails live distro (https://tails.boum.org/).
    check_tails_tor_version

    read_sudo_pwd

    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip python3-setuptools -y || true  # Ignore error in case packets can not be persistently installed

    cd $HOME/
    git clone https://github.com/tfctesting/tfc.git
    t_sudo mv $HOME/tfc/ /opt/tfc/
    cd /opt/tfc

    verify_tcb_requirements_files
    verify_files

    create_user_data_dir

    t_sudo python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay.txt --require-hashes -d /opt/tfc/

    # Pyserial
    t_sudo python3.7 -m pip install /opt/tfc/${PYSERIAL}

    # Stem
    t_sudo python3.7 -m pip install /opt/tfc/${STEM}

    # PySocks
    t_sudo python3.7 -m pip install /opt/tfc/${PYSOCKS}

    # Requests
    t_sudo python3.7 -m pip install /opt/tfc/${URLLIB3}
    t_sudo python3.7 -m pip install /opt/tfc/${IDNA}
    t_sudo python3.7 -m pip install /opt/tfc/${CHARDET}
    t_sudo python3.7 -m pip install /opt/tfc/${CERTIFI}
    t_sudo python3.7 -m pip install /opt/tfc/${REQUESTS}

    # Flask
    t_sudo python3.7 -m pip install /opt/tfc/${WERKZEUG}
    t_sudo python3.7 -m pip install /opt/tfc/${MARKUPSAFE}
    t_sudo python3.7 -m pip install /opt/tfc/${JINJA2}
    t_sudo python3.7 -m pip install /opt/tfc/${ITSDANGEROUS}
    t_sudo python3.7 -m pip install /opt/tfc/${CLICK}
    t_sudo python3.7 -m pip install /opt/tfc/${FLASK}

    # Cryptography
    t_sudo python3.7 -m pip install /opt/tfc/${SIX}
    t_sudo python3.7 -m pip install /opt/tfc/${ASN1CRYPTO}
    t_sudo python3.7 -m pip install /opt/tfc/${PYCPARSER}
    t_sudo python3.7 -m pip install /opt/tfc/${CFFI}
    t_sudo python3.7 -m pip install /opt/tfc/${CRYPTOGRAPHY}

    cd $HOME
    rm -r $HOME/tfc

    t_sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    t_sudo mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/

    t_sudo rm -r /opt/tfc/.git/
    t_sudo rm -r /opt/tfc/launchers/
    t_sudo rm -r /opt/tfc/src/receiver/
    t_sudo rm -r /opt/tfc/src/transmitter/
    t_sudo rm -r /opt/tfc/tests/
    t_sudo rm    /opt/tfc/dd.py
    t_sudo rm    /opt/tfc/install.sh
    t_sudo rm    /opt/tfc/install.sh.asc
    t_sudo rm    /opt/tfc/pubkey.asc
    t_sudo rm    /opt/tfc/README.md
    t_sudo rm    /opt/tfc/requirements.txt
    t_sudo rm    /opt/tfc/requirements-dev.txt
    t_sudo rm    /opt/tfc/requirements-relay.txt
    t_sudo rm    /opt/tfc/requirements-venv.txt
    t_sudo rm    /opt/tfc/tfc.py
    t_sudo rm    /opt/tfc/${PYSERIAL}
    t_sudo rm    /opt/tfc/${STEM}
    t_sudo rm    /opt/tfc/${PYSOCKS}
    t_sudo rm    /opt/tfc/${URLLIB3}
    t_sudo rm    /opt/tfc/${IDNA}
    t_sudo rm    /opt/tfc/${CHARDET}
    t_sudo rm    /opt/tfc/${CERTIFI}
    t_sudo rm    /opt/tfc/${REQUESTS}
    t_sudo rm    /opt/tfc/${WERKZEUG}
    t_sudo rm    /opt/tfc/${MARKUPSAFE}
    t_sudo rm    /opt/tfc/${JINJA2}
    t_sudo rm    /opt/tfc/${ITSDANGEROUS}
    t_sudo rm    /opt/tfc/${CLICK}
    t_sudo rm    /opt/tfc/${FLASK}
    t_sudo rm    /opt/tfc/${SIX}
    t_sudo rm    /opt/tfc/${ASN1CRYPTO}
    t_sudo rm    /opt/tfc/${PYCPARSER}
    t_sudo rm    /opt/tfc/${CFFI}
    t_sudo rm    /opt/tfc/${CRYPTOGRAPHY}
    t_sudo rm -f /opt/install.sh
    t_sudo rm -f /opt/install.sh.asc
    t_sudo rm -f /opt/pubkey.asc

    install_complete "Installation of the TFC Relay configuration is now complete."
}


t_sudo () {
    # Execute command as root on Tails.
    echo ${sudo_pwd} | sudo -S $@
}


install_relay () {
    # Determine the Networked Computer OS for Relay Program installation.
    if [[ "$(lsb_release -a 2>/dev/null | grep Tails)" ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


read_sudo_pwd () {
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


check_tails_tor_version () {
    # Check that the Tails distro is running Tor 0.3.5 or newer.
    included=($(tor --version |awk '{print $3}' |head -c 5))
    required="0.3.5"

    if ! [[ "$(printf '%s\n' "$required" "$included" | sort -V | head -n1)" = "$required" ]]; then
        clear
        echo -e "\nError: This Tails includes Tor $included but Tor $required is required. Exiting.\n" 1>&2
        exit 1
    fi
}


kill_network () {
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


add_serial_permissions () {
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


c_echo () {
    # Justify printed text to the center of the terminal
    printf "%*s\n" $(( ( $(echo $1 | wc -c ) + 80 ) / 2 )) "$1"
}


check_rm_existing_installation () {
    # Remove TFC installation directory if TFC is already installed.
    if [[ -d "/opt/tfc" ]]; then
        if [[ ${sudo_pwd} ]]; then
            t_sudo rm -r /opt/tfc  # Tails
        else
            sudo rm -r /opt/tfc    # *buntu
        fi
    fi
}


create_user_data_dir () {
    # Backup TFC user data directory if it exists and has files in it.
    if [[ -d "$HOME/tfc" ]]; then
        if ! [[ -z "$(ls -A $HOME/tfc/)" ]]; then
            mv $HOME/tfc $HOME/tfc_userdata_backup_at_$(date +%Y-%m-%d_%H-%M-%S)
        fi
    fi
    mkdir -p $HOME/tfc 2>/dev/null
}


modify_terminator_font_size () {
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


get_screen_width () {
    # Output the width of the screen resolution.
    xdpyinfo | grep dimensions | sed -r 's/^[^0-9]*([0-9]+).*$/\1/'
}


install_complete () {
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


dpkg_check () {
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


arg_error () {
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


root_check () {
    # Check that the installer was not launched as root.
    if [[ !$EUID -ne 0 ]]; then
        clear
        echo -e "\nError: This installer must not be run as root. Exiting.\n" 1>&2
        exit 1
    fi
}


architecture_check () {
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
