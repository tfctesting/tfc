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


dl_verify () {
    # Download a TFC file from the GitHub repository and authenticate it
    # by comparing its SHA512 hash against the hash pinned in this
    # installer file.

    torsocks wget https://raw.githubusercontent.com/tfctesting/tfc/master/$2$3 -q

    # Check the SHA512 hash of the downloaded file
    if sha512sum $3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        if [[ ${sudo_pwd} ]]; then
            echo ${sudo_pwd} | sudo -S mkdir --parents /opt/tfc/$2
            echo ${sudo_pwd} | sudo -S mv $3           /opt/tfc/$2
            echo ${sudo_pwd} | sudo -S chown root      /opt/tfc/$2$3
            echo ${sudo_pwd} | sudo -S chmod 644       /opt/tfc/$2$3
        else
            sudo mkdir --parents /opt/tfc/$2
            sudo mv $3           /opt/tfc/$2
            sudo chown root      /opt/tfc/$2$3
            sudo chmod 644       /opt/tfc/$2$3
        fi

        # Check the SHA512 hash of the moved file
        if sha512sum /opt/tfc/$2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
            echo OK - Pinned SHA512 hash matched file /opt/tfc/$2$3
        else
            echo Error: /opt/tfc/$2$3 had invalid SHA512 hash
            exit 1
        fi

    else
        echo Error: $3 had invalid SHA512 hash
        exit 1
    fi
}


download_common () {
dl_verify d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
dl_verify 04bc1b0bf748da3f3a69fda001a36b7e8ed36901fa976d6b9a4da0847bb0dcaf20cdeb884065ecb45b80bd520df9a4ebda2c69154696c63d9260a249219ae68a '' LICENSE-3RD-PARTY
dl_verify 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
dl_verify 6a6434cdbb35c5dc0ebce6ee961da0d3afffe09b9cf0988cf08cc55d9cd9195462c1b986ec96e3521f88dea7c390daa7419446efd4bf3ed7383991e7f7347828 src/common/ crypto.py
dl_verify ce3a2b1890393801cad88162772a4d90799f95dc7d438c64856db92fa0a9b02431077e4c856a18c0953b242efc37e035fce96740b9379c966bd9fd76338889ef src/common/ db_contacts.py
dl_verify a071463fbc0e83237cc482ef709c0957f8774c325730c89a3deb7839d0997e47a3163c896df70e96e1c150f2f7dda7b096c808bba3dededddcb0036bfcc0f63c src/common/ db_groups.py
dl_verify 4855baf9d9bd48d210981e380ebc2d7ff65b7e13392606f386769e10ba918843e50ba6174e51a74f2d6841aa8b1f466e7f65a901143f484bdbe312ccbf9eb11e src/common/ db_keys.py
dl_verify 13138abd171b7b8db7b7443aa2cef5a5b000aa96a23a9169089c12b8ae6c4f23b5519b248a54be8767862adce03e98def314e471ffd74fdfc9bf1fa8f31c8e90 src/common/ db_logs.py
dl_verify 8d53e7348abf71aa1e054e5e852e171e58ed409c394213d97edc392f016c38ce43ed67090d3623aaa5a3f335992fd5b0681cfb6b3170b639c2fa0e80a62af3a4 src/common/ db_masterkey.py
dl_verify 516577100e4e03068cfcb0169975b86a258b8aafddddf995f434c98d0b2d81a2d96a45bca473ddeb6980dfd71420f489eee2d82a9053bf02c87d1acddf9b7ecf src/common/ db_onion.py
dl_verify 83b2a6d36de528106202eebccc50ca412fc4f0b6d0e5566c8f5e42e25dd18c67ae1b65cf4c19d3824123c59a23d6258e8af739c3d9147f2be04813c7ede3761d src/common/ db_settings.py
dl_verify 804e8124688e808440db585f6b1a05667666353684a4b31535100df7e54f0c5b91f5d61998a64717e710a62c7d8185b99b6012f713f3becaa7d73a39dcb5e774 src/common/ encoding.py
dl_verify 0e3e6a40928ab781dbbca03f2378a14d6390444b13e85392ea4bdfb8e58ae63f25d6f55b2637f6749e463844784ea9242db5d18291e891ee88776d4c14498060 src/common/ exceptions.py
dl_verify 77b810f709739543dc40b1d1fbafb2a95d1c1772b929d3a4247c32e20b9bb40039c900ff4967c4b41118567463e59b7523fbbbf993b34251e46c60b8588f34ab src/common/ gateway.py
dl_verify e27f950719760cc2f72db8e4a3c17389b2a52f34476c0ac4aeb17b050d27cb86209d49b83b049943c2bd97228de433834061dc0abffd61459502cd1303aca9c1 src/common/ input.py
dl_verify 18efc508382167d3259c2eb2b8adcddda280c7dbc73e3b958a10cf4895c6eb8e7d4407bc4dc0ee1d0ab7cc974a609786649491874e72b4c31ad45b34d6e91be3 src/common/ misc.py
dl_verify f47308851d7f239237ed2ae82dd1e7cf92921c83bfb89ad44d976ebc0c78db722203c92a93b8b668c6fab6baeca8db207016ca401d4c548f505972d9aaa76b83 src/common/ output.py
dl_verify dc5fdd0f8262815386896e91e08324cda4aa27b5829d8f114e00128eb8e341c3d648ef2522f8eb5b413907975b1270771f60f9f6cdf0ddfaf01f288ba2768e14 src/common/ path.py
dl_verify f80a9906b7de273cec5ca32df80048a70ea95e7877cd093e50f9a8357c2459e5cffb9257c15bf0b44b5475cdd5aaf94eeec903cc72114210e19ac12f139e87f3 src/common/ reed_solomon.py
dl_verify 644bde78f17ad02c6c776767e21adc35a7c3c4daca36ca28b1558c2c55b57c21559551ac3868ccef025731138cfada1e71568e77988535a349f3eb094a7de7eb src/common/ statics.py
}


download_relay () {
dl_verify 1dd17740ffb6bd4da5de8b00da8e0e1e79d9c81771bf62dee9d3e85e3fd6b1254ec1d011c217b0102f08384c03b63a002b6cddc691a2d03eaa3faddd8cef5a15 '' relay.py
dl_verify ddcefcf52d992f9027b530471a213e224382db5fbb516cc8dee73d519e40110f9fcca1de834a34e226c8621a96870f546b9a6b2f0e937b11fd8cd35198589e8b '' requirements-relay.txt

dl_verify 51639b1c45250388ffde2b016f7a61c73a69d0ffc9fe0bdf401092fc768caaca4684731be90d8deb54115acf69abbcbd6355e958cbe2278d777477f62c202aad launchers/ TFC-RP.desktop
dl_verify ab31bea212c71fd9879c535e4dde0cd1b188652b9825a00eb33b3e0addcabddfcdaf421ada2739a7281133071c365a4da7b1a2bb495fad1b8a6212355ad010b1 launchers/ TFC-RP-Tails.desktop

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
dl_verify 62ac101830793c4bbf9b85f714b6d3609ae8f05aa7be36d32c54df1b27ec8c0b17e71de8ad3db4af9ebba6886d0ec4cf7990c36a13469fa316b4bc19b2fe7086 src/relay/ client.py
dl_verify 02c764d58ef8d02f95050cec41aa41fa90938ea08e0107ed49d3ae73357115b48f23f291dfc238ec3e45b12a705089b5c2ad3a1b30f27abb0a4c7498271161a3 src/relay/ commands.py
dl_verify 1df9b4352c0bf69086ba0badc46e74fa4eb6e5ff4ca326f5faad8e86d103b3837b5028c58f3274ab8ed87fa1aa7ef4e764f058b32615cced4acf0fe7d81650ac src/relay/ onion.py
dl_verify bc6d33d5e9439c1e7baf82c1eb43fbb21af6109db366082d124be2b3c70f90e6dda7f38f0e5cd55e3de0019ced0e0548f10fbe3792f0f621a4f2e31a0ef8496d src/relay/ server.py
dl_verify 380a78c8c0918e33fb6be39a4c51f51a93aa35b0cf320370d6fb892b5dade920e8ca4e4fe9d319c0a0cdc5b3a97f609fdee392b2b41175379200b1d793b75593 src/relay/ tcb.py
}


download_tcb () {
dl_verify cec2bc228cd3ef6190ea5637e95b0d65ea821fc159ebb2441f8420af0cdf440b964bdffd8e0791a77ab48081f5b6345a59134db4b8e2752062d7c7f4348a4f0f '' tfc.py
dl_verify 0711aabf9c0a60f6bd4afec9f272ab1dd7e85f1a92ee03b02395f65ed51f130d594d82565df98888dbf3e0bd6dfa30159f8bd1afed9b5ed3b9c6df2766b99793 '' requirements.txt

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
dl_verify f91c0f616555725e0d2a4d8e2ee2bf39e1ebc4cbdf0a2547f4e4b5e4f1ee88743273cffb422a43dff98ba42772b18ceb4c270628f933392e27fa5cd6cae991ce src/transmitter/ commands.py
dl_verify f7cf493506a19b9732ae9f780aeb131342a47644632fcf88f0df01f0bda88252fdbad37a4b80e87f97e57feb50079ac2e5194598d745163846e30fdd6d32fe60 src/transmitter/ commands_g.py
dl_verify a1b6af28645df531be3a670375ce3a3da1a48b279d646f04b3c14cfbdf7006060955f33595a2963f98a495ec16dfe969325842495d8fbfae5f93e1459ed047c4 src/transmitter/ contact.py
dl_verify 184c35a32a3858893c67622a21fc7fdbd88bc61f82d4b655ad26ef008563cdb31430a3b713b92c98ea8d983ebadd0db6f9de3f9b1c07ac3dce4cf405aedf21ae src/transmitter/ files.py
dl_verify 019c178982f89b93ba69d26e60625a868380ac102b10351ac42c4d1321a45dd7186694d86028371185a096cce2e2bbe2d68210552439e34c3d5166f67b3578ee src/transmitter/ input_loop.py
dl_verify 742fba91ebd67dca247d03df4cf1820fc6b07e6966449282d7c4019f48cc902dc8dfc4120be9fdd6e61a4f00dd7753a08565a1b04395bc347064631d957c9d82 src/transmitter/ key_exchanges.py
dl_verify a59619b239b747298cc676a53aa6f87a9ef6511f5e84ec9e8a8e323c65ab5e9234cb7878bd25d2e763d5f74b8ff9fe395035637b8340a5fd525c3dc5ccbf7223 src/transmitter/ packet.py
dl_verify c2f77f8d3ebf12c3816c5876cd748dc4d7e9cd11fe8305d247783df510685a9f7a6157762d8c80afda55572dcae5fe60c9f39d5ec599a64d40928a09dd789c35 src/transmitter/ sender_loop.py
dl_verify 5d42f94bf6a6a4b70c3059fd827449af5b0e169095d8c50b37a922d70955bf79058adc10da77ebb79fb565830168dccb774547b6af513b7c866faf786da7c324 src/transmitter/ traffic_masking.py
dl_verify 22e8ba63c1391233612155099f5f9017d33918180f35c2552e31213862c76e3048d552f193f9cd3e4e9a240c0ef9bef4eabefe70b37e911553afeceede1133ca src/transmitter/ user_input.py
dl_verify 39a7b3e4457d9aa6d53cb53d38c3ed9adbd9e3250008b4e79b5a174b9227fd0fac6dad30e6e9b8fe3d635b25b2d4dfc049804df48d04f5dfcc1016b2e0a42577 src/transmitter/ windows.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
dl_verify 35b035f2794b5d7618eeafd91781246a0100bac9ff6a1f643b16068d5b2dc2946c799e91beba77d94e4118f99d6d6653974ebd5d4008133131f3bf44a7a190fb src/receiver/ commands.py
dl_verify 09f921aaaeae96ee6e9ff787990864ba491d4f8b10c613ab2a01f74c00b62d570270323ea2f5dc08befd8aa7bf4be0c609f8dca1862e4465e521b8016dff14da src/receiver/ commands_g.py
dl_verify 7b1d45caf3faf28c484d7d8d0c96ff9ba6e840682b002e438eac620904d3ca39483009a079d300489d80e22025ba301fa483f235193de5b55a62e9dedb25967f src/receiver/ files.py
dl_verify 5dee12fdbb8bade16e2d7f97c8791a39f408ec7eaeee89c75beac799584f9ae4d6d3e9495693630d7cb2c8a167c3e542f0d28b78725821ff14f04eb706afbe71 src/receiver/ key_exchanges.py
dl_verify 2894c847fe3f69a829ed7d8e7933b4c5f97355a0d99df7125cee17fffdca9c8740b17aa512513ae02f8f70443d3143f26baea268ace7a197609f6b47b17360b7 src/receiver/ messages.py
dl_verify 57ebdf412723b5ab4f683afeda55f771ef6ef81fde5a18f05c470bca5262f9ff5eefd04a3648f12f749cec58a25fa62e6dfb1c35e3d03082c3ea464ef98168b1 src/receiver/ output_loop.py
dl_verify 3b84dbe9faffeab8b1d5953619e38aefc278ce4e603fd63beaee878af7b5daff46b8ed053ad56f11db164b1a3f5b694c6704c66588386b06db697281c9f81bbf src/receiver/ packet.py
dl_verify 1e5240d346a016b154faf877199227edf76e027d75e1e921f2024c5dd1d0a40c1de7e9197077786a21474a4bbf2c305d290214aacdea50f5abaeb39963ca08a6 src/receiver/ receiver_loop.py
dl_verify e84a92fa500492af0cc16038fd388c74c387334898b870e57bc599d1b95da85b579d50ba403cdfc82ce8d4d5765fc59e772796d54faa914d0b5874150428d762 src/receiver/ windows.py
}


download_common_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/ __init__.py
dl_verify c20421e2293f058df4e03dee49e609b51fc1d39e69b4c44dd7580f88a5b2bf0729261167cb69fb0ff81b3838e3edca0e408c5c6410e4d43d06d6c0aa1ef6f805 tests/ mock_classes.py
dl_verify 2acdcd76d44caa417e9d1b3439816c4f07f763258b8240aa165a1dc0c948d68c4d4d5ac5e0ff7c02a0abc594e3d23883463a9578455749c92769fea8ee81490d tests/ utils.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/common/ __init__.py
dl_verify 56c5906ae9d9f8aa6906cf89bde9f9fbe54f787828a55dbcaafffc748e5de48ba9ca96da4c897319b3c8f893d42333e1c6d59571c9a4c24c3d05e1aca4e855fe tests/common/ test_crypto.py
dl_verify 65c2c0c8f187968bb9174678c0beaf52fea3a1fa328c13529bec3eeae1c15e2541a88c607955cf39409d0ea9f330b3ef6d6abacd51d436ab51502266034043fc tests/common/ test_db_contacts.py
dl_verify acb42f11a07872f0f967f0b6fb213c2688883eeb361f1cd4003edccf193f905ee7e1d8750cf9d72e12fdc4b1afa9b9295c2dd2c1c8ed58f8760fe84b7800509b tests/common/ test_db_groups.py
dl_verify f885b3e54eee8fbe593416eb93f9e2a287ae33c7ed21556cc1a3b72c46d313fca03d8c4af385eba230e93a0fb04f5c3b8a2dedf46b2443f3a6a63fc9eeb443e2 tests/common/ test_db_keys.py
dl_verify af1c212e0f4afe281475f6d14681445450b6e4bdd416ef2f8f7e1bc8afc0dca19430349f8bb086301a280858423d37b774077108fac721df047faa9c9c3498ee tests/common/ test_db_logs.py
dl_verify 4e7436d7316d56f50f604a900eddc6427bb2fe348073848b1d7845484f51739686c781935118a18bdc52d7848a46f24909ea630306c46f518ec9b72768c3f648 tests/common/ test_db_masterkey.py
dl_verify 81f53a6a5f072f9861d4f1d6af590c55ff82803a1a783ae7a485ebf5ba730840cf2aed132a5d8629cc8c63307fbfad9070e88b72f913655ce36aa9e48cf98b85 tests/common/ test_db_onion.py
dl_verify 58ed5e733ac373a6c3d69ff7218207a60b9e4138a549da1a9de158d770f5b2514d7042e4ec7feed86966388523ace278797535a77be926f34c406ac3bc4e96ce tests/common/ test_db_settings.py
dl_verify 9f22ef4ef64f8113ce11d69a5cc13ee032a056068c7bb3efd2ff2dc4fa7d48bc758e47e4a826f7b7607223d9ce14b114e361bf2065704f75d9bd1a8ac9d86653 tests/common/ test_encoding.py
dl_verify 3dea267fa9b4361890f374157b137c9f76946f3289f4faf4b293814f26f9769fb202ec98c6fd044891b2a51a3bb69f67fec46022210ebaf27f7270e9dfc779eb tests/common/ test_exceptions.py
dl_verify 3d2d5077bc946a1327c64598a3d7bb30786a6ccb089f5fc67330b05a3d867c46deb0d5cec593927782e1bfbf7efe74678f6aa4b62a3306ba33fa406537ee6499 tests/common/ test_gateway.py
dl_verify dad966ace979c486134dd3146a50eb2d26054984ca8fcad203d61bf9ae804db04664df21e8293e307fbfe9c331cb59a06a46626fb36f445f50ef0fba63b5d93d tests/common/ test_input.py
dl_verify 23d4ddd293defa5ac3dd4eada0e8e9263203c51d9d0260d370a362557f93bb74dbfff75620463e4c046db3350b54ee75889398c58be16df8dcffb928220815a9 tests/common/ test_misc.py
dl_verify d595d7b6c0e05f1c99a89f8dc2e662eff4127f0ad0b807156a4e6f42c9113e33302c00b311e9fdfcfce20e1fea331da02bbeb41a7c44d8e05795317711da8225 tests/common/ test_output.py
dl_verify 32da13fe8c0377257a5dd94d54c9a439b20308dbba7cbbd42798119f759c46d5948901eac78be9c2db984a3fc9791213c4913c49997a951b7458124d350c4ee4 tests/common/ test_path.py
dl_verify 1e320f69f236daed5f0fb2e6fda4b5b533dd628fff7db0ee8a6b405efe3c24138a43f24b45693017219cd885779f5ae57d3523d264e077ba9d3b9d2027b95d9c tests/common/ test_reed_solomon.py
dl_verify 223f66cbb3ff0567eba27b66c3be30bd292b6ab1405ea52af79e4adafc87901212998576665bfee5e40e9ece7cc0d369179945be903ae36e5016942cf8c7fd2b tests/common/ test_statics.py
}


download_relay_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/relay/ __init__.py
dl_verify 067ecc7824df51e4f663992730422153fb86b679df013d4a65de4e2a996ce43c9dd1bcb2ffb43b1ddf3831c63998ec1b8ecf27407865836a92e93fb9ab798953 tests/relay/ test_client.py
dl_verify 2431fd853a9a0089a3837f1e20455c2d58d96722d5b803fe9e3dc9aa09a3e5fbffa3b0fa9e3e723d81a2aa2abd6b19275777ba6eb541ec1b403854260dd14591 tests/relay/ test_commands.py
dl_verify a310932a2ccbd2dff1ff95a811d90afc87d735583fb25fca7ec531f912358cb72ef4151ad271626ce6fab047738bad513b906d7a01640dd245c7787a6114b62e tests/relay/ test_onion.py
dl_verify 42e494245869a5e652fe6bdcf5e21d1a0299c9ad7485d075fe7cf1d2d53118b444d8563bbea837316f00cbfea31117d569cf4e8694443ab5b50f606369aec987 tests/relay/ test_server.py
dl_verify 54c3026e797e75c46ca1d1493f6a396643948f707f1bc8ad377b7c625fda39d4e0fa6b0ec0fe39149ef0250568caf954e22ae8ebe7e7ac00ca8802ffbc6ae324 tests/relay/ test_tcb.py
}


download_tcb_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/transmitter/ __init__.py
dl_verify 3bdb8fd64bb2b4070da025e0187e434b5178b645fb08ec822bdd732bac3824316a8d13ded95e5e7bf754dddda5ea1f5805b6c2a3b46e8100509d3f5b32d18278 tests/transmitter/ test_commands.py
dl_verify c2429b5ffc32aa4a6377fef726553d7c731672367cb4eaa338c0a2099b3fe0455fa8a79c4b86afd9077a53422403649bc1fcf7540e4f996dc0890819c34d9135 tests/transmitter/ test_commands_g.py
dl_verify 3baaa1dc6dff7771f6167d699a81c6cb14f7b0ea307b83797d342a95b21f89d9f2c21e54feac0474f61174a1c708b3f02bc0e3a6b0b504bda8c03cdd16e5fefe tests/transmitter/ test_contact.py
dl_verify 3d86131dfd775aea2ea7c0500759befac8a5d7fe35f590974b2af56da42929db927c0bd86a352a38412fbb79c2bff09d33271b26ebd9aead1bf2b702918cc02a tests/transmitter/ test_files.py
dl_verify 3bc9c3275353f49516fdb2bc9d9a86286c121f085d5382980e118b0ea123da9b9829edeb172448416f30955c9a1c1c3704f36cfa4700ced86c33009e362d0b69 tests/transmitter/ test_input_loop.py
dl_verify 284fefc2a4986948a5ee4de1f935482b43011347b5454ab685f4a79a1036d1bf0518db536381dfddf706318bb44b584db37cfbf8fa07aac1b631a278dfe298d7 tests/transmitter/ test_key_exchanges.py
dl_verify 0c16f45ad9fda006b58a45a7c9a4b9777cf05d08f59c9207addbc27936c29a6aa2aa59146f0ef32fb883a5e24211c5dbdfbf5ad9cf9b72e999e599e9eda0d2ef tests/transmitter/ test_packet.py
dl_verify 49aa0e761771893e8bc057c8e305eb8b5e7103df9a31c80eba333db739f0b2c521eca59901f35bf2e319360902c8be12b112a29948461b73662554bdf55bf6d4 tests/transmitter/ test_sender_loop.py
dl_verify fd4d6cf68a4e555a60caf8efc6ebc6747990ed1c582036c6cc92012c5af82b49b32c42398bf822fda8257e84c822bdb8158260164a8774aea72723ddbe99e639 tests/transmitter/ test_traffic_masking.py
dl_verify b71f7d8e3ce943dca2516f730c9919633f40568af905ac32e05b126e06f2c968c9b0b795cfad81a696511cd07534a0593ef1c9b5d5299ab88b2aff32b9059b64 tests/transmitter/ test_user_input.py
dl_verify 5be56563cab2c9007b6be7ff767778e3fb0df1d3374174d6b6ef7dc6d66b0c692cd798a0a77f156c3eb1ad979a3b532b681db97c4d1948ff8f85cd4a1fa2d51d tests/transmitter/ test_windows.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/receiver/ __init__.py
dl_verify d80af580f76c3c58d72828ab190a055a03f7e74ae17ccbaa2f70dd94e01b7efd85888ac51eefed94d6671027660a8080600f2e1e908bd77622c36ba258a8936e tests/receiver/ test_commands.py
dl_verify dce0fe6cd05915f1a0450259a08e9935b077f9b3af61f315812834811a5c82095b72bea5e4b283fd2b8285e86f8ee4897d43f42a99261767b77841deb471d980 tests/receiver/ test_commands_g.py
dl_verify eb86007ca9b0cfeb4d364b1fb53409443c8b9f95770979c471b8462c1c41205b96afd357670a9cd5949e8360b738d9284a9e726ee6ab89e09a0306b105f1a720 tests/receiver/ test_files.py
dl_verify 01bf3274c675b8cbe6379f8fb1883e0d4ed6c69d164b2c6a44794786d21f2604efc262b34372dfb581607655e6e1e73c178660d3e97f4f2c9bdfb11e4166b2fd tests/receiver/ test_key_exchanges.py
dl_verify 7b9d27497d5765739ee435c02a379e792ad510dd893ff0d3871a7d3f97d196274921a2d26fa656edb5e7974a390155e7c1914135d3e1b6a82ed8f94d46263b66 tests/receiver/ test_messages.py
dl_verify affbd5bccd0fcd87bb50e13b497b1ba3c29ccec954fa53f62bff1a28baa7b35376f614fb54c922ed4605a37f6aa1463efff43a6267619b04a605a2181222e873 tests/receiver/ test_output_loop.py
dl_verify da34f5bdcd8b108b45e955d545954de32c9d8959c26e9d2e3104106139fb2fec69aabd6d5d127beacef7a09ee4f16aab0a92ee7d76b0fa6cd199e56032c12257 tests/receiver/ test_packet.py
dl_verify 717722763a41267929b6038abe859eececee20e68497d0f3c04268b6b8274a04e39e3f8d37d0928c8459c7ef52478176c933d8ec8b2bd0b93ff952a9b92b86f4 tests/receiver/ test_receiver_loop.py
dl_verify e6df26dc7b829b8536e454b99c6c448330fc5cff3ff12a5ebc70103a5fb15ab4fcb8fcb785e27201228b6f50ec610ef214bee4f2d5ff35995b4f00ae23217bc0 tests/receiver/ test_windows.py
}


download_local_test_specific () {
dl_verify dec90e113335d3274d87c3e12dda5a3205df57bd10c1e0532ecad34409520ce0596db21e989478836d4a0ea44da8c42902d2d8f05c9ad027a5560b4d0d5b9f13 '' dd.py

dl_verify 2f426d4d971d67ebf2f59b54fb31cff1a3e2567e343bfa1b3e638b8e0dffed5d0c3cac1f33229b98c302fee0cca3cc43567c2c615b5249a2db6d444e89e5fc70 launchers/ terminator-config-local-test
dl_verify 529ea0b39bfb9037f2515128a9e2bd898a6590f2ff2e81a9bf841cb5d36065f7b98bbeae27749940eb698190ad579ae77854c738d60b03dc5b83358fdf1125e0 launchers/ TFC-Local-test.desktop
}


download_tcb_specific () {
dl_verify a880c6a5b8b05cb3d20eaf840f2fc3e5cae5f00216bb685bfe7489101f5762deb1c7e7755287d8c19f527a4eac4a5c2f5806890f17087215ef4fc787315e4e6a launchers/ TFC-TxP.desktop
dl_verify 4093fdfcd041d9c155714c5b14faf3101adf86ef9a14881cd8d0a0d55dd8f83b76de76e4bdbb5c75d5ce6900d1ea698460375442d7179df2451e38a793000d7f launchers/ TFC-RxP.desktop
}


download_dev_specific () {
dl_verify 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
}


download_venv () {
dl_verify ef3a981be2babfb021d669a6fa0bba20251dc3fa3db66359ed41ee67906baf5b0b5df3b6da28c8b0b2cbfd63636a28d0bbb402abc2cbe00c9b183fabb4d8458e '' requirements-venv.txt
}


install_tcb () {
    create_install_dir
    dpkg_check

    sudo torsocks apt update
    sudo torsocks apt install libssl-dev python3-pip python3-setuptools python3-tk net-tools -y

    download_venv
    download_common
    download_tcb
    download_tcb_specific
    #download_common_tests
    #download_tcb_tests

    create_user_data_dir
    cd $HOME/tfc/

    torsocks pip3 download -r /opt/tfc/requirements-venv.txt --require-hashes
    torsocks pip3 download -r /opt/tfc/requirements.txt      --require-hashes

    kill_network

    pip3 install virtualenv-16.4.0-py2.py3-none-any.whl
    sudo python3 -m virtualenv /opt/tfc/venv_tcb --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    sudo pip3 install six-1.12.0-py2.py3-none-any.whl
    sudo pip3 install pycparser-2.19.tar.gz
    sudo pip3 install cffi-1.11.5-cp36-cp36m-manylinux1_x86_64.whl
    sudo pip3 install argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
    sudo pip3 install PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
    sudo pip3 install pyserial-3.4-py2.py3-none-any.whl
    sudo pip3 install asn1crypto-0.24.0-py2.py3-none-any.whl
    sudo pip3 install cryptography-2.5-cp34-abi3-manylinux1_x86_64.whl
    deactivate

    sudo mv /opt/tfc/tfc.png                   /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-TxP.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/TFC-RxP.desktop /usr/share/applications/

    sudo rm -r /opt/tfc/launchers/
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-venv.txt

    rm $HOME/tfc/virtualenv-16.4.0-py2.py3-none-any.whl
    rm $HOME/tfc/six-1.12.0-py2.py3-none-any.whl
    rm $HOME/tfc/pycparser-2.19.tar.gz
    rm $HOME/tfc/cffi-1.11.5-cp36-cp36m-manylinux1_x86_64.whl
    rm $HOME/tfc/argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
    rm $HOME/tfc/PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
    rm $HOME/tfc/pyserial-3.4-py2.py3-none-any.whl
    rm $HOME/tfc/asn1crypto-0.24.0-py2.py3-none-any.whl
    rm $HOME/tfc/cryptography-2.5-cp34-abi3-manylinux1_x86_64.whl

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


install_local_test () {
    create_install_dir
    dpkg_check

    upgrade_tor
    sudo torsocks apt update
    sudo torsocks apt install libssl-dev python3-pip python3-setuptools python3-tk terminator -y

    download_venv
    download_common
    download_tcb
    download_relay
    download_local_test_specific
    #download_common_tests
    #download_tcb_tests
    #download_relay_tests

    torsocks pip3 install -r   /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3 -m virtualenv /opt/tfc/venv_tfc              --system-site-packages

    . /opt/tfc/venv_tfc/bin/activate
    sudo torsocks pip3 install -r /opt/tfc/requirements.txt       --require-hashes
    sudo torsocks pip3 install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                                /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-Local-test.desktop       /usr/share/applications/
    sudo mv /opt/tfc/launchers/terminator-config-local-test /opt/tfc/
    modify_terminator_font_size "sudo" "/opt/tfc/terminator-config-local-test"

    sudo rm -r /opt/tfc/launchers/
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt

    install_complete "Installation of TFC for local testing is now complete."
}


install_developer () {
    dpkg_check

    upgrade_tor
    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk terminator -y

    cd $HOME
    torsocks git clone https://github.com/maqp/tfc.git
    cd $HOME/tfc/

    torsocks pip3 install -r requirements-venv.txt --require-hashes
    python3.6 -m virtualenv venv_tfc --system-site-packages

    . /$HOME/tfc/venv_tfc/bin/activate
    torsocks pip3 install -r requirements.txt       --require-hashes
    torsocks pip3 install -r requirements-relay.txt --require-hashes
    torsocks pip3 install -r requirements-dev.txt
    deactivate

    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"

    sudo cp $HOME/tfc/tfc.png                   /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-Dev.desktop /usr/share/applications/
    sudo sed -i "s|\$HOME|${HOME}|g"            /usr/share/applications/TFC-Dev.desktop

    chmod a+rwx -R $HOME/tfc/

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


install_relay_ubuntu () {
    create_install_dir
    dpkg_check

    upgrade_tor
    sudo torsocks apt update
    sudo torsocks apt install libssl-dev python3-pip python3-setuptools -y

    download_venv
    download_common
    download_relay
    #download_common_tests
    #download_relay_tests

    torsocks pip3 install -r     /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3.6 -m virtualenv /opt/tfc/venv_relay            --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    sudo torsocks pip3 install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                  /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RP.desktop /usr/share/applications/

    sudo rm -r /opt/tfc/launchers/
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/requirements-relay.txt

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


install_relay_tails () {
    check_tails_tor_version

    # Cache password so that Debian doesn't keep asking
    # for it during install (it won't be stored on disk).
    read_sudo_pwd
    create_install_dir

    echo ${sudo_pwd} | sudo -S apt update
    echo ${sudo_pwd} | sudo -S apt install libssl-dev python3-pip python3-setuptools -y

    download_common
    download_relay
    #download_common_tests
    #download_relay_tests

    create_user_data_dir
    cd $HOME/tfc/

    torsocks pip3 download -r /opt/tfc/requirements-relay.txt --require-hashes

    # Pyserial
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install pyserial-3.4-py2.py3-none-any.whl

    # Stem
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install stem-1.7.1.tar.gz

    # PySocks
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install PySocks-1.6.8.tar.gz

    # Requests
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install urllib3-1.24.1-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install idna-2.8-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install chardet-3.0.4-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install certifi-2018.11.29-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install requests-2.21.0-py2.py3-none-any.whl

    # Flask
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Werkzeug-0.14.1-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install MarkupSafe-1.1.0-cp36-cp36m-manylinux1_x86_64.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Jinja2-2.10-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install itsdangerous-1.1.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Click-7.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Flask-1.0.2-py2.py3-none-any.whl

    # Cryptography
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install six-1.12.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install asn1crypto-0.24.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install pycparser-2.19.tar.gz
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install cffi-1.11.5-cp36-cp36m-manylinux1_x86_64.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install cryptography-2.5-cp34-abi3-manylinux1_x86_64.whl

    cd $HOME
    rm -r $HOME/tfc

    echo ${sudo_pwd} | sudo -S mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    echo ${sudo_pwd} | sudo -S mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/

    echo ${sudo_pwd} | sudo -S rm -r /opt/tfc/launchers/
    echo ${sudo_pwd} | sudo -S rm    /opt/tfc/requirements-relay.txt

    install_complete "Installation of the TFC Relay configuration is now complete."
}


install_relay () {
    if [[ "$(lsb_release -a 2>/dev/null | grep Tails)" ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


read_sudo_pwd () {
    read -s -p "[sudo] password for ${USER}: " sudo_pwd
    until (echo ${sudo_pwd} | sudo -S echo '' 2>/dev/null)
    do
        echo -e '\nSorry, try again.'
        read -s -p "[sudo] password for ${USER}: " sudo_pwd
    done
    echo
}


check_tails_tor_version () {
    included=($(tor --version |awk '{print $3}' |head -c 5))
    required="0.3.5"

    if ! [[ "$(printf '%s\n' "$required" "$included" | sort -V | head -n1)" = "$required" ]]; then
        clear
        echo -e "\nError: This Tails includes Tor $included but Tor $required is required. Exiting.\n" 1>&2
        exit 1
    fi
}


upgrade_tor () {
    available=($(apt-cache policy tor |grep Candidate | awk '{print $2}' |head -c 5))
    required="0.3.5"

    # If Ubuntu's repository does not provide 0.3.5, add Tor Project's repository
    if ! [[ "$(printf '%s\n' "$required" "$available" | sort -V | head -n1)" = "$required" ]]; then

        sudo torsocks apt install apt-transport-tor -y

        if [[ -f /etc/apt/sources.list.d/torproject.list ]]; then
            sudo rm /etc/apt/sources.list.d/torproject.list
        fi

        if [[ -f /etc/upstream-release/lsb-release ]]; then
            codename=($(cat /etc/upstream-release/lsb-release |grep DISTRIB_CODENAME |cut -c 18-))  # Linux Mint etc.
        else
            codename=($(lsb_release -a 2>/dev/null |grep Codename |awk '{print $2}'))  # *buntu
        fi

        echo "deb tor://sdscoq7snqtznauu.onion/torproject.org ${codename} main" | sudo tee -a /etc/apt/sources.list.d/torproject.list
        sudo cp -f /etc/apt/sources.list.d/torproject.list /etc/apt/sources.list.d/torproject.list.save

        torsocks wget -O - -o /dev/null http://sdscoq7snqtznauu.onion/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
        gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -

        sudo apt update
        sudo apt install tor -y
    fi
}


kill_network () {
    for interface in /sys/class/net/*; do
        sudo ifconfig `basename ${interface}` down
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
    # Justify printed text to center of terminal
    printf "%*s\n" $(( ( $(echo $1 | wc -c ) + 80 ) / 2 )) "$1"
}


create_install_dir () {
    if [[ ${sudo_pwd} ]]; then
        # Tails
        if [[ -d "/opt/tfc" ]]; then
            echo ${sudo_pwd} | sudo -S rm -r /opt/tfc
        fi
        echo ${sudo_pwd} | sudo -S mkdir -p /opt/tfc 2>/dev/null

    else
        # *buntu
        if [[ -d "/opt/tfc" ]]; then
            sudo rm -r /opt/tfc
        fi
        sudo mkdir -p /opt/tfc 2>/dev/null
    fi
}


create_user_data_dir () {
    if [[ -d "$HOME/tfc" ]]; then
        mv $HOME/tfc tfc_backup_at_$(date +%Y-%m-%d_%H-%M-%S)
    fi
    mkdir -p $HOME/tfc 2>/dev/null
}


modify_terminator_font_size () {
    width=$(get_screen_width)
    # Defaults in terminator config file are for 1920 pixels wide screens
    if (( $width < 1600 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 8/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 7/g'   $2  # Data Diode config
    elif (( $width < 1920 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 9/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 8.5/g' $2  # Data Diode config
    fi
}


get_screen_width () {
    xdpyinfo | grep dimensions | sed -r 's/^[^0-9]*([0-9]+).*$/\1/'
}


install_complete () {
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
    clear
    echo -e "\nUsage: bash install.sh [OPTION]\n"
    echo    "Mandatory arguments"
    echo    "  tcb      Install Transmitter/Receiver Program (*buntu 18.04+)"
    echo    "  relay    Install Relay Program                (*buntu 18.04+ / Tails (Debian Buster+))"
    echo -e "  local    Install insecure local testing mode  (*buntu 18.04+)\n"
    exit 1
}


root_check() {
    if [[ !$EUID -ne 0 ]]; then
       clear
       echo -e "\nError: This installer must not be run as root. Exiting.\n" 1>&2
       exit 1
    fi
}


architecture_check () {
    if ! [[ "$(uname -m 2>/dev/null | grep x86_64)" ]]; then
        clear
        echo -e "\nError: Invalid system architecture. Exiting.\n" 1>&2
        exit 1
    fi
}


set -e
architecture_check
root_check
sudo_pwd='';

case $1 in
    tcb   ) install_tcb;;
    relay ) install_relay;;
    local ) install_local_test;;
    dev   ) install_developer;;
    *     ) arg_error;;
esac
