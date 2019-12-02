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
CERTIFI=certifi-2019.9.11-py2.py3-none-any.whl
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
SETUPTOOLS=setuptools-41.6.0-py2.py3-none-any.whl
SIX=six-1.13.0-py2.py3-none-any.whl
# STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.7-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.7.7-py2.py3-none-any.whl
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
    compare_digest 3a3f8a79420ddb792f647c0bb2a82ac6bfec70f4497005a6ca77ba113cfda40bda502456156860b2a92b464eaf26b23e78bcf907d849ec40a08357955f31549d '' requirements.txt
    compare_digest 97558ed189976ccd54e3a25bcf639f1944aa43f4a4f42ff5ef2cf22349a7b649272e91746041b4e04b2f33adf1fab8818c339b1cc58f9353af3e5ac76cb1ec0b '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest bcb8a7ce1eb2d2f064b560ca5a8e467f84e3a0c3d643771e7782c792e89494600436e52c12f0a8471bf4a1da116f82ed732b8e06783534227a31f576f7adbd6c '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 7e519d20fef24e25e88ec4a9c03abadf513b084e05038f17c62ca7899c2f9174a953caa0bfbd3b61e455e243513cdab737c22a34d73ebab07b65d3ce99100f0a '' LICENSE-3RD-PARTY
    compare_digest 99815d0cfbca7d83409b7317947fe940fe93fd94b50e6099a566563ee6999e33830fd883ff61e5367a040d5fda3f2a43165ef0dc6155e14a573e07dc27eba70d '' relay.py
    compare_digest 3904003688f993c6566fb8cc39e7bd8f820ef3ec0d097b7e467a5aa3019f480a026ae424bfb5473ff71c01002dc386528a010a8fb36cd0f5a03eb0c355450d61 '' requirements-dev.txt
    compare_digest 119fbe604a01ad0ef1d6e758ed6ee8dc46be4d746207b0cda1d4c17ba12621d32e6f479229856c6008a77f796bbd778dbecc27bb38dca817d88c257a9d3b27b8 '' requirements-relay.txt
    compare_digest 1696663138ca74e4c85caeeea82e34168ddbb1dd1a626a12064c43515859590e17c982dd0f1de2d807039794884bf053c147060760c84751143214e2af3611de '' requirements-relay-tails.txt
    compare_digest 550a82b9c07376e9eaf1117f77362f89c401169a848010110c2f8f2d99d50376f4cc5308d8b7e1928e68f15834aca7d5c9a9a7e7b8db956e5e55755ab7ea0a25 '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest 7e24d0962e0be4b8e206d9390e888caab10604f5bf1bb29af4b91c4c20e42bcc04ef4ef15ce3248ac68c0acfd2e391a96a5567d87d91223f7be63a05b9dbf843 '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest 50bb3db478184b954480069e40e47167f28f13e55aa87961eed36804c612a8c25e9ab0c0505cf5d36d790051ccfb465a2d7641ab3efb659503b634541d07e9c2 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest 6e1c1082b7850e55fe19fb2ebe0f622dea16e038072adcfe1347305324d10b97bbc443d7ed1ff3ee141d647b4561874c7736ba449c1e8e34dccd4be9dab5db8b launchers/ TFC-Local-test.desktop
    compare_digest 6a6469b5b11cb081e1f9e2848cb328d92f283f94f977f8e89984fa115fbeb719e6b094c9de0c1ff5a4f5f3fd66d3ca71bce1a3a5e4ca3ae454557ad261f8acf6 launchers/ TFC-RP.desktop
    compare_digest 6a6469b5b11cb081e1f9e2848cb328d92f283f94f977f8e89984fa115fbeb719e6b094c9de0c1ff5a4f5f3fd66d3ca71bce1a3a5e4ca3ae454557ad261f8acf6 launchers/ TFC-RP-Tails.desktop
    compare_digest 4b387996983b6b900a53aedaba0a542eb89416fed0e99ed845680e41748bbad65956c5d4662dfce4b5519412a10404e6c995464c26c74298e0db37f55b3dcd2c launchers/ TFC-RxP.desktop
    compare_digest 54b1ff5b89f12548594f65f20b4bd615f6659cdf47188be720c05d3126b8efb13e86257e4f2a1728fca758613519805da66eea3dee01215d389d9d9af6944f4d launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest de1269cbea3f6d42b4c96f9ab8e09d62a29fdcb093d9338f236c144b2cdf89b0f96aaaf62b48465930b2731676b2509fd436dc106e29b4453d8eda86cc6391f7 src/common/ crypto.py
    compare_digest 987aa85bf2a187f5fafc497eb82fd6e41ae629cdb5685da885035c38546a17151d4ba7636674875416d70ea95cb3709eed1bdc7e2338eabd085df504136b5659 src/common/ database.py
    compare_digest f9bc7faa730c9031aa70541be3e1a9aaaff9bec14c52d8b7b4ebaa87cd1d05048238abdbe198d5b8bfddc802bc80ccb38fb44bd9459565d26c696dd9d73ee65b src/common/ db_contacts.py
    compare_digest ef32bf3c3bd7c57cf0521db9e41920e4aa60daf6d795592eebf23d4b8eca97b3b9a5ff3f11e89d1ec6b64212bf5b9a38c53bc6b87613b955f0e500e0de228093 src/common/ db_groups.py
    compare_digest 2a25018e319de5438883e2af2d81d863b7fd340d071cbaeb47f8f8a7f5c93e12db7d62bce22775f938ad5766fd476b0b8c404cef44f5f00a72214243f6f90034 src/common/ db_keys.py
    compare_digest 4fe9f2ea5a16d6b81aaf82abb86742b2df99101e72c32d046a04d2e0ff2a15216bb63a54d65965d313c8f1a453f579846c64b3f6a259e44b79342bad01e8bee8 src/common/ db_logs.py
    compare_digest 721af2edb687eaeab91bbff2baf8b14c0c7a5bd9ac35ac584eb3b0293df948682e080fafb7a1e8944cb364051da0d583b48c91dfe52eb9d399b08017c3621a14 src/common/ db_masterkey.py
    compare_digest c9000d541149835aa0812aa4b3108356d2f9465a767ea4273ece6340212eff287447af9247df4cea309ef7f8a5cfc887a01c8190523d1616164dd0f98718905f src/common/ db_onion.py
    compare_digest 18e86599ee813be8a38d5775cff7d423735677bc40f1758dcc676d683b29dd3b4ba3eba72a300a1c3fabc4d68ad211329cef0c934403909491cb981e4a1bcda8 src/common/ db_settings.py
    compare_digest 7a673e6feb7a5b2e3417d2c0eee82a59b3730a5d241938a84fd866dfc838c3cd63d7ef96772d43f62df740a2ba1001456746dd6c86e950484eac3ebabed498ce src/common/ encoding.py
    compare_digest b4b502381c3d37908f6550e52c0fdabcedb0cd4b89700bd4aca0478b8185d2d7e5b75aa684eb7f72d46ec2f21d3455ac10d4629532e37496b58656b88bc9ce72 src/common/ exceptions.py
    compare_digest 452a2c1c953c7b4226c51ecf59dce9b163f997e81956c3147f7533cff8b868f637cf9be6556a854840139a5a1ab6fa3f190ef18a16bbdc4435a7438d0b3ab788 src/common/ gateway.py
    compare_digest 72cfc8cad6aecf6913ecb8cf9635158ed0113a1168b522c0b032f21880a42d2e5642d7a9adf54574611daa03af5bbebdaab9b3617d67eacd041d42cea0b5ab15 src/common/ input.py
    compare_digest 061474135b9b27c2ff9b1b30cb48b35fc615a91332fce615992323e3db76f25b3a27229a4f88ae317c9421310b415174e3379fab608c733574189a9b6fa18eb6 src/common/ misc.py
    compare_digest 280562cc55555dbac9fa83e9930c86147b28e42e7639d04d52c362f674da27cdd5797433c2bb067c4785246eb85ca0068d6daf26b94f5110964c4b35ede6f4b1 src/common/ output.py
    compare_digest 819705c44801c734eeebecf84078067ee7efe4b473bd9c036bef9c730f0fc7789f2d17996e058a36d5f05a8456672eda660ff8c323f1e09fc5daa56cf575b81f src/common/ path.py
    compare_digest 00b07b62a6ab177d86d8aacf240affa52eb9020c3a5687b4a60c347c7cfc20d2a606cd3cf2a4abf145a97736ef018f6ec5e62831bb86893b53552a0a283fe8be src/common/ reed_solomon.py
    compare_digest 984dc826bf429769aa57ce202940b1b8f5415a0a4115676d437936a6cf886d8884d8925771af3d94dc3748bdf16edab148492ba91cf766d6ae1f8a41c1dbdd22 src/common/ statics.py
    compare_digest f05c27de8d1a90dc72aeefc9e9b7ac350140668cf2ec2a18c8f33ab7219fe5e13557717f68bada8357bb98d41fbafd56754eaae523d9e660670066727ef137f7 src/common/ word_list.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest 66b5f2713e1783f6e9f1e53aeafe211fa96319ef883926ded96fa16a594ddff91baa9b9dff3c10552237a0ac9d44388780a3b8765fc452debdfb48fe7d86288d src/receiver/ commands.py
    compare_digest 0811721780e7b3e189c22cbbba13117f0d7f493977cacc80becd33857fcdbe422e220a9879b691cdbe5b4e17beaf929726601fdb25cb7e942757aae5d94a49db src/receiver/ commands_g.py
    compare_digest 60167b93510b5757377455391b94a4c54b5493eea4920374462022876fece7582cb8e2fbe6a76aba8cce10fda81f3096426e669596e2dd98032016ddaabd054d src/receiver/ files.py
    compare_digest e24c2ea3b66ae0134ea096ca42086a1d5cfe2f98d7f006a233ab91f51d5b0901779a2e1cdddfd9821ff09bb55b769c9d1a50b3533095a7aad9b0623218f90e93 src/receiver/ key_exchanges.py
    compare_digest 4a76cf6361c980d96ce51db88944eb94b65e688ce87eca51ea88a72a6c6841b8e9ab169a5df0d4b60a8894e2455968d1105ef4e1fb117d90eff340a05e47df4d src/receiver/ messages.py
    compare_digest ff06a420be606bffb5a35dccd1a20d19993f05f20a87f7a2b257cc13d2e44e35d957c4ff0b0814397fcc04f86475ead735a047067bf2a7e145f3052f30a5a7d4 src/receiver/ output_loop.py
    compare_digest 461d7cae3967504cd7f08efd5bc2a575df7e201263612329864cebf3a7b1e49a7e3a4f639502c996f06581befdcb8ba1b968a017c00e279e1802d5c386bbd960 src/receiver/ packet.py
    compare_digest 20c6754ddb6261c7a3b479e6ab7bf78eb0ef8783e2141373d7aba857f413091b78dcc9c32667dd8f8d5c41927102da7e35c4c4fcb0aa7376dc42b08c0c01d6e2 src/receiver/ receiver_loop.py
    compare_digest efba6c3a4762c5c7509bc3e30b75479d4cb7e56e0d022401376e085f6c115f489d9a89fc203080b4e67e475897ee7078f4eeeaea855ceca5b4e51ed2db82fcae src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest 226836aeb214c5bef07bb66383fcf38285ee3921398dc8e1797c6f1dc8608114bbfde53b6d7a8823b1cebebffca8a10a26886823dd79326b7ab4929395a173c1 src/relay/ client.py
    compare_digest c32b5b78e28567d5ef0c6f41f1a3c69f6d31b1cb3b9d58faf6516fa27fc62e12b2f359f7b60176b5fe20a2d94725f5fd76a879d4b795513d1588f8ecf9bae5b0 src/relay/ commands.py
    compare_digest 8192da7588bf4c6cdd05facab8443b64b932d78181f632b6842b3d14b257b8d9b76d559414f197eb4b74946ac11544920aa1692926556471abd7f9da760fb5b4 src/relay/ onion.py
    compare_digest 382cc987853d7dfffef1af25c487a9b0d1d431f2aff17da723e247b01cbd431a6298ecafc3f93c4f6db3c6bf523e28aa81655681379b528d6b6a1d855a5652c2 src/relay/ server.py
    compare_digest f60e75581ec996098d4eff996fa959acf8a5c8b5790635b94fdf7892ea2958258c1fda8fa46aab7cca812c13b96cc653d528fb77a5d73784ab6e3583841e5602 src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest 85fb70157d497defb757cc0b09877a7fad13c19411af61622b2b89672432fecf741bc966f8d32864b8bffd8fff01d9bbed42f6b3e2bd1b0f7e282db1843dfdcd src/transmitter/ commands.py
    compare_digest b88b3046beb0a9a1de55a9e504e922c1f962cfea78fc60fc6c039ebe813dcfd1b440d3c4aa154d6751f60e7fe5287ae35ebdea826fbd99544ee56fb27d77b05f src/transmitter/ commands_g.py
    compare_digest 132461d7425a7f1ce644ff1766cedc7cbe35b00b65ffada7bd7cc5f7db230f257ee0ccbc2b94f7171cc653037678a31907949171af304465977439d468d5f1cb src/transmitter/ contact.py
    compare_digest e0aa8bd5449617f0e11d56b9ada5680200134ed9b22e8fffb59f9d958d58892cff6008301776173e8e20853e73226b5987d2320dde7df939d9f15c84f4762699 src/transmitter/ files.py
    compare_digest 7cb9fc9d095f40ce2de6b49c9bd58b9dcab6b835fe7749dce8642c3c87b0eee10c4e53ff986c09ae26fb7b8aad7fe87c5fd56a734f2e013f69195213b9d5e9ec src/transmitter/ input_loop.py
    compare_digest 21225ef2f66933e31a7fbd9882cce1817cd187aad6cb17e473c4115251bdfb44791d27a75d867f9f4b776645d6feb4bbda6a1c4c3d8ce3a1b5b07fee40289ae7 src/transmitter/ key_exchanges.py
    compare_digest 63e6fc3e298e99672aa41db73868908d0e4c1ab297a902f6387ce7e27d68713150e7e7451b5533dde1c52662b6394342a8bf94af946ac6ca4d3154faeaf3fc01 src/transmitter/ packet.py
    compare_digest 91386783148ffa8ffdb5fc979b482cbb22e17f89c615bd773c9636ca1769ff08ecd9f02ce299c58e5fb9a9b3aa6de442065c127e0823ebcde05af85e0aab2424 src/transmitter/ sender_loop.py
    compare_digest 945b410d8709e93fb7aff1487a1dbe0fa4fe314d22f96c23b9be807629301ebed1b6d47a8e2d87f86bf1111eeb53b02f70fc67ab0bd8112006aea13d3a814bcc src/transmitter/ traffic_masking.py
    compare_digest 678ae2b63667d93b1d4467d029ab04778614ddf6c09dff4bb61d262373353cd7fe6b8b535292fdf28e1be36c8b57534dee9eb745ee94c72b051798ac4e1cbccd src/transmitter/ user_input.py
    compare_digest 9bed701e404acb40e14fc38a6b777e9f02b750532f3f5654b70b23d6883cf6487852ea5e57a2cc00e7b0d8e87ec61c2b96a3dc6bda319d9f16ed66649c4e8159 src/transmitter/ windows.py
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
    compare_digest e80eb04615d1dcd2546bd5ceef5408bbb577fa0dd725bc69f20dd7840518af575f0b41e629e8164fdaea398628813720a6f70a42e7748336601391605b79f542 '' ${VIRTUALENV}
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
    compare_digest 2e90929aa61c847e1d414d427b08403679ba5f512a56d58b92ee64d47e8a2c5da18e47126e5f59faca335b3a4b5ec9857aa323d866252546a6df42c3e3ef3884 '' ${SETUPTOOLS}
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
