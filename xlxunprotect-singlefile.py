""" Tool for removing vhdl and verilog content protection """
import sys
import re
import struct
from Crypto.Cipher import AES, DES
from Crypto.Util import Counter
import zlib
import argparse
import StringIO
from base64 import b64decode
import binascii


def uudecode(data):
    dec = ""
    for line in data.split("\n"):
        dec += binascii.a2b_uu(line)
    return dec


keys = {
    "15": {"key":"93B5313FBB924FC9A57F40CBECE9EA3F41A6916E5BBC4AD8931F003C613BF934", "iv":"1C9C5CFB776F42EC8970FB3918D67B43"},
    # 30
    #  .. these keys are in the binary, but don't seem to be used.
    # "32":{"key":"886592C2B46F3CD6", "iv":"E78437FD7C4503F3"},
    # "33":{"key":"7EB0C67E6B9B81E4", "iv":"FB744BDFFBAEE2B6"},
    # "34":{"key":"2990DC694EF16DC9", "iv":"567DFFD0706FE1AB"},
    # "35":{"key":"94FED660DE79DD61", "iv":"BFA101DDDECD319A"},
    # "36":{"key":"1CF07C2287EBE145", "iv":"7284567847970F9F"},
    # "37":{"key":"278D7318A95839DF", "iv":"0D9B9E4FB62AF137"},
    #   9E5C257AF9954B05 F6D554BCDFF4BD32
    "38": {"key": "F143CB05DA5FE26A", "iv": "0D9B9E4FB62AF137"},
    # 43
    "50": {"key": "B0E430FB8E024FB4AC0732270D9C3A88", "iv": "2C7F9EEBAE5D40BB8F6BC0B5EF240526"},
    "51": {"key": "8C700049CF544C24A7ABDBC0E896C4D1", "iv": "6D815F2526BAF48AB26519155E45AA49"},
    "60": {"key": "C145AF345F87526C233ADBC875051993A549C46663518B0859E35C1469DDA49D", "iv": "6F4A2505AD8367A4535ECE74D6438EA6"},
    "61": {"key": "2B3B4291844844DEA978A5175A7A8611BA8CFCF39DE54295B778CA7B29A0E537", "iv": "E9029FB591804136B858EFBE07A55729"},
    "62": {"key": "0DE4DDBC43D64F488DC9CE26D5161FA09E0EB0979DD34E4C8E8BB82B71BC9AEB", "iv": "D9A3D631B46BC3AA232219577DA16C48"},
    "64": {"key": "57D2680C0AD24BD38CFC2F0842DA67E5791207B8178042918DD7FC23B284D13A", "iv": "18C9FBCE90144BE997F910FA993FE28F"},
    "65": {"key": "581F4AA947971B02C9B76860BF153E027C0D9257937ABE03853FE928CADC6642", "iv": "4FF0F201813FBEAFA62AACDD88222910"},
    "80": {"key": "030E0F5C4123594F",                "iv": "43A25FFF66954813"},

    # "HY"   -- keys are encoded in the header.

    # these formats i have not yet decoded:
    # "HL"
    # "c1"

    # "D0"  - 'debug'
}


# decode hex values in key dictionary
for val in keys.itervalues():
    val["key"] = val["key"].decode("hex")
    val["iv"] = val["iv"].decode("hex")


class empty: pass


def parseheader(data):
    if not data:
        return
    m = re.match(r'^XlxV(\d\d|HY)(DM|EB)([ 0-9a-f]{7}[0-9a-f])([ 0-9a-f]{7}[0-9a-f])$', data)
    if not m:
        return

    obj = empty()
    obj.version = m.group(1)
    obj.encoding = m.group(2)
    obj.fullsize = int(m.group(3), 16)
    obj.compsize = int(m.group(4), 16)
    return obj


def strip_padding(data):
    n = ord(data[-1])
    if 1 <= n <= 16 and data[-n:] == chr(n) * n:
        return data[:-n]
    return data


def cbcdecrypt(data, keyiv):
    blksize = len(keyiv["iv"])
    keysize = len(keyiv["key"])
    datsize = len(data)

    if keysize == 8:
        cipher = DES
    else:
        cipher = AES

    C = cipher.new(keyiv["key"], cipher.MODE_CBC, IV=keyiv["iv"])
    padding = datsize % blksize

    plain = ""
    for o in xrange(0, datsize-padding, blksize):
        plain += C.decrypt(data[o:o+blksize])
    return plain


# for HY
def gethword(data, o):
    value, = struct.unpack_from("<H", data, o)

    return value, o+2


# for HY
def getbytes(data, o):
    len, o = gethword(data, o)
    return data[o:o+len], o+len


##########################################################################################
#  keys for begin_protected sections, obtained by reverse engineering various binaries.

rsa3072 = empty()
rsa3072.m = 0xe0e2d4d1dad44fc898a15af4d42b6ee1139f4d1a987b61c0fd088859743a3750c9056a188f79370c75e6c8e9149d94efee0b5ac3f9674d22fbc4c20d8cd22de48051282fc428335623df0afde048550de985c3792903e978abb7d71caccc5117915fb85c09c00a242f010c51a12dc6cd93ede18fd80e5bbbc30a7a34ec44cb09f41debdf1c61d00dc9d5ce15a2c5a33d52a235b344c642d1b10bba08b138b93cb9fe76b0dbd266ed680a4e92774383ca8569db443bc7e0e4df051a23ee746fae579c7bbf6ca7b8ef8018a9122d7c10688ad4efe399a32c72008f7ce9ce6478993d3550f703331a21006c4676e9b7ebe8e61bee2df30c7246cef4c5454aace788dad45f7d9aeda1064d936074e629b54354b3b38de27f64eadfe4d14eaf9b12c39f0b2c2ccbac976930a998476bebc21d9425d8115894a9dfaab6893bb415175049099721f243ab24727d19d80451303372491e95a4328b5650f483fdad51cdc9c91ca785fc12020a313bf1c1f6fe27a14b4b670f7085089d6fe6da71897964a1
rsa3072.e = 0x03
rsa3072.d = 0x95ec8de13c8d8a85bb163ca3381cf4960d14de11bafcebd5fe05b03ba2d17a35db58f165b4fb7a084e99db460dbe634a9eb23c82a644de1752832c09088c1e98558b701fd81acce417ea0753eadae35e9bae8250c6029ba5c7cfe4bdc888360fb63fd03d5bd55c181f5608366b73d9de629e965fe55ee7d28206fc23482ddcb14d6947ea12ebe0093139340e6c83c228e1c179222dd981e120b27c05cb7b26287bfef9cb3d36ef48f006df0c4f8257dc58f13cd827da95edea0366c29ef84a72fa796d7c9d4d4506e8acafb113c9b39823f355cd9c16ff4815aa2a68f8ff0c2e95cd910120b1e2af251d3c9967e765f5575b1b6304269aede57ea49025f88a367989fd7f2a89d8d01bf8b485b0bfe08cac720d6857c4db6eeb0ac5cfa68c6780a4df161a6ba1e6215cc1a3034768ef022505b1d2faca87f812ac71a7cead15f5ab7f8a4e9d55e3a02e2eebe3bb4293a528cc91976d6b50122460d529dae8397ef05288bd86043ed6902a50bfb15ab2af6dd44b7ffdade4b2f76646e7223513cb
rsa3072.name = "rsa3072"

# ISE 13.1 key ( april 2011 )
rsa2048 = empty()
rsa2048.m = 0xdfe6242b11772ce803207e33111ff538ddd08b46078cba394305fe7311eeb13291d7043078ba06e95ace0b379d5b52cf6874ff3aea61a462a00879189b1f9e9bbe8f7d622b89aad1e916fdf4c41e99b690e3d15d1feb4d10cddefe10a055f9899afc88f819fb44d33a5954ed45cf90ac27f16deed6159c8465840ff0a3f2e3624f3ddf4d3558111afc450cbb447a01417bc84d83f52bb2aa91229746dd0b390d831fd822578e6b28539f66c1771caa13cb2694b704648c232c6525b04e270c04ed149a35cbb4b74882cd0f2cd147f1181f65d9e260f65188dbd5a77cb07837917565c211e5ce0418066e628cc6b079e298085aa7c37ed0f22726b1e1964edb81
rsa2048.e = 0x03
rsa2048.d = 0x9544181cb64f7345576afeccb6154e25e935b22eafb326d0d759544cb69f20cc613a02cafb26af463c895ccfbe3ce1df9af8aa2746ebc2ec6ab050bb12151467d45fa8ec1d0671e1460f53f882bf11246097e0e8bff23360893f540b158ea65bbca85b5011522de226e6389e2e8a6072c54b9e9f3963bdad9902b54b17f742404ae9ef667880e3c5cc1860313a7f595994d905e018efd0a4e65999fbac9f8edef836c7acbfc2effd2a385f92b13c959bbe731fc19013619a33497a73c671867cff08c721973c1d003f9ef3062a13e3c0940096b9dde97c21de370e7eb2701ddc4b39ab1f812ae82e3eb53153c59478acadb20583e85ea3e8814fac9feb473003
rsa2048.name = "rsa2048-13.1"

# ISE 14.7
rsa_2013_09 = empty()
rsa_2013_09.m = 0xe8bc1330745b231c3f0268eaf8cd0eaacadb06f79b4129b4ae15841230f886a604cb574c3e0b523357ea5b5b48824854798c1d494511c4c5d36c149d1b83a666b9ea1f08273683af7858c9a4d2ad90fa2d292f9c98ea50ef6eaefd513845d678051e3e3220b372faeaaf249330fd184ee7c6019eeea6e0865e513b3468518008a13e8de2af74c3093eeff17a12c8f7e4bf95ae9e8c6ac147a686d2d10f16f6a76ae10a30c416de87765260937dce94d6af7cad3c590ad60f7bb600573fbd255d553d4ff9c861654ede488fd25fadc30ef68d1b38de653b59a53fdddce048de9a9378d64f2d23b9c582b55a4f2481ef92de4ebc77ee6fb83dfef7ff253a0d4b9b
rsa_2013_09.e = 0x10001
rsa_2013_09.d = 0x3bfd86c0bdad644e7a9b6769f1fa0166dae53c5584ca7632a190e03b442e3b9efdab607441a5ef6956a70d27697853a69ab2183673bc51c9606702a5409b5dc02afa0347b9bbde93d364a78d79d4cd82ff331797b8fee51fe29aeea709e74e921f579d5694814d090a875cd9280e853e8995cb83292710c6f1f6e458eceedd1e5e76a195534332877caab0dfb941d58392176608868acc46090359c87bc5354f31bc104a2fddcc631d2d175f0c1535e78d075daaed2ba72dc59df67d538b8d33211671a4e21538d52115b6d9e57544209dc362533fb897bb9931a6c0c20291a009079f6864921fea57ff7cd0528844b574bd98c65e23d927a622d22e917e2a19
rsa_2013_09.name = "rsa2013-09-14.7"

# either nov 2014, or vivado 2014.1 ??
rsa_2014_03 = empty()
rsa_2014_03.m = 0xb31bb84c5138a0f8c01cad9202f41f851d2b1925a5cc366afedcc327d3d68ae559e3aa92226898b6ecd6d785570625cb57ad608db133ad834c4bf38e7ca51fce3f3e1b6e4d59349f8a4523874d8a5c800c2e652c66661525c5b9a0bc8eaf183d2304c4ac0c0539d29f7462de788ea5772ce743cd8e8a7979a6210e1e28b3c2c4c3211b48ac1cae49f89597ba7f42c924aa987664683cedd2e9945798cdcbcee1106c1d7728673394989eb195fbe026a60c472f9c8b780573f7c3f2a39895d906ffbcf17d10d855bd2946e3736926174db5ffa8a76c3b92d8548bfc2bf9ae4e49301f3e58d8a53a77fccefbcaeaa29db684623b17484abb57005965806bf68d03
rsa_2014_03.e = 0x10001
rsa_2014_03.d = 0xacd3f7bfb4b427284100ab3ff497aa7ea149c02742d84e3e6a958dbf35bb952580da9df20b3fd0f4da8ee942a259ad488cdf210738d17c01f1326cdfb64903ead9bdcd6c5f38cffd8ec7ee63962007e80b590d898d79bdb848163a1318bfbe6ce808a6dab972a57c271f8073d9f313996efbedc241643f997203fd827e960f3e7e7fd97c70a8902db90435e1e31a9c8d8a726b013857435adaaa0e9fe74c2974798b3a1abf37dbf07d1dac14778954e707cfb22a6becb55cfd933fac4e8ba8c123a2f6b6e9a9d736a3b520280381f3904897b6f82e1f48bd3e3a0af87c45635776b6f8f5df5547eb84f4a8dcbcde730380c5f1f7c6c11e031e50931faff920a9
rsa_2014_03.name = "rsa2014-03"

rsa_2015_12 = empty()
rsa_2015_12.m = 0xbcc59e729c21f56d17ceb0cd2db2cc5e1be3be276bfb87bea42c0cca6c2cb152eb8420b93231d10e8e085276081dd399b4c485bb4571c94690771122bfc9136d20cc839d2349142f66cd10bd3b3a3af4b26042872febff75cb3d5cee0c6591c26a8b00a27d552b60fe47ebc0ee0fec75a0b2bc53feb8571f19c155570b5f4c6f8e3f38852f807d21f7338d3cd91408cacde161e85130745779c4e5a7c29d212175d5aea69394df61870f64b56c10f962c18211bbdbd6e5232a91ef0d4d9f1cc44930d249c3575079986369b656d7fe7bfb3324bd4f8c035c1701ad0616d01e661abfb35d89b18c1a9f73f4f42080417fb1496f927039485321bcb2129c8c7dd1
rsa_2015_12.e = 0x10001
rsa_2015_12.d = 0x9ff07412391550a330e3afcaf7e820ddaf95a35c3552752de25d6c2ce9c0683190586f7d59f8f95ef29a3c7bc2deba94e5a30887a60c0574231caec919639d70fdb429e32ead514be436e4f2dfc6b382f5cb3732e1387c466a7fc047f4faeda7a2abc94ae314115fe9b2381e4bd5f40ba9af267fa836b9a221293c4c36d774a32f1bf3f2425a6d5e0714f962b7e2679d9df0ea89eaf4b5a9183151087faf4340cb390a809401f281c7eff9754547c2ad2421f5fa6701c8a4ff9a81abbc3920b7a09e83cd972aaf9c2b6169b70e76106556ed6a4a895204d26ca49e0a03b85716132ad48c6492459cb7550fdbace65546dd493f922e61b0f44e806bd6999d4401
rsa_2015_12.name = "rsa2015-12"

# altera - MGC-DVT-MTI
alterakey = empty()
alterakey.m = 0xb7f12cd1f2eeb1c3530a44340fad93b240c017203fbf9414cdec39766e5db9fbeb5b294710915328e999029edd5667fc13db65fb23969391a827eafa405d1f17401bb7b1a9fe72156e967af6a754317b51959b9b6de230a009faf405635f1d758bc04d3205747dfb3bda6ad0966f45a94b550de5eaa87c88ac9fc1e3d93a0e75
alterakey.e = 0x010001
alterakey.d = 0x291876fd091b8f17a68bdaa50f03a6c5e27588352a48f11a9ccf341f639509226178e286000b97dac225ef51f2fd8509ea9dcff10608743bcca7ee75aebf9f5c3f0e89075f59d1c44dbe06e304027e98c8bb9e3d3904d6591234508ce711942458026066dc0b134ac58c777210ac55663884dd4ef01ed0f9113bf0f516482bd9
alterakey.name = "altera"

# mentor graphics  MGC-VERIF-SIM-RSA-1
mentorkey = empty()
mentorkey.m = 0xa725f41bf8b2f34cc5f7351011b2fec0f3e2d5e5280c1090af21ff5389fd9e9a2e33d2ab69f04fa75fb405ce8713942942e8372adaa22f109729a948134c3fa627a82b25227e478031c4282f1d8530a13f345ecd10811aa4ac66315b54549cd05c266e1950b7b1633f3def63a3eab43df67e5ed640dafde05cb33309c8e91c19
mentorkey.e = 0x010001
mentorkey.d = 0x23e1d4eeb04c1248f7f2a2d4894828c25958e7dc22e5bc24a3442420d5edb93f960d8ffb3669dd5fabfee4843aa12c5c533db0a2257f4da53d1e3775fe968ecf0ebf5f45de9e59dcb201d18f0916143c7c5cfbfe77ddf8483ceecd9434bfd2adc427a6265572a52e7b5d363f6af6e37f144a660c675fcc2f8a7bb4005b859b51
mentorkey.name = "mentor"

mentorpreckey = empty()
mentorpreckey.m = 0  # 2048 bits
mentorpreckey.e = 0
mentorpreckey.d = 0
mentorpreckey.name = "MGC-PREC-RSA"  # Mentor Graphics Corporation

aldec15key = empty()
aldec15key.m = 0xd7e4a1a3bc1b995e795ad791964d405abf6076c4885a91f92eaed811b772194c947253477247da432b206df876aa4b6aae10bd48a0be2034c9f375df65419965b5dd943716de10b778ced66ebedd7594cfa7b81e5d88ccb7d5c84037695c098fc06ca5a48043ebe0469947fe1e20e6d2aa0d6b6bd46dfc773d00dae66dcc2bcf40c8c2a61ae985e7890353f798817822dd35ab724a98a24c83503eabd5779a32d8efca2f28688e1b87a7b09b653e0fbd3408b7de2cfdfec6000d8cd6547d87af8e8f717ca33d7672f1e440bb1f2a9390ce11158a80050b1bae29d1a997aca51de0b4254ca14f1d222738e34391a8fb48bd0f0ac9cf732bc5d5e2064037712d6f
aldec15key.e = 0x10001
aldec15key.d = 0   # todo
aldec15key.name = "ALDEC15_001"

aldec08key = empty()
aldec08key.m = 0   # 2048 bits
aldec08key.e = 0
aldec08key.d = 0   # todo
aldec08key.name = "ALDEC08_001"

microkey = empty()
microkey.m = 0xc6f391efede8d2bb5da208286d0ededcb4390618df72e75a7ee8e48a79bedb5dee8bcf5cbf18e46982910da76c92581f9250c64c5ca261420a6ac2afdccad6c5b68895f92db62da5041754fd20d5f3798b60acc0a9edb4fd2699479140647f1ccae50fc583af88743f7e9a8dc146a853fde3a789ef73be8afc53b5e16e7a23f8576f6dffd2cf33cf29f2de01dfa9c12ef039fc3a93560d8e1f67883dbd0141866bfbd478c9974351bef247ad7626084c2558f423cebbbef258f8261071ffd0a12ac913a5507abe457ffc85f939dd4e66f6b1879c7ec4f09228481b9a3bf4bb1697b6f9c12506b8c5d30cede1e09460d26d9d80d77720d6ab71ac29f4e5fe8d05ce048b2393da2a1f0c3b6aa3174b64f6f82fa503211f84635a3ed65d660c1ac1bea9fa850b695288be6e059efb1b52af2df4aa62648e391e8e424a264fb6e7cb9423adb69239420951a28e3db5e39c7dbe75d720d8ae388b888f52bf6b676390ffb603726fb79df3f20bfd2628fdc42f74ef6e690a5e42ce2c385ec06c83e8c92449f8229aafc20a00ffb4a40e9669fd94a855180c7c3be7eb49b373fd18e9db5a5f8153b3226276e401b4a36db2c19255019a8ce28471f50e560b25930b9720f20e0c6a0711d142e1f7af7b9baeb9c31b1f0f299a32347581b3d1721c539759356d7256f35a3d70bb70abc87ae2921776e88177a70f3678d3febe9fd911452ef8bf374e32fe424a8c503ab430d2906f5a6d03c941514c9e7719901f6c4cfed4853e73000c99047b14ca5b26d68a25e35d71c1defe73a6e247675ba5b4d05c5455e52f6e672e44bf3054c1ef5e8e7ceaa0ee1ce9342cf5caf8a2d1af93f54320fb6fbf2de0f24e99b2a04f4c5077c8753ae9f68fad597d0b2f6a0b85d1d33e40e3be116a14534fb5238782ccc1b7f11f76ef0f644fc8c908f9881760d3e6d481d09588302f8c77abb41c52943c6d82a9b481e7c624963be88aeef402f6b2efdbc001112f8e48e555660a2c93238aebdac1e4463d6b4a75e057c0e1cd485458d497a42d87866925f45b355cc50700ddf96918bfb849d8dd4560d82b7c17bfa42843d6156a0efc9cc2185040adcfe62da72f1d4c88dda7777e283b09f2dd1d624bc71138aff10a0335ebad21965780fd0f851d6c99f70415e513c1ee7a9c30e904926cc9ac9b4218fbebeb73d77e3a8329914c46ac0539649679aee9769f609dbdd1f925b1f7639188e495aaa8be20d9d4ea6130690d0aa51ad09b25a4f06e3db540804041e11dcc50d419a51f56ec6948316f0a34136d6e7eaa15868cab6b86e809b04d90157e1aeed328e72042e3de4dedfce4bf61b03ac1116983419d74d351
microkey.e = 0x10001
microkey.d = 0   # todo
microkey.name = "MSC-IP-KEY-RSA"  # Microsemi Corporation

syn05key = empty()
syn05key.m = 0xc9bb1068c89d8821d9ca1d78c1b5e75293fc94afa3258e682e91aa0df496e4f317055a74585775777da89d7129464c311092e52b84604b8dddd051b6650d658ab76299128d9d4b4fc6cac9cdb32bef8310930986fd7ed211efe512ac0af5493bedc3049dc2f2708e725f87ff2bd43d592e672c3f8d87a04bee4c11d2f49ebdf78f0b57e439ad6e0bb6fb3306f599ca822c10513fdfde174c14228c554738c0fa926f391c2162d644867c2f4db94126c9f29de4f52df0e2fc3e566688a44cfff428188ff3b407312b9507274c03b27b83ab31281f76871d83a6fd688ddb35639cb08f117138003dde716398bb09ab78bf3f496fe539ad9c2617dd692bcb0e0179
syn05key.e = 0x10001
syn05key.d = 0   # todo
syn05key.name = "SYNP05_001"  # Synopsys  Synplicity

synvcskey = empty()
synvcskey.m = 0   # 1024 bits
synvcskey.e = 0
synvcskey.d = 0   # todo
synvcskey.name = "SNPS-VCS-RSA-1"  # Synopsys

vcskey = empty()
vcskey.m = 0  # 1600 bits?
vcskey.e = 0
vcskey.d = 0   # todo
vcskey.name = "VCS001"  # VCS

cdskey = empty()
cdskey.m = 0   # a 512 bit modulus
cdskey.e = 0
cdskey.d = 0   # todo
cdskey.name = "CDS_RSA_KEY"  # Cadence Design Systems

unknownkey = empty()
unknownkey.m = 0xba3906195fefa77d93b143c62d163a1868114dd426fc016cba773f06fc27c50b55fe17df7366b9ada9e346b95d42d6e3919ba3b78129a0c0617a23e6f662733515c4046df0db07d0e289d89aa1a10a27c9d6136844cdf37287f7b30db80681c5b3dde6ecfde842654ab290db799a626f48cb67a0bc89abed9eff2017927ea4e1
unknownkey.e = 0x10001
unknownkey.d = 0   # todo
unknownkey.name = "unknown"

acmekey = empty()
acmekey.m = 0xa1fd3c93c6feb24e91b1051434441b9335cd3981cc277530443a02552a29e3f5b3625022e8154dd84c66bf2fe334a537d1fde7ad888bb5027160f58e2c2976266828f1d7fee1381d3b8542bebe5d3135793bd35fd0d30c2841f56c1dcb536f044ff0d19529baa53fffd02fea35502d453e2c72159cbaa0c9d150b2e8072d2cf1
acmekey.e = 0x10001
acmekey.d = 0   # todo
acmekey.name = "ACME_KEY7_11"


# list of known private keys
privkeys = (rsa3072, rsa2048, rsa_2013_09, rsa_2014_03, rsa_2015_12, mentorkey, alterakey)


# rsa privatekey decrypt x
def rsadec(key, x):
    return pow(x, key.d, key.m)


# convert bigint x to big-endian byte string
def getbin(x):
    x = "%x" % x
    while len(x) % 128:
        x = "0" + x
    return x.decode("hex")


# rsa-unwrap encrypted key
# input and output: byte string
def unwrap(key, wrapped):
    dec = rsadec(key, int(wrapped.encode("hex"), 16))
    b = getbin(dec)
    if ord(b[0]) == 0 and ord(b[1]) == 2:
        # remove PKCS#1 1.5 padding: 00, 02, ...non-zero-random... 00, <data>
        ix = b.find("\x00", 1)
        return b[ix+1:]
#   else:
#       sys.stdout.write("`unwrap %s %s\n" % (key.name, b.encode("hex")))


# decode HYbrid  key section
def decrypt_hy_keys(data):
    o = 0
    key2048, o = getbytes(data, o)
    count, o = gethword(data, o)
    key3072, o = getbytes(data, o)
    wrapped_key, o = getbytes(data, o)
    wrapped_iv, o = getbytes(data, o)

    key = unwrap(rsa2048, unwrap(rsa3072, wrapped_key))
    iv = unwrap(rsa2048, unwrap(rsa3072, wrapped_iv))

    if struct.unpack_from(">L", key2048, 0)[0] != 0xdfe6242b:
        print >> sys.stderr, "HY: key2k= %08x  %s" % key2048.encode("hex")
    if struct.unpack_from(">L", key3072, 0)[0] != 0xe0e2d4d1:
        print >> sys.stderr, "HY: key3k= %s" % key3072.encode("hex")
    if count != 1:
        print >> sys.stderr, "HY: count=%d" % count

    if o < len(data):
        print >> sys.stderr, "HY: left: %s" % data[o:].encode("hex")

    return {"key": key, "iv": iv}


# oldest IP encoding: only compression
def isStubFile(fh):
    fh.seek(0)
    hdr = fh.readline()
    return hdr == "XILINX-XDB 0.1 STUB 0.1 ASCII\n"


# is old-style Xlx file
def isXlxFile(fh):
    fh.seek(0)
    hdr = fh.read(8)
    return re.match(r'XlxV(\d\d|HY|c1)(DM|EB)', hdr) != None


# not processing binary files ( xlx files start with ascii hdr )
def isBinary(fh):
    fh.seek(0)
    hdr = fh.read(0x18)
    return hdr.find("\x00") >= 0


# decode Xlx file chunk
def decodechunk(hdr, data):
    if hdr.version in keys:
        data = cbcdecrypt(data, keys[hdr.version])
    elif hdr.version == "HY":
        return decrypt_hy_keys(data)

    try:
        if data:
            if hdr.encoding == "DM":
                data = b64decode(data)
            C = zlib.decompressobj(15)
            full = C.decompress(data)

            return full
    except Exception, e:
        print >> sys.stderr, "ERROR %s in (%08x) %s" % (e, len(data), data[0:16].encode("hex"))


# read and decode Xlx chunk
def readchunk(fh):
    hdrdata = fh.read(0x18)
    if not hdrdata:
        return
    hdr = parseheader(hdrdata)
    if not hdr:
        return
    data = fh.read(hdr.compsize)

    return decodechunk(hdr, data)


# process old style stub header
#  2 variants, one  has XlxV32 data embedded,
#  the other is 'rle' encoded -> rledecode
#  involving ascii 0x20 - 0x7f chars
def readstubhdr(fh):
    state = 0
    while True:
        c = fh.read(1)
        if c is None or len(c) == 0:
            # eof
            return False
        if state < 3 and c == '#':
            state += 1
        elif state < 3:
            print >> sys.stderr, "invalid stub hdr %d %02x" % (state, ord(c))
            return False
        elif state == 3 and '0' <= c <= '9':
            pass
        elif state == 3 and c == ':':
            return True
        else:
            print >> sys.stderr, "invalid stub hdr %d %02x" % (state, ord(c))
            return False


def getxdmtype(line):
    m = re.match(r'XILINX-XDM V1\.\d([a-z]*)', line)
    if m:
        return m.group(1)


def rledecode(x):
    return "".join(chr(ord(x[i]) ^ (i & 15)) for i in range(len(x)))


# process Xlx file
# note: "HY" key is different for each file
def dumpxlx(fh):
    if "HY" in keys:
        keys.pop("HY")
    hasstubs = False

    if isStubFile(fh):
        secondline = fh.readline()
        hasstubs = True
    else:
        fh.seek(0)
    if hasstubs:
        subver = getxdmtype(secondline)
        #  'u': NOCOMPRESS
        #  'e': RLE
        #  '':  COMPRESS
        if subver == "e":
            yield rledecode(fh.read())
            return

    while True:
        if hasstubs:
            if not readstubhdr(fh):
                break
        chunk = readchunk(fh)
        if not chunk:
            break
        if type(chunk) == dict:
            # add HY key to keys table
            keys["HY"] = chunk
        else:
            yield chunk


# code for decoding ieee 1364-2005  type IP protection
class ProtectParser:
    # note: keyblocks can be decrypted using private key
    #        -> pkcs#1 v1.5 padded symmetric key
    #       datablock starts with IV block
    def __init__(self, args):
        self.verbose = args.verbose
        self.clear()

    def clear(self):
        self.props = {}
        self.keys = []

    @staticmethod
    def pragma_protect(line):
        # note: VHDL: `protect ...
        #    verilog: `pragma protect ...
        m = re.search(r'^\s*`(?:pragma\s+)?protect\s+(.*)', line)
        if m:
            return m.group(1)

    def moveprop(self, k, dst):
        if k in self.props:
            dst[k] = self.props[k]
            del self.props[k]

    def addkey(self, keyblock):
        kprop = {"key_block": keyblock}

        for k in ["key_keyname", "key_keyowner", "key_method", "encoding"]:
            self.moveprop(k, kprop)

        self.keys.append(kprop)

    def adddata(self, datablock):
        if "data_block" in self.props:
            print >> sys.stderr, "prot: multiple data blocks"
        self.props["data_block"] = datablock

    def parsetoken(self, text):
        m = re.match(r'\s+', text)
        if m:
            return m.end(), None, None
        m = re.match(r',', text)
        if m:
            return m.end(), None, None
        m = re.match(r'\s*(\w+)\s*=\s*"([^"]*)"', text)
        if m:
            return m.end(), m.group(1), m.group(2)
        m = re.match(r'\s*(\w+)\s*=\s*(\d+)', text)
        if m:
            return m.end(), m.group(1), int(m.group(2))

        m = re.match(r'\s*(\w+)\s*=\s*(\(.*?\))', text)
        if m:
            return m.end(), m.group(1), m.group(2)

        m = re.match(r'\s*(\w+)', text)
        if m:
            return m.end(), m.group(1), True

        print >> sys.stderr, "prot: unknown: '%s'" % text
        return 1, None, None

    def parse_properties(self, line):
        o = 0
        while o < len(line):
            r, k, v = self.parsetoken(line[o:])
            o += r
            if k is not None:
                yield k, v

    def process_file(self, fh):
        keyblock = None
        datablock = None
        for line in fh.xreadlines():
            pp = self.pragma_protect(line)
            if pp:
                # when protect line found -> close {data|key}block
                if keyblock is not None:
                    self.addkey(keyblock)
                    keyblock = None
                elif datablock is not None:
                    self.adddata(datablock)
                    datablock = None

                for k, v in self.parse_properties(pp):
                    self.props[k.lower()] = v

                # handle the various tags
                if "begin_protected" in self.props:
                    del self.props["begin_protected"]
                    self.keys = []
                elif "end_protected" in self.props:
                    del self.props["end_protected"]
                    self.decrypt()
                    self.clear()
                elif "key_block" in self.props:
                    del self.props["key_block"]
                    keyblock = ""
                elif "data_block" in self.props:
                    del self.props["data_block"]
                    datablock = ""

            # collect data
            elif keyblock is not None:
                keyblock += line
            elif datablock is not None:
                datablock += line
            else:
                # ignore plain text
                sys.stdout.write(line)

    def findkey(self, keys, keylen):
        res = None
        for k in keys:
            thiskey = None
            wrapped = self.decode(k["encoding"], k["key_block"])
#           sys.stdout.write("`unwrap: wraped=%s\n" % wrapped.encode("hex"))
            for privkey in privkeys:
                key = unwrap(privkey, wrapped)
                if key and len(key) == keylen:
                    thiskey = (key, privkey.name, k["key_keyname"], k["key_keyowner"])
                    if not self.verbose and thiskey:
                        return thiskey
            if self.verbose:
                if thiskey:
                    print "--- %s ; %s ; %s was decrypted using %s" % (k["key_keyname"], k["key_keyowner"], thiskey[0].encode("hex"), thiskey[1])
                    res = thiskey
                else:
                    print "--- %s ; %s  could not be decrypted" % (k["key_keyname"], k["key_keyowner"])
                    print k
        return res

    def decode(self, encoding, data):
        if encoding.lower().find("uuencode") > 0:
            return uudecode(data)
        return b64decode(data)

    def decrypt(self):
        key = None

        if self.props["data_method"].lower() == "aes256-cbc":
            keylength = 32
        else:  # if self.props["data_method"].lower() == "aes128-cbc":
            keylength = 16

        if self.keys:
            key = self.findkey(self.keys, keylength)
        else:
            # todo: find CDS_DATA_KEY, from ncprotect
            #       or  MTI static key
            key = None

        if key:
            key, privname, keyname, keyowner = key
            data = self.decode(self.props["encoding"], self.props["data_block"])
            if  len(data)<16:
                print "ERROR: no iv"
                return
            plain = cbcdecrypt(data[16:], {"key": key, "iv": data[0:16]})
            plain = strip_padding(plain)
            sys.stdout.write("`pragma begin_decoded privkey=\"%s\", key_keyname=\"%s\", key_keyowner=\"%s\"\n" % (privname, keyname, keyowner))
            sys.stdout.write(plain)
            sys.stdout.write("`pragma end_decoded\n")
        else:
            descriptions = ["%s:%s" % (k["key_keyowner"], k["key_keyname"]) for k in self.keys]
            if "data_keyname" in self.props:
                descriptions.append("DATAKEY/%s:%s" % (self.props["data_keyowner"], self.props["data_keyname"]))
            sys.stdout.write("`pragma protect: no known key found: %s\n" % ",".join(descriptions))


def process_protect(fh, args):
    P = ProtectParser(args)
    P.process_file(fh)



parser = argparse.ArgumentParser(description='Tool for decoding xilinx protected files, or begin_protected sections from verlog code.')
parser.add_argument('--verbose',  '-v', action='store_true', help='print info for each key')
parser.add_argument('files', type=str, metavar='FILE', nargs='*', help='a protected data file')


args = parser.parse_args()

if not args.files or (len(args.files)==1 and args.files[0]=='-'):
    process_protect(sys.stdin, args)
else:
    for fn in args.files:
        if len(args.files) > 1:
            print "==> %s <==" % (fn)
        isFirst = True
        isRecursiveStub = False
        alldata = ""
        with open(fn) as fh:
            if isBinary(fh):
                pass
            elif isXlxFile(fh) or isStubFile(fh):
                fh.seek(0)
                for chunk in dumpxlx(fh):
                    if isFirst:
                        isRecursiveStub = chunk[0:30] == "XILINX-XDB 0.1 STUB 0.1 ASCII\n"
                        isFirst = False
                    if isRecursiveStub:
                        alldata += chunk
                    else:
                        sys.stdout.write(chunk)

                # some files are doubly encoded
                if isRecursiveStub:
                    for chunk in dumpxlx(StringIO.StringIO(alldata)):
                        sys.stdout.write(chunk)
            else:
                fh.seek(0)
                process_protect(fh, args)

        if len(args.files) > 1:
            print
