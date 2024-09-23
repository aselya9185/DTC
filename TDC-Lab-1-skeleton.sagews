︠d3b4e9ce-f7c1-4077-ae00-ddd8758830c9as︠
%auto
typeset_mode(True, display=False)
︡274e43fe-04e9-4da8-98c5-4377fcff4aba︡{"done":true}
︠d3241a61-8266-496d-ae7e-989a0ebe9ebes︠
#########################################################################################
#
# PUBLIC HELPERS
#
# You can use these functions and definitions in your implementation
#
#########################################################################################

import hashlib

def doublehash(data):
    """
    Compute the double sha256 of data.

    Args:
        data (bytearray): The first parameter.

    Returns:
        bytearray: sha256(sha256(data)).
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash_160(public_key):
    """
    Compute the hash160 of public_key.

    Args:
        public_key (bytearray): The first parameter.

    Returns:
        string: hexadecimal string with ripemd160(sha256(public_key).
    """
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.hexdigest()

def public_key_to_bc_address(public_key, v=None):
    """
    Generate bitcoin P2PKH address from public key.
    https://en.bitcoin.it/w/images/en/9/9b/PubKeyToAddr.png

    Args:
        public_key (str) : hexadecimal public key.
        v (str) : hexadecimal network prefix.

    Returns:
        str : bitcoin address.
    """
    h160 = hash_160(bytearray.fromhex(public_key))
    if v == None:
        v = "00"  # mainnet network is assumed
    vh160 = v + h160
    h = doublehash(bytearray.fromhex(vh160))
    addr = bytearray.fromhex(vh160) + h[0:4]
    return b58encode(addr)

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """
    Encode v to base58.

    Args:
        v (bytearray): Bytes to encode.

    Returns:
        string: base 58 encoded string.
    """
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * c

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0: nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def b58decode(v, length=None):
    """
    decode v into a string of len bytes.
    Args:
        v (string): a base 58 encoded string.

    Returns:
        string: decoded byte array.
    """
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]: nPad += 1
        else: break

    result = chr(0)*nPad + result
    if length is not None and len(result) != length:
        return None

    return result
︡a939d2ed-2f16-45a3-8a95-56656bd917f5︡{"done":true}
︠d45318f7-eea8-42ed-90af-84d081115a71s︠
#########################################################################################
#
# BITCOIN PARAMETER VALUES
#
# You can use these definitions in your implementation
#
#########################################################################################

p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 -1
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

K = GF(p)
C = EllipticCurve(K, [ a, b ])
BTC_EC_FIXED_POINT = C.point((Gx, Gy))
︡f9c36722-3366-4c42-b8f1-541f26f6f285︡{"done":true}
︠012e7ec7-da01-45e5-9993-a86ebfd902c6s︠
# EXERCISE 1: Bitcoin key generation
#
# Function key_gen()
#
#

def key_gen():

    output = [None, None]

    #### IMPLEMENTATION GOES HERE ####



    ##################################

    return output
︡07fe6b66-e3b0-4c7d-b641-447b997e1d30︡{"done":true}
︠36f2d434-ba82-40d3-8a0a-89f946a35392s︠
# EXERCISE 2: Bitcoin public key computation
#
# Function pk_from_sk()
#
#

def pk_from_sk(sk):

    pk = None

    #### IMPLEMENTATION GOES HERE ####



    ##################################

    return pk
︡ce4535f6-6d3d-4cbd-a40a-67e8e48a1b89︡{"done":true}
︠bf1258ee-1f00-4ce3-b369-6afcadb97105s︠
# EXERCISE 3: Bitcoin WIF private key export
#
# Function sk_to_wif()
#
#

def sk_to_wif(sk, network, compressed):

    wif = ""

    #### IMPLEMENTATION GOES HERE ####


    ##################################

    return wif
︡3f16c38b-e67c-4c35-8cd5-65ae556326ca︡{"done":true}
︠f61c3c24-429e-4d8d-b5db-67c8c8a3f48bs︠
# EXERCISE 4: Bitcoin get address
#
# Function get_address()
#
#

def get_address(pk, network, compressed):

    address = ""

    #### IMPLEMENTATION GOES HERE ####



    ##################################

    return address
︡ef68f941-d6f5-46fc-84f1-c1875b19beac︡{"done":true}
︠458f789f-9ecb-441f-8be1-ecf107cc2c8ds︠
# EXERCISE 5: Vanity addresses
#
# Code to create vanity addresses from a prefix
#
#
#### IMPLEMENTATION GOES HERE ####



##################################
︡25986cc7-0697-4a9a-ba81-001c06826386︡{"done":true}
︠64b32d37-0f3c-41d7-a8f1-7f48bcff2a50s︠
####################################################################################
# TEST CASES EXERCICE 1
####################################################################################

(sk,pk)= key_gen()

if (str(type(sk)) == '<class \'sage.rings.integer.Integer\'>'):
    print ("Test 1.1 True")
else:
    print ("Test 1.1 False: Secret key variable does not have a correct type.")

if ( str(type(pk)) == '<class \'sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field\'>'):
    print ("Test 1.2 True")
else:
    print ("Test 1.2 False: Public key variable does not have a correct type.")
︡5447d4ed-f92b-421f-bc69-4026fcb6c946︡{"stdout":"Test 1.1 False: Secret key variable does not have a correct type.\n"}︡{"stdout":"Test 1.2 False: Public key variable does not have a correct type.\n"}︡{"done":true}
︠8328e793-fb3c-47e4-a03c-2e97dd8b8380s︠
####################################################################################
# TEST CASES EXERCICE 2
####################################################################################

SK = 0xa7fdb283e6f17cae5cc528dede844693833b01901da4565c0f720d243808456
PK = pk_from_sk(SK)

exp_PK = C.point((102932110615030912195251714675399137743967004457752232542823874303141694029081, 50595351503105113425370052851377959471829273805383542424721209405607880519256))

print("Test 2.1", PK == exp_PK)

SK = 0x52c9f61de317a5775cfb739fb0b2a8be272c50fd3f12d4759c69d258428b00bf
PK = pk_from_sk(SK)

exp_PK = C.point((54437664866244252025592075707005352202084641410804777694752336694468431883643, 68945548390797962169466413067814862457806470235695926355975243061659496318512))

print("Test 2.2", PK == exp_PK)
︡bbd83205-c704-4b0c-a3aa-278082f18a5a︡{"stdout":"Test 2.1 False\n"}︡{"stdout":"Test 2.2 False\n"}︡{"done":true}
︠c88f19c3-5e1a-4fb3-9b89-aa6f7b3be723s︠
####################################################################################
# TEST CASES EXERCICE 3
####################################################################################

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'MAINET', compressed = False)

exp_wif = '5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn'

print ("Test 3.1", wif == exp_wif)

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'MAINET', compressed = True)

exp_wif = 'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ'

print ("Test 3.2", wif == exp_wif)

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'TESTNET', compressed = False)

exp_wif = '91pPmKypfMGxN73N3iCjLuwBjgo7F4CpGQtFuE9FziSieVTY4jn'

print ("Test 3.3", wif == exp_wif)

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'TESTNET', compressed = True)

exp_wif = 'cNcBUemoNGVRN9fRtxrmtteAPQeWZ399d2REmX1TBjvWpRfNMy91'

print ("Test 3.4", wif == exp_wif)
︡98a19074-b545-4d50-9299-c6395dbb0882︡{"stdout":"Test 3.1 False\n"}︡{"stdout":"Test 3.2 False\n"}︡{"stdout":"Test 3.3 False\n"}︡{"stdout":"Test 3.4 False\n"}︡{"done":true}
︠1334a995-4de1-46a4-b76e-17a981eb136bs︠
####################################################################################
# TEST CASES EXERCICE 4
####################################################################################

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', False)

exp_address = '1thMirt546nngXqyPEz532S8fLwbozud8'

print("Test 4.1", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', False)

exp_address = 'mgQeemwrt5Y3Zo1TgxDMtxEkzeweW3gXAg'

print("Test 4.2", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', True)
exp_address = '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'

print("Test 4.3", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', True)

exp_address = 'mj8v7r8KzDyoHK9rpdQtHYq6piRVCKpVSV'

print("Test 4.4", address == exp_address)
︡f02bd1ed-ecd8-4c83-8add-369aa99182ab︡{"stdout":"Test 4.1 False\n"}︡{"stdout":"Test 4.2 False\n"}︡{"stdout":"Test 4.3 False\n"}︡{"stdout":"Test 4.4 False\n"}︡{"done":true}
︠f197b2e4-9417-473c-93dd-ba541d2b393as︠
︡8de0555e-508a-4361-90e4-c24ed009f5e6︡{"done":true}









