︠d3b4e9ce-f7c1-4077-ae00-ddd8758830c9a︠
%auto
typeset_mode(True, display=False)
︡a454fe63-ccd4-4ae1-b437-3c3d527f221d︡{"done":true}
︠d3241a61-8266-496d-ae7e-989a0ebe9ebes︠
#########################################################################################
#
# PUBLIC HELPERS
#
# You can use these functions and definitions in your implementation
#
#########################################################################################

import hashlib
import time

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
︡ae6b83fa-d199-4117-9125-0f5d7b57a1b7︡{"done":true}
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
# print(BTC_EC_FIXED_POINT)
︡19d812df-b9cf-4676-b2fd-7258e11f9e4a︡{"done":true}
︠012e7ec7-da01-45e5-9993-a86ebfd902c6s︠
# EXERCISE 1: Bitcoin key generation
#
# Function key_gen()
#
#

def key_gen():

    d = ZZ(GF(C.cardinality()).random_element())    # private key, generate a random element
    pd = BTC_EC_FIXED_POINT * d      # Public key
    return [d, pd]

︡7897947e-0d6d-43d0-962d-efb727ecfeb5︡{"done":true}
︠36f2d434-ba82-40d3-8a0a-89f946a35392s︠
# EXERCISE 2: Bitcoin public key computation
#
# Function pk_from_sk()
#
#

def pk_from_sk(sk):

    pk = BTC_EC_FIXED_POINT * sk

    return pk
︡569ac1bf-4849-4066-838f-804a1b910f54︡{"done":true}
︠bf1258ee-1f00-4ce3-b369-6afcadb97105s︠
# EXERCISE 3: Bitcoin WIF private key export
#
# Function sk_to_wif()
#
#

def sk_to_wif(sk, network, compressed):
# sk should be in hex

#     print("sk: ", sk, "with type: ", type(sk))

    # 1. Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses.
    if network == 'MAINET':
        prefix = '80'
    elif network == 'TESTNET':
        prefix = 'ef'

    # 2. add a 0x01 byte at the end if the private key will correspond to a compressed public key.
    if compressed == True:
        suffix = '01'
    else:
        suffix = ''

#     print("prefix: ", prefix, "with type: ", type(prefix))
#     print("suffix: ", suffix, "with type: ", type(suffix))


    extended_key = prefix + sk + suffix
#     print("extended key: ", extended_key, "with type: ", type(extended_key))

    extended_key_bytes = bytearray.fromhex(extended_key)
#     print("extended_key_bytes: ", extended_key_bytes, "with type: ", type(extended_key_bytes))

    # 3. Perform SHA-256 hash on the extended key.
    # 4. Perform SHA-256 hash on result of SHA-256 hash.
    dhash = doublehash(extended_key_bytes)
#     print("dhash: ", dhash, "with type: ", type(dhash))

    # 5. Take the first 4 bytes of the second SHA-256 hash; this is the checksum.
    checksum = dhash[:4]
#     print("checksum: ", checksum, "with type: ", type(checksum))

    # 6. Add the 4 checksum bytes from point 5 at the end of the extended key from point 2.
    wif_bytes = extended_key_bytes + checksum

    # 7. Convert the result from a byte string into a base58 string using Base58Check encoding. This is the wallet import format (WIF).
    wif = b58encode(wif_bytes)
    return wif

︡2e427784-8380-482a-b701-3126e8a2e40f︡{"done":true}
︠f61c3c24-429e-4d8d-b5db-67c8c8a3f48bs︠
# EXERCISE 4: Bitcoin get address
#
# Function get_address()
#
#

def get_address(pk, network, compressed):

#     print("pk: ", pk, " type: ", type(pk))
# pk:  (41637322786646325214887832269588396900663353932545912953362782457239403430124 : 16388935128781238405526710466724741593761085120864331449066658622400339362166 : 1)  type:  <class 'sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field'>

    x = pk.xy()[0]
    y = pk.xy()[1]

#     print("x: ", x, "with type: ", type(x))
#     print("y: ", y, "with type: ", type(y))

#     # Convert coordinates to hexadecimal
    x_hex = hex(x)[2:]
    y_hex = hex(y)[2:]

#     print("x_hex: ", x_hex, "with type: ", type(x_hex))
#     print("y_hex: ", y_hex, "with type: ", type(y_hex))

# Implement case when compressed = True
    if compressed:
        compressed_public_key = '02'
        compressed_public_key += x_hex
        pk_hex = compressed_public_key

    else:
        # Concatenate x and y coordinates for uncompressed public key
        pk_hex = '04' + x_hex + y_hex
#     print("pk_hex: ", pk_hex)
#     pk_hex:  045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176

    # Determine the network prefix
    if network == 'MAINET':
        prefix = '00'
    elif network == 'TESTNET':
        prefix = '6f'


    # Generate the Bitcoin address using public_key_to_bc_address function
    address = public_key_to_bc_address(pk_hex, v=prefix)
#     print("ADDRESS: ", address)

    return address

︡62fa09aa-ab7f-4463-ba64-097ff834b1bb︡{"done":true}
︠458f789f-9ecb-441f-8be1-ecf107cc2c8ds︠
# EXERCISE 5: Vanity addresses
#
# Code to create vanity addresses from a prefix
#
#

def create_vanity_address(prefix):
    start_time = time.time()
    count = 0
    while True:
        (sk,pk)= key_gen()
#         print("sk: ", sk, "pk: ", pk)

        address = get_address(pk,'MAINET', False)
#         print("ADDRESS: ", address, "with type: ", type(address))

#         print("private key: ", sk)
        sk_hex = hex(sk)[2:]
#         print("private key in hex: ", sk_hex, "with type: ", type(sk_hex))
        wif_sk = sk_to_wif(sk_hex, 'MAINET', False)
#         print("WIF private key: ", wif_sk, "with type: ", type(wif_sk))

        count += 1
        print("count: ", count)

        # Check if the address starts with the desired prefix
        if address.startswith(prefix):
            end_time = time.time()
            time_taken = end_time - start_time
            return address, wif_sk, time_taken


︡adb49e45-ab15-4fdd-83ca-ea541d621f5a︡{"done":true}
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
︡42bbdbdb-80fc-4c42-91b8-051f1a44097e︡{"stdout":"Test 1.1 True\n"}︡{"stdout":"Test 1.2 True\n"}︡{"done":true}
︠8328e793-fb3c-47e4-a03c-2e97dd8b8380s︠
####################################################################################
# TEST CASES EXERCICE 2
####################################################################################

SK = 0xa7fdb283e6f17cae5cc528dede844693833b01901da4565c0f720d243808456
PK = pk_from_sk(SK)
# print("PK: ", PK)
exp_PK = C.point((102932110615030912195251714675399137743967004457752232542823874303141694029081, 50595351503105113425370052851377959471829273805383542424721209405607880519256))

print("Test 2.1", PK == exp_PK)

SK = 0x52c9f61de317a5775cfb739fb0b2a8be272c50fd3f12d4759c69d258428b00bf
PK = pk_from_sk(SK)

exp_PK = C.point((54437664866244252025592075707005352202084641410804777694752336694468431883643, 68945548390797962169466413067814862457806470235695926355975243061659496318512))

print("Test 2.2", PK == exp_PK)
︡eceb0aef-12b4-4958-814f-58e846784333︡{"stdout":"Test 2.1 True\n"}︡{"stdout":"Test 2.2 True\n"}︡{"done":true}
︠c88f19c3-5e1a-4fb3-9b89-aa6f7b3be723so︠
####################################################################################
# TEST CASES EXERCICE 3
####################################################################################

sk = '1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd'
# print(type(sk))
wif = sk_to_wif(sk,'MAINET', compressed = False)

exp_wif = '5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn'

print ("Test 3.1", wif == exp_wif)

sk = '1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd'
wif = sk_to_wif(sk,'MAINET', compressed = True)

exp_wif = 'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ'

print ("Test 3.2", wif == exp_wif)

sk = '1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd'
wif = sk_to_wif(sk,'TESTNET', compressed = False)

exp_wif = '91pPmKypfMGxN73N3iCjLuwBjgo7F4CpGQtFuE9FziSieVTY4jn'

print ("Test 3.3", wif == exp_wif)

sk = '1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd'
wif = sk_to_wif(sk,'TESTNET', compressed = True)

exp_wif = 'cNcBUemoNGVRN9fRtxrmtteAPQeWZ399d2REmX1TBjvWpRfNMy91'

print ("Test 3.4", wif == exp_wif)
︡4383771d-e0d8-4fd5-a771-4fe2ba7ee8d0︡{"stdout":"Test 3.1 True\n"}︡{"stdout":"Test 3.2 True\n"}︡{"stdout":"Test 3.3 True\n"}︡{"stdout":"Test 3.4 True\n"}︡{"done":true}
︠1334a995-4de1-46a4-b76e-17a981eb136bs︠
####################################################################################
# TEST CASES EXERCICE 4
####################################################################################

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', False)

exp_address = '1thMirt546nngXqyPEz532S8fLwbozud8'
# print("EXP_ADDRESS: ", exp_address)
print("Test 4.1", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', False)

exp_address = 'mgQeemwrt5Y3Zo1TgxDMtxEkzeweW3gXAg'
# print("EXP_ADDRESS: ", exp_address)
print("Test 4.2", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', True)
exp_address = '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'
# print("EXP_ADDRESS: ", exp_address)
print("Test 4.3", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', True)

exp_address = 'mj8v7r8KzDyoHK9rpdQtHYq6piRVCKpVSV'
# print("EXP_ADDRESS: ", exp_address)
print("Test 4.4", address == exp_address)
︡97592d58-b8c3-4613-bab7-3c3bc4203652︡{"stdout":"Test 4.1 True\n"}︡{"stdout":"Test 4.2 True\n"}︡{"stdout":"Test 4.3 True\n"}︡{"stdout":"Test 4.4 True\n"}︡{"done":true}
︠6b5464a1-225f-4d15-b6f7-1f5313718c4f︠
####################################################################################
# TEST CASES EXERCICE 5
####################################################################################

prefixes = ["1TBC", "qTBC"]
prefix = "1TBC"
vanity_address, wif_sk, time_taken = create_vanity_address(prefix)
print("vanity_address: ", vanity_address, "\nprivate key: ", wif_sk, "\nTime taken: ", time_taken)

︡bcff1223-d8f9-406d-b17e-5c268d916a94︡{"stdout":"count:  1\ncount:  2\ncount:  3\ncount:  4\ncount:  5\ncount:  6\ncount:  7\ncount:  8\ncount:  9\ncount:  10\ncount:  11\ncount:  12\n"}︡{"stderr":"Error in lines 3-3\nTraceback (most recent call last):\n  File \"/cocalc/lib/python3.11/site-packages/smc_sagews/sage_server.py\", line 1244, in execute\n    exec(\n  File \"\", line 1, in <module>\n  File \"\", line 8, in create_vanity_address\n  File \"\", line 11, in sk_to_wif\nValueError: non-hexadecimal number found in fromhex() arg at position 65\n"}︡{"done":true}









