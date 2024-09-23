︠5743a866-e09e-44c6-b5a1-a475a4154ba2s︠
f=x^4 + x + 1
k.<a> = GF(2^4, modulus=f)
b = [a for a in k.list()][1]
R.<x> = k[]
g = x^2 + x + b^3
L = [c for c in k.list()][2:14]
C = codes.GoppaCode(g, L)
G = C.generator_matrix()
H = C.parity_check_matrix()

print("C: \n", C)
print("G: \n", G)
print("H: \n", H)
︡d7532213-7d56-455a-b83d-8a5a82c16b8a︡{"stdout":"C: \n [12, 4] Goppa code over GF(2)\n"}︡{"stdout":"G: \n [1 0 0 0 0 1 1 1 0 1 1 0]\n[0 1 0 0 1 1 0 0 1 0 1 1]\n[0 0 1 0 0 1 1 0 1 1 1 1]\n[0 0 0 1 0 0 1 1 1 1 0 0]\n"}︡{"stdout":"H: \n [0 0 1 0 1 0 0 0 0 0 0 1]\n[0 1 1 1 0 0 0 0 1 0 0 0]\n[0 0 0 0 1 1 0 1 0 1 1 1]\n[1 1 0 0 0 1 1 1 0 0 0 0]\n[0 1 1 0 1 1 0 1 0 1 1 0]\n[1 1 0 0 0 0 1 0 1 0 0 0]\n[1 1 1 1 0 1 1 0 1 1 0 1]\n[0 1 0 1 1 1 1 0 1 1 1 1]\n"}︡{"done":true}
︠a14dff36-a7f0-40aa-9c74-61d2b06a4ebcs︠
P_values = [
           [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
           [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
           [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
           [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
           [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
           [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
           [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
           [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
           ]
P_zero_matrix = matrix(ZZ, 12, 12)
# print(P_zero_matrix)
P = matrix(ZZ, P_values)

print("P:\n", P)
︡8d036d39-988b-4a17-a8ba-8775927a053a︡{"stdout":"P:\n [1 0 0 0 0 0 0 0 0 0 0 0]\n[0 1 0 0 0 0 0 0 0 0 0 0]\n[0 0 1 0 0 0 0 0 0 0 0 0]\n[0 0 0 0 0 0 0 0 1 0 0 0]\n[0 0 0 0 1 0 0 0 0 0 0 0]\n[0 0 0 1 0 0 0 0 0 0 0 0]\n[0 0 0 0 0 1 0 0 0 0 0 0]\n[0 0 0 0 0 0 0 1 0 0 0 0]\n[0 0 0 0 0 0 1 0 0 0 0 0]\n[0 0 0 0 0 0 0 0 0 1 0 0]\n[0 0 0 0 0 0 0 0 0 0 1 0]\n[0 0 0 0 0 0 0 0 0 0 0 1]\n"}︡{"done":true}
︠c98b6d13-cc09-4779-af44-6b2c7d8282a3s︠
S_values = [
           [1, 0, 0, 1],
           [0, 1, 0, 1],
           [0, 1, 0, 0],
           [0, 0, 1, 1]
           ]
S_zero_matrix = matrix(ZZ, 4, 4)
# print(S_zero_matrix)
S = matrix(ZZ, S_values)

print("S:\n", S)
︡9d3458cc-fb57-46e8-b1d1-8d93a02583eb︡{"stdout":"S:\n [1 0 0 1]\n[0 1 0 1]\n[0 1 0 0]\n[0 0 1 1]\n"}︡{"done":true}
︠3d8e4d26-3e28-44ae-979c-8fabc8d4b309s︠
G_pub = S * G * P
print("G_pub \n", G_pub)
︡511559e0-18a9-45fb-b5d7-dd8a7de48ca6︡{"stdout":"G_pub \n [1 0 0 1 0 0 1 0 1 0 1 0]\n[0 1 0 1 1 1 0 1 1 1 1 1]\n[0 1 0 1 1 0 1 0 0 0 1 1]\n[0 0 1 1 0 0 0 1 1 0 1 1]\n"}︡{"done":true}
︠7ba144a5-b017-47e7-a7ea-b4dc8eb62fefs︠
# PUBLIC KEY

t = 2
PK = [G_pub, t]
print(PK)
︡3561d5fc-7db2-46af-a7d1-50fa616bc3ac︡{"stdout":"[[1 0 0 1 0 0 1 0 1 0 1 0]\n[0 1 0 1 1 1 0 1 1 1 1 1]\n[0 1 0 1 1 0 1 0 0 0 1 1]\n[0 0 1 1 0 0 0 1 1 0 1 1], 2]\n"}︡{"done":true}
︠cec38b60-1c6f-4f2d-8079-eee2ff4ea576s︠
# Sending a message

m = vector(k, [1, 0, 1, 1])                                # message
e = vector(k, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])        # random error vector

c_encr = m * G_pub                                         # encrypt the message without error
print("encrypted message without error: \n", c_encr)

c = m * G_pub + e                                          # encrypt the message adding the error
print("\nencrypted message with error: \n", c)
︡ab85deb7-12c8-4a3d-8bdc-c1dcff5994e3︡{"stdout":"encrypted message without error: \n (1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0)\n"}︡{"stdout":"\nencrypted message with error: \n (1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0)\n"}︡{"done":true}
︠ffab8dc5-ba96-4918-a720-e0c795fa2725s︠
# Decoding

def HammingDecodeVector(H, c):
    print("\nencrypted message with error: \n", c)            # (1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0)

    s = c*H.transpose()                                       # calculate the syndrome
    print("syndrome:\n", s)

    if s == vector(k, [0,0,0,0,0,0,0,0]):
        print("no syndrome found")
    else:
        print("syndrome found")
        while s != vector(k, [0,0,0,0,0,0,0,0]):
            for i in range(H.ncols()):
                if H.column(i) == s:
                    print("Error found in position:", i)
                    c[i] = 1 - c[i]                            # (1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0) + (0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
                    print("Corrected vector (c + error):\n", c)


                    s = c*H.transpose()


        return c

print('H:\n',H)
corrected = HammingDecodeVector(H, c)

S_inverse = S.inverse()
print("corrected[:4]: ", corrected[:4])
print("S_inverse: ", S_inverse)
message = corrected[:4] * S_inverse
print("\nDecrypted message: \n", message)


︡d3c9279b-3ba2-40cc-82f4-cb5a3f7f2dd1︡{"stdout":"H:\n [0 0 1 0 1 0 0 0 0 0 0 1]\n[0 1 1 1 0 0 0 0 1 0 0 0]\n[0 0 0 0 1 1 0 1 0 1 1 1]\n[1 1 0 0 0 1 1 1 0 0 0 0]\n[0 1 1 0 1 1 0 1 0 1 1 0]\n[1 1 0 0 0 0 1 0 1 0 0 0]\n[1 1 1 1 0 1 1 0 1 1 0 1]\n[0 1 0 1 1 1 1 0 1 1 1 1]\n"}︡{"stdout":"\nencrypted message with error: \n (1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0)\nsyndrome:\n (0, 0, 1, 1, 1, 0, 1, 1)\nsyndrome found\nError found in position: 5\nCorrected vector (c + error):\n (1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0)\n"}︡{"stdout":"corrected[:4]:  (1, 1, 1, 0)\n"}︡{"stdout":"S_inverse:  [ 1 -1  1  0]\n[ 0  0  1  0]\n[ 0 -1  1  1]\n[ 0  1 -1  0]\n"}︡{"stderr":"Error in lines 22-22\nTraceback (most recent call last):\n  File \"/cocalc/lib/python3.11/site-packages/smc_sagews/sage_server.py\", line 1244, in execute\n    exec(\n  File \"\", line 1, in <module>\n  File \"sage/structure/element.pyx\", line 3599, in sage.structure.element.Vector.__mul__\n    return coercion_model.bin_op(left, right, mul)\n  File \"sage/structure/coerce.pyx\", line 1248, in sage.structure.coerce.CoercionModel.bin_op\n    raise bin_op_exception(op, x, y)\nTypeError: unsupported operand parent(s) for *: 'Vector space of dimension 4 over Finite Field in a of size 2^4' and 'Full MatrixSpace of 4 by 4 dense matrices over Rational Field'\n"}︡{"done":true}









