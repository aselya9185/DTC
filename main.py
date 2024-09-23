# Import necessary modules
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, PublicKey

def generate_keys_and_save(filename):
    # Always remember to setup the network
    setup("testnet")  # Use testnet
    print(f"Private key exported to {filename}.")
    # Create a private key (randomly)
    priv = PrivateKey()
    wif = priv.to_wif(compressed=True)
    print("\nPrivate key WIF:", wif)

    # Get the public key
    pub = priv.get_public_key()
    print("Public key:", pub.to_hex(compressed=True))

    # Get address from public key
    address = pub.get_address()
    print("Address:", address.to_string())
    print("Hash160:", address.to_hash160())

    with open(filename, 'w') as f:
        f.write("Private key: {}\n".format(wif))
        f.write("Public key: {}\n".format(pub.to_hex(compressed=True)))
        f.write("Address: {}\n".format(address.to_string()))
        f.write("Hash160: {}\n".format(address.to_hash160()))

    print("\n--------------------------------------\n")
    return address.to_string()

def main():

    # THE COMMENTED CODE WAS USED TO CALL THE generate_keys_and_save()
    # THE GENERATED KEYS AND ADDRESSES WERE SAVED TO FILES
    #
    #
    # Generate and save keys for k1
    # k1_address = generate_keys_and_save("k1")
    #
    # # Generate and save keys for k2
    # k2_address = generate_keys_and_save("k2")
    #
    # # Generate and save keys for k3
    # k3_address = generate_keys_and_save("k3")
    #
    #
    # # # Print the addresses generated
    # # print("k1 Address:", k1_address)
    # # print("k2 Address:", k2_address)
    # # print("k3 Address:", k3_address)
    #
    # with open('k1', 'r') as f:
    #     print("k1: \n", f.read())
    # with open('k2', 'r') as f:
    #     print("k2: \n", f.read())
    # with open('k3', 'r') as f:
    #     print("k3: \n", f.read())


if __name__ == "__main__":
    main()