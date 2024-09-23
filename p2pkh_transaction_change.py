# Copyright (C) 2018-2022 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.


from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress, PrivateKey
from bitcoinutils.script import Script


def main():
    # always remember to setup the network
    setup("testnet")

    txid = "b2fc1963cb5a878419a97669e9e4e592a6a3db8b31886bad81d7d355283e7fb2"
    tx_index = 0  # Index of the output in the transaction
    sat_input_amount = to_satoshis(0.0001)  # Amount of Satoshis in the UTXO
    sat_output_amount = to_satoshis(0.00002)   # to friend k1
    sat_fees = to_satoshis(0.00008)

    # Calculate change
    sat_change_amount = sat_input_amount - sat_output_amount - sat_fees     # to k3

    # create transaction input from tx id of UTXO
    txin = TxInput(txid, tx_index)

    # create transaction output using P2PKH scriptPubKey (locking script)
    addr_friend = P2pkhAddress("mfbJ8as397hBcTBrWCJoYWSox3ghMUuqLM")    # friend's address
    txout = TxOutput(
        sat_output_amount,
        Script(
            ["OP_DUP", "OP_HASH160", addr_friend.to_hash160(), "OP_EQUALVERIFY", "OP_CHECKSIG"]
        ),
    )

    # create another output to get the change - remaining 0.01 is tx fees
    # note that this time we used to_script_pub_key() to create the P2PKH
    # script
    change_addr = P2pkhAddress("mxTs6e9PKdvLNCCTcsm8u1otdoQ9hTDg21")    # k3 address
    change_txout = TxOutput(sat_change_amount, change_addr.to_script_pub_key())
    # change_txout = TxOutput(to_satoshis(0.29), Script(['OP_DUP', 'OP_HASH160',
    #                                     change_addr.to_hash160(),
    #                                     'OP_EQUALVERIFY', 'OP_CHECKSIG']))

    # create transaction from inputs/outputs -- default locktime is used
    tx = Transaction([txin], [txout, change_txout])

    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())

    # use the private key corresponding to the address that contains the
    # UTXO we are trying to spend to sign the input
    sk = PrivateKey("cVgu2nup3NfNjTKp2ZNNGxGtjY8BGRNQeKDosZtvSiW39WY49vNo")

    # note that we pass the scriptPubkey as one of the inputs of sign_input
    # because it is used to replace the scriptSig of the UTXO we are trying to
    # spend when creating the transaction digest
    from_addr = P2pkhAddress("mhvU7t1GYaiFtrRgUwAF9EoB4c3NYLRKHR")
    sig = sk.sign_input(
        tx,
        0,
        Script(
            [
                "OP_DUP",
                "OP_HASH160",
                from_addr.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
    )
    # print(sig)

    # get public key as hex
    pk = sk.get_public_key().to_hex()

    # set the scriptSig (unlocking script)
    txin.script_sig = Script([sig, pk])
    signed_tx = tx.serialize()

    signed_tx_bytes = tx.get_size()

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + signed_tx)

    # print the size of the final transaction
    print("\nSigned transaction size (in bytes):\n" + str(signed_tx_bytes))

    # Calculate satoshis per byte
    sat_per_byte = sat_fees / signed_tx_bytes

    print("\nAmount transferred to friend: {:.8f} BTC".format(sat_output_amount / 1e8))
    print("Fees paid: {:.8f} BTC".format(sat_fees / 1e8))
    print("Total amount of satoshis paid as a fee:", sat_fees)
    print("Number of satoshis per byte:", sat_per_byte)

if __name__ == "__main__":
    main()
