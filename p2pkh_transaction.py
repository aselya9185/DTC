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

    # The pointer to a UTXO consists of the transaction hash and the output index, which starts at 0
    txid = "50c550eeefd67a5828a09308af1c3511a94984b7a440052f2c16624e0c6c1e28"
    tx_index = 1  # Index of the output in the transaction
    sat_input_amount = to_satoshis(0.00051005)  # Amount of Satoshis in the UTXO
    sat_output_amount = to_satoshis(0.0001)

    # create transaction input from tx id of UTXO
    txin = TxInput(txid, tx_index)

    # create transaction output using P2PKH scriptPubKey transferring bitcoins to k2's address
    k2_addr = P2pkhAddress("mhvU7t1GYaiFtrRgUwAF9EoB4c3NYLRKHR")
    txout = TxOutput(sat_output_amount,
                     Script(
                         ["OP_DUP", "OP_HASH160", k2_addr.to_hash160(), "OP_EQUALVERIFY", "OP_CHECKSIG"]
                     ),
                )

    # # create another output to get the change - remaining 0.01 is tx fees
    # # note that this time we used to_script_pub_key() to create the P2PKH
    # # script
    # change_addr = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
    # change_txout = TxOutput(to_satoshis(0.29), change_addr.to_script_pub_key())
    # # change_txout = TxOutput(to_satoshis(0.29), Script(['OP_DUP', 'OP_HASH160',
    # #                                     change_addr.to_hash160(),
    # #                                     'OP_EQUALVERIFY', 'OP_CHECKSIG']))

    # create transaction from inputs/outputs
    tx = Transaction([txin], [txout])

    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())

    # use the private key corresponding to the k1's address to sign the transaction
    sk_k1 = PrivateKey("cQg3M3oRop3N7X7MzRqgz1aLDEGZVE3bCMV5UcovTUu6r5z2SuGw")
    k1_addr = P2pkhAddress("mfbJ8as397hBcTBrWCJoYWSox3ghMUuqLM")
    sig = sk_k1.sign_input(tx, 0,
                           Script(
                               [
                                   "OP_DUP",
                                   "OP_HASH160",
                                   k1_addr.to_hash160(),
                                   "OP_EQUALVERIFY",
                                   "OP_CHECKSIG",
                               ]
                           ),
                        )

    print("sig: ", sig)

    # get public key as hex
    pk = sk_k1.get_public_key().to_hex()

    # set the scriptSig (unlocking script)
    txin.script_sig = Script([sig, pk])
    signed_tx = tx.serialize()

    signed_tx_bytes = tx.get_size()

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + signed_tx)

    # Calculate the fees paid
    sat_fees = sat_input_amount - sat_output_amount

    # Calculate satoshis per byte
    sat_per_byte = sat_fees / signed_tx_bytes

    print("\nInput amount: {:.8f} BTC".format(sat_input_amount / 1e8))
    print("Amount transferred: {:.8f} BTC".format(sat_output_amount / 1e8))
    print("Fees paid: {:.8f} BTC".format(sat_fees / 1e8))
    print("Total amount of satoshis paid as fee: {}".format(sat_fees))
    print("Number of bytes in the transaction: {}".format(str(signed_tx_bytes)))
    print("Satoshis per byte: {:.2f}".format(sat_per_byte))

if __name__ == "__main__":
    main()
