import json
import argparse
import socket
import random
import numpy as np
from datetime import datetime
from py_ecc.bn128 import *
from web3 import Web3
from collections import defaultdict
from typing import List, Tuple
from mpyc.runtime import mpc
from helper import *

# Setup Argument Parser
def setup_parser():
    parser = argparse.ArgumentParser(description="Anonymous Credentials Registration")
    parser.add_argument("--number-of-attribute", type=int, default=10, help="Maximum number of attributes issuer can sign.")
    parser.add_argument("--req-ip", type=str, default='127.0.0.1', help="IP where the organization is running.")
    parser.add_argument("--req-port", type=str, required=True, help="Port on which the organization is running.")
    parser.add_argument("--address", type=str, required=True, help="Blockchain address of the organization.")
    parser.add_argument("--rpc-endpoint", type=str, required=True, help="Node RPC endpoint for blockchain connection.")
    parser.add_argument("--Issuer", type=str, required=True, help="Issuer ID")
    return parser.parse_args()

# Blockchain Setup
def setup_blockchain_connection(rpc_endpoint):
    w3 = Web3(Web3.HTTPProvider(rpc_endpoint, request_kwargs={'timeout': 300}))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to the Ethereum node.")
    return w3

# Load Contract Files
def load_contracts():
    with open('./build/contracts/RequestCredential.json') as f:
        user_abi = json.load(f)
    with open('./build/contracts/IssueCredential.json') as f:
        issuer_abi = json.load(f)
    with open('./build/contracts/SetupPublicParams.json') as f:
        setup_abi = json.load(f)
    return user_abi, issuer_abi, setup_abi


# Class Definitions
class Commitments:
    def __init__(self, commitments: List[bytes]):
        self.commitments = commitments

class Issuer:
    def __init__(self, id, shares_and_salts: List[Tuple[int, bytes]]):
        self.id = id
        self.own_shares_and_salts = shares_and_salts
        self.other_commitments = {}
        self.other_shares = defaultdict(list)

    @staticmethod
    def commit(rng, id, batch_size):
        shares_and_salts = [(random.getrandbits(256), rng.bytes(32)) for _ in range(batch_size)]
        commitments = Issuer.compute_commitments(shares_and_salts)
        return Issuer(id, shares_and_salts), Commitments(commitments)

    def receive_commitment(self, sender_id, commitments):
        if self.id == sender_id:
            raise ValueError("Sender ID cannot be the same as self ID")
        if sender_id in self.other_commitments:
            raise ValueError("Already have commitment from participant")
        if len(self.own_shares_and_salts) != len(commitments.commitments):
            raise ValueError("Incorrect number of commitments")
        self.other_commitments[sender_id] = commitments

    def receive_shares(self, sender_id, shares_and_salts: List[Tuple[int, bytes]]):
        if self.id == sender_id:
            raise ValueError("Sender ID cannot be the same as self ID")
        if sender_id not in self.other_commitments:
            raise ValueError("Missing commitment from participant")
        if sender_id in self.other_shares:
            raise ValueError("Already have shares from participant")
        if len(self.own_shares_and_salts) != len(shares_and_salts):
            raise ValueError("Incorrect number of shares")
        self.other_shares[sender_id] = [share for share, _ in shares_and_salts]

    def compute_joint_randomness(self):
        joint_randomness = []
        for i in range(len(self.own_shares_and_salts)):
            sum_value = self.own_shares_and_salts[i][0]
            for shares in self.other_shares.values():
                sum_value += shares[i]
            joint_randomness.append(sum_value)
        return joint_randomness

    @staticmethod
    def compute_commitments(shares_and_salts):
        return [hash_function(share, salt) for share, salt in shares_and_salts]


# PK-SK Pair Retrieval
def get_pk_sk_pair(args):
    global sk, X, pk
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.req_ip, 3000))
        s.sendall(args.Issuer.encode('utf-8'))

        # Accumulate data in chunks
        received_data = []
        while True:
            data = s.recv(1024)
            if not data:
                break
            received_data.append(data)

        # Process received pk_sk_pair
        pk_sk_pair = b''.join(received_data).decode('utf-8')
        # print(f"pk_sk_pair: {pk_sk_pair}")
        pk, sk, X = pk_sk_pair.split(":")
        sk = int(sk.split("\"")[0])
        pk = pk.split("\"")[1]
    print_with_timestamp("Got pk and sk")

# MPC Setup
async def generate_H0():
    await mpc.start()
    global H0
    issuer_id = mpc.pid

    np_rng = np.random.default_rng()
    issuer, commitments = Issuer.commit(np_rng, issuer_id, 1)
    commitments_share = await mpc.transfer(commitments.commitments)

    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_commitment(party_id, Commitments(commitments_share[party_id]))

    shares = await mpc.transfer(issuer.own_shares_and_salts)
    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_shares(party_id, shares[party_id])

    H0 = issuer.compute_joint_randomness()
    print_with_timestamp(f"Issuer {issuer_id} Computed H0 Jointly via MPC: {H0}")
    await mpc.shutdown()

def generate_H():
    global H_values_G1, H0
    L = args.number_of_attribute
    H_values = deterministic_random_oracle(H0[0], L)
    H_values.insert(0, H0[0])

    for value in enumerate(H_values):
        H = hashG1(str(value).encode('utf-8'))
        H_values_G1.append(H)
    print_with_timestamp("Generated All Public Parameter")

def issuer_public_parameter():
    if issuer_id == 0:
        _H = [[h[0].n, h[1].n] for h in H_values_G1]
        transaction = setup_contract.functions.sendPublicParam(tuple(_H), X).transact({
            'from': issuer_address,
        })
        print_with_timestamp(f"Issuer {issuer_id} has published the public parameters in blockahin.")

def listen_broadcast_sig_req():
    global attributes, sig_id, s_id, B_dash, k, c, no_of_private_attribute
    # time.sleep(5)
    try:
        request_filter = user_contract.events.SigReqBroadcast.create_filter(from_block="latest")
        entries = request_filter.get_all_entries()
        if entries:
            # print_with_timestamp("Event log entries:", entries)
            s_id = entries[0]['args']['sid']
            sig_id = entries[0]['args']['sigid']
            attributes = entries[0]['args']['attribute']
            no_of_private_attribute = entries[0]['args']['no_of_private_attribute']
            B_dash = entries[0]['args']['B_dash']
            k = entries[0]['args']['k']
            c = entries[0]['args']['c']
            print_with_timestamp(f"attributes:  {attributes}")
        else:
            # print_with_timestamp("No events found")  # Moved print_with_timestamp above return
            return
    except Exception as e:
        print_with_timestamp(f"An error occurred while listening for events: {e}")


def listen_attribute():
    global r_i, r_value, s, H_values_G1, attributes, B_dash, no_of_private_attribute

    # print_with_timestamp(f"Length of attributes: {len(attributes)}")
    while(len(attributes)==0):
        listen_broadcast_sig_req()
    # verify(B_dash, k, c)
    print_with_timestamp("Got attributes and ZKPOK from user via blockain")
    print_with_timestamp("ZKPOK already verified in blockchain....")

# Secure Computation Functions
async def mpc_compute_partial_cred():
    global sk, issuer_id, e, r_value, u_i, o, lemda_i
    issuers = len(mpc.parties)

    secnum = mpc.SecFld(o)
    secure_e_value = secnum(random.randint(2, o))

    await mpc.start()
    combined_e = await secure_addition(secure_e_value)
    await mpc.shutdown()

    e = int(combined_e) % o
    r_value = (random.randint(2, o) * (issuer_id + 1)) % o

    secure_r_value = secnum(r_value)
    indexes = [i + 1 for i in range(issuers)]
    lagrange_value = lagrange_basis(indexes, issuer_id + 1, o, x=0)
    secret_share = (lagrange_value * sk) % o
    secure_secret_share = secnum(secret_share)
    r_multiply_x = 0

    for i in range(issuers):
        if i == mpc.pid:
            await mpc.start()
            lemda_i = await secure_multiplier(secure_r_value, 1, secure_secret_share, i)
            r_multiply_x = lemda_i + r_value * secret_share
            await mpc.shutdown()
        else:
            await mpc.start()
            await secure_multiplier(secure_r_value, 2, secure_secret_share, i)
            await mpc.shutdown()

    u_i = r_multiply_x + r_value*combined_e #denominator of partial credential
    # print_with_timestamp(f"u_i:{u_i}")

    r_value = r_value%o
    u_i = int(u_i)%o
    lemda_i = int(lemda_i)%o
    print_with_timestamp(f"Issuer {issuer_id} Computed Partial Credential Jointly via MPC")
    # print_with_timestamp(f"Partial Credential: e={e}, u_i={u_i}, r_value={r_value}, lemda_i: {lemda_i}")

# Blockchain Functions
def issue_partial_credential():
    global r_i, u_i, s_id, sig_id, e, pk, issuer_id, B_lemda

    _R_i = (r_i[0].n, r_i[1].n)
    _B_lemda = (B_lemda[0].n, B_lemda[1].n)

    # _pk = ((pk[0].coeffs[1].n, pk[0].coeffs[0].n), (pk[1].coeffs[1].n, pk[1].coeffs[0].n))

    transaction = issuer_contract.functions.issuePartialCredential(s_id, sig_id, issuer_id, e, u_i, _R_i, _B_lemda, pk).transact({
        'from': issuer_address,
    })
    print_with_timestamp(f"Issued Partial Credential on Blockchain")

def compute_r_i_and_B_lemda():
    global r_i, r_value, s, H_values_G1, attributes, B_dash, no_of_private_attribute, lemda_i, B_lemda
    B_dash_int = [int(x) for x in B_dash]
    params = setup()

    B = compute_B(params, H_values_G1, no_of_private_attribute, B_dash_int, attributes )
    r_i = multiply(B, r_value)
    B_lemda = multiply(B, lemda_i)
    # print_with_timestamp(f"r_i: {r_i}")
    # print_with_timestamp(f"B_lemda: {B_lemda}")
   
def main():
    global args, issuer_contract, user_contract, setup_contract, issuer_address, r_i, issuer_id, H_values_G1, o, attributes, sk, e, s, u_i, s_id, sig_id, r_value, X, B_dash, z, c
    attributes = []
    o = curve_order
    sk = None
    pk = None
    H_values_G1 = []
    e=0
    s=0
    r_i=0
    u_i=None
    s_id=None
    sig_id=None
    r_value=None
    args = setup_parser()
    X=None
    B_dash = []
    z = None
    c = None
    lemda_i = 0
    B_lemda = None

    issuer_index = args.Issuer
    issuer_id = int(issuer_index[1:])

    # Load contract ABIs
    user_abi, issuer_abi, setup_abi = load_contracts()

    # Setup blockchain connection
    # print("issuer_ working")
    w3 = setup_blockchain_connection(args.rpc_endpoint)
    # print("issuer_ working")
    # Set issuer address and instantiate contracts
    issuer_address = w3.to_checksum_address(args.address)
    user_contract = w3.eth.contract(address=user_abi['networks']['5777']['address'], abi=user_abi['abi'])
    issuer_contract = w3.eth.contract(address=issuer_abi['networks']['5777']['address'], abi=issuer_abi['abi'])
    setup_contract = w3.eth.contract(address=setup_abi['networks']['5777']['address'], abi=setup_abi['abi'])

    print_with_timestamp("Blockchain setup complete.")
    print_with_timestamp(f"Issuer Address: {issuer_address}")

    # MPC and PK-SK Pair retrieval
    get_pk_sk_pair(args)

    # Execute MPC setup for H0 and generate public parameters H
    mpc.run(generate_H0())
    generate_H()

    # Upload public parameter for the issuer
    # take_time(f"Issuer {issuer_id} start_time for issuer_public_parameter", time.time())
    issuer_public_parameter()
    # take_time(f"Issuer {issuer_id} end_time for issuer_public_parameter", time.time())

    # take_time(f"Issuer {issuer_id} start_time for listen_attribute", time.time())
    listen_attribute()
    take_time(f"Issuer {issuer_id} start_time for issue_partial_credential", time.time())

    # Start secure MPC computation for issuing partial credentials
    take_time(f"Issuer {issuer_id} start_time for mpc_compute_partial_cred", time.time())
    mpc.run(mpc_compute_partial_cred())
    take_time(f"Issuer {issuer_id} end_time for mpc_compute_partial_cred", time.time())


    # take_time(f"Issuer {issuer_id} start_time for compute_r_i_and_B_lemda", time.time())
    compute_r_i_and_B_lemda()
    # take_time(f"Issuer {issuer_id} end_time for compute_r_i_and_B_lemda", time.time())

    # Issue partial credential on blockchain
    issue_partial_credential()
    take_time(f"Issuer {issuer_id} end_time for issue_partial_credential", time.time())


if __name__ == "__main__":
    main()
