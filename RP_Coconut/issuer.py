import json
import jsonpickle
from py_ecc_tester import *
from datetime import datetime
import time
from py_ecc.bn128 import *
import argparse
import os
import pickle
import socket
from web3 import Web3
import random
import numpy as np
import hashlib
from collections import defaultdict
from typing import List, Tuple
from constants import *
import ast
from py_ecc.bn128 import FQ12, neg
issuer_id = None 
attributes=[]
commitments=[]
cm = None
# Setup Argument Parser
def setup_parser():
    parser = argparse.ArgumentParser(description="Anonymous Credentials Registration")
    #parser.add_argument("--number-of-attribute", type=int, default=10, help="Maximum number of attributes issuer can sign.")
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

def encodeG2(g2):
	return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)

def encodeVk(vk):
  g2, g2x, g1y, g2y = vk
  encoded_vk = []
  encoded_vk.append(encodeG2(g2))
  encoded_vk.append(encodeG2(g2x))
  encoded_vk.append(g1y)
  encoded_g2y = []
  for i in range(len(g2y)):
    encoded_g2y.append(encodeG2(g2y[i]))
  encoded_vk.append(encoded_g2y)
  return tuple(encoded_vk)

  
def decodeVk(encoded_vk):
  encoded_g2, encoded_g2x, g1y, encoded_g2y = encoded_vk
  vk = []
  vk.append(decodeToG2(encoded_g2))
  vk.append(decodeToG2(encoded_g2x))
  vk.append(g1y)
  g2y = []
  for i in range(len(encoded_g2y)):
    g2y.append(decodeToG2(encoded_g2y[i]))
  vk.append(g2y)
  return tuple(vk)

def get_pk_sk_pair():
    global sk, X
    buffer = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.req_ip, int(args.req_port)))
        s.sendall(args.Issuer.encode('utf-8'))
         # Initialize a list to accumulate the received data
        while True:
          part = s.recv(8192).decode()  # Receive in chunks
          if "\n\nEND\n\n" in part:  # Check for end marker
            buffer.append(part.replace("\n\nEND\n\n", ""))
            break
          buffer.append(part)

        # Combine all parts and decode
        keysJSON = ''.join(buffer)
        keys = jsonpickle.decode(keysJSON)
        return keys

def print_with_timestamp(message):
    """Print the given message with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"[{timestamp}] {message}")

def issuer_public_parameter(verification_key,aggregate_vk):
    if issuer_id == 0:
        encoded_hs = [(hs[i][0].n, hs[i][1].n) for i in range(len(hs))]
        (_, alpha, g1_beta, beta)= aggregate_vk
        encoded_alpha = ((alpha[0].coeffs[1].n, alpha[0].coeffs[0].n), (alpha[1].coeffs[1].n, alpha[1].coeffs[0].n))
   
        encoded_beta = [((beta[i][0].coeffs[1].n,beta[i][0].coeffs[0].n),(beta[i][1].coeffs[1].n,beta[i][1].coeffs[0].n)) for i in range(len(beta))]
        encoded_g1_beta = [(g1_beta[i][0].n, g1_beta[i][1].n) for i in range(len(g1_beta))]

        transaction = setup_contract.functions.sendPublicParam(encoded_hs,encoded_alpha,encoded_beta,encoded_g1_beta ).transact({
            'from': issuer_address,
        })
        print_with_timestamp(f"Issuer {issuer_id} has published the public parameters in blockahin.")

    print_with_timestamp(f"Issuer {issuer_id} has published the public keys in blockahin.")



def listen_broadcast_sig_req():
    global cm, no_of_private_attribute
    
    # time.sleep(5)
    #emitRequest(address sender, uint256[2] cm, uint256[2][] commitments, string[] public_m)
    try:
        request_filter = user_contract.events.emitRequest.create_filter(fromBlock="latest")
        entries = request_filter.get_all_entries()
        if entries:
          for event in entries:
            received_cm = event['args']['cm']
            received_commitments = event['args']['commitments']
            public_attributes = event['args']['public_m']           
            # print_with_timestamp("Event log entries:", event)
            print(f"received_cm= {received_cm}")
            print(f"received_commitments= {received_commitments}")
            print(f"public_attributes= {public_attributes}")
            cm = (FQ(received_cm[0]), FQ(received_cm[1]))
            for i in range(len(received_commitments)):
              commitments.append((FQ(received_commitments[i][0]), FQ(received_commitments[i][1])))
            for i in range(len(public_attributes)):
              attributes.append(int.from_bytes(sha256(public_attributes[i].encode("utf8").strip()).digest(), "big") % o)
        # else:
        #     #print_with_timestamp("No events found")
    except Exception as e:
        print_with_timestamp(f"An error occurred while listening for events: {e}")

def listen_attribute():
    global  attributes, no_of_private_attribute

    # print_with_timestamp(f"Length of attributes: {len(attributes)}")
    while(len(attributes)==0):
        listen_broadcast_sig_req()
    # verify(B_dash, k, c)
    print_with_timestamp("Got attributes and ZKPOK from user via blockain")
    print_with_timestamp("ZKPOK already verified in blockchain....")

def issuePartialCredentials(request, sk,verification_key,issuer_id):
  (cm, commitments, public_m) = request
  #h = hashG1(to_binary256(cm))
  Lambda = (cm, commitments)
  print(f"commitments received in issue credentials:{commitments}")
  st = time.time()
  blind_sig = BlindSignAttr(params, sk, Lambda, public_m)
  send_h = [blind_sig[0][0].n, blind_sig[0][1].n]
  send_t = [blind_sig[1][0].n, blind_sig[1][1].n]
  (_, A, g1_B, B)= verification_key

  encoded_A = ((A[0].coeffs[1].n, A[0].coeffs[0].n), (A[1].coeffs[1].n, A[1].coeffs[0].n))
  encoded_B = [((B[i][0].coeffs[1].n,B[i][0].coeffs[0].n),(B[i][1].coeffs[1].n,B[i][1].coeffs[0].n)) for i in range(len(B))]
  encoded_g1_B = [(g1_B[i][0].n, g1_B[i][1].n) for i in range(len(g1_B))]
  tx_hash = issuer_contract.functions.issuePartialCredential(send_h, send_t,encoded_A,encoded_B,encoded_g1_B,issuer_id).transact({'from':issuer_address})
  et = time.time()
  print("Time for publishing partial credential over blockchain:",et-st)
  print_with_timestamp(f"Issuer {issuer_id} has issued the partial credentials")



def main():
  global args,params, issuer_contract, user_contract, setup_contract, issuer_address, issuer_id, o, sk, hs, aggregate_vk

  # attributes = []
  # commitments = []
  o = curve_order
  sk = None
  args = setup_parser()
  issuer_index = args.Issuer
  issuer_id = int(issuer_index[1:])

  q=MAX_ATTRIBUTES
  ttp="AC"
  params = setup(q, ttp)
  # Load contract ABIs
  user_abi, issuer_abi, setup_abi = load_contracts()

  # Setup blockchain connection
  w3 = setup_blockchain_connection(args.rpc_endpoint)
  _, o, g1, hs, g2, e = params

  # Set issuer address and instantiate contracts
  issuer_address = w3.to_checksum_address(args.address)
  user_contract = w3.eth.contract(address=user_abi['networks']['5777']['address'], abi=user_abi['abi'])
  issuer_contract = w3.eth.contract(address=issuer_abi['networks']['5777']['address'], abi=issuer_abi['abi'])
  setup_contract = w3.eth.contract(address=setup_abi['networks']['5777']['address'], abi=setup_abi['abi'])

  print_with_timestamp("Blockchain setup complete.")
  print_with_timestamp(f"Issuer Address: {issuer_address}")
  pk_sk_pair = get_pk_sk_pair()
  (encoded_vk, sk, encoded_aggregate_key) = pk_sk_pair
  
  verification_key = decodeVk(encoded_vk)
  aggregate_vk = decodeVk(encoded_aggregate_key)
  print(f"aggregate_key: {aggregate_vk}")
  print(f"verification_key: {verification_key}")
 
  issuer_public_parameter(verification_key,aggregate_vk)
  listen_attribute()
  request = (cm, commitments, attributes)
  print(f"request:{request}")


  st = time.time()
  issuePartialCredentials(request, sk,verification_key,issuer_id) #Added issuer id to find lagrange coefficient
  et = time.time()
  print("Total Time for issuing partial credential :",et-st)

if __name__ == "__main__":
    main()