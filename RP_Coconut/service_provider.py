import json
import time
import ast
from web3 import Web3
from py_ecc.bn128 import *
from datetime import datetime

def print_with_timestamp(message):
    """Print the given message with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"[{timestamp}] {message}")

def listen_spok(SPOK_contract):
    global public_attribute, request_flag
    
    try:
        request_filter = SPOK_contract.events.emitVerify.create_filter(fromBlock="latest")
        parameters = request_filter.get_all_entries()

        if parameters:
            for event in parameters:
                credential= event['args']['credential']
                public_attribute = event['args']['public_m']

                print(f"Verified Credential: {credential}")
                print(f"public_attribute: {public_attribute}")
                print(f"length public_attribute: {len(public_attribute)}")
                request_flag = 1

        else:
            #print_with_timestamp("No credentials found.")
            return None

    except Exception as e:
        print_with_timestamp(f"Error in listen_spok: {str(e)}")
        return None

def main():
    # try:
        global request_flag
        w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))

        tf = json.load(open('./build/contracts/VerifyCredential.json'))
        verify_contract_instance = w3.eth.contract(address = tf['networks']['5777']['address'], abi = tf['abi'])

        print_with_timestamp("Blockchain setup complete.")

        print_with_timestamp("Waiting for Randomize Credential...")
        request_flag = 0
        while (request_flag==0):
            listen_spok(verify_contract_instance)

        print_with_timestamp("Got verified Randomize Credential")

if __name__ == "__main__":
    main()
