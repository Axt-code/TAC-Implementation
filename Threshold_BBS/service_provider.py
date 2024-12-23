import json
import time
import ast
from web3 import Web3
from py_ecc.bn128 import *
from datetime import datetime
from helper import *
# from event_listener import listen_public_parameter

public_attribute = []
total_attributes = None


def connect_to_ethereum(provider_url):
    """Connect to the Ethereum node and return the Web3 instance."""
    w3 = Web3(Web3.HTTPProvider(provider_url, request_kwargs={'timeout': 300}))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to the Ethereum node.")
    return w3


def is_valid_eth_address(address):
    """Check if the given address is a valid Ethereum address."""
    return Web3.is_address(address)


def read_contract_abi(contract_name):
    """Read and return the ABI for the given contract."""
    file_path = f'./build/contracts/{contract_name}.json'
    try:
        with open(file_path, 'r') as file:
            return json.load(file)['abi']
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        print_with_timestamp(f"Error loading ABI for {contract_name}")
        return None


def get_address_by_label(file_path, label):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if label in line:
                    # Extract the address after the label
                    return line.split(":")[1].strip()
        return None  # Return None if label is not found
    except Exception as e:
        print_with_timestamp(f"Error reading label '{label}' from {file_path}: {e}")
        return None


def setup_contract(w3, contract_address, contract_name):
    """Return a contract instance given the address and contract name."""
    if not is_valid_eth_address(contract_address):
        print_with_timestamp(f"Invalid contract address for {contract_name}.")
        return None
    abi = read_contract_abi(contract_name)
    if abi:
        return w3.eth.contract(address=contract_address, abi=abi)
    return None

def listen_spok(SPOK_contract):
    """Listen for the 'SPOKBroadcast' event and extract the proof."""
    global public_attribute, total_attributes
    try:
        request_filter = SPOK_contract.events.SPOKBroadcast.create_filter(from_block="latest")
        parameters = request_filter.get_all_entries()


        if parameters:
            for event in parameters:
                params = event['args']['pi']
                points = event['args']['points']

                # Parse parameters
                pi = (params['c'], params['s'], params['t'], params['u_i'], params['_timestamp'])

                # Extract attributes
                public_attribute = event['args']['public_attribute']
                total_attributes = event['args']['total_attributes']

                # Parse elliptic curve points
        
                A_bar = (FQ(points.A_bar[0]), FQ(points.A_bar[1]))
                B_bar = (FQ(points.B_bar[0]), FQ(points.B_bar[1]))

                # print_with_timestamp(F"public_attribute: {public_attribute}")

                return (A_bar, B_bar, pi)
        else:
            # print_with_timestamp("No 'SPOKBroadcast' events found.")
            return None

    except Exception as e:
        print_with_timestamp(f"Error in listen_spok: {str(e)}")
        return None


# Main execution flow
def main():
    try:
        provider_url = "http://127.0.0.1:7546"
        w3 = connect_to_ethereum(provider_url)

        # Read contract addresses from file
        file_path = "./SC_output.txt"
        verify_cred_address = get_address_by_label(file_path, "VerifyCredentialInstance address")

        # Initialize contract instances
        SPOK_contract_instance = setup_contract(w3, verify_cred_address, 'VerifyCredential')

        print_with_timestamp("Blockchain setup complete.")


        print_with_timestamp("Waiting for Randomize Credential...")

        proof = None
        while not proof:
            proof = listen_spok(SPOK_contract_instance)

        print_with_timestamp("Got verified Randomize Credential")
     

    except Exception as e:
        print_with_timestamp(f"An unexpected error occurred: {str(e)}")


if __name__ == "__main__":
    main()
