import json
import time
import ast
from web3 import Web3
from py_ecc.bn128 import *
from datetime import datetime
from helper import *
# from event_listener import listen_public_parameter


def print_with_timestamp(message):
    """Print the given message with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"[{timestamp}] {message}")


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


def listen_public_parameter(setup_contract):
    """Listen for the 'PublicParam' event and update H and X accordingly."""
    global H, X
    time.sleep(5)  # Adjust as necessary
    try:
        request_filter = setup_contract.events.PublicParam.create_filter(from_block="latest")
        parameters = request_filter.get_all_entries()

        if parameters:
            for event in parameters:
                H = event['args']['H']
                X = event['args']['X']
                # print_with_timestamp(f"Public parameters received: H = {H}, X = {X}")

            # Convert and validate X
            X = ast.literal_eval(X.split("\"")[0])  # Sanitize and convert X
            X = decodeToG2(X)

            # Ensure H is on the curve
            for i, h in enumerate(H):
                h = (FQ(h[0]), FQ(h[1]))
                if not is_on_curve(h, b=3):
                    print_with_timestamp(f"h at index {i} is not on the curve.")
                H[i] = h

        else:
            print_with_timestamp("No 'PublicParam' events found.")

    except Exception as e:
        print_with_timestamp(f"Error in listen_public_parameter: {str(e)}")


def listen_spok(SPOK_contract):
    """Listen for the 'SPOKBroadcast' event and extract the proof."""
    global public_attribute, no_of_private_attribute
    try:
        request_filter = SPOK_contract.events.SPOKBroadcast.create_filter(from_block="latest")
        parameters = request_filter.get_all_entries()

        if parameters:
            for event in parameters:
                params = event['args']['pi']
                points = event['args']['points']

                # Parse parameters
                pi = (params['c'], params['re'], params['rr2'], params['rr3'], 
                      params['rs_dash'], params['_timestamp'], params['rm'])

                # Extract attributes
                public_attribute = event['args']['attribute']
                no_of_private_attribute = event['args']['no_of_private_attribute']

                # Parse elliptic curve points
                A_dash = (FQ(points.A_dash[0]), FQ(points.A_dash[1]))
                A_bar = (FQ(points.A_bar[0]), FQ(points.A_bar[1]))
                d = (FQ(points.d[0]), FQ(points.d[1]))

                return (A_dash, A_bar, d, pi)
        else:
            # print_with_timestamp("No 'SPOKBroadcast' events found.")
            return None

    except Exception as e:
        print_with_timestamp(f"Error in listen_spok: {str(e)}")
        return None


# Main execution flow
def main():
    try:
        provider_url = "http://127.0.0.1:7545"
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
        # flag = verifyCred(params, H, X, proof, public_attribute, no_of_private_attribute)

        # print_with_timestamp(f"Credential verification result: {flag}")

    except Exception as e:
        print_with_timestamp(f"An unexpected error occurred: {str(e)}")


if __name__ == "__main__":
    main()
