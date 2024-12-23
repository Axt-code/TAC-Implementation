from web3 import Web3
import argparse
import json
import time
from py_ecc.bn128 import *
import random
from helper import *
import ast


parser = argparse.ArgumentParser(description="Generate a stacked bar chart with customizable values.")
parser.add_argument("--address", type=str, required=True, help="Blockchain address of the organization.")
parser.add_argument("--total-issuers", type=int, required=True, help="Total number of issuers.")
parser.add_argument("--threshold-issuers", type=int, required=True, help="Threshold number of issuers.")
args = parser.parse_args()

# Assign arguments to variables
total_issuer = args.total_issuers
threshold_issuer = args.threshold_issuers
user_address = args.address

sid=None
sigi=None
public_attribute=[]
private_attribute=[]
partial_credential_entries = None
s_0 = None
s_1 = None
s = None
U = None
R = None
data_vector = []
H = []
e1=None
X = None
(G, o, g1, g2, e) = ((FQ, FQ2, FQ12), curve_order, G1, G2, pairing)

B = None
A = None

def connect_to_ethereum_node():
    """Establish a connection to the Ethereum node."""
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))
    if not w3.is_connected():
        raise Exception("Failed to connect to the Ethereum node.")
    return w3
# Load Contract Files
def load_contracts():
    with open('./build/contracts/RequestCredential.json') as f:
        user_abi = json.load(f)
    with open('./build/contracts/IssueCredential.json') as f:
        issuer_abi = json.load(f)
    with open('./build/contracts/SetupPublicParams.json') as f:
        setup_abi = json.load(f)
    with open('./build/contracts/VerifyCredential.json') as f:
        spok_abi = json.load(f)
    return user_abi, issuer_abi, setup_abi, spok_abi


def create_contract_instance(w3, address, abi):
    """Create an instance of a contract."""
    return w3.eth.contract(address=address, abi=abi)

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

def read_attributes(file_path):
    """Read attributes from a file and convert them to integers or lists."""
    attributes = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                key, value = line.strip().split('=')
                attributes[key] = value.split(',') if ',' in value else value

        sid = int(attributes['sid'])
        sigid = int(attributes['sigid'])
        public_attribute = [convert_to_int(attr) for attr in attributes['public_attribute']]
        private_attribute = [convert_to_int(attr) for attr in attributes['private_attribute']]
        return sid, sigid, public_attribute, private_attribute
    except Exception as e:
        print_with_timestamp(f"Error reading attributes: {e}")
        raise


def listen_for_event(contract, event_name, from_block='latest', timeout=300):
    """Listen for a specified event from a contract."""
    event_filter = contract.events[event_name].create_filter(from_block=from_block)
    try:
        time.sleep(5)  # Adjust sleep duration based on network latency
        events = event_filter.get_all_entries()
        return events
    except Exception as e:
        print_with_timestamp(f"Error listening for {event_name} event: {e}")
        return []

def decode_H_and_X(event):
    """Decode the public parameters H and X from an event."""
    global H, X
    H = event['args']['H']
    X = event['args']['X']
    
    X = X.split("\"")[0]
    X = ast.literal_eval(X)
    X = decodeToG2(X)

    H = [(FQ(h[0]), FQ(h[1])) for h in H]
    return H, X

def blinding_attribute(private_attribute):
    """Compute the blinding attribute using private attributes."""
    global s_0, H
    s_0 = s_0 or random.randint(2, o)
    t1 = [multiply(H[i + 1], (ai) % o) for i, ai in enumerate(private_attribute)]
    t2 = multiply(H[0], s_0)
    return add(t2, ec_sum(t1))

def make_pi_a( ):
    global s_0, H
    B_dash = blinding_attribute(private_attribute)
    print_with_timestamp("Blinded Private attribute")
    r = [random.randint(2, o) for _ in range(len(private_attribute)+1)]
    k0 = multiply(H[0], r[0])
    k1 = ec_sum([multiply(H[i+1], r[i+1]) for i in range(len(private_attribute))])
    k = add(k0, k1)
    # print_with_timestamp(f"k: {k}")
    c = to_challenge(B_dash , k, H)
    c=c%o
    # print_with_timestamp(f"c: {c}")
    z = []
    z.append((r[0] + (s_0 * c)) % o)

    for i, ai in enumerate(private_attribute):
        z.append((r[i+1] + (ai)%o * c)%o)

    # print_with_timestamp(f"z: {z}")
    return (B_dash, z, c)

def make_B(public_attribute, private_attribute,):
    global s, H, B
    t = add(multiply(H[0], s),  ec_sum([multiply(H[i+1], (ai)%o) for i, ai in enumerate(private_attribute)]))  
    t = add(t, ec_sum([multiply(H[i + len(private_attribute) + 1], ai % o) for i, ai in enumerate(public_attribute)]))
    B = add(g1, t)


def broadcast_blind_sig_req(user_contract, sid, sigid, public_attribute, private_attribute, user_address):
    """Broadcast a blinded signature request to the User contract."""
    global s_0, H, w3
    try:
        pi_a = make_pi_a()
        

        print_with_timestamp("Made ZKPOK.")
        B_dash, z, c = pi_a
        B_dash = (B_dash[0].n, B_dash[1].n)
        H_as_tuple = tuple([list(map(lambda x: x.n, h)) for h in H])

        tx_hash = user_contract.functions.broadcastSigReq(
            sid, sigid, public_attribute, len(private_attribute), B_dash, z, c, H_as_tuple
        ).transact({'from': user_address})

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        print_with_timestamp("Signature request successful" if receipt.status == 1 else "Transaction failed")
    except Exception as e:
        print_with_timestamp(f"Error broadcasting blind signature request: {e}")

def listen_partial_credentials(issuer_contract):
    """Process partial credential events and extract relevant information."""
    global data_vector, s_1, U, R, e1, threshold_issuer, o, issuer_id, R_i, B_lemda, pk_i
    seen_entries = set()  # Set to keep track of unique event entries
    
    # Create the filter outside the loop
    request_filter = issuer_contract.events.PartialCredential.create_filter(from_block="latest")

    while len(data_vector) < threshold_issuer:
        # try:
            # Fetch all entries from the filter
            partial_credential_entries = request_filter.get_all_entries()

            if partial_credential_entries:
                for entry in partial_credential_entries:
                    # Convert the entry to a hashable form to check uniqueness
                    entry_tuple = tuple((k, tuple(v) if isinstance(v, list) else v) for k, v in entry['args'].items())
                    
                    # Only process new unique entries
                    if entry_tuple not in seen_entries:
                        seen_entries.add(entry_tuple)
                        print_with_timestamp("New unique event log entry.")

                        sigid = entry['args']['sigid']
                        sid = entry['args']['sid']
                        issuer_id = entry['args']['issuer_id']
                        e1 = entry['args']['e']
                        s_1 = entry['args']['s']
                        u_i = entry['args']['u_i']
                        R_i = entry['args']['R_i']
                        B_lemda = entry['args']['B_lemda']
                        pk_i = entry['args']['pk_i']

                        if U is None:
                            U = (u_i)%o
                        else:
                            U = (U + u_i)%o 

                        R_i = decodeToG1(R_i)
                        B_lemda = decodeToG1(B_lemda)
                        pk_i = pk_i.split("\"")[0]
                        pk_i = ast.literal_eval(pk_i)
                        pk_i = decodeToG2(pk_i)

                        if R is None:
                            R = R_i
                        else:
                            R = add(R, R_i) 


                        #     print("R is on cure")

                        # Store the data in the vector
                        data_entry = {
                            'client': entry['args']['client'],
                            'sid': sid,
                            'sigid': sigid,
                            'issuer_id': issuer_id,
                            'e1': e1,
                            's_1': s_1,
                            'u_i': u_i,
                            'R_i': R_i,
                            'B_lemda': B_lemda,  #k_i
                            'pk_i': pk_i
                        }

                        # Print values and their types
                        # for key, value in data_entry.items():
                        #     print(f"{key}: Value = {value}, Type = {type(value)}")

                        # 
                        e1 = e1 % o
                        u_i = u_i % o

                        data_vector.append(data_entry)
                        # print(f"data_entry: {data_entry}")

def unblind_signature():
    """Unblind the signature and return the result."""
    global s, s_0, s_1
    s = (s_1 + s_0) % o
    # print(f"s: {s}")
    return s

def verify_signature():
    """Verify the obtained signature."""
    global U, B, A, public_attribute, private_attribute, e1, H, X, o, R, U, s
    # print(f"s: {s}")

    U_inv = modInverse(U, o)
    A = multiply(R, U_inv)
    p21 = B
    p11 = multiply(g2, e1)
    p12 = add(X, p11)
    p1 = pairing(p12, A)
    p2 = pairing(g2, p21)

    if p1 == p2:
        print_with_timestamp("Credential verification successful.")
    else:
        print_with_timestamp("Credential verification failed.")


def broadcast_show_cred(contract, proof, user_address):
    global public_attribute, private_attribute, H, X

    (A_dash,A_bar,d,pi)=proof                                       
    #(c,rm,re,rr2,rr3,rs_dash,_timestamp)=pi
    A_dash = (A_dash[0].n, A_dash[1].n)
    A_bar = (A_bar[0].n, A_bar[1].n)
    d = (d[0].n, d[1].n)
    no_of_private_attr = len(private_attribute)
    _H = []

    for h in H:
        _H.append([h[0].n, h[1].n])  

    _H = tuple(_H)

    _X = ((X[0].coeffs[1].n, X[0].coeffs[0].n), (X[1].coeffs[1].n, X[1].coeffs[0].n))

    try:
        tx_hash = contract.functions.broadcastSPOK(sid, sigid, _H, _X, pi, A_dash, A_bar, d, public_attribute, no_of_private_attr).transact({'from': user_address})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        if receipt.status == 1:
            print_with_timestamp("Published SPOK and Randomize Credential to blockchain")
        else:
            print_with_timestamp("SPOK Transaction failed")
    except Exception as e:
        print_with_timestamp(f"An error occurred: {type(e).__name__}, Error details: {e}")
    return

def verify_partial_cred(issuer_id, B_lemda, pk_i, u_i, R_i, e):
    global B, total_issuer
    
    (G, o, g1, g2, pairing) = setup()

    indexes = [i + 1 for i in range(total_issuer)]
    li = lagrange_basis(indexes, issuer_id+1, o)
    # print(f"issuer_id:{issuer_id} li: {li}")
    # print(f"B: {B}, u_i: {u_i}")
    p1 = pairing(g2, multiply(B,  u_i))
    p21 = pairing(add (multiply(g2, e), multiply(pk_i, li)), R_i)
    p22 =  pairing(g2, B_lemda)
    p2 = p21*p22
    # print(f"p1: {p1} p2:{p2}")
    return p1 == p2

def verify_partial():
    global data_vector

    for d in data_vector:
        take_time(f"User start time for verify_partial for Issuer {d['issuer_id']}", time.time())
        if verify_partial_cred(d["issuer_id"], d["B_lemda"], d["pk_i"], d["u_i"], d["R_i"], d["e1"]):
            print_with_timestamp(f"Partial credential of issuer {d['issuer_id']}: Verified")
        else:
            print_with_timestamp(f"Partial credential of issuer {d['issuer_id']}: Not Verified")
        take_time(f"User end time for verify_partial for Issuer {d['issuer_id']}", time.time())

def main():
    global sid, sigid, public_attribute, private_attribute, w3, e1, A, s, proof, user_address
    w3 = connect_to_ethereum_node()

    # Step 2: Load contract details and attributes
    file_path = "./SC_output.txt"
    setup_contract_address = get_address_by_label(file_path, "SetupPublicParamsInstance address")
    request_cred_address = get_address_by_label(file_path, "RequestCredentialInstance address")
    issue_cred_address = get_address_by_label(file_path, "IssueCredentialInstance address")
    verify_cred_address = get_address_by_label(file_path, "VerifyCredentialInstance address")
    # user_address = "0x29eF92ffC8FC32e87517Dd0179fB243Cfb540bdC"

    user_abi, issuer_abi, setup_abi, spok_abi = load_contracts()

    # Step 3: Create contract instances
    user_contract = create_contract_instance(w3, request_cred_address, user_abi['abi'])
    issuer_contract = create_contract_instance(w3, issue_cred_address, issuer_abi['abi'])
    setup_contract = create_contract_instance(w3, setup_contract_address, setup_abi['abi'])
    SPOK_contract = w3.eth.contract(address=verify_cred_address, abi=spok_abi['abi'])

    print_with_timestamp("Blockchain setup complete.")

    # Step 4: Read and parse attributes
    sid, sigid, public_attribute, private_attribute = read_attributes('attributes.txt')

    print_with_timestamp("Read attributes from the file.")
    
    # Step 5: Retrieve public parameters
    events = listen_for_event(setup_contract, 'PublicParam')
    if events:
        decode_H_and_X(events[0])
        print_with_timestamp("Retrieved public parameters.")

    # Step 6: Broadcast the blind signature request
    take_time(f"User start_time for Credential request time", time.time())
    broadcast_blind_sig_req(user_contract, sid, sigid, public_attribute, private_attribute, user_address)
    take_time(f"User end_time for Credential request time", time.time())

    # Step 7: Listen for partial credential events
    # entries = listen_for_event(issuer_contract, 'PartialCredential', from_block='latest')
    
    take_time(f"User start_time for listen_partial_credentials and unblind", time.time())
    listen_partial_credentials(issuer_contract)
    unblind_signature()
    take_time(f"User end_time for listen_partial_credentials and unblind", time.time())


    take_time(f"User start_time for verify_partial", time.time())
    make_B(public_attribute, private_attribute)
    verify_partial()
    take_time(f"User end_time for verify_partial", time.time())


    take_time(f"User start_time for verify_signature", time.time())
    verify_signature()
    take_time(f"User end_time for verify_signature", time.time())


    take_time(f"User start_time for make_spok", time.time())
    sign=(A,e1,s)
    proof = make_spok(X, private_attribute,public_attribute, B, H,sign)
    print_with_timestamp("Generated SPOK for Randomize Credential")
    broadcast_show_cred(SPOK_contract, proof, user_address)
    take_time(f"User end_time for make_spok", time.time())

if __name__ == "__main__":
    main()
