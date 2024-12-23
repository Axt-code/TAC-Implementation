from web3 import Web3
import json
import time
from py_ecc.bn128 import *
from py_ecc_tester import *
import random
import hashlib
# from helper import *
from datetime import datetime
import argparse
from constants import *
from web3.datastructures import AttributeDict
from py_ecc.bn128 import is_on_curve, b2


public_key_vector = []
data_vector = []
H=[]
g1_beta=[]
beta=[]
alpha=None

def setup_parser():
    parser = argparse.ArgumentParser(description="User Creation")
    parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which user is running.")
    parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a user is connected to blockchain network.")
    
    return parser.parse_args()

def decodeToG1(X):
  _X = (FQ(X[0]), FQ(X[1]))
  return _X

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)


def print_with_timestamp(message):
    """Print the given message with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def convert_to_int(value):
    try:
        return int(value)
    except ValueError:
        # Use hashlib to create a consistent hash
        hashed_value = hashlib.sha256(value.encode()).hexdigest()
        return int(hashed_value, 16) % (10 ** 8)


def read_attributes(file_path):
    attributes = {}
    with open(file_path, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')
            attributes[key] = value.split(',') if ',' in value else value

    # Convert `sid` and `sigid` to integers
    sid = int(attributes['sid'])
    sigid = int(attributes['sigid'])

    # Convert public and private attributes into a list of integers if possible
    public_attribute = [convert_to_int(attr) for attr in attributes['public_attribute']]
    private_attribute = [convert_to_int(attr) for attr in attributes['private_attribute']]
    print(f"public_attribute from file:{public_attribute}")
    print(f"private_attribute from file:{private_attribute}")

    return sid, sigid, public_attribute, private_attribute


def listen_public_parameter():

    global H, g1_beta, alpha,  beta
    global public_key_vector
    key_entries = set()

    time.sleep(5)  # Adjust sleep duration based on your needs
        # Create a filter to listen for the 'PublicParam' event from the Setup contract
    #all_events = setup_contract.events  # All available events
    #public_param_event = all_events['PublicParam']  # Select specific event
    #key_event = all_events['PublicKey']
    #request_filter = public_param_event.create_filter(fromBlock="latest")
    request_filter = setup_contract.events.PublicParam.create_filter(fromBlock="latest")
    parameters = request_filter.get_all_entries()
    if parameters:
        for event in parameters:
            H = event['args']['H']
            g1_beta = event['args']['g1_beta']
            alpha = event['args']['alpha']
            beta = event['args']['beta']
            
            # print_with_timestamp("Event log entries:", event)
            for i, h in enumerate(H):
                H[i] = (FQ(h[0]), FQ(h[1]))
                # H[i] = decodeToG1(h)

                # H[i] = h 
            for i, gb in enumerate(g1_beta):
                g1_beta[i] = (FQ(gb[0]), FQ(gb[1]))
                # g1_beta[i] = decodeToG1(gb)
                # g1_beta[i] = gb 
            # alpha = decodeToG2(alpha)
            alpha = ((FQ2([alpha[1], alpha[0],]),FQ2([alpha[3], alpha[2],])))
            for i, b in enumerate(beta):
                # gb = (FQ(gb[0]), FQ(gb[1]))
                # beta[i] = decodeToG2(b)
                beta[i]= ((FQ2([b[1], b[0],]),FQ2([b[3], b[2],])))
                # g1_beta[i] = gb 
            print("Received public params from blockchain:")
    else:
        print_with_timestamp("No events found")

    
    
def CredentialRequest(public_parameters,all_attr, no_of_private_attribute):
    Lambda, os = PrepareCredRequest(public_parameters, all_attr, no_of_private_attribute)
    (cm, commitments, pi_s) = Lambda
    send_cm = (cm[0].n, cm[1].n)
    send_commitments = [(commitments[i][0].n, commitments[i][1].n) for i in range(len(commitments))]
    _H = [(H[i][0].n, H[i][1].n) for i in range(len(H))]
    no_of_public_attributes = len(all_attr)-no_of_private_attribute 
    print("sending for verification")
    str_public_m = [str(all_attr[no_of_private_attribute+i]) for i in range(no_of_public_attributes)]
    
    #st = time.time()
    tx_hash = request_contract.functions.RequestCred( send_cm, send_commitments, pi_s, str_public_m, _H).transact({'from':user_addr})
    #et = time.time()
    #print("Time for credential request Verification at Smart Contract is:",et-st)
    return Lambda, os

def make_hashable(obj):
    if isinstance(obj, list):
        return tuple(make_hashable(item) for item in obj)  # Convert lists to tuples
    elif isinstance(obj, dict):
        return tuple((k, make_hashable(v)) for k, v in obj.items())  # Convert dicts to tuples of (key, value)
    elif isinstance(obj, AttributeDict):  # Handle web3's AttributeDict
        return tuple((k, make_hashable(v)) for k, v in obj.items())  # Convert it to a tuple of (key, value)
    else:
        return obj  # Return the object as is if it’s a hashable type


def listen_partial_credentials(params,signs,os,aggregate_vk):
    global data_vector
    seen_entries = set()  # Set to keep track of unique event entries
    #count =0
    # Create the filter outside the loop
    
    request_filter = issuer_contract.events.PartialCredential.create_filter(fromBlock="latest")
    while len(data_vector) < tv:
        # try:
            # Fetch all entries from the filter
        partial_credential_entries = request_filter.get_all_entries()
        if partial_credential_entries:
            for entry in partial_credential_entries:
                
                entry_tuple = make_hashable(entry['args'])

                if entry_tuple not in seen_entries:
                    seen_entries.add(entry_tuple)

                    # Access values directly, since they're hashable now
                    _h = make_hashable(entry['args']['h'])
                    _t = make_hashable(entry['args']['t'])

                    g1_B = make_hashable(entry['args']['g1_B'])
                    A = make_hashable(entry['args']['A'])
                    B = make_hashable(entry['args']['B'])
                    issuer_id = make_hashable(entry['args']['issuer_id'])
                    h = (FQ(_h[0]), FQ(_h[1]))
                    t = (FQ(_t[0]), FQ(_t[1]))
                    blind_sig = (h, t)
                    
                    print(f"h received: {h}")
                    print(f"t received: {t}")
                    g1_B = list(g1_B)  # Convert tuple to list
                    B = list(B)
# ciphershares.append(((FQ2([encoded_ciphershares[i][1], encoded_ciphershares[i][0],]), FQ2([encoded_ciphershares[i][3],encoded_ciphershares[i][2],]),), (FQ2([encoded_ciphershares[i][5], encoded_ciphershares[i][4],]), FQ2([encoded_ciphershares[i][7],encoded_ciphershares[i][6],]),)))

                    for j, gb in enumerate(g1_B):
                        g1_B[j]= (FQ(gb[0]), FQ(gb[1]))
                        
                        # g1_B[j] = decodeToG1(gb) 
                    #A = decodeToG2(A)
                    A= ((FQ2([A[1], A[0],]),FQ2([A[3], A[2],])))
                    print("A_i on curve:", is_on_curve(A, b2))
                    
                    for j, b in enumerate(B):
                        # B[j] = decodeToG2(b)
                        B[j]= ((FQ2([b[1], b[0],]),FQ2([b[3], b[2],])))
                        print("B_i on curve:", is_on_curve(B[j], b2))

                    # count = count+1
                    
                    data_vector.append({
                            'client': entry['args']['client'],
                            'h': h,
                            't': t,
                            'g1_B':g1_B,
                            'A':A,
                            'B':B,
                            'issuer_id':issuer_id,
                        })
                    print_with_timestamp("New Entry Added in vector\n")

                        # Check if n unique entries have been added, and exit the loop if so
                    if len(data_vector) >= tv:
                        print_with_timestamp(f"Collected {tv} unique entries. Exiting.")
                        return


def RequestService(params,aggr_sig, verify_contract, aggregate_vk,private_m,public_m):

    Theta = ProveCred(params, aggregate_vk, aggr_sig, private_m)
    (G, o, g1, hs, g2, e) = params
    (g2, _, _, beta) = aggregate_vk
    (kappa, nu, sigma, pi_v, _, timestamp) = Theta
    (h, s) = sigma
    result = VerifyCred(params, aggregate_vk, Theta)
    print(f"Local Credential verification:{result}")
    (G, o, g1, H_bar, g2, e)=params
    (_g2, _alpha, _g1_beta, _beta)=aggregate_vk
    (kappa, nu, sigma_prime, pi_v, Aw, timestamp)=Theta
    send_kappa = ((kappa[0].coeffs[1].n, kappa[0].coeffs[0].n),(kappa[1].coeffs[1].n, kappa[1].coeffs[0].n))
    send_nu = (nu[0].n, nu[1].n)
    _H = [(H_bar[i][0].n, H_bar[i][1].n) for i in range(len(H_bar))]
    send_alpha = ((_alpha[0].coeffs[1].n,_alpha[0].coeffs[0].n),(_alpha[1].coeffs[1].n,_alpha[1].coeffs[0].n))
    send_beta = [((_beta[i][0].coeffs[1].n,_beta[i][0].coeffs[0].n),(_beta[i][1].coeffs[1].n,_beta[i][1].coeffs[0].n)) for i in range(len(_beta))]
    send_Aw = ((Aw[0].coeffs[1].n,Aw[0].coeffs[0].n),(Aw[1].coeffs[1].n,Aw[1].coeffs[0].n))
    send_sigma = [(sigma_prime[i][0].n, sigma_prime[i][1].n) for i in range(len(sigma_prime))]
    print("sending randomized credential for verification")
    print(f"Randomized credential: {send_sigma}")
    print(f"Kappa in sending {send_kappa}")
    print(f"nu in local verification: {send_nu}")
    print(f"alpha in sending: {send_alpha}")
    print(f"beta in sending: {send_beta}")
    str_public_m = [str(public_m[i]) for i in range(len(public_m))]
    send_theta = (send_kappa,send_nu,send_sigma, pi_v )
    # send_g1=(g1[0].n, g1[1].n)
    # send_g2=((_g2[0].coeffs[1].n,_g2[0].coeffs[0].n),(_g2[1].coeffs[1].n,_g2[1].coeffs[0].n))
    st = time.time()
    
    tx_hash = verify_contract.functions.VerifyCred( send_theta, _H, send_alpha,send_beta, str_public_m, send_Aw, timestamp ).transact({
    'from': user_addr,
    'gas': 5000000  
})
    
    et = time.time()
    # print("Time for credential Verification at Smart Contract is:",et-st)

def VerifyPartialCredential(params,data_vector,index,attributes_all,os): 
    (_, o, _, _, g2, e) = params 
    
    h = data_vector[index]["h"]
    t = data_vector[index]["t"]
    issuer_index = data_vector[index]["issuer_id"]
    A_i = data_vector[index]["A"]
    B_i = data_vector[index]["B"]
    g1_B_i = data_vector[index]["g1_B"]
    b_sig = (h,t)
    u_sign = Unblind(params, g1_B_i, b_sig, os)
    (h,s_i)=u_sign
    # print(f"index:{index}")
    # print(f"A_i:{A_i}")
    # print(f"B_i:{B_i}")
    # print(f"g1_B_i:{g1_B_i}")
    # print(f"attributes:{attributes_all}")
    # print(f"s_i:{s_i}")
    kappa_h=add(A_i, ec_sum([multiply(B_i[i], attributes_all[i]) for i in range(len(attributes_all))])) 
    p1 = e(kappa_h, h)
    p2 = e(g2, s_i)
    # print(f"kappa_h:{kappa_h}")
    # print(f"p2:{p2}")
    result = ((p1== p2)and not is_inf(h))
    return  result, u_sign ,issuer_index

def main():
    global H, g1_beta, alpha,  beta, setup_contract,request_contract,user_addr, issuer_contract,signs, tn, tv
    tv = THRESHOLD_ISSUERS
    tn = TOTAL_ISSUERS
    signs = [None] * (tn+1)
    q=MAX_ATTRIBUTES
    ttp="AC"
    pub_params = setup(q, ttp)
    (G, o, g1, hs, g2, e) = pub_params
    args = setup_parser()
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))
    
    user_addr = args.address

    with open('./build/contracts/SetupPublicParams.json') as f:
        tfs = json.load(f)
    
    setup_contract = w3.eth.contract(address=tfs['networks']['5777']['address'], abi=tfs['abi'])

    if not w3.is_connected():
        raise Exception("Failed to connect to the Ethereum node.")

    tf = json.load(open('./build/contracts/RequestCredential.json'))
    request_contract = w3.eth.contract(address = tf['networks']['5777']['address'], abi = tf['abi'])

    tfi = json.load(open('./build/contracts/IssueCredential.json'))
    issuer_contract = w3.eth.contract(address = tfi['networks']['5777']['address'], abi = tfi['abi'])
   
    tfv = json.load(open('./build/contracts/VerifyCredential.json'))
    verify_contract = w3.eth.contract(address = tfv['networks']['5777']['address'], abi = tfv['abi'])
   
    setup_addr = args.address
    st1 = time.time()
    listen_public_parameter()
    params = (G, o, g1, H, g2, e)
    aggregate_vk = (g2, alpha, g1_beta, beta)
    # Read attributes from the text file
    
    sid, sigid, public_attribute, private_attribute = read_attributes('attributes.txt')
    all_attr = private_attribute + public_attribute
    # attr_mod =  [a % o for a in all_attr]
    # private_mod = [a % o for a in private_attribute]
    # pub_mod = [a % o for a in public_attribute]

    Lambda, os = CredentialRequest(params,all_attr, len(private_attribute))
    print(f"length of os: {len(os)}")
    
    et1 = time.time() 
    print("Credential Request time :",et1-st1)
    st2 = time.time()
    listen_partial_credentials(params,signs,os,aggregate_vk)
    et2 = time.time()

    # print("Credential Issuance time :",et2-st1)
    # count=0
    # while count < len(data_vector): 
    #     h_=data_vector[count]["h"]
    #     t_=data_vector[count]["t"]
    #     print(f"index for h,t:{count}")
    #     print(f"t_:{count}")
    #     b_sig=(h_,t_)
    #     signs[count]=Unblind(params, aggregate_vk, b_sig, os)
    #     count=count+1
    
    index=0
    while index < len(data_vector): 
        st3 = time.time()  
        result, u_sign, issuer_index = VerifyPartialCredential(params,data_vector,index,private_attribute,os)
        print(f"Partial credential result for issuer {issuer_index} {result}")
        signs[issuer_index] = u_sign
        print(f"sign at {issuer_index} is :{signs[issuer_index]}")
        index=index+1
        et3 = time.time()
        print("Partial credential verification time :",et3-st3)
          
    print(f"signs array:{signs}")
    st = time.time()
    aggr_sig = AggCred(params, signs) 
    RequestService(params,aggr_sig, verify_contract,aggregate_vk,private_attribute,public_attribute)
    et = time.time()
    print("Time for credential verification:",et-st)
    #verify the aggregate credential locally first
if __name__ == "__main__":
    main()
