from py_ecc.bn128 import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
import hashlib
from mpyc.runtime import mpc
# from mpyc.runtime import mpc
import time
from datetime import datetime


def print_with_timestamp(message):
    """Print the given message with a timestamp including milliseconds."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{timestamp}] {message}")

# Function to log messages with timestamps to a .txt file
def take_time(message, elapsed_time=None, file_path="timing_log.txt"):
    with open(file_path, "a") as log_file:
        if elapsed_time is not None:
            log_file.write(f"{message}: {elapsed_time:.6f} seconds\n")
        else:
            log_file.write(f"{message}\n")
            
def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 3) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
    return (beta, y)

def hashG1(byte_string):
    beta = 0
    y = 0
    x = int.from_bytes(byte_string, "big") % curve_order
    while True :
        (beta, y) = FindYforX(x)
        if beta == pow(y, 2, field_modulus):
            return(FQ(x), FQ(y))
        x = (x + 1) % field_modulus

def to_binary256(point) :
    if isinstance(point, str):
        return sha256(point.encode("utf8").strip()).digest()
    if isinstance(point, int):
        return point.to_bytes(32, 'big')
    if isinstance(point[0], FQ):
        point1 = point[0].n.to_bytes(32, 'big')
        point2 = point[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()
    if isinstance(point[0], FQ2):
        point1 = point[0].coeffs[0].n.to_bytes(32, 'big') + point[0].coeffs[1].n.to_bytes(32, 'big')
        point2 = point[1].coeffs[0].n.to_bytes(32, 'big') + point[1].coeffs[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0][0], encoded_g2[0][1],]), FQ2([encoded_g2[1][0], encoded_g2[1][1],]))

def decodeToG1(i):
    return (FQ(i[0]),FQ(i[1]))

def to_challenge(B_dash, k, H):

    _list = [to_binary256(B_dash)]    
    _list.append(to_binary256(k))

    for i in range(len(H)):
        _list.append(to_binary256(H[i]))

    # _list.append(_Hb)
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]
    Chash =  sha256(Cstring).digest()
    return int.from_bytes(Chash, "big", signed=False)

def setup():
    return ((FQ, FQ2, FQ12), curve_order, G1, G2, pairing)

def poly_eval(coeff, x):
    """ evaluate a polynomial defined by the list of coefficient coeff at point x """
    return sum([coeff[i] * ((x) ** i) for i in range(len(coeff))])

def ttp_keygen(t, n ):
    o=curve_order
    g2=G2
    assert n >= t and t > 0
    p = [random.randint(2, o) for _ in range(0,t)]
    # p_i = [poly_eval(p,i) % o for i in range(1,n+1)]
    p_i = [poly_eval(p,i) % o for i in range(0,n+1)]
    sk = list(p_i)
    vk = [multiply(g2, pi) for pi in p_i]
    x = p_i[0]
    print(f"x: {x}\n")
    X = multiply(g2, x)
    return (sk[1:], vk[1:], X)

def ec_sum(list):
    """ sum EC points list """
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret


def ec_sum(list):
    """ sum EC points list """
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1 
    if (m == 1):
        return 0
    while (a > 1):
        # q is quotient
        q = a // m
        t = m
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
        # Update x and y
        y = x - q * y
        x = t
    # Make x positive
    if (x < 0):
        x = x + m0
    return x

def lagrange_basis(indexes, index, o, x=0):
    """ generates all lagrange basis polynomials """
    l = None
    #for i in indexes:
    numerator, denominator = 1, 1
    for j in indexes:
        if j != index:
            numerator = (numerator * (x - j)) % o
            denominator = (denominator * (index - j)) % o
    l=((numerator * modInverse(denominator, o)) % o)
    return l

def compute_B(params, H_value, no_of_private_attribute, BlindAttr=None, PublicAttr=None):
    (G, o, g1, g2, e) = params

    public_result=None
    blind_result=None
    if PublicAttr:
        # print(f"message_length:{len(message)}")
        prod_list = [multiply(H_value[no_of_private_attribute+i+1], mi) for i, mi in enumerate(PublicAttr)]
        public_result = ec_sum(prod_list)
    if BlindAttr:
        blind_result = (FQ(BlindAttr[0]), FQ(BlindAttr[1]))

    if(public_result): 
        result = add(g1, public_result)
    
    if(blind_result): 
        result = add(result, blind_result)

    return result


#execute below code when credential request is received
async def secure_addition(e_value):
    # print(f"current issuer id:{mpc.pid}")
    #await mpc.start()
    issuers = len(mpc.parties)
    # print(f"issuers:{issuers}")
    self_id = mpc.pid
    # print(f"self pid:{self_id}")     
    #a_sec = mpc.input(secint(e_value))
    #b_sec = mpc.input(secint(s_value))
    a_sec =  mpc.input(e_value)
    #b_sec =  mpc.input(s_value)
    result =  mpc.sum(a_sec) 
    #result1 =  mpc.sum(b_sec)  
    res=  await mpc.output(result) 
    #res1=  await mpc.output(result1) 
    # print('Addition result of e:', res)
    # print('Addition result of s:', res1)
    #await mpc.shutdown()
    return res

async def secure_multiplier(r_value,mode,secret_share,sender_id):
    # print(f"current issuer id:{mpc.pid}")
    # print(f"Sender id: {sender_id}")
    #print(f" r: {r_value}, other_isuuer: {issuer}")
    #await mpc.start()
    issuers = len(mpc.parties)
    # print(f"issuers:{issuers}")
    self_id = mpc.pid
    # print(f"self pid:{self_id}")   
    if mode == 1: #for sender
        sec_num = r_value 
        # print(f"sec_num for mode 1:{sec_num}")
    else:       
        sec_num = secret_share 
        # print(f"sec_num for mode != 1:{sec_num}") 
    a_sec = mpc.input(sec_num)
    #print(f"a_sec:{a_sec[0]}")
    result = 0
    for i in range(issuers):
        if i!=sender_id:
            result = result+mpc.mul(a_sec[sender_id],a_sec[i]) 
            # print(f"result:{result}")
        #else:
            #result = result+0
    res=  await mpc.output(result) 
    # print('Multiplication result:', res)
    #await mpc.shutdown()
    return res

def hash_function(share: int, salt: bytes):
    data = share.to_bytes(32, 'big') + salt
    return hashlib.sha3_256(data).digest()

def deterministic_random_oracle(input_value, L):
    input_str = str(input_value)
    length = len(input_str)
    seed = int(hashlib.sha256(input_str.encode()).hexdigest(), 16)
    random.seed(seed)
    random_values = []
    for _ in range(L):
        random_value = ''.join(random.choices('0123456789', k=length))
        random_values.append(random_value)
    return random_values



#####For signature proving#########
#####statement is 
def to_challenge_spok(elements):
    _list = [to_binary256(x) for x in elements]
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]
    Chash =  sha256(Cstring).digest()
    return int.from_bytes(Chash, "big", signed=False)

def make_spok(private_m, public_m, H, sign):
    (G, o, g1, g2, pairing) = setup()
    # (X) = vk
    (A,e) = sign
    # print(f"A in proof:{A}")
    r = random.randint(2, o)
    A_bar= multiply(A, r)
    # print(f"A_bar:{A_bar}")
    #r3=modInverse(r1,o)
    len_of_private_m = len(private_m)
    total_attr = len(private_m)+len(public_m)
    C_j_m = add(g1, ec_sum([multiply(H[i], public_m[j]) for i, j in zip(range(len_of_private_m , total_attr), range(len(public_m)))]))
    # print(f"C_j_m in make:{C_j_m}")
    alpha = random.randint(2, o)
    beta = random.randint(2, o)
    private_term = multiply(ec_sum([multiply(H[i], (ai)%o) for i, ai in enumerate(private_m)]),r)
    temp = add(multiply(C_j_m,r),neg(multiply(A_bar,e)))
    B_bar = add(private_term,temp)
    # print(f"B_bar:{B_bar}")  
    delta = [random.randint(2, o) for i in range(len(private_m))]
    U2 = ec_sum([multiply(H[i], delta[i]) for i in range(len(private_m))])
    U1 = add(multiply(C_j_m,alpha),(multiply(A_bar,beta)))
    U = add(U2, U1)
    # print(f"U in make:{U}")
    _timestamp = int(time.time())
    
    c = to_challenge_spok_onchain(g1, g2, A_bar, B_bar, U, H, public_m,  _timestamp)
    # print(f"public_m:{public_m}")
    # print(f"timestamp:{_timestamp}")
    # print(f"c:{c}")
    u_i = [(delta[i]+ r*c*int(private_m[i])) % o for i in range(len(private_m))]
    s = (alpha + r*c) % o
    t = (beta - c*e) % o 
    pi=(A_bar,B_bar,c,s,t,u_i,_timestamp)  
    return pi

def to_challenge_spok_onchain(g1, g2, A_bar, B_bar, U, H, public_attr, timestamp):
    
    _list = [to_binary256(g1)]
    _list.append(to_binary256(g2))
    _list.append(to_binary256(A_bar))
    _list.append((to_binary256(B_bar)))
    _list.append((to_binary256(U)))
    for i in range(len(H)):
        _list.append(to_binary256(H[i]))
    for i in range(len(public_attr)):
        _list.append(to_binary256(public_attr[i]))
    _list.append(to_binary256(timestamp))
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]

    # print(f"Cstring: {Cstring}")
    Chash =  sha256(Cstring).digest()
    # print(f"Chash: {Chash}")
    return int.from_bytes(Chash, "big", signed=False)

def verify_spok(H, proof, public_m, total_attributes):
    (G, o, g1, g2, pairing) = setup()
    # (X)=vk
    # print(f"no_of_attr: {total_attributes}")
    # print(f"no_of_public_attr: {len(public_m)}")
    no_of_private_attr = total_attributes-len(public_m)
    # print(f"no_of_private_attr: {no_of_private_attr}")
    (A_bar,B_bar,c,s,t,u_i,_timestamp) = proof
    C_j_m = add(g1, ec_sum([multiply(H[i], public_m[j]) for i, j in zip(range(no_of_private_attr, total_attributes), range(len(public_m)))]))
    # print(f"C_j_m in verify:{C_j_m}")
    U1 = add(multiply(A_bar,t),neg(multiply(B_bar, c)))
    U2 = add(multiply(C_j_m,s),ec_sum([multiply(H[i], u_i[i]) for i in range(no_of_private_attr)]))
    U = add(U1, U2)
    # print(f"U in verify:{U}")   
    # print(f"timestamp:{_timestamp}")
    c_bar = to_challenge_spok_onchain(g1, g2, A_bar, B_bar, U, H, public_m, _timestamp)
    # print(f"public_m:{public_m}")
    # print(f"c_bar:{c_bar}")
    # print(f"c:{c}")
    return c_bar==c   

def verifyCred(params,H, vk, proof,public_m,total_attributes):
    (G, o, g1, g2, pairing) = params
    (X)=vk
    (A_bar,B_bar,c,s,t,u_i,_timestamp) = proof
    assert verify_spok(params,H, X, proof,public_m,total_attributes)
    return pairing(X, A_bar)==pairing(g2, B_bar)
#######################
