from py_ecc.bn128 import *
#from py_ecc.bls12_381 import *
from TTP import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
import time

def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 3) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
   # print("field_modulus in functions:"+str(field_modulus))
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

def setup(q=1, AC = "h"):
    assert q > 0
    hs = [hashG1((AC+"%s"%i).encode("utf8")) for i in range(q)]
    return ((FQ, FQ2, FQ12), curve_order, G1, hs, G2, pairing)

def ttp_setup(q, ttp= "h"):
	assert q > 0
	hs = [hashG1((ttp+("h%s")% i).encode("utf8")) for i in range(q)]
	return ((FQ, FQ2, FQ12), G1, int(curve_order), hs)

def poly_eval(coeff, x):
     #evaluate a polynomial defined by the list of coefficient coeff at point x 
    return sum([coeff[i] * ((x) ** i) for i in range(len(coeff))])

def ttp_keygen(params, t, n):
    (G, o, g1, hs, g2, e) = params
    q = len(hs)
    assert n >= t and t > 0 and q > 0
    v = [random.randint(2, o) for _ in range(0,t)]
    w = [[random.randint(2, o) for _ in range(0,t)] for _ in range(q)]
    x = [poly_eval(v,i) % o for i in range(1,n+1)]
    y = [[poly_eval(wj,i) % o for wj in w] for i in range(1,n+1)]
    sk = list(zip(x, y))
    #added betas for RP_Coconut
    vk = [(g2, multiply(g2, x[i]), [multiply(g1, y[i][j]) for j in range(len(y[i]))], [multiply(g2, y[i][j]) for j in range(len(y[i]))]) for i in range(len(sk))]
    #to check aggregate key
    # a= poly_eval(v,0) % o
    # b= [poly_eval(wj,0) % o for wj in w]
    # agg_k= (g2, multiply(g2, a), [multiply(g1, b[j]) for j in range(len(b))], [multiply(g2, b[j]) for j in range(len(b))])
    # print(f"aggregate key in TTP: {agg_k}")
    return (sk, vk)


def to_binary256(point):
    if isinstance(point, str):
        return sha256(point.encode("utf8").strip()).digest()
    if isinstance(point, int):
        point_bytes = point.to_bytes((point.bit_length() + 7) // 8, 'big')
        return point_bytes.rjust(32, b'\x00')
    if isinstance(point[0], FQ):
        point1 = point[0].n.to_bytes((point[0].n.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')
        point2 = point[1].n.to_bytes((point[1].n.bit_length() + 7) // 8, 'big').rjust(32, b'\x00')
        return sha256(point1 + point2).digest()
    if isinstance(point[0], FQ2):
        point1 = (point[0].coeffs[0].n.to_bytes((point[0].coeffs[0].n.bit_length() + 7) // 8, 'big').rjust(32, b'\x00') +
                  point[0].coeffs[1].n.to_bytes((point[0].coeffs[1].n.bit_length() + 7) // 8, 'big').rjust(32, b'\x00'))
        point2 = (point[1].coeffs[0].n.to_bytes((point[1].coeffs[0].n.bit_length() + 7) // 8, 'big').rjust(32, b'\x00') +
                  point[1].coeffs[1].n.to_bytes((point[1].coeffs[1].n.bit_length() + 7) // 8, 'big').rjust(32, b'\x00'))
        return sha256(point1 + point2).digest()



def to_challenge(elements):
    _list = [to_binary256(x) for x in elements]
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]
    Chash =  sha256(Cstring).digest()
    return int.from_bytes(Chash, "big", signed=False)

def compute_hash(params, cm):
    (G, o, g1, hs, g2, e) = params
    h = hashG1(to_binary256(cm))
    return h

def ec_sum(list):
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

def lagrange_basis(indexes, o, x=0):
    l = []
    for i in indexes:
        numerator, denominator = 1, 1
        for j in indexes:
            if j != i:
                numerator = (numerator * (x - j)) % o
                denominator = (denominator * (i - j)) % o
        l.append((numerator * modInverse(denominator, o)) % o)
    return l

def agg_key(params, vks):
    (G, o, g1, hs, g2, e) = params
    filter = [vks[i] for i in range(len(vks)) if vks[i] is not None]
    indexes = [i+1 for i in range(len(vks)) if vks[i] is not None]
    l = lagrange_basis(indexes,o)
    (_, alpha, g1_beta, beta) = zip(*filter)
    q = len(beta[0])
    aggr_alpha = ec_sum([multiply(alpha[i], l[i]) for i in range(len(filter))])
    aggr_g1_beta = [ec_sum([multiply(g1_beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_beta = [ec_sum([multiply(beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_vk = (g2, aggr_alpha, aggr_g1_beta, aggr_beta)
    return aggr_vk

def make_pi_s(params, commitments, cm, os, r, all_attr, no_of_private_attributes):
    (G, o, g1, hs, g2, e) = params
    #attributes = private_m + public_m
    assert len(commitments) == len(os) and len(commitments) == no_of_private_attributes
    assert len(all_attr) <= len(hs)
    # create the witnesses
    wr =random.randint(2, o)
    wos = [random.randint(2, o) for _ in os]
    wm = [random.randint(2, o) for _ in range(no_of_private_attributes)]
      # compute h
    h = hashG1(to_binary256(cm))
    # compute the witnesses commitments
    Aw = [add(multiply(g1, wos[i]), multiply(h, wm[i])) for i in range(no_of_private_attributes)]
    Bw = add(multiply(g1, wr), ec_sum([multiply(hs[i], wm[i]) for i in range(len(wm))]))
   
    c = to_challenge([g1, g2, cm, h, Bw]+hs+Aw)
    # create responses
    rr = (wr - c * r) % o
    ros = [(wos[i] - c*os[i]) % o for i in range(len(wos))]
    rm = [(wm[i] - c*all_attr[i]) % o for i in range(len(wm))] #only for private attributes
    # print(f"Aw={Aw}")
    #print(f"Bw={Bw}")
    #print(f"c={c}")
    return (c, rr, ros, rm)

#def verify_pi_s(params, commitments, cm, prevParams, prevVcerts, proof):
def verify_pi_s(params, commitments, cm, proof):
    (G, o, g1, hs, g2, e) = params
    (c, rr, ros, rm) = proof
    assert len(commitments) == len(ros)
    # re-compute h
    h = hashG1(to_binary256(cm))
    # re-compute witnesses commitments
    Aw = [add(multiply(commitments[i], c), add(multiply(g1, ros[i]), multiply(h, rm[i])))for i in range(len(commitments))]
    Bw = add(multiply(cm, c), add(multiply(g1, rr), ec_sum([multiply(hs[i], rm[i]) for i in range(len(rm))])))
    c_bar = to_challenge([g1, g2, cm, h, Bw]+hs+Aw)
    # print(f"Aw={Aw}")
    print(f"Bw={Bw}")
    print(f"c={c}")
    print(f"c_bar={c_bar}")
    # print(f"length of rm ={len(rm)}")
    return c == c_bar

#def PrepareCredRequest(params, aggr_vk, prevParams, all_attr, include_indexes, public_m=[]):
def PrepareCredRequest(params, all_attr, no_of_private_attributes):
    
    assert no_of_private_attributes > 0
    (G, o, g1, hs, g2, e) = params
    #attributes = private_m + public_m
    print("len(attributes)"+str(len(all_attr)))
    print("len(hs)"+str(len(hs)))
    assert len(all_attr) <= len(hs)
    # build commitment
    rand = random.randint(2, o)#generates random number 
    #compute commitments for each message(RP_Coconut) 
    cm = add(multiply(g1, rand), ec_sum([multiply(hs[i], all_attr[i]) for i in range(no_of_private_attributes)]))
    #cm = add(multiply(g1, rand), ec_sum([multiply(hs[i], all_attr[i]) for i in range(len(all_attr))]))

    print("cm"+str(cm)) 
    h = hashG1(to_binary256(cm))
    print(f"h in prepare credential request:{h}")
    os = [random.randint(2, o) for _ in range(no_of_private_attributes)]
    commitments = [add(multiply(g1, os[i]), multiply(h, all_attr[i])) for i in range(no_of_private_attributes)]
    # pi_s = make_pi_s(params, commitments, cm, os, rand, public_m, private_m, all_attr, prevParams, include_indexes)
    pi_s = make_pi_s(params, commitments, cm, os, rand, all_attr,no_of_private_attributes)
    result = verify_pi_s(params, commitments, cm, pi_s) #temporary
    print(f"proof verification is:{result}")
    print(f"os in credential request:{os}")
    Lambda = (cm, commitments, pi_s)
    return Lambda, os

# def BlindSign(params, sk, prevParams, prevVcerts, all_pks, Lambda, public_m=[]):
#     (G, o, g1, hs, g2, e) = params
#     (x, y) = sk
#     for i in range(len(prevVcerts)):
#         if not VerifyVcerts(prevParams[i], all_pks[i], prevVcerts[i][1], SHA256(prevVcerts[i][0])):
#             return None
#     (cm, commitments, pi_s) = Lambda
#     assert (len(commitments)+len(public_m)) <= len(hs)
#     assert verify_pi_s(params, commitments, cm, prevParams, prevVcerts, pi_s)
#     h = hashG1(to_binary256(cm))
#     t1 = [multiply(h, mi) for mi in public_m]
#     t2 = add(multiply(h, x), ec_sum([multiply(bi, yi) for yi,bi in zip(y, commitments+t1)]))
#     sigma_tilde = (h, t2)
#     return sigma_tilde

def BlindSignAttr(params, sk, Lambda, public_m=[]):
    (G, o, g1, hs, g2, e) = params
    (x, y) = sk
    (cm, commitments) = Lambda
    assert (len(commitments)+len(public_m)) <= len(hs)
    h = hashG1(to_binary256(cm))
    print(f"h:{h}")
    print(f"len(commitments):{len(commitments)}")
    # t1 = [multiply(h, mi) for mi in public_m]
    # t2 = add(multiply(h, x), ec_sum([multiply(bi, yi) for yi,bi in zip(y, commitments+t1)]))
    t2 = add(multiply(h, x), ec_sum([multiply(bi, yi) for yi,bi in zip(y, commitments)]))
    print(f"t2:{t2}")
    sigma_tilde = (h, t2)
    return sigma_tilde

def Unblind(params, aggr_vk, sigma_tilde, os):
    g1_beta = aggr_vk
    (h, c_tilde) = sigma_tilde
    #change for RP_Coconut
    print(f"g1_beta in unblind:{g1_beta}")
    print(f"c_tilde in unblind:{c_tilde}")
    print(f"os values:{os}")
    sigma = (h, add(c_tilde, neg(ec_sum([multiply(g1_beta[j], os[j]) for j in range(len(os))]))))
    return sigma

#l(i) is getting calculated wrong that is why final verification is failing
def AggCred(params, sigs):
    (G, o, g1, hs, g2, e) = params
    filter = [sigs[i] for i in range(len(sigs)) if sigs[i] is not None]
    indexes = [i+1 for i in range(len(sigs)) if sigs[i] is not None]
    print(f"filter:{filter}")
    print(f"indexes:{indexes}")
    l = lagrange_basis(indexes,o)
    (h, s) = zip(*filter)
    aggr_s = ec_sum([multiply(s[i], l[i]) for i in range(len(filter))])
    aggr_sigma = (h[0], aggr_s)
    return aggr_sigma

def make_pi_v(params, aggr_vk, sigma, private_m, kappa, t):
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, _, beta) = aggr_vk
    (h, s) = sigma
    wm = [random.randint(2, o) for i in range(len(private_m))]
    wt = random.randint(2, o)
    Aw = add(add(multiply(g2, wt), alpha), ec_sum([multiply(beta[i], wm[i]) for i in range(len(private_m))]))
   # Aw = add(multiply(g2, wt),ec_sum([multiply(beta[i], wm[i]) for i in range(len(wm))]))

    #Aw = ec_sum([multiply(beta[i], wm[i]) for i in range(len(wm))])
    Bw = multiply(h, wt)
    _timestamp = int(time.time())

    print(f"Private attributes in proof:{private_m}")
    # print(f"Aw in proof:{Aw}")
    # print(f"Bw in proof:{Bw}")
    
    c = to_challenge([g1, g2, alpha, Bw,Aw, kappa]+ hs + beta + [_timestamp])
    rm = [(wm[i] - c*private_m[i]) % o for i in range(len(private_m))]
    rt = (wt - c*t) % o

    return (Aw, _timestamp, (c, rm, rt))

#def ProveCred(params, aggr_vk, sigma, private_m, disclose_index, disclose_attr, disclose_attr_enc, public_m):
def ProveCred(params, aggr_vk, sigma, private_m):
    assert len(private_m) > 0
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, _, beta) = aggr_vk
    (h, s) = sigma
    assert len(private_m) <= len(beta)
    r_prime = random.randint(2, o)
    (h_prime , s_prime) = (multiply(h, r_prime), multiply(s, r_prime))
    sigma_prime =(h_prime, s_prime)
    r = random.randint(2, o)
    kappa = ec_sum([multiply(g2, r), alpha, ec_sum([multiply(beta[i], private_m[i]) for i in range(len(private_m))])])
    #kappa = add(multiply(g2, r),ec_sum([multiply(beta[i], int(private_m[i])) for i in range(len(private_m))]))
    #kappa = ec_sum([multiply(beta[i], private_m[i]) for i in range(len(private_m))])
    nu = multiply(h_prime, r)
    Aw, timestamp, pi_v = make_pi_v(params, aggr_vk, sigma_prime, private_m, kappa, r)
    Theta = (kappa, nu, sigma_prime, pi_v, Aw, timestamp)
    print(f"Private attributes in making kappa :{private_m}")
    # aggr = None
    # if len(public_m) != 0:
    #     aggr = ec_sum([multiply(beta[i+len(private_m)], public_m[i]) for i in range(len(public_m))])
    return Theta

def verify_pi_v(params, aggr_vk, sigma, kappa, nu, proof, timestamp):
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, _, beta) = aggr_vk
    (h, s) = sigma
    (c, rm, rt) = proof
    new_kappa = kappa
    #Aw = add(add(multiply(g2, wt), alpha), ec_sum([multiply(beta[i], wm[i]) for i in range(len(private_m))]))

    # Aw = add(add(multiply(new_kappa, c), multiply(g2, rt)), add(multiply(alpha, (o - c + 1)%o), undisclosed_sum))
    Aw = add(add(add(multiply(new_kappa, c), multiply(g2, rt)), multiply(alpha, (o - c + 1)%o)),ec_sum([multiply(beta[i], rm[i]) for i in range(len(rm))]))
    #Aw = add(multiply(kappa, c),ec_sum([multiply(beta[i], rm[i]) for i in range(len(rm))]))

    Bw = add(multiply(nu, c), multiply(h, rt))

    # print(f"Aw in verify:{Aw}")
    # print(f"Bw in verify:{Bw}")

    return c == to_challenge([g1, g2, alpha, Bw,Aw, kappa]+ hs + beta + [timestamp])

def VerifyCred(params, aggr_vk, Theta, public_m=[]):
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, g1_beta, beta) = aggr_vk
    (kappa, nu, sigma, pi_v, _, timestamp) = Theta
    (h, s) = sigma
    print(f"sigma in verifycred:{sigma}")
    assert verify_pi_v(params, aggr_vk, sigma, kappa, nu, pi_v, timestamp)
    return e(kappa, h) == e(g2, add(s, nu)) and not is_inf(h) 
