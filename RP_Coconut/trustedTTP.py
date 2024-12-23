import argparse
import jsonpickle
import os
import socket
import subprocess
import time
from py_ecc.bn128 import *
from py_ecc_tester import *
from constants import *

def encodeG2(g2):
	return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)

def encodeG2List(g2_list):
  encoded_g2_list = []
  for g2 in g2_list:
    if g2 is not None:
      encoded_g2_list.append(encodeG2(g2))
    else:
      encoded_g2_list.append(None)
  return encoded_g2_list

def decodeToG2List(encoded_g2_list):
  g2_list = []
  for encoded_g2 in encoded_g2_list:
    if encoded_g2 is not None:
      g2_list.append(decodeToG2(encoded_g2))
    else:
      g2_list.append(None)
  return g2_list

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

def encodeVkList(vks):
  encoded_vks = []
  for vk in vks:
    if vk is not None:
      encoded_vks.append(encodeVk(vk))
    else:
      encoded_vks.append(None)
  return encoded_vks

def decodeVkList(encoded_vks):
  vks = []
  for encoded_vk in encoded_vks:
    if encoded_vk is not None:
      vks.append(decodeVk(encoded_vk))
    else:
      vks.append(None)
  return vks

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

def kill_process_using_port(port):
    try:
        
        pid = int(subprocess.check_output(["lsof", "-t", "-i:" + str(port)]).strip())
        print(f"Found process {pid} using port {port}. Terminating it.")
    
        os.kill(pid, 9)
    except subprocess.CalledProcessError:
        print(f"No process found using port {port}.")
    except Exception as e:
        print(f"Error killing process on port {port}: {e}")


def bind_socket_with_retry(socket_obj, ip, port, retries=MAX_RETRIES, delay=RETRY_DELAY):
    for attempt in range(retries):
        try:
            socket_obj.bind((ip, int(port)))
            print(f"Successfully bound to IP {ip} on port {port}")
            return True
        except OSError as e:
            if e.errno == 98: 
                print(f"Port {port} is already in use, retrying in {delay} second(s)...")
                kill_process_using_port(port)
                time.sleep(delay)
            else:
                print(f"Failed to bind to port {port}: {e}")
                return False
    return False


def initialize_socket(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if bind_socket_with_retry(s, ip, port):
        s.listen(20)
        return s
    else:
        print(f"Failed to bind socket to IP {ip} on port {port} after multiple attempts.")
        return None


def main():
    
    parser = argparse.ArgumentParser(description="Anonymous Credentials Service")
    parser.add_argument("--req-ip", type=str, default='127.0.0.1', help="IP address where the organization is running.")
    parser.add_argument("--req-port", type=str, required=True, help="Port where the organization is running.")
    parser.add_argument("--total-issuers", type=int, required=True, help="Total number of issuers.")
    parser.add_argument("--threshold-issuers", type=int, required=True, help="Threshold number of issuers.")
    args = parser.parse_args()

    if args.threshold_issuers > args.total_issuers:
        print("Threshold issuers cannot be greater than total issuers. Exiting.")
        exit(1)
    
    q=MAX_ATTRIBUTES
    ttp="AC"
    params = setup(q, ttp)
    # Generate keys for issuers
    print("Generating keys for issuers...")
    sk, vk = ttp_keygen(params, args.threshold_issuers, args.total_issuers )
    aggregate_vk = agg_key(params, vk)
    encoded_vks = encodeVkList(vk)
    encoded_aggregate_vk = encodeVk(aggregate_vk)
    # decoded_agg_key = decodeVk(encoded_aggregate_vk)
    # (A,B,C,D) = decoded_agg_key
    # print(f"A:{A}, B:{B}")
    # # Display generated keys
    # for idx, (secret, public) in enumerate(zip(sk, vk)):
    #     print(f"Issuer {idx} - Secret Key: {secret}, Public Key: {public}\n")
    #     print(f"aggregate key:{aggregate_vk}")

    # Initialize socket
    socket_obj = initialize_socket(args.req_ip, args.req_port)
    if not socket_obj:
        print("Server initialization failed. Exiting.")
        exit(1)

    
    
    print(f"ttp is now listening on {args.req_ip}:{args.req_port}")

    key_request_count = 0
    # try:
    while key_request_count < args.total_issuers:
        conn, addr = socket_obj.accept()
        validator = conn.recv(8192).decode()
        print(f"Connection received from: {addr}. Issuer: {validator}")

        try:
            issuer_id = int(validator[1:])  # Assuming issuer ID is the second character onwards
            #keys = f"{vk[issuer_id]}:{sk[issuer_id]}:{encoded_aggregate_vk}"
            keys = (encoded_vks[issuer_id], sk[issuer_id],encoded_aggregate_vk)
            print(f"Issuer {issuer_id} - Secret Key: {sk[issuer_id]}")
            print(f" Public Key: {vk[issuer_id]}")
            print(f"Aggregate Key: {encoded_aggregate_vk}\n")
            keys_json = jsonpickle.encode(keys)
            conn.sendall(keys_json.encode() + b"\n\nEND\n\n")
            #conn.send(keys_json.encode())
            key_request_count += 1
        except (ValueError, IndexError):
            print(f"Invalid validator ID: {validator}")
        finally:
            conn.close()

if __name__ == "__main__":
    main()
