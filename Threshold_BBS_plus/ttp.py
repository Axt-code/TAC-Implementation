import argparse
import jsonpickle
import os
import socket
import subprocess
import time
from py_ecc.bn128 import *
from helper import *
from datetime import datetime

# Constants for retry logic
MAX_RETRIES = 5
RETRY_DELAY = 1  # seconds

# Utility Function: Print with Timestamp
def print_with_timestamp(message):
    """Print the given message with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"[{timestamp}] {message}")

def kill_process_using_port(port):
    try:
        # Find the PID of the process using the port
        pid = int(subprocess.check_output(["lsof", "-t", "-i:" + str(port)]).strip())
        print(f"Found process {pid} using port {port}. Terminating it.")
        
        # Kill the process
        os.kill(pid, 9)
    except subprocess.CalledProcessError:
        print(f"No process found using port {port}.")
    except Exception as e:
        print(f"Error killing process on port {port}: {e}")


def bind_socket_with_retry(socket_obj, ip, port, retries=MAX_RETRIES, delay=RETRY_DELAY):

    for attempt in range(retries):
        try:
            socket_obj.bind((ip, int(port)))
            print_with_timestamp(f"Successfully bound to IP {ip} on port {port}")
            return True
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print_with_timestamp(f"Port {port} is already in use, retrying in {delay} second(s)...")
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
    # Argument parsing
    parser = argparse.ArgumentParser(description="Anonymous Credentials Service")
    parser.add_argument("--req-ip", type=str, default='127.0.0.1', help="IP address where the organization is running.")
    parser.add_argument("--req-port", type=str, required=True, help="Port where the organization is running.")
    parser.add_argument("--total-issuers", type=int, required=True, help="Total number of issuers.")
    parser.add_argument("--threshold-issuers", type=int, required=True, help="Threshold number of issuers.")
    args = parser.parse_args()

    # Validate the input for issuers
    if args.threshold_issuers > args.total_issuers:
        print_with_timestamp("Threshold issuers cannot be greater than total issuers. Exiting.")
        exit(1)

    # Generate keys for issuers
    print_with_timestamp("Generating keys for issuers...")
    sk, vk, X = ttp_keygen(args.threshold_issuers, args.total_issuers)
    
    
    print_with_timestamp(f"Generated keys for issuers..\n")

    # Initialize socket
    socket_obj = initialize_socket(args.req_ip, args.req_port)
    if not socket_obj:
        print_with_timestamp("Server initialization failed. Exiting.")
        exit(1)

    print_with_timestamp(f"ttp is now listening on {args.req_ip}:{args.req_port}")

    key_request_count = 0
    try:
        while key_request_count < args.total_issuers:
            conn, addr = socket_obj.accept()
            validator = conn.recv(8192).decode()
            print_with_timestamp(f"Connection received from: {addr}. Issuer: {validator}")

            try:
                issuer_id = int(validator[1:])  # Assuming issuer ID is the second character onwards
                keys = f"{vk[issuer_id]}:{sk[issuer_id]}:{X}"
                print_with_timestamp(f"Issuer {issuer_id} - Got it's key pair\n")
                keys_json = jsonpickle.encode(keys)
                conn.send(keys_json.encode())
                key_request_count += 1
            except (ValueError, IndexError):
                print_with_timestamp(f"Invalid validator ID: {validator}")
            finally:
                conn.close()

    except Exception as e:
        print_with_timestamp(f"Error occurred: {e}")
    finally:
        print_with_timestamp("Shutting down the server.")
        socket_obj.shutdown(socket.SHUT_RDWR)
        socket_obj.close()


if __name__ == "__main__":
    main()
