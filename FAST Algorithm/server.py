# import socket
# import threading

# HEADER = 64
# PORT = 5050
# SERVER = socket.gethostbyname(socket.gethostname())
# ADDR = (SERVER, PORT)
# FORMAT = 'utf-8'
# DISCONNECT_MESSAGE = "!DISCONNECT"

# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind(ADDR)

# def setup(lam):
#     T = {}
#     print("Setup Completed. Long term key initiated, State and Index map initiated")
#     return T

# def handle_client(conn, addr, T):
#     print(f"Connected by {addr}")
#     u = conn.recv(1024)  # Receive the u-value from the client
#     e = conn.recv(1024)  # Receive the e-value from the client
#     print(f"u-value: {u}")
#     print(f"e-value: {e}")
#     conn.close()

# def start_server():
#     server.listen()
#     print(f"Server is listening on {SERVER}:{PORT}")
#     while True:
#         conn, addr = server.accept()
#         thread = threading.Thread(target=handle_client, args=(conn, addr, T))
#         thread.start()
#         print(f"Active connections: {threading.active_count() - 1}")

# T = {"file1.txt": b'encrypted_data_1', "file2.txt": b'encrypted_data_2'}

# start_server()


import socket
import threading
import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def pseudorandom_permutation(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def inverse_permutation(key, encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)

def hash_text_sha256(input_text):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_text.encode(FORMAT))
    return sha256_hash.hexdigest()

def hash_byte_string_sha3_256(input_bytes):
    sha3_256_hash = hashlib.sha3_256()
    sha3_256_hash.update(input_bytes)
    return sha3_256_hash.digest()

def hash_byte_string_blake2b(input_bytes):
    blake2b_hash = hashlib.blake2b(digest_size=32)
    blake2b_hash.update(input_bytes)
    return blake2b_hash.digest()

def xor_bytes(b1, b2):
    # Adjust to handle different length byte strings
    max_len = max(len(b1), len(b2))
    b1 = b1.ljust(max_len, b'\x00')
    b2 = b2.ljust(max_len, b'\x00')
    return bytes([x ^ y for x, y in zip(b1, b2)])

def concatenate_byte_strings(*byte_strings):
    return b''.join(byte_strings)

def string_to_byte_string(input_string):
    return input_string.encode(FORMAT)

def setup(lam):
    T = {}
    print("Setup Completed. Long term key initiated, State and Index map initiated")
    return T

def update_server(conn, addr, T):
    print(f"Connected by {addr}")
    
    # Step 14: Receive u and e from client
    u = conn.recv(1024)  # Receive the u-value from the client
    e = conn.recv(1024)  # Receive the e-value from the client
    print(f"Received u-value: {u}")
    print(f"Received e-value: {e}")
    
    # Step 21: Store the entry in T
    T[u] = e
    
    conn.close()

def start_server():
    server.listen()
    print(f"Server is listening on {SERVER}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=update_server, args=(conn, addr, T))
        thread.start()
        print(f"Active connections: {threading.active_count() - 1}")

T = {}

start_server()
# print(T)

def search_server(conn, addr, T):

    print(f"Connected by {addr}")
    
    # Step 1: Receive the search token from the client
    search_token = conn.recv(1024)
    print('Search Token received')
    
    # Step 2: Extract encrypted keyword and current state from search token
    encrypted_keyword = search_token[:32]  # first 32 bytes are the encrypted keyword
    current_state = search_token[32:]  # Remaining bytes are the current state
    
    # Step 3: Initialize result set and set of deleted file identifiers
    result_set = set()
    D = set()
    
    # Step 4: Perform backward search in the update sequence
    for (u, e) in reversed(T.items()):
        # Generate ephemeral key k_i for each entry
        k_i = hash_byte_string_sha3_256(concatenate_byte_strings(encrypted_keyword, u))
        
        # Recover previous state `st_i` using the ephemeral key
        previous_state = inverse_permutation(k_i, current_state)
        
        # Check if this entry is an "add" or "delete" update and process accordingly
        b_ind, b_op, _ = e[:32], e[32:33], e[33:]  # Extract components from `e`
        ind = b_ind.decode(FORMAT)
        op = int.from_bytes(b_op, 'big')  # Convert `b_op` to integer (0 for delete, 1 for add)
        
        if op == 0:  # Delete operation
            D.add(ind)  # Add `ind` to deleted set
        elif op == 1:  # Add operation
            if ind in D:
                D.remove(ind)  # Remove from `D` if it was previously deleted
            else:
                result_set.add(ind)  # Add to result set if not in `D`
        
        # Update current state to the previous state for the next iteration
        current_state = previous_state
    
    # Send the result set back to the client
    conn.send(str(result_set).encode(FORMAT))
    conn.close()
    print("Search completed. Results sent to the client.")



