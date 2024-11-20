# import socket
# import os
# import time
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import hashlib

# HEADER = 64
# PORT = 5050
# SERVER = socket.gethostbyname(socket.gethostname())
# ADDR = (SERVER, PORT)
# FORMAT = 'utf-8'
# DISCONNECT_MESSAGE = "!DISCONNECT"

# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client.connect(ADDR)

# def pseudorandom_permutation(key, data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return cipher.encrypt(pad(data.encode(), AES.block_size))

# def inverse_permutation(key, encrypted_data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()

# def hash_text_sha256(input_text):
#     sha256_hash = hashlib.sha256()
#     sha256_hash.update(input_text.encode(FORMAT))
#     return sha256_hash.hexdigest()

# def hash_byte_string_sha3_256(input_bytes):
#     sha3_256_hash = hashlib.sha3_256()
#     sha3_256_hash.update(input_bytes)
#     return sha3_256_hash.digest()

# def hash_byte_string_blake2b(input_bytes):
#     blake2b_hash = hashlib.blake2b(digest_size=32)
#     blake2b_hash.update(input_bytes)
#     return blake2b_hash.digest()

# def xor_bytes(b1, b2):
#     if len(b1) != len(b2):
#         raise ValueError("Byte strings must be of the same length to XOR")
#     return bytes([x ^ y for x, y in zip(b1, b2)])

# def concatenate_byte_strings(*byte_strings):
#     return b''.join(byte_strings)

# def string_to_byte_string(input_string):
#     return input_string.encode(FORMAT)

# def setup(lam):
#     size = int(lam / 8)
#     ks = os.urandom(size)
#     S = {}
#     return S, ks

# def fast_update(key, S, ind, w, op):
#     tw = pseudorandom_permutation(key, hash_text_sha256(w))
#     stc = S[w]

#     kc_next = os.urandom(32)
#     if stc:
#         stc_next = pseudorandom_permutation(kc_next, stc.decode(FORMAT))
#     else:
#         stc_next = pseudorandom_permutation(kc_next, "init_state")

#     # c += 1
#     S[w] = stc_next

#     b_ind = string_to_byte_string(ind)
#     b_op = string_to_byte_string(str(op))

#     term1 = concatenate_byte_strings(b_ind, b_op, kc_next)
#     term2 = hash_byte_string_sha3_256(concatenate_byte_strings(tw, stc_next))

#     e = xor_bytes(term1, term2)
#     u = hash_byte_string_blake2b(concatenate_byte_strings(tw, stc_next))

#     # Send u and e to server
#     client.send(u)
#     time.sleep(1)
#     client.send(e)

# S = {"crypto": b'initial_state_crypto', "encryption": b'initial_state_encryption'}
# T = {"file1.txt": b'encrypted_data_1', "file2.txt": b'encrypted_data_2'}

# key = os.urandom(32)
# ind = 'file1.txt'
# w = 'crypto'
# op = 0

# fast_update(key, S, ind, w, op)


import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import hashlib

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


def pseudorandom_function(key, message):
    # pseudo random funciton (prf) --  cryptographic function that, given an input and a secret key, produces
    # output that is indistinguishable from a truly random function to anyone without knowledge of the secret key.
    # this execution is using hmac and sha256
    # A pseudorandom Function cant be reversed, by any chance we can never figure out the encoded message

    return hmac.new(key, message.encode(), hashlib.sha256).digest()

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
    size = int(lam / 8)
    ks = os.urandom(size)
    S = {}
    return S, ks

def fast_update(key, S, ind, w, op):
    # Step 4: Calculate tw
    tw = pseudorandom_function(key, string_to_byte_string(hash_text_sha256(w)))
    
    # Step 5-6: Retrieve stc and initialize c
    (stc, c) = S.get(w, (None, 0))
    
    # Step 7-10: Generate a new state if stc is None
    if stc is None:
        stc = os.urandom(32)
        c = 0
    
    # Step 9: Generate new key kc+1
    kc_next = os.urandom(32)
    
    # Step 10: Calculate new stc+1
    stc_next = pseudorandom_permutation(kc_next, stc)
    S[w] = (stc_next, c + 1)
    
    # Step 11-12: Create e
    b_ind = string_to_byte_string(ind)
    b_op = bytes([op])  # Using 0 or 1 as op
    term1 = concatenate_byte_strings(b_ind, b_op, kc_next)
    term2 = hash_byte_string_sha3_256(concatenate_byte_strings(tw, stc_next))
    e = xor_bytes(term1, term2)
    
    # Step 13: Calculate u
    u = hash_byte_string_blake2b(concatenate_byte_strings(tw, stc_next))
    
    # Step 14: Send u and e to server
    client.send(u)
    time.sleep(1)
    client.send(e)

S = {}
key = os.urandom(32)
ind = 'file1.txt'
w1 = 'crypto'
w2 = 'sahil'
op = 0  # Use 0 for delete, 1 for add

# fast_update(key, S, ind, w1, op)
# fast_update(key, S, ind, w2, op)
# print(S)

# def fast_search(key, S, w):
#     # Step 4: Calculate tw
#     tw = pseudorandom_permutation(key, string_to_byte_string(hash_text_sha256(w)))

#     # Step 5-6: Retrieve stc and initialize c
#     (stc, c) = S.get(w, (None, 0))

#     if not stc:
#         return 0
#     else:
#         # send tw, current state and c to server
#         client.send(tw)
#         time.sleep(1)

#         client.send(stc)
#         time.sleep(1)

#         client.send(c)
#         time.sleep(1)

import os

def search_client(key, S, w):
    # Step 1: Retrieve the current state for the keyword `w` from S
    (stc, _) = S.get(w, (None, 0))
    if stc is None:
        print("Keyword not found in S.")
        return
    
    # Step 2: Generate the encrypted keyword (search token)
    encrypted_keyword = pseudorandom_permutation(key, string_to_byte_string(hash_text_sha256(w)))
    
    # Step 3: Concatenate the encrypted keyword and current state as the search token
    search_token = concatenate_byte_strings(encrypted_keyword, stc)
    
    # Step 4: Send the search token, state and c to the server
    client.send(search_token)
    print("Search token sent to the server.")

    client.send(stc)
    print("Current State sent to the server.")

    # client.send(c)
    # print("counter sent to the server.")
    
    # Step 5: Receive and print search results
    search_results = client.recv(4096)
    print("Search results received from server:", search_results.decode(FORMAT))




