# import socket
# import socket
# import os
# import time
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import hashlib
# import hmac
# import hashlib
# import plyvel
# import pickle

# # -----------------------------------------Imported necessary libraries ------------------------------------------

# CLIENT = socket.gethostbyname(socket.gethostname())
# PORT = 2614
# FORMAT = 'utf-8'
# # BYTESIZE = 

# # ------------------------------- Setting up supporting funcitons ---------------------------------------------------

# def pseudorandom_function(key, message):
#     # pseudo random funciton (prf) --  cryptographic function that, given an input and a secret key, produces
#     # output that is indistinguishable from a truly random function to anyone without knowledge of the secret key.
#     # this execution is using hmac and sha256
#     # A pseudorandom Function cant be reversed, by any chance we can never figure out the encoded message

#     return hmac.new(key, message.encode(), hashlib.sha256).digest()

# def pseudorandom_permutation(key, data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return cipher.encrypt(pad(data, AES.block_size))

# def inverse_permutation(key, encrypted_data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return unpad(cipher.decrypt(encrypted_data), AES.block_size)

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
#     # Adjust to handle different length byte strings
#     max_len = max(len(b1), len(b2))
#     b1 = b1.ljust(max_len, b'\x00')
#     b2 = b2.ljust(max_len, b'\x00')
#     return bytes([x ^ y for x, y in zip(b1, b2)])

# def concatenate_byte_strings(*byte_strings):
#     return b''.join(byte_strings)

# def string_to_byte_string(input_string):
#     return input_string.encode(FORMAT)

# def hash_byte_string_sha384(input_bytes):
#     sha384_hash = hashlib.sha384()  # Initialize SHA-384 hash object
#     sha384_hash.update(input_bytes)  # Update with the input byte string
#     return sha384_hash.digest()  # Return the hash digest as bytes

# def adjust_and_concatenate(ind, op):
#     # Convert op to a single byte (0 or 1)
#     op_byte = bytes([op])  # This will give a byte with value 0 or 1

#     # Convert ind to bytes
#     ind_bytes = ind.encode()

#     # Calculate available space for ind (48 bytes total minus 1 byte for op)
#     max_ind_size = 16 - len(op_byte)

#     # Truncate ind if necessary
#     if len(ind_bytes) > max_ind_size:
#         ind_bytes = ind_bytes[:max_ind_size]

#     # If the combined length is less than 48 bytes, pad ind with '*'
#     if len(ind_bytes) < max_ind_size:
#         ind_bytes = ind_bytes.ljust(max_ind_size, b'*')  # Pad with '*'

#     # Combine ind and op_byte
#     combined = ind_bytes + op_byte

#     return combined

def pseudorandom_function(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).digest()

def pseudorandom_permutation(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def inverse_permutation(key, encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)

def hash_text_sha256(input_text):
    return hashlib.sha256(input_text.encode(FORMAT)).hexdigest()

def hash_byte_string_sha3_256(input_bytes):
    return hashlib.sha3_256(input_bytes).digest()

def hash_byte_string_blake2b(input_bytes):
    return hashlib.blake2b(input_bytes, digest_size=32).digest()

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1.ljust(len(b2), b'\x00'), b2.ljust(len(b1), b'\x00')))

def concatenate_byte_strings(*byte_strings):
    return b''.join(byte_strings)

def string_to_byte_string(input_string):
    return input_string.encode(FORMAT)

def hash_byte_string_sha384(input_bytes):
    return hashlib.sha384(input_bytes).digest()

def adjust_and_concatenate(ind, op):
    ind_bytes = ind.encode()[:15]  # Ensure max length of 15 bytes
    return ind_bytes.ljust(15, b'*') + bytes([op])

# # ------------------------------------ Algorithm starts here ---------------------------------------------------------

def fast_client_setup():
    # size = int(lam / 8)
    ks = os.urandom(32)
    S = plyvel.DB('S.db', create_if_missing=True)
    print("S - Setup successfully!")
    # S = {}
    return S, ks

def fast_client_update(key, S, ind, w, op):
    # Step 4: Calculate tw
    tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
    
    # Step 5-6: Retrieve stc and initialize c
    pickled_value = S.get(w.encode(), default=None)

    # Check if the value was found in the database
    if pickled_value is not None:
        stc, c = pickle.loads(pickled_value)
    else:
        stc = None
        c = 0

    # Step 7-10: Generate a new state if stc is None
    if stc is None:
        stc = key  # Generate a random 32-byte value for stc
        c = 0  # Initialize c to 0
    
    # Step 9: Generate new key kc+1
    kc_next = os.urandom(32)
    
    # Step 10: Calculate new stc+1
    stc_next = pseudorandom_permutation(kc_next, stc)

    # Serialize the new state
    value = pickle.dumps((stc_next, c + 1))

    # Store the serialized value in the database
    S.put(w.encode(), value)
    
    # Step 11-12: Create e
    term1 = concatenate_byte_strings(adjust_and_concatenate(ind, op), kc_next) # this will always be of size 48 bytes, op will be at the end, and the ind will be truncated or padded acc to size
    term2 = hash_byte_string_sha384(concatenate_byte_strings(tw, stc_next))# this will alwayys be of size 48 bytes
    e = xor_bytes(term1, term2) # of 48 bytes
    
    # Step 13: Calculate u
    u = hash_byte_string_blake2b(concatenate_byte_strings(tw, stc_next))
    
    # Step 14: Send u and e to server
    # client.send(u)
    # print(f'SENT - u')
    # client.send(e)
    # print(f'SENT - e')
    # client.close()

    # rather than sending u,e to server this function will just return the u,e values

    return u,e

# def fast_client_search(key, S, w):
#     # Step 4: Calculate tw
#     tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
    
#     # Step 5-6: Retrieve stc and initialize c
#     pickled_value = S.get(w.encode(), default=None)
#     print(f'pickled_vlue-->{pickled_value}')
#     # Check if the value was found in the database
#     if pickled_value is not None:
#         stc, c = pickle.loads(pickled_value)
#     else:
#         stc = None
#         c = 0

#     # Step 7-10: if stc is None, return 0
#     if stc is None:
#         return b"exit",b"exit",0 
    
#     # # Step 2: Generate the encrypted keyword (search token)
#     # encrypted_keyword = pseudorandom_permutation(key, string_to_byte_string(hash_text_sha256(w)))
    
#     # # Step 3: Concatenate the encrypted keyword and current state as the search token
#     # search_token = concatenate_byte_strings(encrypted_keyword, stc)
    
#     # Step 4: Send the search token, state and c to the server
#     # client.send(tw)
#     # print("Search token sent to the server.")

#     # client.send(stc)
#     # print("Current State sent to the server.")

#     # client.send(c)
#     # print("counter sent to the server.")
#     return tw, stc, c
#     # # Step 5: Receive and print search results
#     # search_results = client.recv(4096)
#     # print("Search results received from server:", search_results.decode(FORMAT))
# # S, ks = fast_client_setup()
# # tw,stc,c = fast_client_search(ks,S,'word')
# # print(f"TW: {tw}")
# # print(f"STC: {stc}")
# # print(f"C: {c}")

# # --------------------------------------- Algorithm ends here ----------------------------------------------------------

# # --------------------------------------------- To start server for update commands ---------------------------------



# def start_update_client():
#     # CLIENT = "10.14.3.246"  # Replace with the actual server IP
#     PORT = 2614             # Replace with the actual server port

#     # Create a socket connection
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
#         client_socket.settimeout(5)  # Set a timeout for socket operations
#         try:
#             client_socket.connect((CLIENT, PORT))
#             print(f"Connected to server at {CLIENT}:{PORT}")

#             # Example of using multiple indices and operations
#             ind1 = 'file1.txt'
#             ind2 = 'file2.txt'
#             w1 = 'crypto'
#             w2 = 'graphical'
#             op1 = 1  # Use 0 for delete, 1 for add
#             op2 = 0
            
#             # Loop to send `u, e` pairs
#             for i in range(1, 6):
#                 if i % 2 == 0:
#                     u, e = fast_client_update(ks, S, ind1, w1, op1)  # Replace with your implementation
#                 else:
#                     u, e = fast_client_update(ks, S, ind2, w2, op2)  # Replace with your implementation

#                 # Send `u` and `e` to the server
#                 client_socket.sendall(u)
#                 # print(f"U - Sent Successfully: {u}")
#                 time.sleep(0.1)  # Ensure buffer is flushed before sending `e`
#                 client_socket.sendall(e)
#                 # print(f"E - Sent Successfully: {e}")
#                 time.sleep(0.1)  # Optional: Add a slight delay between sends

#             # Send exit signals for both `u` and `e`
#             exit_message = b"exit"
#             time.sleep(0.1)  # Ensure the final `u, e` pair is flushed before sending exit
#             client_socket.sendall(exit_message)
#             # print("U - Exit message sent.")
#             client_socket.sendall(exit_message)
#             # print("E - Exit message sent.")

#         except socket.timeout:
#             print("Connection timed out.")
#         except Exception as e:
#             print(f"An error occurred: {e}")
#         finally:
#             print("Closing connection.")



# # setup of 'S' and 'ks' 
# S, ks = fast_client_setup()
# start_time_client = time.time()
# start_update_client()

# end_time_client = time.time()

# time_elasped_client = end_time_client - start_time_client
# print(f'Time elasped for client - {time_elasped_client}')

import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import plyvel
import pickle

CLIENT = socket.gethostbyname(socket.gethostname())
PORT = 2614
FORMAT = 'utf-8'

def fast_client_setup():
    ks = os.urandom(32)
    S = plyvel.DB('S.db', create_if_missing=True)
    print("S - Setup successfully!")
    return S, ks

def start_update_client():
    with socket.create_connection((CLIENT, PORT), timeout=5) as client_socket:
        try:
            print(f"Connected to server at {CLIENT}:{PORT}")

            updates = [("file1.txt", "crypto", 1), ("file2.txt", "graphical", 0)]
            messages = [fast_client_update(ks, S, ind, w, op) for i, (ind, w, op) in enumerate(updates * 1)]
            client_socket.sendall(b''.join(u + e for u, e in messages))
            client_socket.sendall(b"exit" * 2)

        except (socket.timeout, Exception) as e:
            print(f"An error occurred: {e}")
        finally:
            print("Closing connection.")

S, ks = fast_client_setup()
start_time_client = time.time()
start_update_client()
end_time_client = time.time()

print(f'Time elapsed for client - {end_time_client - start_time_client}')

