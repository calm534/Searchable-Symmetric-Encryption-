import socket
import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import hashlib
import plyvel
import pickle

# -----------------------------------------Imported necessary libraries ------------------------------------------

CLIENT = socket.gethostbyname(socket.gethostname())
PORT = 2614
FORMAT = 'utf-8'
# BYTESIZE = 

# ------------------------------- Setting up supporting funcitons ---------------------------------------------------

def pseudorandom_function(key, message):
    # pseudo random funciton (prf) --  cryptographic function that, given an input and a secret key, produces
    # output that is indistinguishable from a truly random function to anyone without knowledge of the secret key.
    # this execution is using hmac and sha256
    # A pseudorandom Function cant be reversed, by any chance we can never figure out the encoded message

    return hmac.new(key, message.encode(), hashlib.sha256).digest()

def pseudorandom_permutation(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

# def pseudorandom_permutation(cipher, data):
#     if len(data) % AES.block_size != 0:
#         data = pad(data, AES.block_size)
#     return cipher.encrypt(data)

# def inverse_permutation(key, encrypted_data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return unpad(cipher.decrypt(encrypted_data), AES.block_size)

def inverse_permutation(cipher, encrypted_data):
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)

# def hash_text_sha256(input_text):
#     sha256_hash = hashlib.sha256()
#     sha256_hash.update(input_text.encode(FORMAT))
#     return sha256_hash.hexdigest()
def hash_text_sha256(input_text, encoding="utf-8"):
    return hashlib.sha256(input_text.encode(encoding)).hexdigest()

# def hash_byte_string_sha3_256(input_bytes):
#     sha3_256_hash = hashlib.sha3_256()
#     sha3_256_hash.update(input_bytes)
#     return sha3_256_hash.digest()

def hash_byte_string_sha3_256(input_bytes):
    return hashlib.sha3_256(input_bytes).digest()

# def hash_byte_string_blake2b(input_bytes):
#     blake2b_hash = hashlib.blake2b(digest_size=32)
#     blake2b_hash.update(input_bytes)
#     return blake2b_hash.digest()

def hash_byte_string_blake2b(input_bytes):
    return hashlib.blake2b(input_bytes, digest_size=32).digest()

# def xor_bytes(b1, b2):
#     # Adjust to handle different length byte strings
#     max_len = max(len(b1), len(b2))
#     b1 = b1.ljust(max_len, b'\x00')
#     b2 = b2.ljust(max_len, b'\x00')
#     return bytes([x ^ y for x, y in zip(b1, b2)])

from itertools import zip_longest
def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip_longest(b1, b2, fillvalue=0))

def concatenate_byte_strings(*byte_strings):
    return b''.join(byte_strings)

def string_to_byte_string(input_string):
    return input_string.encode(FORMAT)

# def hash_byte_string_sha384(input_bytes):
#     sha384_hash = hashlib.sha384()  # Initialize SHA-384 hash object
#     sha384_hash.update(input_bytes)  # Update with the input byte string
#     return sha384_hash.digest()  # Return the hash digest as bytes

def hash_byte_string_sha384(input_bytes):
    return hashlib.sha384(input_bytes).digest()

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

def adjust_and_concatenate(ind, op):
    # Convert op to a single byte
    op_byte = bytes([op])

    # Encode `ind` and truncate if necessary
    ind_bytes = ind.encode()[:15]  # Directly enforce max length (16 - 1)

    # Pad `ind_bytes` with '*' if needed
    ind_bytes = ind_bytes.ljust(15, b'*')  

    return ind_bytes + op_byte  # Concatenate `ind_bytes` and `op_byte`


# ------------------------------------ Algorithm starts here ---------------------------------------------------------

def fast_client_setup():
    # size = int(lam / 8)
    ks = os.urandom(32) # lambda bit long term key, will be used to encrypt keywords 
    S = plyvel.DB('S.db', create_if_missing=True) # will be used to store states on the client side
    print("S - Setup successfully!")
    # S = {}
    return S, ks

# def fast_client_update(key, S, ind, w, op):
#     # Step 4: Calculate tw
#     tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
    
#     # Step 5-6: Retrieve stc and initialize c
#     pickled_value = S.get(w.encode(), default=None)

#     # Check if the value was found in the database
#     if pickled_value is not None:
#         stc, c = pickle.loads(pickled_value)
#     else:
#         stc = None
#         c = 0

#     # Step 7-10: Generate a new state if stc is None
#     if stc is None:
#         stc = key  # Generate a random 32-byte value for stc
#         c = 0  # Initialize c to 0
    
#     # Step 9: Generate new key kc+1
#     kc_next = os.urandom(32)
    
#     # Step 10: Calculate new stc+1
#     stc_next = pseudorandom_permutation(kc_next, stc)

#     # Serialize the new state
#     value = pickle.dumps((stc_next, c + 1))

#     # Store the serialized value in the database
#     S.put(w.encode(), value)
    
#     # Step 11-12: Create e
#     term1 = concatenate_byte_strings(adjust_and_concatenate(ind, op), kc_next) # this will always be of size 48 bytes, op will be at the end, and the ind will be truncated or padded acc to size
#     term2 = hash_byte_string_sha384(concatenate_byte_strings(tw, stc_next))# this will alwayys be of size 48 bytes
#     e = xor_bytes(term1, term2) # of 48 bytes
    
#     # Step 13: Calculate u
#     u = hash_byte_string_blake2b(concatenate_byte_strings(tw, stc_next))
    
#     # Step 14: Send u and e to server
#     # client.send(u)
#     # print(f'SENT - u')
#     # client.send(e)
#     # print(f'SENT - e')
#     # client.close()

#     # rather than sending u,e to server this function will just return the u,e values

#     return u,e

def fast_client_update(key, S, ind, w, op):
    
    # Step 4: Calculate tw
    w_hashed = hash_text_sha256(w)  # Precompute hash once
    tw = pseudorandom_function(key, w_hashed)  # 32 bytes
    
    # Step 5-6: Retrieve stc and c
    pickled_value = S.get(w.encode())
    print(f'pickled value - {pickled_value}')

    if pickled_value is not None:
        stc_prev, c = pickle.loads(pickled_value) # prev state # denoted as stc in paper
    else:
        stc_prev = os.urandom(32)  # Random 32-byte value if new
        c = 0
        S.put(w.encode(),pickle.dumps(stc_prev,c))
    
    # Step 9-10: Generate new state
    kc_next = os.urandom(32) # random ephemeral key  # denoted as k_c+1 in paper
    stc_next = pseudorandom_permutation(kc_next, stc_prev) # current state # denoted as stc_c+1 in paper

    # Store updated state in database
    S.put(w.encode(), pickle.dumps((stc_next, c + 1)))

    # Precompute common term
    combined_tw_stc = concatenate_byte_strings(tw, stc_next)
    
    # Step 11-12: Create e
    term1 = concatenate_byte_strings(adjust_and_concatenate(ind, op), kc_next)  # Always 48 bytes
    term2 = hash_byte_string_sha384(combined_tw_stc)  # Always 48 bytes
    e = xor_bytes(term1, term2)  # Always 48 bytes # encrypted index entry - used to store ind, operation, kc_next on server side 

    # Step 13: Calculate u
    u = hash_byte_string_blake2b(combined_tw_stc) # reference # used to store keyword and next_state

    return u, e


def fast_client_search(key, S, w):
    # Step 4: Calculate tw
    tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
    
    # Step 5-6: Retrieve stc and initialize c
    pickled_value = S.get(w.encode(), default=None)
    print(f'pickled_vlue-->{pickled_value}')
    # Check if the value was found in the database
    if pickled_value is not None:
        stc, c = pickle.loads(pickled_value)
    else:
        stc = None
        c = 0

    # Step 7-10: if stc is None, return 0
    if stc is None:
        return b"exit",b"exit",0 

    return tw, stc, c

S, ks = fast_client_setup()
w1 = "sahil"
# w2 = "xenex"
# S.put(w1.encode(),pickle.dumps(b'intial_key',0))
# S.put(w2.encode(),pickle.dumps(os.urandom(32),2))

# pickled_value = S.get(w2.encode(), default=None)
# print(f"pickled value - {pickled_value}")

u,e = fast_client_update(ks, S, 'file', w1, 0)


    # # Step 5: Receive and print search results
    # search_results = client.recv(4096)
    # print("Search results received from server:", search_results.decode(FORMAT))
# S, ks = fast_client_setup()
# tw,stc,c = fast_client_search(ks,S,'word')
# print(f"TW: {tw}")
# print(f"STC: {stc}")
# print(f"C: {c}")

# --------------------------------------- Algorithm ends here ----------------------------------------------------------

# --------------------------------------------- To start server for update commands ---------------------------------



# def start_update_client(m):
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
#             for i in range(1, m+1):
#                 if i % 2 == 0:
#                     u, e = fast_client_update(ks, S, ind1, w1, op1)  # Replace with your implementation
#                 else:
#                     u, e = fast_client_update(ks, S, ind2, w2, op2)  # Replace with your implementation

#                 # Send `u` and `e` to the server
#                 client_socket.sendall(u)
#                 print(f"U - Sent Successfully: {u}")
#                 time.sleep(0.1)  # Ensure buffer is flushed before sending `e`
#                 client_socket.sendall(e)
#                 print(f"E - Sent Successfully: {e}")
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

def start_update_client(m):
    # CLIENT = "10.14.3.246"  # Replace with the actual server IP
    PORT = 2614             # Replace with the actual server port

    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(5)  # Set a timeout for socket operations
        try:
            client_socket.connect((CLIENT, PORT))
            print(f"Connected to server at {CLIENT}:{PORT}")

            # Example of using multiple indices and operations
            ind1 = 'file1.txt'
            ind2 = 'file2.txt'
            w1 = 'crypto'
            w2 = 'graphical'
            op1 = 1  # Use 0 for delete, 1 for add
            op2 = 0
            
            # Loop to send u, e pairs
            for i in range(1, m+1):
                if i % 2 == 0:
                    u, e = fast_client_update(ks, S, ind1, w1, op1)  # Replace with your implementation
                else:
                    u, e = fast_client_update(ks, S, ind2, w2, op2)  # Replace with your implementation

                # Send u and e to the server
                client_socket.sendall(u)
                print(f"U - Sent Successfully: {u}")
                time.sleep(0.1)  # Ensure buffer is flushed before sending e
                client_socket.sendall(e)
                print(f"E - Sent Successfully: {e}")
                time.sleep(0.1)  # Optional: Add a slight delay between sends

            # Send exit signals for both u and e
            exit_message = b"exit"
            time.sleep(0.1)  # Ensure the final u, e pair is flushed before sending exit
            client_socket.sendall(exit_message)
            print("U - Exit message sent.")
            client_socket.sendall(exit_message)
            print("E - Exit message sent.")

        except socket.timeout:
            print("Connection timed out.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Closing connection.")

# def start_update_client(ks, S):
#     """Establish a socket connection to send encrypted update requests to the server."""

#     # client_ip = "10.14.3.246"  # Replace with the actual server IP
#     # port = 2614             # Replace with the actual server port
    
#     # File-keyword mapping
#     data_pairs = [
#         ('file1.txt', 'crypto', 1),
#         ('file2.txt', 'graphical', 0)
#     ]

#     try:
#         # Create a socket connection
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
#             client_socket.settimeout(5)  # Set timeout for network operations
#             client_socket.connect((CLIENT,PORT))
#             print(f"Connected to server at {CLIENT}:{PORT}")

#             # Send updates in alternating fashion
#             for i in range(1, 5):
#                 ind, w, op = data_pairs[i % 2]  # Alternate between the two pairs
#                 u, e = fast_client_update(ks, S, ind, w, op)  
#                 print(f'U - {u}')
#                 print(f'E - {e}')
#                 # Send `u` and `e` to the server
#                 client_socket.sendall(u)
#                 client_socket.sendall(e)

#             # Send exit signals for both `u` and `e`
#             exit_message = b"exit"
#             client_socket.sendall(exit_message)
#             client_socket.sendall(exit_message)

#             print("Update process completed. Exit signal sent.")

#     except socket.timeout:
#         print("Connection timed out. Server is unreachable.")
#     except socket.error as e:
#         print(f"Socket error: {e}")
#     except Exception as e:
#         print(f"Unexpected error: {e}")
#     finally:
#         print("Closing connection.")

# def start_update_client(m):
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
#             for i in range(1, m+1):
#                 if i % 2 == 0:
#                     u, e = fast_client_update(ks, S, ind1, w1, op1)  # Replace with your implementation
#                 else:
#                     u, e = fast_client_update(ks, S, ind2, w2, op2)  # Replace with your implementation

#                 # # Send `u` and `e` to the server
#                 # client_socket.send(u)
#                 # print(f"U - Sent Successfully: {u}")
#                 # time.sleep(0.1)  # Ensure buffer is flushed before sending `e`
#                 # client_socket.send(e)
#                 # print(f"E - Sent Successfully: {e}")
#                 # time.sleep(0.1)  # Optional: Add a slight delay between sends

#                 # pickling u,e and sending to server

#                 # Serialize (u, e) using pickle
#                 data = pickle.dumps((u, e))

#                 # Send data
#                 client_socket.sendall(data)

#                 time.sleep(0.1)

#             # Send exit signals for both `u` and `e`
#             u,e = b"exit"
#             # Serialize (u, e) using pickle
#             data = pickle.dumps((u, e))

#             # Send data
#             client_socket.sendall(data)
#             # time.sleep(0.1)  # Ensure the final `u, e` pair is flushed before sending exit
#             # client_socket.send(exit_message)
#             # # print("U - Exit message sent.")
#             # client_socket.send(exit_message)
#             # print("E - Exit message sent.")

#         except socket.timeout:
#             print("Connection timed out.")
#         except Exception as e:
#             print(f"An error occurred: {e}")
#         finally:
#             print("Closing connection.")


# setup of 'S' and 'ks' 
# S, ks = fast_client_setup()
# m = 4
# u,e = fast_client_update(ks, S, 'file1', 'graphical', 0)
# print(f'U - {u}')
# print(f'E - {e}')
# start_time_client = time.time()
# start_update_client(m)

# end_time_client = time.time()

# time_elasped_client = end_time_client - start_time_client
# time_elasped_client_query = time_elasped_client/m
# print(f'Time elasped for client - {time_elasped_client}')
# print(f'Time elasped for client query- {time_elasped_client_query}')


# --------------------------------------------- To start client for update commands ENDS ---------------------------------

# --------------------------------------------- To start client for search commands ---------------------------------

def start_search_client(key, S, words):
    """Handles multiple search requests with the server."""
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((CLIENT,PORT))

    results = {}

    try:
        for w in words:
            tw, stc, c = fast_client_search(key, S, w)
            print(f"TW - {tw}")
            print(f"STC - {stc}")
            print(f"C - {c}")
            if stc == None:
                stc = b'initial_state'
                c = 1
                c = c.to_bytes(1)
                S.put(w,pickle.dumps({stc,c}))

            request_data = pickle.dumps((tw, stc, c))  # Serialize the data
            
            client_socket.sendall(request_data)  # Send data to the server
            
            response_data = client_socket.recv(4096)  # Receive response
            result = pickle.loads(response_data)  # Deserialize the response
            
            # result = b"Test result"

            results[w] = result  # Store the result

        client_socket.sendall(pickle.dumps(b"exit"))  # Send exit signal
    finally:
        client_socket.close()
    
    return results  # Return all search results

# S,ks = fast_client_setup()  
# # ws = {'graphical','crypto'}
# # S.put(b'graphical',pickle.dumps({b'initial state1',b'1'}))
# # S.put(b'crypto',pickle.dumps({b'initial state2',b'1'}))
# # results = start_search_client(ks,S, 'graphical')
# # print("The SEARCH RESULTS are as follows: \n")
# # for result in results:
# #     print(f"{result}\n")

# for key, value in S:
#     print(key)
#     print(value)
# --------------------------------------------- To start client for search commands ENDS ---------------------------------



# ind1 = 'file1.txt'
# w1 = 'crypto'
   
# # setup of 'S' and 'ks' 
# S, ks = fast_client_setup()

# tw, stc, c = fast_client_search(ks, S, w1)

# # Set up the client
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client_socket.connect((CLIENT, PORT))  # Connect to the server

# # Send 3 separate values to the server
# values_to_send = [tw, stc, c]  # Example values, replace with your values

# for value in values_to_send:
#     client_socket.send(value)  # Send each value separately

# # Receive the processed result from the server
# result = client_socket.recv(1024)
# print(f"Received processed result from server: {result}")

# # Close the client socket
# client_socket.close()






# Start the client
# start_update_client()

# #  final one
# def start_update_client():
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
#                     u, e = fast_client_update(ks, S, ind1, w1, op1)
#                 else:
#                     u, e = fast_client_update(ks, S, ind2, w2, op2)

#                 # Send `u` and `e` to the server
#                 client_socket.sendall(u)
#                 print("U - Sent Successfully")
#                 client_socket.sendall(e)
#                 print("E - Sent Successfully")
#                 time.sleep(1)  # Optional: Add a delay between sends

#             # Send exit message after all `u, e` pairs are sent
#             exit_message = b"exit"
#             client_socket.sendall(exit_message)
#             print("Exit message sent to the server.")

#         except socket.timeout:
#             print("Connection timed out.")
#         except Exception as e:
#             print(f"An error occurred: {e}")
#         finally:
#             print("Closing connection.")


# def start_client():
#     # Create a socket connection
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
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
#                 # import time
#                 if i % 2 == 0:
#                     u, e = fast_client_update(ks, S, ind1, w1, op1)
#                     # Send `u` and `e` to the server
#                     client_socket.send(u)
#                     print("U - Sent Successfully")
#                     client_socket.send(e)
#                     print("E - Sent Successfully")
#                     # time.sleep(1)
#                 else:
#                     u, e = fast_client_update(ks, S, ind2, w2, op2)
#                     # Send `u` and `e` to the server
#                     client_socket.send(u)
#                     print("U - Sent Successfully")
#                     client_socket.send(e)
#                     print("E - Sent Successfully")
#                     # time.sleep(1)

                

#             # Send exit message after all `u, e` pairs are sent
#             u_exit = b"exit"
#             e_exit = b"exit"  # Convert the message to bytes
#             client_socket.send(u_exit)
#             client_socket.send(e_exit)
#             # e_exit = b"close"
#             # client_socket.send(e_exit)
#             print("Exit message sent to the server.")
#             client_socket.close()
        
#         except Exception as e:
#             print(f"An error occurred: {e}")
#         finally:
#             # Ensure the socket connection is closed
#             print("Closing connection.")

# def start_client():


#     # Create a socket connection
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
#         client_socket.connect((CLIENT, PORT))

#         # Example of using multiple indices and operations
#         ind1 = 'file1.txt'
#         ind2 = 'file2.txt'
#         w1 = 'crypto'
#         w2 = 'graphical'
#         op1 = 1  # Use 0 for delete, 1 for add
#         op2 = 0
#         # Send an exit message to the server after the loop ends
#         exit_message = b"exit"  # Convert the message to bytes

#         # fast_client_update(ks, S, ind1, w1, op1, client_socket)

#         for i in range(1, 3):
#             if i % 2 == 0:
#                 u,e = fast_client_update(ks, S, ind1, w1, op1)
#                 client_socket.send(u)
#                 print("U - Sent Successfully")
#                 client_socket.send(e)
#                 print("E - Sent Successfully")
#             else:
#                 u,e = fast_client_update(ks, S, ind2, w2, op2)
#                 client_socket.send(u)
#                 print("U - Sent Successfully")
#                 client_socket.send(e)
#                 print("E - Sent Successfully")
        
#     client_socket.send(exit_message)
#     print("Exit message sent to the server.")
#     print("Client - Done")

# 26th Jan


# attempt 1
# def start_client():
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
#                     u, e = fast_client_update(ks, S, ind1, w1, op1)
#                 else:
#                     u, e = fast_client_update(ks, S, ind2, w2, op2)

#                 # Send `u` and `e` to the server
#                 client_socket.sendall(u)
#                 print("U - Sent Successfully")
#                 client_socket.sendall(e)
#                 print("E - Sent Successfully")
#                 time.sleep(1)  # Optional: Add a delay between sends

#             # Send exit messages for both `u` and `e`
#             exit_message = b"exit"
#             client_socket.sendall(exit_message)  # Send `u = exit`
#             print("U - Exit message sent.")
#             client_socket.sendall(exit_message)  # Send `e = exit`
#             print("E - Exit message sent.")

#         except socket.timeout:
#             print("Connection timed out.")
#         except Exception as e:
#             print(f"An error occurred: {e}")
#         finally:
#             print("Closing connection.")

# attempt 2



# def start_client():
#     # CLIENT = "127.0.0.1"  # Replace with the actual server IP
#     # PORT = 12345          # Replace with the actual server port

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
#                 client_socket.send(u)
#                 print(f"U - Sent Successfully: {u}")
#                 client_socket.send(e)
#                 print(f"E - Sent Successfully: {e}")
#                 time.sleep(0.1)  # Optional: Add a slight delay between sends

#             # Send exit signals for both `u` and `e`
#             exit_message = b"exit"
#             time.sleep(0.1)  # Ensure the final `u, e` pair is flushed before sending exit
#             client_socket.sendall(exit_message)
#             print("U - Exit message sent.")
#             client_socket.sendall(exit_message)
#             print("E - Exit message sent.")

#         except socket.timeout:
#             print("Connection timed out.")
#         except Exception as e:
#             print(f"An error occurred: {e}")
#         finally:
#             print("Closing connection.")



# # this works
# def start_update_client():
#     # CLIENT = "10.14.3.246"  # Replace with the actual server IP
#     # PORT = 2614             # Replace with the actual server port

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
#                 print(f"U - Sent Successfully: {u}")
#                 time.sleep(0.1)  # Ensure buffer is flushed before sending `e`
#                 client_socket.sendall(e)
#                 print(f"E - Sent Successfully: {e}")
#                 time.sleep(0.1)  # Optional: Add a slight delay between sends

#             # Send exit signals for both `u` and `e`
#             exit_message = b"exit"
#             time.sleep(0.1)  # Ensure the final `u, e` pair is flushed before sending exit
#             client_socket.sendall(exit_message)
#             print("U - Exit message sent.")
#             client_socket.sendall(exit_message)
#             print("E - Exit message sent.")

#         except socket.timeout:
#             print("Connection timed out.")
#         except Exception as e:
#             print(f"An error occurred: {e}")
#         finally:
#             print("Closing connection.")

# This is the one that I dumped, the one below
# def start_search_client():
#     # CLIENT = "10.14.3.246"  # Replace with the actual server IP
#     # PORT = 2614             # Replace with the actual server port

#     # Create a socket connection
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
#         client_socket.settimeout(5)  # Set a timeout for socket operations
#         try:
#             client_socket.connect((CLIENT, PORT))
#             print(f"Connected to server at {CLIENT}:{PORT}")

#             # Example of using multiple indices and operations
#             # ind1 = 'file1.txt'
#             # ind2 = 'file2.txt'
#             # key = os.urandom(32)
#             w1 = 'crypto'
#             w2 = 'graphical'
#             op1 = 1  # Use 0 for delete, 1 for add
#             op2 = 0
            
#             # Loop to send `u, e` pairs
#             for i in range(1, 6):
#                 if i % 2 == 0:
#                     tw, stc, c = fast_client_search(ks, S, w1)  # Replace with your implementation
#                     # Send `u` and `e` to the server
#                     client_socket.send(tw)
#                     print(f"tw - Sent Successfully")
#                     time.sleep(0.1)  # Ensure buffer is flushed before sending `stc`
#                     client_socket.send(stc)
#                     print(f"stc - Sent Successfully")
#                     time.sleep(0.1)  # Optional: Add a slight delay between sends
#                     client_socket.send(c.to_bytes)
#                     print(f"c - Sent Successfully")
#                     time.sleep(0.1)  # Optional: Add a slight delay between sends
#                     # client_socket.listen()
#                     # print("Client is listening...")

#                     # conn, addr = client_socket.accept()
#                     # print(f"Accepted connection from {addr}")
#                     # value = conn.recv(1024)  # Receive the `value` value
#                     # print(f"Received search results: {value}")
                
#                 else:
#                     tw, stc, c = fast_client_search(ks, S, w2)  # Replace with your implementation
#                     # Send `u` and `e` to the server
#                     client_socket.send(tw)
#                     print(f"tw - Sent Successfully")
#                     time.sleep(0.1)  # Ensure buffer is flushed before sending `stc`
#                     client_socket.send(stc)
#                     print(f"stc - Sent Successfully")
#                     time.sleep(0.1)  # Optional: Add a slight delay between sends
#                     client_socket.send(c.to_bytes)
#                     print(f"c - Sent Successfully")
#                     time.sleep(0.1)  # Optional: Add a slight delay between sends
#                     # client_socket.listen()
#                     # print("Client is listening...")

#                     # conn, addr = client_socket.accept()
#                     # print(f"Accepted connection from {addr}")
#                     # value = conn.recv(1024)  # Receive the `value` value
#                     # print(f"Received search results: {value}")

#                 # # Send `u` and `e` to the server
#                 # client_socket.sendall(tw)
#                 # print(f"tw - Sent Successfully: {tw}")
#                 # time.sleep(0.1)  # Ensure buffer is flushed before sending `stc`
#                 # client_socket.sendall(stc)
#                 # print(f"stc - Sent Successfully: {stc}")
#                 # time.sleep(0.1)  # Optional: Add a slight delay between sends
#                 # client_socket.sendall(c.to_bytes)
#                 # print(f"c - Sent Successfully: {c}")
#                 # time.sleep(0.1)  # Optional: Add a slight delay between sends

#             # Send exit signals for both `u` and `e`
#             exit_message = b"exit"
#             time.sleep(0.1)  # Ensure the final `u, e` pair is flushed before sending exit
#             client_socket.send(exit_message)
#             print("tw - Exit message sent.")
#             client_socket.send(exit_message)
#             print("stc - Exit message sent.")
#             client_socket.send(b'0')
#             print("c - Exit message sent.")

            

#         except socket.timeout:
#             print("Connection timed out.")
#         # except Exception as e:
#         #     print(f"An error occurred: {e}")
#         finally:
#             print("Closing connection.")

# setup of 'S' and 'ks' 
# S, ks = fast_client_setup()
# start_update_client()


# Start the client
# start_client()

# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client.connect((CLIENT,PORT))

# # setup of 'S' and 'ks' 
# S, ks = fast_client_setup()

# while True:
#     print(f'Connected to Server')
#     ind1 = 'file1.txt'
#     w1 = 'crypto'
#     op1 = 1
#     u,e = fast_client_update(ks, S, ind1, w1, op1)
#     client.send(u)
#     print('SENT - u')
#     client.send(e)
#     print('SENT - e')
#     client.send(b'quit')

# client.close()

# -------------------------------------- SEARCH FUNCTION TESTING -------------------------------------------
# def test_fast_client_search(key, S, w):
#     # Step 4: Calculate tw
#     tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
#     print(f"TW - {tw}")
#     # Step 5-6: Retrieve stc and initialize c
#     pickled_value = S.get(w.encode(), default=None)
#     print(f'pickled_vlue-->{pickled_value}')
#     # Check if the value was found in the database
#     if pickled_value is not None:
#         stc, c = pickle.loads(pickled_value)
#     else:
#         stc = None
#         c = 0
#     print(f'STC - {stc}')
#     print(f"c - {c}")
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


# # setup of 'S' and 'ks' 
# S, ks = fast_client_setup()
# results = test_fast_client_search(ks, S, 'crypto')
# print(results)