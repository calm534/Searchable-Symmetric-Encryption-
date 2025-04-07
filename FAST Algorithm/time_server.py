import socket
import socket
import threading
import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import plyvel
import pickle
import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import plyvel
import pickle


# -----------------------------------------Imported necessary libraries ------------------------------------------

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 2614
FORMAT = 'utf-8'
BUFFER_SIZE = 4096  # Larger buffer to reduce `recv` calls

# BYTESIZE = 

# # ------------------------------- Setting up supporting funcitons ---------------------------------------------------

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

# def hash_byte_string_blake2b(input_bytes): #(H1 Hash)
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

# def hash_byte_string_sha384(input_bytes): #(H2 hash)
#     sha384_hash = hashlib.sha384()  # Initialize SHA-384 hash object
#     sha384_hash.update(input_bytes)  # Update with the input byte string
#     return sha384_hash.digest()  # Return the hash digest as bytes

# def inverse_adjust_and_concatenate(combined):
#     # Extract the last byte as the op value
#     op_byte = combined[-1:]  # Last byte is the op value
#     op = int.from_bytes(op_byte, byteorder='big')  # Convert byte to integer

#     # Remaining bytes represent the ind (with potential padding)
#     ind_bytes = combined[:-1]  # Exclude the last byte for op

#     # Remove padding ('*') from ind_bytes
#     ind = ind_bytes.rstrip(b'*').decode()  # Decode to string after removing padding

#     return ind, op

def print_contents_of_T(T):
    # Print the content of T
    print("Contents of T:")
    for u, e in T:
        print(f"u:{u}, e:{e}")

# #     # print("Contents of T:")
# #     # with T.iterator() as it:
# #     #     for key, value in it:
# #     #         print(f"u:{key}, e:{value}")  # Decode keys and values for readability

# def inverse_adjust_and_concatenate(combined):
#     # Extract the last byte as the op value
#     op_byte = combined[-1:]  # Last byte is the op value
#     op = int.from_bytes(op_byte, byteorder='big')  # Convert byte to integer

#     # Remaining bytes represent the ind (with potential padding)
#     ind_bytes = combined[:-1]  # Exclude the last byte for op

#     # Remove padding ('*') from ind_bytes
#     ind = ind_bytes.rstrip(b'*').decode()  # Decode to string after removing padding

#     return ind, op

# # def insert_with_linked_list(db, key, value):
# #     """
# #     Inserts a key-value pair while maintaining a linked list structure.
# #     """
# #     last_key = db.get(b'__last_inserted_key__')
# #     db.put(key, value)
# #     if last_key:
# #         db.put(key + b'__prev', last_key)  # Store the previous key link
# #     db.put(b'__last_inserted_key__', key)  # Update last inserted key

# def print_content_of_plyvel_db(db):
#     """
#     Prints key-value pairs in insertion order using the linked list approach.
#     """
#     key = db.get(b'__last_inserted_key__')
#     while key:
#         value = db.get(key)
#         print(key.decode(), "->", value.decode())
#         key = db.get(key + b'__prev')  # Move to the previous key

def pseudorandom_function(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).digest()

def pseudorandom_permutation(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, AES.block_size))

def inverse_permutation(key, encrypted_data):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted_data), AES.block_size)

def hash_text_sha256(input_text):
    return hashlib.sha256(input_text.encode(FORMAT)).hexdigest()

def hash_byte_string_sha3_256(input_bytes):
    return hashlib.sha3_256(input_bytes).digest()

def hash_byte_string_blake2b(input_bytes):
    return hashlib.blake2b(input_bytes, digest_size=32).digest()

def xor_bytes(b1, b2):
    min_len = min(len(b1), len(b2))
    return bytes(x ^ y for x, y in zip(b1[:min_len], b2[:min_len]))

def concatenate_byte_strings(*byte_strings):
    return b''.join(byte_strings)

def string_to_byte_string(input_string):
    return input_string.encode(FORMAT)

def hash_byte_string_sha384(input_bytes):
    return hashlib.sha384(input_bytes).digest()

def adjust_and_concatenate(ind, op):
    return ind.encode()[:15].ljust(15, b'*') + bytes([op])


# # ------------------------------------ Algorithm starts here ---------------------------------------------------------

def fast_server_setup():
    T = plyvel.DB('T.db', create_if_missing=True)
    print("Server Setup Completed - T initiated")
    return T

def fast_server_update(u, e,T):
    # print(f"Connected by {addr}")
    # T = plyvel.DB('T.db', create_if_missing=True)
    T = T.put(u,e)
    return T

# def fast_server_search(tw, stc, c, T):

#     # print(f"Connected by {addr}")
    
#     # # Step 1: Receive the search token from the client
#     # tw = conn.recv(1024)
#     # print('Search Token received')

#     # stc = conn.recv(1024)
#     # print('Current state received')

#     # c = conn.recv(1024)
#     # print('Counter received')
    
#     # Step 3: Initialize result set and set of deleted file identifiers
#     ID = set()  # Using set for ID
#     delta = set()  # Using set for Δ (delta)
#     sti = stc

#     for i in range(c, 0, -1):  # Loop from c to 1
#         u = hash_byte_string_blake2b(concatenate_byte_strings(tw,sti))  # Compute hash H1(tw || sti)
#         e = T.get(u)  # Retrieve e from the database T
#         print(f'U-{u}')
#         print(f'E-{e}')
#         if e is None:
#             raise ValueError(f"Key {u} not found in database")

#         # Decode e by XORing with H2(tw || sti)
#         # decoded = bytes(a ^ b for a, b in zip(e, H2(tw + sti)))
#         term = hash_byte_string_sha384(concatenate_byte_strings(tw,sti))
#         decoded = xor_bytes(e,term)

#         # ind = int.from_bytes(decoded[:4], 'big')  # Convert the first 4 bytes to an integer
#         # op = decoded[4:7].decode()  # Convert the next 3 bytes to a string (e.g., "add" or "del")
#         ki = decoded[-32:]  # last 32 bytes will be ki
#         ind, op = inverse_adjust_and_concatenate(decoded[:-32])
        
#         if op == 0: # op = delete
#             delta.add(ind)  # Add `ind` to delta
#         elif op == 1: # op = add
#             if ind in delta:
#                 delta.remove(ind)  # Remove `ind` from delta
#             else:
#                 ID.add(ind)  # Add `ind` to ID

#         # Update sti using the inverse permutation function
#         sti = inverse_permutation(ki, sti)
    
#     # conn.send(ID[-1])
#     # conn.close()
#     return (list(ID)[-1])

# # --------------------------------------- Algorithm ends here ----------------------------------------------------------

# # --------------------------------------------- To start server for update commands ---------------------------------

# def start_update_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         start_time_server = time.time()
#         # print(f"Accepted connection from {addr}")

#         T = fast_server_setup()  # Initialize T

#         try:
#             while True:
#                 # Receive `u`
#                 u = conn.recv(1024)  # Receive the `u` value
#                 if not u:
#                     # print("No data received for u. Closing connection.")
#                     break
#                 # print(f"Received u: {u}")

#                 # Receive `e`
#                 e = conn.recv(1024)  # Receive the `e` value
#                 if not e:
#                     # print("No data received for e. Closing connection.")
#                     break
#                 # print(f"Received e: {e}")

#                 # Process the valid `u, e` pair if they are not "exit"
#                 if u != b"exit" or e != b"exit":
#                     # T = fast_server_update(u, e, T)
#                     T.put(u,e)
#                     # print("Updated T with the received u, e pair.")

#                 # Check for exit condition (after processing the pair)
#                 if u == b"exit" and e == b"exit":
#                     # print("Exit signal received. Closing connection.")
#                     break

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             end_time_server = time.time()
#             print("Connection closed.")
#             time_elasped_server = end_time_server - start_time_server
#             print(f'Time elasped for server - {time_elasped_server}')
#             return T




# T = start_update_server()
# # T = fast_server_setup()
# # print_contents_of_T(T)

def start_update_server():
    with socket.create_server((SERVER, PORT)) as server:
        server.listen()
        print("Server is listening...")
        
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn,)).start()

def handle_client(conn):
    T = fast_server_setup()
    start_time_server = time.time()
    
    try:
        data = conn.recv(BUFFER_SIZE)
        if not data:
            return
        
        messages = data.split(b"exit")[:-1]  # Split incoming data and remove last empty entry
        for i in range(0, len(messages), 2):
            u, e = messages[i], messages[i + 1]
            T.put(u, e)

    except Exception as ex:
        print(f"An error occurred: {ex}")
    finally:
        conn.close()
        return T
        print(f"Connection closed. Time elapsed for server: {time.time() - start_time_server}")

start_update_server()



