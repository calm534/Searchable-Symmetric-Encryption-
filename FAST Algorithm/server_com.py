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


# -----------------------------------------Imported necessary libraries ------------------------------------------

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 2614
FORMAT = 'utf-8'
# BYTESIZE = 

# ------------------------------- Setting up supporting funcitons ---------------------------------------------------

# def pseudorandom_permutation(key, data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return cipher.encrypt(pad(data, AES.block_size))

def pseudorandom_permutation(cipher, data):
    if len(data) % AES.block_size != 0:
        data = pad(data, AES.block_size)
    return cipher.encrypt(data)

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

# def hash_byte_string_blake2b(input_bytes): #(H1 Hash)
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

# def hash_byte_string_sha384(input_bytes): #(H2 hash)
#     sha384_hash = hashlib.sha384()  # Initialize SHA-384 hash object
#     sha384_hash.update(input_bytes)  # Update with the input byte string
#     return sha384_hash.digest()  # Return the hash digest as bytes

def hash_byte_string_sha384(input_bytes):
    return hashlib.sha384(input_bytes).digest()

# def inverse_adjust_and_concatenate(combined):
#     # Extract the last byte as the op value
#     op_byte = combined[-1:]  # Last byte is the op value
#     op = int.from_bytes(op_byte, byteorder='big')  # Convert byte to integer

#     # Remaining bytes represent the ind (with potential padding)
#     ind_bytes = combined[:-1]  # Exclude the last byte for op

#     # Remove padding ('*') from ind_bytes
#     ind = ind_bytes.rstrip(b'*').decode()  # Decode to string after removing padding

#     return ind, op

def inverse_adjust_and_concatenate(combined):
    op = combined[-1]  # Directly extract last byte as integer
    ind = combined[:-1].decode().rstrip('*')  # Decode first, then strip '*'
    return ind, op

def print_contents_of_T(T):
    # Print the content of T
    print("Contents of T:")
    for u, e in T:
        print(f"u:{u}, e:{e}")

#     # print("Contents of T:")
#     # with T.iterator() as it:
#     #     for key, value in it:
#     #         print(f"u:{key}, e:{value}")  # Decode keys and values for readability

# def inverse_adjust_and_concatenate(combined):
#     # Extract the last byte as the op value
#     op_byte = combined[-1:]  # Last byte is the op value
#     op = int.from_bytes(op_byte, byteorder='big')  # Convert byte to integer

#     # Remaining bytes represent the ind (with potential padding)
#     ind_bytes = combined[:-1]  # Exclude the last byte for op

#     # Remove padding ('*') from ind_bytes
#     ind = ind_bytes.rstrip(b'*').decode()  # Decode to string after removing padding

#     return ind, op

def inverse_adjust_and_concatenate(combined):
    op = combined[-1]  # Directly extract last byte as integer
    ind = combined[:-1].decode().rstrip('*')  # Decode first, then strip padding
    return ind, op

# def insert_with_linked_list(db, key, value):
#     """
#     Inserts a key-value pair while maintaining a linked list structure.
#     """
#     last_key = db.get(b'__last_inserted_key__')
#     db.put(key, value)
#     if last_key:
#         db.put(key + b'__prev', last_key)  # Store the previous key link
#     db.put(b'__last_inserted_key__', key)  # Update last inserted key

# def print_content_of_plyvel_db(db):
#     """
#     Prints key-value pairs in insertion order using the linked list approach.
#     """
#     key = db.get(b'__last_inserted_key__')
#     while key:
#         value = db.get(key)
#         print(key.decode(), "->", value.decode())
#         key = db.get(key + b'__prev')  # Move to the previous key

# ------------------------------------ Algorithm starts here ---------------------------------------------------------

def fast_server_setup():
    T = plyvel.DB('T.db', create_if_missing=True) # used to store the encrypted index
    print("Server Setup Completed - T initiated")
    return T

def fast_server_update(u, e,T):
    # print(f"Connected by {addr}")
    # T = plyvel.DB('T.db', create_if_missing=True)
    T = T.put(u,e)
    return T

def fast_server_search(tw, stc, c, T):

    # print(f"Connected by {addr}")
    
    # # Step 1: Receive the search token from the client
    # tw = conn.recv(1024)
    # print('Search Token received')

    # stc = conn.recv(1024)
    # print('Current state received')

    # c = conn.recv(1024)
    # print('Counter received')
    
    # Step 3: Initialize result set and set of deleted file identifiers
    ID = set()  # Using set for ID
    delta = set()  # Using set for Δ (delta)
    sti = stc

    for i in range(c, 0, -1):  # Loop from c to 1
        u = hash_byte_string_blake2b(concatenate_byte_strings(tw,sti))  # Compute hash H1(tw || sti)
        e = T.get(u)  # Retrieve e from the database T
        print(f'U-{u}')
        print(f'E-{e}')
        if e is None:
            raise ValueError(f"Key {u} not found in database")

        # Decode e by XORing with H2(tw || sti)
        # decoded = bytes(a ^ b for a, b in zip(e, H2(tw + sti)))
        term = hash_byte_string_sha384(concatenate_byte_strings(tw,sti))
        decoded = xor_bytes(e,term)

        # ind = int.from_bytes(decoded[:4], 'big')  # Convert the first 4 bytes to an integer
        # op = decoded[4:7].decode()  # Convert the next 3 bytes to a string (e.g., "add" or "del")
        ki = decoded[-32:]  # last 32 bytes will be ki
        ind, op = inverse_adjust_and_concatenate(decoded[:-32])
        
        if op == 0: # op = delete
            delta.add(ind)  # Add `ind` to delta
        elif op == 1: # op = add
            if ind in delta:
                delta.remove(ind)  # Remove `ind` from delta
            else:
                ID.add(ind)  # Add `ind` to ID

        # Update sti using the inverse permutation function
        sti = inverse_permutation(ki, sti)
    
    # conn.send(ID[-1])
    # conn.close()
    return (list(ID)[-1])

# --------------------------------------- Algorithm ends here ----------------------------------------------------------

# --------------------------------------------- To start server for update commands ---------------------------------

# def start_update_server(m):
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
        
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
#                     start_time_server = time.time()
#                     T = fast_server_update(u, e, T)
#                     end_time_server = time.time()
#                     # T.put(u,e)
#                     # print("Updated T with the received u, e pair.")

#                 # Check for exit condition (after processing the pair)
#                 if u == b"exit" and e == b"exit":
#                     # print("Exit signal received. Closing connection.")
#                     break

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
            
#             print("Connection closed.")
#             time_elasped_server = end_time_server - start_time_server
#             time_elasped_server_query = time_elasped_server/m
#             print(f'Time elasped for server - {time_elasped_server}')
#             print(f'Time elasped for server query - {time_elasped_server_query}')
#             return T

def start_update_server(m):
    # Server setup
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER, PORT))  # Use your desired IP and port
    server.listen()
    print("Server is listening...")

    while True:
        conn, addr = server.accept()
        
        print(f"Accepted connection from {addr}")



        try:
            while True:
                # Receive u
                u = conn.recv(1024)  # Receive the u value
                if not u:
                    print("No data received for u. Closing connection.")
                    break
                print(f"Received u: {u}")

                # Receive e
                e = conn.recv(1024)  # Receive the e value
                if not e:
                    print("No data received for e. Closing connection.")
                    break
                print(f"Received e: {e}")

                # Process the valid u, e pair if they are not "exit"
                if u != b"exit" or e != b"exit":
                    # T = fast_server_update(u, e, T)
                    start_time_server = time.time()
                    # T = fast_server_update(u,e,T)
                    T.put(u,e)
                    end_time_server = time.time()
                    print("Updated T with the received u, e pair.")
                    

                # Check for exit condition (after processing the pair)
                if u == b"exit" and e == b"exit":
                    print("Exit signal received. Closing connection.")
                    break

        except Exception as ex:
            print(f"An error occurred: {ex}")
        finally:
            conn.close()
            print("Connection closed.")
            time_elasped_server = end_time_server - start_time_server
            time_elasped_server_query = time_elasped_server/m
            print(f'Time elasped for server - {time_elasped_server}')
            print(f'Time elasped for server query - {time_elasped_server_query}')
            return T
        
# def start_update_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  
#     server.listen()
#     print("Server is listening...")

#     while True:  # Keep server running indefinitely
#         conn, addr = server.accept()
#         start_time_server = time.time()

#         T = fast_server_setup()  # Initialize T

#         try:
#             while True:
#                 # Receive `u, e` in a single read
#                 data = conn.recv(2048)  # Read both values together to reduce blocking calls
#                 if not data:
#                     break  # No data received, close connection

#                 parts = data.split(b"||")  # Assuming a delimiter "||" to separate u and e
#                 if len(parts) != 2:
#                     continue  # Ignore invalid data format

#                 u, e = parts
#                 if u == b"exit" and e == b"exit":
#                     break  # Exit condition

#                 T.put(u, e)  # Update `T`

#         except Exception as ex:
#             print(f"An error occurred: {ex}")

#         finally:
#             conn.close()
#             end_time_server = time.time()
#             print("Connection closed.")
#             print(f'Time elapsed for server - {end_time_server - start_time_server}')
#             return T

# def start_update_server(m):
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
        
#         # print(f"Accepted connection from {addr}")

#         T = fast_server_setup()  # Initialize T
        

#         try:
#             while True:
#                 # # Receive `u`
#                 # u = conn.recv(1024)  # Receive the `u` value
#                 # if not u:
#                 #     # print("No data received for u. Closing connection.")
#                 #     break
#                 # # print(f"Received u: {u}")

#                 # # Receive `e`
#                 # e = conn.recv(1024)  # Receive the `e` value
#                 # if not e:
#                 #     # print("No data received for e. Closing connection.")
#                 #     break
#                 # # print(f"Received e: {e}")

#                 # # Process the valid `u, e` pair if they are not "exit"
#                 # if u != b"exit" or e != b"exit":
#                 #     # T = fast_server_update(u, e, T)
#                 #     T.put(u,e)
#                 #     # print("Updated T with the received u, e pair.")

#                 # # Check for exit condition (after processing the pair)
#                 # if u == b"exit" and e == b"exit":
#                 #     # print("Exit signal received. Closing connection.")
#                 #     break

#                 # Receive data
#                 data = conn.recv(4096)
    
#                 if not data:
#                     break  # No more data, exit loop
    
#                 # Deserialize (u, e) using pickle
#                 u, e = pickle.loads(data)

#                  # Check for exit condition
#                 if u == b"exit" and e == b"exit":
#                     print("Received exit command. Closing connection.")
#                     break  # Stop receiving and close the connection
                
#                 start_time_server = time.time()
#                 T = fast_server_update(u,e,T)
#                 end_time_server = time.time()

#     # # Store the pair in logsdb
#     # store_in_logsdb(u, e)

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
            
#             print("Connection closed.")
#             time_elasped_server = end_time_server - start_time_server
#             time_elasped_server_query = time_elasped_server/m
#             print(f'Time elasped for server - {time_elasped_server}')
#             print(f'Time elasped for server query - {time_elasped_server_query}')
            return T


T = fast_server_setup()  # Initialize T
m = 4
T = start_update_server(m)

# T = fast_server_setup()
# print_contents_of_T(T)






# --------------------------------------------- To start server for update commands ENDS ----------------------------------------

# --------------------------------------------- To start server for search commands ---------------------------------

def start_search_server(T):
    """Handles multiple incoming search requests from clients."""

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER,PORT))
    server_socket.listen(5)  # Allow multiple clients
    
    print(f"Server is listening on {SERVER}:{PORT}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected to {addr}")

        try:
            while True:
                request_data = conn.recv(4096)
                if not request_data:
                    break
                
                request = pickle.loads(request_data)
                
                if request == b"exit":
                    print("Exit message received from the client")
                    break  # Stop processing
                
                tw, stc, c = request  # Extract received data
                
                result = fast_server_search(tw, stc, c, T)  # Process search
                print(f'RESULT - {result}')
                conn.sendall(pickle.dumps(result))  # Send response
            
        finally:
            conn.close()

# T = fast_server_setup()
# start_search_server(T)
# print_contents_of_T(T)


# --------------------------------------------- To start server for search commands ENDS ---------------------------------


# # Set up the server
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_socket.bind((SERVER, PORT))  # Bind to localhost and port 12345
# server_socket.listen(1)

# print("Server is listening...")

# # Accept the client connection
# client_socket, client_address = server_socket.accept()
# print(f"Connection from {client_address}")

# # Receive 3 separate values from the client
# tw = (client_socket.recv(1024))  # Receive the first value
# stc = (client_socket.recv(1024))  # Receive the second value
# c = int(client_socket.recv(1024))  # Receive the third value
# print(f"Received values: {tw}, {stc}, {c}")

# T = plyvel.DB('T')

# # Process the values using the function
# result = fast_server_search(tw,c,T)

# # Send the result back to the client
# client_socket.send(str(processed_result).encode())

# # Close the client connection
# client_socket.close()

# T = start_update_server()
# print_content_of_plyvel_db(T)


# 1 - update
# def start_update_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()

#         try:
#             while True:
#                 # Step 14: Receive u and e from client
#                 u = conn.recv(1024)  # Receive and decode the u-value
#                 if not u:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received u")

#                 e = conn.recv(1024)  # Receive and decode the e-value
#                 if not e:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received e")

#                 # Check for exit condition
#                 if u == b"exit" or e == b"exit":
#                     print("Exit message received. Closing connection.")
#                     break

#                 # Update T using fast_server_update
#                 T = fast_server_update(u, e, T)
#                 print(f"Updated T")

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")
#             return T

# T = 
# for u, e in T:
#     print(f"U - {u}")
#     print(f"E - {e}")

    # try:
    #     while True:
    #         # Step 14: Receive u and e from client
    #         u = conn.recv(1024)  # Receive the u-value from the client
    #         print(f"Received u")
    #         e = conn.recv(1024)  # Receive the e-value from the client
    #         print(f"Received e")
            
    #         # If no data is received (client disconnected)
    #         if not u or not e:
    #             print(f"Client {addr} has disconnected.")
    #             break

            # if u or e == b'EXIT':
            #     print(f"Client {addr} has disconnected.")
            #     break   
            
            # print(f"Received u-value: {u}")
            # print(f"Received e-value: {e}")
            
            # Step 21: Store the entry in T (assuming T is a dictionary or some data structure)
            # T.put(u, e)  # Storing the key-value pair in T

    # except Exception as e:
    #     print(f"Error while communicating with {addr}: {e}")
    
    # finally:
        # print('Finally')
        # conn.close()  # Ensure the connection is closed once done

        # # Print the content of T
        # print("Contents of T:")
        # with T.iterator() as it:
        #     for key, value in it:
        #         print(f"u:{key}, e:{value}")  # Decode keys and values for readability

        # print(f"Connection with {addr} closed.")

# # Server setup
# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind((SERVER, PORT))  # Use your desired IP and port
# server.listen()
# print("Server is listening...")

# while True:
#     conn, addr = server.accept()
#     print(f"Accepted connection from {addr}")

#     T = fast_server_setup()

#     try:
#         while True:
#             # Step 14: Receive u and e from client
#             u = conn.recv(1024)  # Receive and decode the u-value
#             print(f"Received u")
#             e = conn.recv(1024) # Receive and decode the e-value
#             print(f"Received e")

#             if u or e == b"exit":  # Exit condition
#                 print("Exit message received. Closing connection.")
#                 conn.close()
#                 break

#             else:
#                 # Update T using fast_server_update
#                 T = fast_server_update(u, e,T)
#                 print(f"Updated T")
            
            

#     except Exception as ex:
#         print(f"An error occurred: {ex}")
#         conn.close()

#     finally:
#         break



# To run the server

# 26th Jan:

# attempt 1
# def start_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()  # Initialize T

#         try:
#             while True:
#                 # Receive `u`
#                 u = conn.recv(1024)  # Receive the `u` value
#                 if not u:
#                     print("No data received for u. Closing connection.")
#                     break
#                 print(f"Received u: {u}")

#                 # Receive `e`
#                 e = conn.recv(1024)  # Receive the `e` value
#                 if not e:
#                     print("No data received for e. Closing connection.")
#                     break
#                 print(f"Received e: {e}")

#                 # Check for exit condition
#                 if u == b"exit" and e == b"exit":
#                     print("Both u and e are 'exit'. Closing connection.")
#                     break

#                 # Process the received `u, e` pair
#                 T = fast_server_update(u, e, T)
#                 print("Updated T with the received u, e pair.")

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")
#             return T

# attempt 2

# def start_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()  # Initialize T

#         try:
#             while True:
#                 # Receive `u`
#                 u = conn.recv(1024)  # Receive the `u` value
#                 if not u:
#                     print("No data received for u. Closing connection.")
#                     break
#                 print(f"Received u: {u}")

#                 # Receive `e`
#                 e = conn.recv(1024)  # Receive the `e` value
#                 if not e:
#                     print("No data received for e. Closing connection.")
#                     break
#                 print(f"Received e: {e}")

#                 # Check for exit condition
#                 if u == b"exit" and e == b"exit":
#                     print("Exit signal received. Closing connection.")
#                     break

#                 # Skip processing if `u` or `e` is `exit`
#                 if u == b"exit" or e == b"exit":
#                     print("Skipping invalid or exit values.")
#                     continue

#                 # Process the valid `u, e` pair
#                 T = fast_server_update(u, e, T)
#                 print("Updated T with the received u, e pair.")

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")
#             return T

# attempt 3 - this works

# def start_update_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         # T = fast_server_setup()  # Initialize T

#         try:
#             while True:
#                 # Receive `u`
#                 u = conn.recv(1024)  # Receive the `u` value
#                 if not u:
#                     print("No data received for u. Closing connection.")
#                     break
#                 print(f"Received u: {u}")

#                 # Receive `e`
#                 e = conn.recv(1024)  # Receive the `e` value
#                 if not e:
#                     print("No data received for e. Closing connection.")
#                     break
#                 print(f"Received e: {e}")

#                 # Process the valid `u, e` pair if they are not "exit"
#                 if u != b"exit" or e != b"exit":
#                     T = fast_server_update(u, e, T)
#                     print("Updated T with the received u, e pair.")

#                 # Check for exit condition (after processing the pair)
#                 if u == b"exit" and e == b"exit":
#                     print("Exit signal received. Closing connection.")
#                     break

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")
#             return T

# This was the one I dumped, the one below
# def start_search_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")


#         try:
#             while True:
#                 values = []
#                 # Receive `tw`
#                 tw = conn.recv(1024)  # Receive the `tw` value
#                 if not tw:
#                     print("No data received for tw. Closing connection.")
#                     break
#                 print(f"Received tw")

#                 # Receive `stc`
#                 stc = conn.recv(1024)  # Receive the `stc` value
#                 if not stc:
#                     print("No data received for stc. Closing connection.")
#                     break
#                 print(f"Received stc")

#                 # Receive `c`
#                 c = conn.recv(1024)  # Receive the `c` value
#                 c_int = int.from_bytes(c, byteorder='big')
#                 if not c:
#                     print("No data received for c. Closing connection.")
#                     break
#                 print(f"Received c: {c_int}")

#                 # Process the valid `u, e` pair if they are not "exit"
#                 if tw != b"exit" or stc != b"exit":
#                     value = fast_server_search(tw,c,T)
#                     values.append(value)
#                     print("Returned the value received.")

#                 # Check for exit condition (after processing the pair)
#                 if stc == b"exit" and tw == b"exit" and c_int == 0:
#                     print("Exit signal received. Closing connection.")
#                     break

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             for value in values:
#                 conn.send(value)
#             conn.close()
#             print("Connection closed.")
        




# print_contents_of_T(T)

# def start_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()

#         try:
#             while True:
#                 # Receive `u` value from the client
#                 u = conn.recv(1024)
#                 if not u:
#                     print("No data received. Closing connection.")
#                     break

#                 # Check if `u` is the exit message
#                 if u == b"exit":
#                     print("Exit message received. Closing connection.")
#                     break
#                 print("Received u")

#                 # Receive `e` value from the client
#                 e = conn.recv(1024)
#                 if not e:
#                     print("No data received. Closing connection.")
#                     break

#                 # Check if `e` is the exit message
#                 if e == b"exit":
#                     print("Exit message received. Closing connection.")
#                     break
#                 print("Received e")

#                 # Process the valid `u, e` pair
#                 T = fast_server_update(u, e, T)
#                 print("Updated T")

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")
#             return T


# def start_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()

#         try:
#             while True:
#                 # Receive `u` value from the client
#                 u = conn.recv(1024)
#                 if not u or u == b"exit":  # Check for exit condition
#                     print("Exit message received or no data. Closing connection.")
#                     break
#                 print(f"Received u")

#                 # Receive `e` value from the client
#                 e = conn.recv(1024)
#                 if not e or e == b"exit":  # Check for exit condition
#                     print("Exit message received or no data. Closing connection.")
#                     break
#                 print(f"Received e")

#                 # Update T using fast_server_update
#                 T = fast_server_update(u, e, T)
#                 print(f"Updated T")

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")
#             return T


# def start_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()

#         try:
#             while True:
#                 # Receive `u` value from the client
#                 u = conn.recv(1024)
#                 if not u:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received u")

#                 # Receive `e` value from the client
#                 e = conn.recv(1024)
#                 if not e:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received e")

#                 # Update T using fast_server_update
#                 T = fast_server_update(u, e, T)
#                 print(f"Updated T")

#                 # Check for exit condition after processing the last pair
#                 if u == b"exit" or e == b"exit":
#                     print("Exit message received. Closing connection.")
#                     break

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")
#             return T


# T = start_server()
# print_contents_of_T(T)
# def start_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()

#         try:
#             while True:
#                 # Step 14: Receive u and e from client
#                 u = conn.recv(1024)  # Receive and decode the u-value
#                 if not u:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received u")

#                 e = conn.recv(1024)  # Receive and decode the e-value
#                 if not e:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received e")

#                 # Check for exit condition
#                 if u == b"exit" or e == b"exit":
#                     print("Exit message received. Closing connection.")
#                     break

#                 # Update T using fast_server_update
#                 T = fast_server_update(u, e, T)
#                 print(f"Updated T")

#         except Exception as ex:
#             print(f"An error occurred: {ex}")
#         finally:
#             conn.close()
#             print("Connection closed.")

# # To run the server
# if __name__ == "__main__":
#     start_server()
# def start_server():
#     # Server setup
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((SERVER, PORT))  # Use your desired IP and port
#     server.listen()
#     print("Server is listening...")

#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         T = fast_server_setup()

#         try:
#             while True:
#                 # Step 14: Receive u and e from client
#                 u = conn.recv(1024)  # Receive and decode the u-value
#                 if not u:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received u")

#                 e = conn.recv(1024)  # Receive and decode the e-value
#                 if not e:
#                     print("No data received. Closing connection.")
#                     break
#                 print(f"Received e")

#                 if u == b"exit" or e == b"exit":  # Exit condition
#                     print("Exit message received. Closing connection.")
#                     break

#                 # Update T using fast_server_update
#                 T = fast_server_update(u, e, T)
#                 print(f"Updated T")

#         except Exception as ex:
#             print(f"An error occurred: {ex}")

#         finally:
#             return T
#             conn.close()
#             print("Connection closed.")
#             break

# To run the server
# if __name__ == "__main__":
#     T = start_server()
#     print_contents_of_T(T)




# def start_server():
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     # SERVER = socket.gethostbyname(socket.gethostname())
#     server.bind((SERVER,PORT))  # Replace with your actual server address and port
#     server.listen()
#     print(f"Server is listening on {SERVER}:{PORT}")
#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")

#         # Step 14: Receive u and e from client
#         u = conn.recv(1024)  # Receive the u-value from the client
#         print(f"Received u")
#         e = conn.recv(1024)  # Receive the e-value from the client
#         print(f"Received e") 

#         T = fast_server_update(u,e)
        # thread = threading.Thread(target=fast_server_update, args=(conn, addr, T))
        # thread.start()
        # print(f"Active connections: {threading.active_count() - 1}")

    # conn, addr = server.accept()
    # print(f"Accepted connection from {addr}")
    # thread_1 = threading.Thread(target=fast_server_update, args=(conn, addr, T))
    # thread_1.start()
    # print(f"Active connections: {threading.active_count() - 1}")

    
    
    


# T = fast_server_setup()
# Start the server
# start_server()



# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind((SERVER,PORT))
# server.listen()

# print('Server is running...\n')
# client_socket, client_address = server.accept()

# while True:
#     u = client_socket.recv(1024)
#     e = client_socket.recv(1024)

#     if u or e == 'quit':
#         print('Ending connection from server side')
#         break

#     else:
#         T = fast_server_setup()
#         fast_server_update(u,e,T)


# ----------------------------------- SEARCH FUNCTION TESTING ------------------------------------------------------
# tw = b'\x01HO\xbb#{\x0b\ni\xa5\xf4\xe9$\x16X\xac\x89C\nL/\xa6`\xc8\xfd\x91c-\x1e\xce\xd1\xf9'
# stc = b'3\x8c\xa6\xf7\x82\xe2\x00\xd2X\x1f\x02\xcc*\xe7\xb6\xe1tp\x18\xab\xb6\xe5`\x94\xb3\x84\x84U\xbd\xb0W\x82\x08\x9c\x84\xc0\xab\x86|\xe4!K\x91j5\xd8\xb3m\xf2\x0f\x93\x90\x10\x92\x91 \x12\x0b\xae\xee\x05MA\xe4'
# c = 2
# T = fast_server_setup()

# u = hash_byte_string_blake2b(concatenate_byte_strings(tw,stc))
# print(u)

# for key, ele in T:
#     print(f"key - {key}, ele - {ele}")

# def test_fst_server_search(tw, stc, c, T):
    
#     # Step 3: Initialize result set and set of deleted file identifiers
#     ID = set()  # Using set for ID
#     delta = set()  # Using set for Δ (delta)
#     sti = stc

#     for i in range(c, 0, -1):  # Loop from c to 1
#         u = hash_byte_string_blake2b(concatenate_byte_strings(tw,sti))  # Compute hash H1(tw || sti)
#         print(f"U recv - {u}")
#         e = T.get(u)  # Retrieve e from the database T
#         print(f"E recv - {e}")

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

# results = fast_server_search(tw, stc, c, T)
# print(results)

